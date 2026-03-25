"""SSH Agent 소켓 프로토콜 및 키 관리 유틸리티."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_ssh_private_key,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ── SSH Agent 프로토콜 상수 ────────────────────────────────────────────────
SSH2_AGENTC_REQUEST_IDENTITIES = 11
SSH2_AGENT_IDENTITIES_ANSWER = 12
SSH2_AGENTC_ADD_IDENTITY = 17
SSH2_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENT_SUCCESS = 6
SSH_AGENT_FAILURE = 5


# ── 프로토콜 인코딩 ───────────────────────────────────────────────────────

def _ssh_string(data: bytes) -> bytes:
    """SSH 프로토콜의 string 타입으로 인코딩."""
    return struct.pack(">I", len(data)) + data


def _ssh_mpint(n: int) -> bytes:
    """정수를 SSH mpint 형식으로 인코딩."""
    if n == 0:
        return _ssh_string(b"")
    nbytes = (n.bit_length() + 8) // 8  # 부호 비트 포함
    b = n.to_bytes(nbytes, byteorder="big", signed=False)
    if b[0] & 0x80:
        b = b"\x00" + b
    return _ssh_string(b)


# ── 소켓 통신 ─────────────────────────────────────────────────────────────

def _agent_request(payload: bytes) -> bytes | None:
    """SSH agent 소켓에 요청을 보내고 응답을 반환."""
    sock_path = os.environ.get("SSH_AUTH_SOCK", "")
    if not sock_path:
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(sock_path)
        msg = struct.pack(">I", len(payload)) + payload
        s.sendall(msg)
        resp_len_raw = b""
        while len(resp_len_raw) < 4:
            chunk = s.recv(4 - len(resp_len_raw))
            if not chunk:
                return None
            resp_len_raw += chunk
        resp_len = struct.unpack(">I", resp_len_raw)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = s.recv(resp_len - len(resp))
            if not chunk:
                return None
            resp += chunk
        s.close()
        return resp
    except Exception:
        return None


# ── Agent 키 조회 ─────────────────────────────────────────────────────────

def _blob_fingerprint(blob: bytes) -> str:
    """Public key blob의 SHA256 fingerprint를 반환."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()


def get_agent_key_map() -> dict[str, bytes]:
    """SSH agent에 로드된 키들의 {fingerprint: blob} 딕셔너리를 반환."""
    resp = _agent_request(bytes([SSH2_AGENTC_REQUEST_IDENTITIES]))
    if not resp or resp[0] != SSH2_AGENT_IDENTITIES_ANSWER:
        return {}
    offset = 1
    if len(resp) < offset + 4:
        return {}
    nkeys = struct.unpack(">I", resp[offset:offset + 4])[0]
    offset += 4
    result: dict[str, bytes] = {}
    for _ in range(nkeys):
        if offset + 4 > len(resp):
            break
        blob_len = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4
        if offset + blob_len > len(resp):
            break
        blob = resp[offset:offset + blob_len]
        fp = _blob_fingerprint(blob)
        result[fp] = blob
        offset += blob_len
        if offset + 4 > len(resp):
            break
        comment_len = struct.unpack(">I", resp[offset:offset + 4])[0]
        offset += 4 + comment_len
    return result


# ── Agent 키 제거 ─────────────────────────────────────────────────────────

def agent_remove_key(blob: bytes) -> bool:
    """SSH agent에서 지정된 public key blob에 해당하는 키를 제거."""
    payload = bytes([SSH2_AGENTC_REMOVE_IDENTITY])
    payload += _ssh_string(blob)
    resp = _agent_request(payload)
    return resp is not None and len(resp) >= 1 and resp[0] == SSH_AGENT_SUCCESS


# ── 키 판별 ───────────────────────────────────────────────────────────────

def is_ssh_private_key(key_data: bytes) -> bool:
    """바이너리 데이터가 SSH 개인키인지 판별."""
    header = key_data[:40]
    if header.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        return True
    if header.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
        return True
    if header.startswith(b"-----BEGIN EC PRIVATE KEY-----"):
        return True
    if header.startswith(b"-----BEGIN DSA PRIVATE KEY-----"):
        return True
    if header.startswith(b"-----BEGIN PRIVATE KEY-----"):
        try:
            key = load_pem_private_key(key_data, password=None)
            return isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey,
                                    ed25519.Ed25519PrivateKey))
        except Exception:
            return False
    if header.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        return True
    return False


# ── 키 로드 및 Agent 추가 ─────────────────────────────────────────────────

def _load_private_key(key_data: bytes, passphrase: str | None = None):
    """PEM 또는 OpenSSH 형식의 개인키를 로드. 키 객체를 반환."""
    pw = passphrase.encode() if passphrase else None
    # OpenSSH 형식은 load_pem_private_key가 인식 못하므로 전용 함수만 사용
    if key_data.lstrip()[:35].startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        return load_ssh_private_key(key_data, password=pw)
    # 전통적인 PEM 형식 (RSA/EC/DSA/PKCS8)
    try:
        return load_pem_private_key(key_data, password=pw)
    except Exception:
        pass
    return load_ssh_private_key(key_data, password=pw)


def _build_add_identity_payload(private_key, comment: str = "") -> bytes:
    """SSH2_AGENTC_ADD_IDENTITY 메시지 본문을 생성."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        nums = private_key.private_numbers()
        pub = nums.public_numbers
        payload = bytes([SSH2_AGENTC_ADD_IDENTITY])
        payload += _ssh_string(b"ssh-rsa")
        payload += _ssh_mpint(pub.n)
        payload += _ssh_mpint(pub.e)
        payload += _ssh_mpint(nums.d)
        payload += _ssh_mpint(nums.iqmp)
        payload += _ssh_mpint(nums.p)
        payload += _ssh_mpint(nums.q)
        payload += _ssh_string(comment.encode())
        return payload

    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        pub_bytes = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw,
        )
        priv_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        payload = bytes([SSH2_AGENTC_ADD_IDENTITY])
        payload += _ssh_string(b"ssh-ed25519")
        payload += _ssh_string(pub_bytes)
        payload += _ssh_string(priv_bytes + pub_bytes)
        payload += _ssh_string(comment.encode())
        return payload

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        curve = private_key.curve
        curve_map = {
            "secp256r1": ("ecdsa-sha2-nistp256", "nistp256"),
            "secp384r1": ("ecdsa-sha2-nistp384", "nistp384"),
            "secp521r1": ("ecdsa-sha2-nistp521", "nistp521"),
        }
        curve_name = curve.name
        if curve_name not in curve_map:
            raise ValueError(f"지원하지 않는 EC 곡선: {curve_name}")
        key_type, nist_name = curve_map[curve_name]
        pub_bytes = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint,
        )
        priv_num = private_key.private_numbers().private_value
        payload = bytes([SSH2_AGENTC_ADD_IDENTITY])
        payload += _ssh_string(key_type.encode())
        payload += _ssh_string(nist_name.encode())
        payload += _ssh_string(pub_bytes)
        payload += _ssh_mpint(priv_num)
        payload += _ssh_string(comment.encode())
        return payload

    raise ValueError(f"지원하지 않는 키 타입: {type(private_key).__name__}")


def agent_add_key(key_data: bytes, passphrase: str | None = None,
                  comment: str = "") -> tuple[bool, str]:
    """SSH agent에 개인키를 추가. (성공 여부, 에러 힌트) 반환."""
    try:
        private_key = _load_private_key(key_data, passphrase)
    except TypeError:
        return False, "passphrase_required"
    except ValueError as e:
        msg = str(e).lower()
        if "password" in msg or "passphrase" in msg or "decrypt" in msg:
            return False, "passphrase_required"
        return False, str(e)
    except Exception as e:
        msg = str(e).lower()
        if "password" in msg or "passphrase" in msg or "encrypt" in msg:
            return False, "passphrase_required"
        return False, str(e)

    try:
        payload = _build_add_identity_payload(private_key, comment)
    except Exception as e:
        return False, str(e)

    resp = _agent_request(payload)
    if resp is not None and len(resp) >= 1 and resp[0] == SSH_AGENT_SUCCESS:
        return True, ""
    return False, "Agent가 키 추가를 거부했습니다"


# ── OpenSSH 키 Comment 추출 ────────────────────────────────────────────────

def _rd(buf: bytes, off: int) -> tuple[bytes, int]:
    """SSH string 타입 읽기."""
    n = struct.unpack(">I", buf[off:off + 4])[0]
    return buf[off + 4:off + 4 + n], off + 4 + n


def _parse_openssh_priv_comment(priv_data: bytes) -> str | None:
    """복호화된 OpenSSH 개인키 섹션에서 comment를 파싱."""
    try:
        check1 = struct.unpack(">I", priv_data[:4])[0]
        check2 = struct.unpack(">I", priv_data[4:8])[0]
        if check1 != check2:
            return None  # 복호화 실패 또는 잘못된 passphrase
        off = 8
        key_type_b, off = _rd(priv_data, off)
        key_type = key_type_b.decode()
        if key_type == "ssh-ed25519":
            _, off = _rd(priv_data, off)   # pubkey
            _, off = _rd(priv_data, off)   # privkey (64 bytes)
        elif key_type == "ssh-rsa":
            for _ in range(6):             # n, e, d, iqmp, p, q
                _, off = _rd(priv_data, off)
        elif key_type.startswith("ecdsa-sha2-"):
            _, off = _rd(priv_data, off)   # curve name
            _, off = _rd(priv_data, off)   # pubkey
            _, off = _rd(priv_data, off)   # private value
        else:
            return None
        comment_b, _ = _rd(priv_data, off)
        s = comment_b.decode(errors="replace")
        return s or None
    except Exception:
        return None


def _bcrypt_decrypt_openssh(cipher: str, kdf_opts: bytes,
                             password: bytes, data: bytes) -> bytes | None:
    """bcrypt KDF로 암호화된 OpenSSH 개인키 블록을 복호화."""
    try:
        import bcrypt as _bcrypt
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        salt_len = struct.unpack(">I", kdf_opts[:4])[0]
        salt = kdf_opts[4:4 + salt_len]
        rounds = struct.unpack(">I", kdf_opts[4 + salt_len:8 + salt_len])[0]

        if cipher in ("aes256-ctr", "aes256-cbc"):
            key_iv = _bcrypt.kdf(password, salt, 48, rounds, ignore_few_rounds=True)
            key, iv = key_iv[:32], key_iv[32:]
            mode = modes.CTR(iv) if cipher == "aes256-ctr" else modes.CBC(iv)
            dec = Cipher(algorithms.AES(key), mode).decryptor()
            return dec.update(data) + dec.finalize()

        if cipher == "chacha20-poly1305@openssh.com":
            # key[0:32] = 데이터 암호화 키(k2), key[32:64] = 헤더/poly1305 키(k1)
            key_material = _bcrypt.kdf(password, salt, 64, rounds, ignore_few_rounds=True)
            k2 = key_material[:32]
            ciphertext = data[:-16]  # 마지막 16 bytes = poly1305 tag 제거
            # IETF ChaCha20: 4-byte counter(LE) + 12-byte nonce
            # 데이터 암호화는 block counter=1, seqnr(nonce)=0
            nonce = b"\x01\x00\x00\x00" + b"\x00" * 12
            dec = Cipher(algorithms.ChaCha20(k2, nonce), mode=None).decryptor()
            return dec.update(ciphertext) + dec.finalize()

        return None
    except Exception:
        return None


def get_key_comment(key_data: bytes, passphrase: str | None = None) -> str | None:
    """OpenSSH 개인키 파일에서 comment를 추출."""
    try:
        stripped = key_data.strip()
        if not stripped.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
            return None

        lines = stripped.decode().splitlines()
        b64 = "".join(l for l in lines if not l.startswith("-----"))
        raw = base64.b64decode(b64)

        magic = b"openssh-key-v1\x00"
        if not raw.startswith(magic):
            return None

        off = len(magic)
        cipher_b, off = _rd(raw, off)
        kdf_b, off = _rd(raw, off)
        kdf_opts_b, off = _rd(raw, off)
        nkeys = struct.unpack(">I", raw[off:off + 4])[0]
        off += 4

        for _ in range(nkeys):
            _, off = _rd(raw, off)

        priv_blob, _ = _rd(raw, off)

        cipher = cipher_b.decode()
        kdf = kdf_b.decode()

        if cipher == "none":
            priv_data = priv_blob
        elif kdf == "bcrypt" and passphrase is not None:
            priv_data = _bcrypt_decrypt_openssh(
                cipher, kdf_opts_b, passphrase.encode(), priv_blob,
            )
            if priv_data is None:
                return None
        else:
            return None

        return _parse_openssh_priv_comment(priv_data)
    except Exception:
        return None


# ── Fingerprint ───────────────────────────────────────────────────────────

def get_key_fingerprint(key_data: bytes, passphrase: str | None = None) -> str | None:
    """개인키 데이터의 SHA256 fingerprint를 반환."""
    try:
        private_key = _load_private_key(key_data, passphrase=passphrase)
        pub_bytes = private_key.public_key().public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH,
        )
        # "ssh-type AAAA..." 형식에서 blob(두 번째 토큰) 추출
        blob = base64.b64decode(pub_bytes.split()[1])
        return _blob_fingerprint(blob)
    except Exception:
        return None
