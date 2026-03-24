"""SSH Agent 소켓 프로토콜 및 키 관리 유틸리티."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import subprocess
import tempfile

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
    try:
        return load_ssh_private_key(key_data, password=pw)
    except Exception:
        pass
    return load_pem_private_key(key_data, password=pw)


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


# ── Fingerprint ───────────────────────────────────────────────────────────

def get_key_fingerprint(key_data: bytes) -> str | None:
    """PEM 개인키 데이터의 SHA256 fingerprint를 반환."""
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as tmp:
            tmp.write(key_data)
            tmp_path = tmp.name
        result = subprocess.run(
            ["ssh-keygen", "-lf", tmp_path],
            capture_output=True, text=True, timeout=5,
        )
        os.unlink(tmp_path)
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split()
        if len(parts) >= 2 and parts[1].startswith("SHA256:"):
            return parts[1]
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
    return None
