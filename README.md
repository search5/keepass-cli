# megabird-pass

KeePass(KDBX) 데이터베이스를 터미널에서 조회하고, SSH 키를 관리하는 TUI 도구입니다.

## 설치

```bash
uv tool install dist/megabird_pass-0.2.0-py3-none-any.whl
```

또는 소스에서 직접:

```bash
uv tool install .
```

### 요구사항

- Python >= 3.9
- 의존성: pykeepass, textual, cryptography, appdirs

## 초기 설정

설치 후 최초 실행 전에 KDBX 데이터베이스 파일을 데이터 디렉터리에 넣어야 합니다.

```bash
megabird-db path    # 데이터 디렉터리 경로 확인
megabird-db push    # 현재 디렉터리의 database.kdbx를 데이터 디렉터리로 복사
```

DB 파일이 없으면 뷰어가 실행되지 않습니다.

## 사용법

### TUI 뷰어

```bash
megabird-pass                  # 기본 DB 파일 사용
megabird-pass /path/to/db.kdbx # 특정 파일 지정
```

실행하면 마스터 패스워드를 입력한 뒤 TUI가 열립니다.

### 키 바인딩

#### 공통

| 키 | 동작 |
|----|------|
| `1` | 비밀번호 탭 |
| `2` | SSH 키 탭 |
| `q` | 종료 |

#### 비밀번호 탭

| 키 | 동작 |
|----|------|
| `Tab` / `Shift+Tab` | 그룹 ↔ 항목 패널 전환 |
| `/` | 검색 (그룹명, 제목, 사용자명, URL) |
| `Esc` | 검색 초기화 |
| `u` | ID 클립보드 복사 |
| `p` | 비밀번호 클립보드 복사 |
| `h` | Host 클립보드 복사 |
| `l` | URL 클립보드 복사 |

#### SSH 키 탭

| 키 | 동작 |
|----|------|
| `a` | 선택한 키를 SSH agent에 추가 |
| `d` | 선택한 키를 SSH agent에서 제거 |

- KDBX에 첨부된 SSH 개인키(RSA, Ed25519, ECDSA)를 자동으로 인식합니다.
- SSH agent 소켓에 직접 통신하여 키 등록 상태를 확인합니다.
- passphrase가 필요한 키는 입력창이 자동으로 표시됩니다.

### DB 파일 관리

데이터베이스 파일은 OS별 데이터 디렉터리에 저장됩니다.

| OS | 경로 |
|----|------|
| macOS | `~/Library/Application Support/megabird_pass/database.kdbx` |
| Linux | `~/.local/share/megabird_pass/database.kdbx` |
| Windows | `C:\Users\<user>\AppData\Local\megabird_pass\database.kdbx` |

`megabird-db` 명령으로 DB 파일을 내보내거나 가져올 수 있습니다.

```bash
megabird-db path               # DB 파일 경로 확인
megabird-db pull               # appdirs → 현재 디렉터리로 복사
megabird-db pull -o backup.kdbx  # 파일명 지정
megabird-db push               # 현재 디렉터리 → appdirs로 저장
megabird-db push -i edited.kdbx  # 파일명 지정
```

덮어쓰기가 필요한 경우 `-f` 옵션을 사용합니다.

## 프로젝트 구조

```
megabird_pass/
  __init__.py
  viewer.py       # TUI 뷰어 (Textual)
  ssh_agent.py    # SSH agent 소켓 통신, 키 판별/추가/제거
  db.py           # DB 파일 관리 CLI
  database.kdbx   # 기본 데이터베이스 (패키지 번들)
main.py           # KDBX 초기 데이터 시딩 스크립트
```

## 라이선스

Internal use only.
