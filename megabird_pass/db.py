"""KDBX 데이터베이스 파일을 appdirs 데이터 디렉터리와 현재 디렉터리 간에 복사하는 CLI."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import appdirs

APP_NAME = "megabird_pass"
DB_FILENAME = "database.kdbx"


def _data_path() -> Path:
    return Path(appdirs.user_data_dir(APP_NAME)) / DB_FILENAME


def cmd_pull(args: argparse.Namespace) -> None:
    """appdirs → 현재 디렉터리로 복사."""
    src = _data_path()
    if not src.exists():
        print(f"데이터베이스가 없습니다: {src}")
        sys.exit(1)
    dest = Path.cwd() / (args.output or DB_FILENAME)
    if dest.exists() and not args.force:
        print(f"이미 존재합니다: {dest}")
        print("덮어쓰려면 --force 옵션을 사용하세요.")
        sys.exit(1)
    shutil.copy2(src, dest)
    print(f"{src} → {dest}")


def cmd_push(args: argparse.Namespace) -> None:
    """현재 디렉터리 → appdirs로 복사."""
    src = Path.cwd() / (args.input or DB_FILENAME)
    if not src.exists():
        print(f"파일을 찾을 수 없습니다: {src}")
        sys.exit(1)
    dest = _data_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not args.force:
        print(f"이미 존재합니다: {dest}")
        print("덮어쓰려면 --force 옵션을 사용하세요.")
        sys.exit(1)
    shutil.copy2(src, dest)
    print(f"{src} → {dest}")


def cmd_path(_args: argparse.Namespace) -> None:
    """데이터베이스 경로 출력."""
    p = _data_path()
    exists = "존재함" if p.exists() else "없음"
    print(f"파일명:  {DB_FILENAME}")
    print(f"경로:    {p}  ({exists})")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="megabird-db",
        description="KDBX 데이터베이스 파일 관리",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    data_path = _data_path()

    p_pull = sub.add_parser("pull", help="appdirs에서 현재 디렉터리로 복사",
                            epilog=f"원본: {data_path}")
    p_pull.add_argument("-o", "--output", help=f"저장할 파일명 (기본: {DB_FILENAME})")
    p_pull.add_argument("-f", "--force", action="store_true", help="기존 파일 덮어쓰기")

    p_push = sub.add_parser("push", help="현재 디렉터리에서 appdirs로 저장",
                            epilog=f"대상: {data_path}")
    p_push.add_argument("-i", "--input", help=f"읽을 파일명 (기본: {DB_FILENAME})")
    p_push.add_argument("-f", "--force", action="store_true", help="기존 파일 덮어쓰기")

    sub.add_parser("path", help="데이터베이스 경로 출력")

    args = parser.parse_args()
    {"pull": cmd_pull, "push": cmd_push, "path": cmd_path}[args.command](args)


if __name__ == "__main__":
    main()
