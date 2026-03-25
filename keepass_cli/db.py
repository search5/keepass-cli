"""CLI to copy KDBX database files between appdirs data directory and current directory."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import appdirs

from keepass_cli.i18n import _

APP_NAME = "keepass_cli"
DB_FILENAME = "database.kdbx"


def _data_path() -> Path:
    return Path(appdirs.user_data_dir(APP_NAME)) / DB_FILENAME


def cmd_pull(args: argparse.Namespace) -> None:
    """Copy from appdirs to current directory."""
    src = _data_path()
    if not src.exists():
        print(_("Database not found: {path}").format(path=src))
        sys.exit(1)
    dest = Path.cwd() / (args.output or DB_FILENAME)
    if dest.exists() and not args.force:
        print(_("Already exists: {path}").format(path=dest))
        print(_("Use --force option to overwrite."))
        sys.exit(1)
    shutil.copy2(src, dest)
    print(f"{src} → {dest}")


def cmd_push(args: argparse.Namespace) -> None:
    """Copy from current directory to appdirs."""
    src = Path.cwd() / (args.input or DB_FILENAME)
    if not src.exists():
        print(_("Source file not found: {path}").format(path=src))
        sys.exit(1)
    dest = _data_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not args.force:
        print(_("Already exists: {path}").format(path=dest))
        print(_("Use --force option to overwrite."))
        sys.exit(1)
    shutil.copy2(src, dest)
    print(f"{src} → {dest}")


def cmd_path(_args: argparse.Namespace) -> None:
    """Print database path."""
    p = _data_path()
    exists = _("exists") if p.exists() else _("not found")
    print(_("Filename:  {filename}").format(filename=DB_FILENAME))
    print(_("Path:    {path}  ({exists})").format(path=p, exists=exists))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="keepass-db",
        description=_("KDBX database file management"),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    data_path = _data_path()

    p_pull = sub.add_parser("pull", help=_("Copy from appdirs to current directory"),
                            epilog=f"Source: {data_path}")
    p_pull.add_argument("-o", "--output", help=_("Output filename (default: {filename})").format(filename=DB_FILENAME))
    p_pull.add_argument("-f", "--force", action="store_true", help=_("Overwrite existing file"))

    p_push = sub.add_parser("push", help=_("Copy from current directory to appdirs"),
                            epilog=f"Target: {data_path}")
    p_push.add_argument("-i", "--input", help=_("Input filename (default: {filename})").format(filename=DB_FILENAME))
    p_push.add_argument("-f", "--force", action="store_true", help=_("Overwrite existing file"))

    sub.add_parser("path", help=_("Show database path"))

    args = parser.parse_args()
    {"pull": cmd_pull, "push": cmd_push, "path": cmd_path}[args.command](args)


if __name__ == "__main__":
    main()
