"""Internationalization support for keepass_cli using Python gettext."""

from __future__ import annotations

import gettext
import os
from pathlib import Path

_LOCALE_DIR = Path(__file__).parent / "locale"


def _detect_language() -> str:
    """Detect language from environment variables."""
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(var, "")
        if val:
            if val.startswith("ko"):
                return "ko"
            if val.startswith("en"):
                return "en"
    return "en"


def _setup_translation() -> gettext.NullTranslations:
    lang = _detect_language()
    try:
        return gettext.translation(
            "keepass_cli",
            localedir=str(_LOCALE_DIR),
            languages=[lang],
        )
    except FileNotFoundError:
        return gettext.NullTranslations()


_translation = _setup_translation()
_ = _translation.gettext
