from __future__ import annotations

import os
from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def _read_version() -> str:
    version = _VERSION_FILE.read_text(encoding="utf-8").strip()
    if not version:
        raise RuntimeError(f"empty Vysion version file: {_VERSION_FILE}")
    return version


VYSION_VERSION = _read_version()
VYSION_REVISION = os.environ.get("VYSION_REVISION", "unknown").strip() or "unknown"
