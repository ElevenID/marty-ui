"""Stable hashes for text-based public demo assets."""

from __future__ import annotations

import hashlib
from pathlib import Path


CANONICAL_TEXT_ASSET_SUFFIXES = {".svg", ".vtt"}


def public_asset_sha256(path: Path) -> str:
    content = path.read_bytes()
    if path.suffix.lower() in CANONICAL_TEXT_ASSET_SUFFIXES:
        content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(content).hexdigest()
