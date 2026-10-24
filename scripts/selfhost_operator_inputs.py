"""Shared input checks for self-host KMS operator commands.

Importing this module performs no provisioning, subprocess or filesystem I/O.
Keep command-specific policy, AppRole and generation orchestration at its owner.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import urlsplit


def private_file(path: Path) -> str:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or path.stat().st_size > 64 * 1024
            or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise ValueError("operator input file is absent or not private")
    return path.read_text(encoding="utf-8")


def private_empty_or_source(path: Path, *, empty: bool) -> Path:
    if os.name != "posix" or not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError("secret generation requires an existing POSIX private directory")
    info = path.stat()
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("secret generation directory must be owner-private")
    if empty and any(path.iterdir()):
        raise ValueError("new secret generation directory must be empty")
    return path.resolve()


def write_private(path: Path, value: str, *, max_bytes: int = 512) -> None:
    if not value or "\n" in value or "\r" in value or len(value) > max_bytes:
        raise ValueError("renewal credential is invalid")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(value + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def snapshot_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname not in
            ("127.0.0.1", "localhost", "::1") or not parsed.port
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("snapshot OpenBao URL must be a local loopback HTTPS origin")
    return value.rstrip("/")
