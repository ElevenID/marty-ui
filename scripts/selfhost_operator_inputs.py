"""Shared input checks for self-host KMS operator commands.

Importing this module performs no provisioning, subprocess or filesystem I/O.
Keep command-specific policy, AppRole and generation orchestration at its owner.
"""

from __future__ import annotations

import os
import json
from collections.abc import Callable
import stat
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .selfhost_native_operator import OperatorCleanupError, operator_bytes
else:
    from selfhost_native_operator import OperatorCleanupError, operator_bytes


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


def private_operator_directory(path: Path, source_root: Path) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_dir()
            or stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError("operator directory must be an existing private directory")
    resolved = path.resolve()
    if resolved.is_relative_to(source_root):
        raise ValueError("operator directory must be outside the source checkout")
    return resolved


def write_owned(path: Path, value: str, mode: int, owner: os.stat_result) -> None:
    """Create only our file, preserving its install owner and role-specific mode."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    created = None
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            created = os.fstat(stream.fileno())
            stream.write(value)
            os.fchown(stream.fileno(), owner.st_uid, owner.st_gid)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception as error:
        if created is None:
            raise OperatorCleanupError("Scoped token refresh requires operator recovery") from error
        try:
            # Private directories remain single-writer. Preserve replacements observed
            # here; this is best-effort cleanup, not an atomic conditional unlink.
            if os.path.samestat(created, path.lstat()):
                path.unlink()
        except FileNotFoundError:
            pass
        raise



def _sync_directory(path: Path) -> None:
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def refresh_scoped_token(bao, token_file: Path, token: str,
                         write: Callable[[Path, str, int], None]) -> None:
    """Stage before native revocation; ambiguity keeps both credentials recoverable."""
    old_token = token_file.read_text(encoding="ascii").strip()
    temporary = token_file.with_name(token_file.name + ".new")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("pending custody token refresh requires operator recovery")
    write(temporary, token, 0o400)
    try:
        # Make the replacement name durable before revoking the old token.
        _sync_directory(token_file.parent)
        operator_bytes(Path(__file__).resolve().parents[1], "operator", "leaf-refresh", bao.endpoint, str(bao.ca),
                       input=json.dumps({"old_token": old_token, "new_token": token,
                                         "operator_token": bao.token}).encode("utf-8"))
        os.replace(temporary, token_file)
        _sync_directory(token_file.parent)
    except OSError as error:
        raise OperatorCleanupError("Scoped token refresh requires operator recovery") from error
