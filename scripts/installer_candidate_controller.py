"""Durably consume a controller dispatch before returning its unsigned receipt.

The caller authenticates the authorization/inventory and independent context,
observes the selected guest/disk/engine, and owns this registry OUTSIDE the guest.
Only the returned bytes may be signed and dispatched. No signing, VM creation,
SSH, installation or acceptance result is performed here. Never copy a guest
snapshot over this registry, remove consumed entries, or retry uncertain writes.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat

import installer_release as release


def _directory(path: Path) -> int:
    release.require(path.is_absolute() and ".." not in path.parts,
                    "controller registry path invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            release.require(info.st_uid in (0, os.geteuid())
                            and (not info.st_mode & 0o022
                                 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                            "controller registry ancestor is untrusted")
        info = os.fstat(fd)
        release.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        "controller registry must be private and caller-owned")
        return fd
    except BaseException:
        os.close(fd)
        raise


def consume(registry: Path, authorization: bytes, inventory: bytes, *, expected: dict,
            guest_id: str, disk_id: str, engine_id: str, installation_id: str,
            consumed_at: int, now: int) -> bytes:
    """One dispatch per nonce in this controller registry, not global one-use.

    Existing entries, including zero-byte crash remnants, refuse every replay.
    The returned unsigned bytes are the exact durable record. A signing failure
    still consumes the dispatch; do not silently issue a replacement transaction.
    """
    receipt = release.controller_consumption(
        authorization, inventory, expected=expected, guest_id=guest_id, disk_id=disk_id,
        engine_id=engine_id, installation_id=installation_id, consumed_at=consumed_at, now=now)
    raw = release.encode(receipt)
    release.require(len(raw) <= release.acceptance.MAX_REPORT_BYTES,
                    "controller receipt exceeds bound")
    parent = _directory(registry)
    locked = False
    owner_pid = os.getpid()
    try:
        locked = True
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = _directory(registry)
        try:
            held, observed = os.fstat(parent), os.fstat(current)
            release.require((held.st_dev, held.st_ino) == (observed.st_dev, observed.st_ino),
                            "controller registry changed")
        finally:
            os.close(current)
        fd = os.open(receipt["nonce"] + ".json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            os.fsync(parent)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.fsync(parent)
        finally:
            os.close(fd)
        return raw
    finally:
        try:
            if locked and os.getpid() == owner_pid:
                while True:
                    try:
                        fcntl.flock(parent, fcntl.LOCK_UN)
                        break
                    except InterruptedError:
                        continue
        finally:
            os.close(parent)
