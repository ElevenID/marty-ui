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


class ControllerLease:
    """Hold the outside-guest registry lock across observation and consumption."""

    def __init__(self, registry: Path):
        self.registry = registry
        self.parent: int | None = None
        self.owner_pid: int | None = None

    def __enter__(self) -> "ControllerLease":
        release.require(self.parent is None, "controller lease already active")
        parent = _directory(self.registry)
        attempted = False
        owner_pid = os.getpid()
        try:
            attempted = True
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = _directory(self.registry)
            try:
                held, observed = os.fstat(parent), os.fstat(current)
                release.require((held.st_dev, held.st_ino) == (observed.st_dev, observed.st_ino),
                                "controller registry changed")
            finally:
                os.close(current)
            self.parent = parent
            self.owner_pid = owner_pid
            return self
        except BaseException:
            try:
                if attempted:
                    _unlock(parent, owner_pid)
            finally:
                os.close(parent)
            raise

    def consume(self, authorization: bytes, inventory: bytes, *, expected: dict,
                guest_id: str, disk_id: str, engine_id: str, installation_id: str,
                consumed_at: int, now: int) -> bytes:
        """Persist exactly one receipt while this controller holds the registry."""
        release.require(self.parent is not None and self.owner_pid == os.getpid(),
                        "controller lease is not held by this process")
        receipt = release.controller_consumption(
            authorization, inventory, expected=expected, guest_id=guest_id, disk_id=disk_id,
            engine_id=engine_id, installation_id=installation_id, consumed_at=consumed_at,
            now=now)
        raw = release.encode(receipt)
        release.require(len(raw) <= release.acceptance.MAX_REPORT_BYTES,
                        "controller receipt exceeds bound")
        current = _directory(self.registry)
        try:
            held, observed = os.fstat(self.parent), os.fstat(current)
            release.require((held.st_dev, held.st_ino) == (observed.st_dev, observed.st_ino),
                            "controller registry changed")
        finally:
            os.close(current)
        fd = os.open(receipt["nonce"] + ".json",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.parent)
        try:
            os.fsync(self.parent)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
            os.fsync(self.parent)
        finally:
            os.close(fd)
        current = _directory(self.registry)
        try:
            held, observed = os.fstat(self.parent), os.fstat(current)
            release.require((held.st_dev, held.st_ino) == (observed.st_dev, observed.st_ino),
                            "controller registry changed after consumption")
        finally:
            os.close(current)
        return raw

    def __exit__(self, _kind, _value, _traceback) -> None:
        parent, owner_pid = self.parent, self.owner_pid
        self.parent = None
        self.owner_pid = None
        if parent is None:
            return
        try:
            _unlock(parent, owner_pid)
        finally:
            os.close(parent)


def _unlock(parent: int, owner_pid: int | None) -> None:
    if owner_pid != os.getpid():
        return
    while True:
        try:
            fcntl.flock(parent, fcntl.LOCK_UN)
            return
        except InterruptedError:
            continue


def consume(registry: Path, authorization: bytes, inventory: bytes, *, expected: dict,
            guest_id: str, disk_id: str, engine_id: str, installation_id: str,
            consumed_at: int, now: int) -> bytes:
    """One dispatch per nonce. Even a partial durable entry refuses replay."""
    with ControllerLease(registry) as lease:
        return lease.consume(authorization, inventory, expected=expected, guest_id=guest_id,
                             disk_id=disk_id, engine_id=engine_id,
                             installation_id=installation_id, consumed_at=consumed_at, now=now)
