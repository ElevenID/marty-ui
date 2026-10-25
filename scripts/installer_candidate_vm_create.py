#!/usr/bin/env python3
"""Create one source-authenticated QEMU overlay; never approve or launch a VM.

Run as root on the trusted Linux controller. The source directory must contain
the official Ubuntu cloud image, its SHA256SUMS and detached signature under
root custody. An intent is durable before any overlay creation. Uncertain or
failed operations retain their intent and partial disk for manual reconciliation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from installer_candidate_controller import _directory
from installer_host_probe import command
import installer_release as release


IMAGE = "noble-server-cloudimg-amd64.img"
SCHEMA = "elevenid.installer-vm-overlay-creation/v1"
TOOLS = (Path("/usr/bin/gpgv"), Path("/usr/bin/qemu-img"))
KEYRING = Path("/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg")
MAX_IMAGE = 2 * 1024 * 1024 * 1024
ENV = {"HOME": "/", "PATH": "/usr/bin:/bin", "LANG": "C"}


def _trusted_file(path: Path, *, maximum: int, readonly: bool = False) -> os.stat_result:
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and info.st_nlink == 1 and 0 < info.st_size <= maximum
                    and not info.st_mode & 0o022
                    and (not readonly or not info.st_mode & 0o222),
                    "VM source file custody invalid")
    return info


def _bytes(path: Path, maximum: int) -> bytes:
    before = _trusted_file(path, maximum=maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        held = os.fstat(fd)
        release.require((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                        "VM source file changed")
        chunks = []
        total = 0
        while chunk := os.read(fd, min(65536, maximum + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            release.require(total <= maximum, "VM source file oversized")
            if total == before.st_size:
                break
        raw = b"".join(chunks)
        after = path.lstat()
        release.require(len(raw) == before.st_size
                        and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                        == (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns),
                        "VM source file changed")
        return raw
    finally:
        os.close(fd)


def _digest_file(path: Path, maximum: int) -> str:
    before = _trusted_file(path, maximum=maximum, readonly=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        held = os.fstat(fd)
        release.require((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                        "VM base image changed")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            release.require(total <= before.st_size, "VM base image grew")
            digest.update(chunk)
        after = path.lstat()
        release.require(total == before.st_size
                        and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                        == (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns),
                        "VM base image changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _source_dir(path: Path) -> None:
    release.require(path.is_absolute() and ".." not in path.parts
                    and path.resolve() == path, "VM source path invalid")
    for item in (path, *path.parents):
        info = item.lstat()
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                        and (not info.st_mode & 0o022
                             or info.st_mode & stat.S_ISVTX),
                        "VM source ancestor custody invalid")


def _tool(path: Path) -> None:
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and not info.st_mode & 0o022 and info.st_mode & 0o111,
                    "VM source tool custody invalid")


def _rebind_directory(path: Path, held: int) -> None:
    current = _directory(path)
    try:
        old, new = os.fstat(held), os.fstat(current)
        release.require((old.st_dev, old.st_ino) == (new.st_dev, new.st_ino),
                        "VM controller directory changed")
    finally:
        os.close(current)


def _external_reference(value: object) -> bool:
    if type(value) is dict:
        return any(key in ("backing-filename", "full-backing-filename",
                           "backing-filename-format", "data-file", "data-file-raw")
                   or _external_reference(item) for key, item in value.items())
    if type(value) is list:
        return any(_external_reference(item) for item in value)
    return False


def _image_info(path: Path) -> dict:
    result = json.loads(command([str(TOOLS[1]), "info", "--output=json", str(path)],
                                env=ENV, timeout=30, limit=65536))
    release.require(type(result) is dict and result.get("format") == "qcow2",
                    "VM image format invalid")
    return result


def verify_source(source: Path) -> dict:
    """Verify the signed official checksum and exact immutable image bytes."""
    release.require(os.geteuid() == 0, "root controller required")
    _source_dir(source)
    for path in (*TOOLS, KEYRING):
        _tool(path) if path in TOOLS else _trusted_file(path, maximum=1024 * 1024)
    sums_path, signature_path = source / "SHA256SUMS", source / "SHA256SUMS.gpg"
    sums = _bytes(sums_path, 1024 * 1024)
    signature = _bytes(signature_path, 65536)
    keyring = _bytes(KEYRING, 1024 * 1024)
    command([str(TOOLS[0]), "--keyring", str(KEYRING), str(signature_path),
             str(sums_path)], env=ENV, timeout=30, limit=4096)
    # Recheck the exact authenticated inputs after gpgv opened their pathnames.
    release.require(_bytes(sums_path, 1024 * 1024) == sums
                    and _bytes(signature_path, 65536) == signature
                    and _bytes(KEYRING, 1024 * 1024) == keyring,
                    "signed VM source changed")
    entries = []
    for line in sums.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        release.require(match is not None, "signed VM checksum format invalid")
        if match.group(2) == IMAGE:
            entries.append(match.group(1))
    release.require(len(entries) == 1, "signed VM image entry unavailable")
    image = source / IMAGE
    actual = _digest_file(image, MAX_IMAGE)
    release.require(actual == entries[0], "signed VM image digest differs")
    release.require(not _external_reference(_image_info(image)),
                    "signed VM image has external dependencies")
    return dict(image_path=str(image), image_sha256=actual,
                manifest_sha256=release.digest(sums),
                signature_sha256=release.digest(signature),
                keyring_sha256=release.digest(keyring))


def _write(parent: int, name: str, record: dict) -> bytes:
    raw = release.encode(record)
    release.require(len(raw) <= 65536 and "/" not in name, "VM creation record invalid")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
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


def _same_disk(vm_fd: int, disk_fd: int) -> os.stat_result:
    held = os.fstat(disk_fd)
    named = os.stat("disk.qcow2", dir_fd=vm_fd, follow_symlinks=False)
    release.require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode)
                    and held.st_uid == named.st_uid == 0
                    and held.st_nlink == named.st_nlink == 1
                    and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
                    "VM overlay identity changed")
    return held


def _create_held(source: Path, registry: Path, vm_parent: Path, *, vm_id: str,
                 virtual_gib: int, provenance: dict, registry_fd: int,
                 vm_parent_fd: int, now: int | None) -> dict:
    image = Path(provenance["image_path"])
    vm_dir = vm_parent / vm_id
    disk = vm_dir / "disk.qcow2"
    started_at = int(time.time()) if now is None else now
    release.require(type(started_at) is int and started_at > 0,
                    "VM creation time invalid")
    intent = dict(schema=SCHEMA, phase="intent", vm_id=vm_id,
                  image=provenance, vm_dir=str(vm_dir), disk_path=str(disk),
                  virtual_gib=virtual_gib, started_at=started_at,
                  qualified=False, launch_authorized=False)
    _rebind_directory(registry, registry_fd)
    _rebind_directory(vm_parent, vm_parent_fd)
    _write(registry_fd, vm_id + ".creation-intent.json", intent)
    _rebind_directory(registry, registry_fd)
    _rebind_directory(vm_parent, vm_parent_fd)
    os.mkdir(vm_id, mode=0o700, dir_fd=vm_parent_fd)
    os.fsync(vm_parent_fd)
    vm_fd = os.open(vm_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=vm_parent_fd)
    try:
        directory = os.fstat(vm_fd)
        release.require(directory.st_uid == 0 and stat.S_IMODE(directory.st_mode) == 0o700,
                        "new VM directory custody invalid")
        _rebind_directory(vm_dir, vm_fd)
        command([str(TOOLS[1]), "create", "-f", "qcow2", "-F", "qcow2",
                 "-b", str(image), str(disk)], env=ENV, timeout=60, limit=16384)
        _rebind_directory(vm_parent, vm_parent_fd)
        _rebind_directory(vm_dir, vm_fd)
        disk_fd = os.open("disk.qcow2", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=vm_fd)
        try:
            _same_disk(vm_fd, disk_fd)
            command([str(TOOLS[1]), "resize", "-f", "qcow2", str(disk),
                     str(virtual_gib) + "G"], env=ENV, timeout=60, limit=16384)
            _rebind_directory(vm_parent, vm_parent_fd)
            _rebind_directory(vm_dir, vm_fd)
            _same_disk(vm_fd, disk_fd)
            info = _image_info(disk)
            release.require(info.get("virtual-size") == virtual_gib * 1024 ** 3
                            and info.get("backing-filename") == str(image)
                            and info.get("backing-filename-format") in (None, "qcow2")
                            and "data-file" not in info,
                            "VM overlay backing or size differs")
            os.fchmod(disk_fd, 0o600)
            disk_info = _same_disk(vm_fd, disk_fd)
            release.require(stat.S_IMODE(disk_info.st_mode) == 0o600,
                            "VM overlay custody invalid")
            os.fsync(disk_fd)
            os.fsync(vm_fd)
            _rebind_directory(registry, registry_fd)
            _rebind_directory(vm_parent, vm_parent_fd)
            _rebind_directory(vm_dir, vm_fd)
            _same_disk(vm_fd, disk_fd)
            release.require(_digest_file(image, MAX_IMAGE) == provenance["image_sha256"]
                            and release.digest(_bytes(source / "SHA256SUMS", 1024 * 1024))
                            == provenance["manifest_sha256"]
                            and release.digest(_bytes(source / "SHA256SUMS.gpg", 65536))
                            == provenance["signature_sha256"]
                            and release.digest(_bytes(KEYRING, 1024 * 1024))
                            == provenance["keyring_sha256"],
                            "VM source changed after overlay creation")
            receipt = dict(schema=SCHEMA, phase="created", vm_id=vm_id,
                           intent_sha256=release.digest(release.encode(intent)),
                           image=provenance, vm_dir=str(vm_dir), disk_path=str(disk),
                           disk_device=disk_info.st_dev, disk_inode=disk_info.st_ino,
                           virtual_gib=virtual_gib, created_at=int(time.time()),
                           qualified=False, launch_authorized=False)
            _write(registry_fd, vm_id + ".creation-receipt.json", receipt)
            _rebind_directory(registry, registry_fd)
            _rebind_directory(vm_parent, vm_parent_fd)
            _rebind_directory(vm_dir, vm_fd)
            _same_disk(vm_fd, disk_fd)
            return receipt
        finally:
            os.close(disk_fd)
    finally:
        os.close(vm_fd)


def create_overlay(source: Path, registry: Path, vm_parent: Path, *,
                   vm_id: str, virtual_gib: int, now: int | None = None) -> dict:
    """Create a single fresh disk; receipt is creation evidence, not VM approval."""
    release.require(os.geteuid() == 0 and type(vm_id) is str
                    and str(uuid.UUID(vm_id)) == vm_id and uuid.UUID(vm_id).version == 4
                    and type(virtual_gib) is int and 20 <= virtual_gib <= 512,
                    "VM creation request invalid")
    for tool in TOOLS:
        _tool(tool)
    provenance = verify_source(source)
    registry_fd = _directory(registry)
    try:
        vm_parent_fd = _directory(vm_parent)
        try:
            return _create_held(source, registry, vm_parent, vm_id=vm_id,
                                virtual_gib=virtual_gib, provenance=provenance,
                                registry_fd=registry_fd, vm_parent_fd=vm_parent_fd,
                                now=now)
        finally:
            os.close(vm_parent_fd)
    finally:
        os.close(registry_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--virtual-gib", required=True, type=int)
    args = parser.parse_args()
    try:
        create_overlay(args.source, args.registry, args.vm_parent,
                       vm_id=args.vm_id, virtual_gib=args.virtual_gib)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM creation refused or uncertain; retain the intent and disk for review.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
