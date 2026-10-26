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
SCHEMA = "elevenid.installer-vm-overlay-creation/v2"
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


def _read_record(parent: int, name: str) -> tuple[bytes, dict]:
    release.require("/" not in name and name.endswith(".json"),
                    "VM creation record name invalid")
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    release.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                    and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                    and 0 < before.st_size <= 65536,
                    "VM creation record custody invalid")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        held = os.fstat(fd)
        release.require((held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns)
                        == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
                        "VM creation record changed")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, before.st_size - len(raw))
            release.require(bool(chunk), "VM creation record truncated")
            raw.extend(chunk)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        release.require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                        == (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns),
                        "VM creation record changed")
        record = release.decode(bytes(raw))
        release.require(release.encode(record) == raw,
                        "VM creation record is not canonical")
        return bytes(raw), record
    finally:
        os.close(fd)


def _same_disk(vm_fd: int, disk_fd: int) -> os.stat_result:
    held = os.fstat(disk_fd)
    named = os.stat("disk.qcow2", dir_fd=vm_fd, follow_symlinks=False)
    release.require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode)
                    and held.st_uid == named.st_uid == 0
                    and held.st_nlink == named.st_nlink == 1
                    and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino),
                    "VM overlay identity changed")
    return held


def _disk_digest(disk_fd: int) -> tuple[int, str]:
    """Hash the bounded, held overlay, rejecting mutation during the read."""
    before = os.fstat(disk_fd)
    release.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 64 * 1024 * 1024,
                    "VM overlay physical size invalid")
    digest = hashlib.sha256()
    os.lseek(disk_fd, 0, os.SEEK_SET)
    remaining = before.st_size
    while remaining:
        block = os.read(disk_fd, min(1024 * 1024, remaining))
        release.require(bool(block), "VM overlay truncated during digest")
        digest.update(block)
        remaining -= len(block)
    after = os.fstat(disk_fd)
    release.require((before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns),
                    "VM overlay changed during digest")
    return before.st_size, digest.hexdigest()


def _data_reference(value: object) -> bool:
    if type(value) is dict:
        return any(key in ("data-file", "data-file-raw") or _data_reference(item)
                   for key, item in value.items())
    if type(value) is list:
        return any(_data_reference(item) for item in value)
    return False


def validate_creation_records(intent_raw: bytes, intent: dict, receipt: dict,
                              vm_dir: Path, vm_id: str, checked_at: int) -> None:
    """Validate the complete immutable v2 record chain, independent of disk location."""
    release.exact(intent, {"schema", "phase", "vm_id", "image", "vm_dir",
                           "disk_path", "virtual_gib", "started_at",
                           "qualified", "launch_authorized"}, "VM creation intent")
    release.exact(receipt, {"schema", "phase", "vm_id", "intent_sha256",
                            "image", "vm_dir", "disk_path", "disk_device",
                            "disk_inode", "disk_bytes", "disk_sha256",
                            "virtual_gib", "created_at", "qualified",
                            "launch_authorized"}, "VM creation receipt")
    release.sha(receipt["disk_sha256"], 64)
    disk = vm_dir / "disk.qcow2"
    release.require(intent["schema"] == receipt["schema"] == SCHEMA
                    and intent["phase"] == "intent" and receipt["phase"] == "created"
                    and intent["vm_id"] == receipt["vm_id"] == vm_id
                    and receipt["intent_sha256"] == release.digest(intent_raw)
                    and intent["image"] == receipt["image"]
                    and intent["vm_dir"] == receipt["vm_dir"] == str(vm_dir)
                    and intent["disk_path"] == receipt["disk_path"] == str(disk)
                    and type(intent["virtual_gib"]) is int
                    and 20 <= intent["virtual_gib"] <= 512
                    and receipt["virtual_gib"] == intent["virtual_gib"]
                    and type(receipt["disk_device"]) is int
                    and type(receipt["disk_inode"]) is int
                    and type(receipt["disk_bytes"]) is int
                    and 0 < receipt["disk_bytes"] <= 64 * 1024 * 1024
                    and type(intent["started_at"]) is int
                    and type(receipt["created_at"]) is int
                    and 0 < intent["started_at"] <= receipt["created_at"]
                    <= min(checked_at + 5, intent["started_at"] + 600)
                    and intent["qualified"] is receipt["qualified"] is False
                    and intent["launch_authorized"] is receipt["launch_authorized"] is False,
                    "VM creation records disagree")


def verify_creation(source: Path, registry: Path, vm_parent: Path, *,
                    vm_id: str, now: int | None = None) -> dict:
    """Revalidate a root-held creation receipt before later seed/launch work."""
    release.require(os.geteuid() == 0 and type(vm_id) is str
                    and str(uuid.UUID(vm_id)) == vm_id and uuid.UUID(vm_id).version == 4,
                    "VM creation identity invalid")
    checked_at = int(time.time()) if now is None else now
    release.require(type(checked_at) is int and checked_at > 0,
                    "VM creation verification time invalid")
    registry_fd = _directory(registry)
    try:
        parent_fd = _directory(vm_parent)
        try:
            vm_dir = vm_parent / vm_id
            vm_fd = _directory(vm_dir)
            try:
                intent_raw, intent = _read_record(registry_fd, vm_id + ".creation-intent.json")
                receipt_raw, receipt = _read_record(registry_fd, vm_id + ".creation-receipt.json")
                disk = vm_dir / "disk.qcow2"
                validate_creation_records(intent_raw, intent, receipt,
                                          vm_dir, vm_id, checked_at)
                provenance = verify_source(source)
                release.require(receipt["image"] == provenance,
                                "VM creation source changed")
                disk_fd = os.open("disk.qcow2", os.O_RDONLY | os.O_NONBLOCK
                                  | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=vm_fd)
                try:
                    info = _same_disk(vm_fd, disk_fd)
                    release.require(type(receipt["disk_device"]) is int
                                    and type(receipt["disk_inode"]) is int
                                    and (info.st_dev, info.st_ino)
                                    == (receipt["disk_device"], receipt["disk_inode"])
                                    and stat.S_IMODE(info.st_mode) == 0o600,
                                    "VM creation disk differs")
                    release.require(type(receipt["disk_bytes"]) is int
                                    and type(receipt["disk_sha256"]) is str
                                    and len(receipt["disk_sha256"]) == 64,
                                    "VM creation disk digest invalid")
                    release.require(_disk_digest(disk_fd)
                                    == (receipt["disk_bytes"], receipt["disk_sha256"]),
                                    "VM creation disk bytes differ")
                    qemu = _image_info(disk)
                    release.require(qemu.get("virtual-size") == receipt["virtual_gib"] * 1024 ** 3
                                    and qemu.get("backing-filename") == provenance["image_path"]
                                    and qemu.get("backing-filename-format") in (None, "qcow2")
                                    and not _data_reference(qemu),
                                    "VM creation backing differs")
                    _same_disk(vm_fd, disk_fd)
                    release.require(_disk_digest(disk_fd)
                                    == (receipt["disk_bytes"], receipt["disk_sha256"]),
                                    "VM creation disk bytes changed during verification")
                finally:
                    os.close(disk_fd)
                _rebind_directory(registry, registry_fd)
                _rebind_directory(vm_parent, parent_fd)
                _rebind_directory(vm_dir, vm_fd)
                release.require(_read_record(registry_fd, vm_id + ".creation-intent.json")[0]
                                == intent_raw
                                and _read_record(registry_fd, vm_id + ".creation-receipt.json")[0]
                                == receipt_raw,
                                "VM creation records changed during verification")
                return receipt
            finally:
                os.close(vm_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(registry_fd)


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
            disk_bytes, disk_sha256 = _disk_digest(disk_fd)
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
                           disk_bytes=disk_bytes, disk_sha256=disk_sha256,
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
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            record = verify_creation(args.source, args.registry, args.vm_parent,
                                     vm_id=args.vm_id)
            release.require(record["virtual_gib"] == args.virtual_gib,
                            "VM creation requested size differs")
        else:
            create_overlay(args.source, args.registry, args.vm_parent,
                           vm_id=args.vm_id, virtual_gib=args.virtual_gib)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM creation refused or uncertain; retain the intent and disk for review.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
