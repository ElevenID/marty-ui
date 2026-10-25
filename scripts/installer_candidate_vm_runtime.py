#!/usr/bin/env python3
"""Move one authenticated pristine overlay into an unprivileged QEMU runtime.

This is a one-way custody transition, not seed, launch, approval or qualification.
An intent survives every failure; retry requires manual reconciliation and a new VM.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import stat
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as creation_module
from installer_candidate_vm_create import (_disk_digest, _read_record, _same_disk,
                                           _write, verify_creation)
import installer_release as release

SCHEMA = "elevenid.installer-vm-runtime-transfer/v1"


def _runtime_parent(path: Path) -> int:
    """Hold a root-owned, searchable but non-listable dedicated runtime parent."""
    release.require(path.is_absolute() and ".." not in path.parts and path != Path("/"),
                    "VM runtime parent path invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            release.require(info.st_uid == 0 and
                            (not info.st_mode & 0o022
                             or info.st_mode & stat.S_ISVTX),
                            "VM runtime ancestor is untrusted")
        info = os.fstat(fd)
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                        and stat.S_IMODE(info.st_mode) == 0o711,
                        "VM runtime parent must be root-owned mode 0711")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same_path(path: Path, held: int, opener) -> None:
    current = opener(path)
    try:
        old, new = os.fstat(held), os.fstat(current)
        release.require((old.st_dev, old.st_ino) == (new.st_dev, new.st_ino),
                        "VM custody path changed")
    finally:
        os.close(current)


def _identity(vm_id: str, uid: int, gid: int) -> str:
    release.require(type(uid) is int and type(gid) is int
                    and 100 <= uid <= 60000 and 100 <= gid <= 60000,
                    "VM runtime identity invalid")
    expected = "mvq_" + base64.b32encode(uuid.UUID(vm_id).bytes).decode("ascii").rstrip("=").lower()
    account = pwd.getpwuid(uid)
    release.require(account.pw_name == expected and account.pw_gid == gid
                    and account.pw_dir in ("/nonexistent", "/var/empty")
                    and account.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin"),
                    "VM runtime account is not dedicated")
    return expected


def _backing_readable(path: Path) -> None:
    """Require the public Ubuntu base to be traversable/readable by the VM UID."""
    for parent in reversed(path.parents):
        info = parent.lstat()
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                        and bool(info.st_mode & stat.S_IXOTH),
                        "VM base ancestor is not traversable")
    image = path.lstat()
    release.require(stat.S_ISREG(image.st_mode) and image.st_uid == 0
                    and bool(image.st_mode & stat.S_IROTH)
                    and not image.st_mode & 0o222,
                    "VM base is not readable by runtime")


def _named_disk(parent: int, held_fd: int, uid: int, gid: int) -> None:
    held = os.fstat(held_fd)
    named = os.stat("disk.qcow2", dir_fd=parent, follow_symlinks=False)
    release.require(stat.S_ISREG(held.st_mode) and stat.S_ISREG(named.st_mode)
                    and (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
                    and held.st_uid == named.st_uid == uid
                    and held.st_gid == named.st_gid == gid
                    and held.st_nlink == named.st_nlink == 1
                    and stat.S_IMODE(held.st_mode) == stat.S_IMODE(named.st_mode) == 0o600,
                    "VM runtime disk name differs")


def transfer(source: Path, registry: Path, vm_parent: Path, runtime_parent: Path, *,
             vm_id: str, uid: int, gid: int) -> dict:
    release.require(os.geteuid() == 0, "root controller required")
    with ControllerLease(registry) as lease:
        creation = verify_creation(source, registry, vm_parent, vm_id=vm_id)
        account = _identity(vm_id, uid, gid)
        _backing_readable(Path(creation["image"]["image_path"]))
        source_dir = vm_parent / vm_id
        target_dir = runtime_parent / vm_id
        vm_fd = _directory(source_dir)
        try:
            parent_fd = _runtime_parent(runtime_parent)
            try:
                release.require(os.fstat(vm_fd).st_dev == os.fstat(parent_fd).st_dev,
                                "VM overlay transfer requires one filesystem")
                _same_path(source_dir, vm_fd, _directory)
                _same_path(runtime_parent, parent_fd, _runtime_parent)
                _same_path(registry, lease.parent, _directory)
                creation_raw, _ = _read_record(lease.parent,
                                                vm_id + ".creation-receipt.json")
                release.require(release.digest(creation_raw) == release.digest(release.encode(creation)),
                                "VM creation receipt changed")
                intent = dict(schema=SCHEMA, phase="intent", vm_id=vm_id,
                              creation_receipt_sha256=release.digest(creation_raw),
                              source_path=creation["disk_path"], target_path=str(target_dir / "disk.qcow2"),
                              disk_device=creation["disk_device"], disk_inode=creation["disk_inode"],
                              disk_bytes=creation["disk_bytes"], disk_sha256=creation["disk_sha256"],
                              runtime_uid=uid, runtime_gid=gid, runtime_account=account,
                              started_at=int(time.time()), qualified=False,
                              launch_authorized=False)
                intent_raw = _write(lease.parent, vm_id + ".runtime-intent.json", intent)
                _same_path(registry, lease.parent, _directory)
                os.mkdir(vm_id, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
                target_fd = os.open(vm_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | os.O_CLOEXEC, dir_fd=parent_fd)
                try:
                    disk_fd = os.open("disk.qcow2", os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW
                                      | os.O_CLOEXEC, dir_fd=vm_fd)
                    try:
                        before = _same_disk(vm_fd, disk_fd)
                        release.require((before.st_dev, before.st_ino)
                                        == (creation["disk_device"], creation["disk_inode"])
                                        and _disk_digest(disk_fd)
                                        == (creation["disk_bytes"], creation["disk_sha256"]),
                                        "VM pristine overlay changed")
                        _same_path(source_dir, vm_fd, _directory)
                        _same_path(runtime_parent, parent_fd, _runtime_parent)
                        os.rename("disk.qcow2", "disk.qcow2", src_dir_fd=vm_fd,
                                  dst_dir_fd=target_fd)
                        moved = os.stat("disk.qcow2", dir_fd=target_fd, follow_symlinks=False)
                        release.require((moved.st_dev, moved.st_ino)
                                        == (before.st_dev, before.st_ino),
                                        "VM overlay move changed identity")
                        os.fchown(disk_fd, uid, gid)
                        os.fchmod(disk_fd, 0o600)
                        os.fsync(disk_fd)
                        os.fsync(vm_fd)
                        os.fsync(target_fd)
                        os.fsync(parent_fd)
                        after = os.fstat(disk_fd)
                        release.require((after.st_dev, after.st_ino, after.st_uid, after.st_gid)
                                        == (before.st_dev, before.st_ino, uid, gid)
                                        and _disk_digest(disk_fd)
                                        == (creation["disk_bytes"], creation["disk_sha256"]),
                                        "VM runtime overlay differs")
                        _named_disk(target_fd, disk_fd, uid, gid)
                        os.fchown(target_fd, uid, gid)
                        os.fchmod(target_fd, 0o700)
                        os.fsync(target_fd)
                        _named_disk(target_fd, disk_fd, uid, gid)
                        rebound = os.open(vm_id, os.O_RDONLY | os.O_DIRECTORY
                                          | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
                        try:
                            release.require((os.fstat(rebound).st_dev, os.fstat(rebound).st_ino)
                                            == (os.fstat(target_fd).st_dev, os.fstat(target_fd).st_ino),
                                            "VM runtime directory changed")
                        finally:
                            os.close(rebound)
                        _same_path(runtime_parent, parent_fd, _runtime_parent)
                        _same_path(source_dir, vm_fd, _directory)
                        _same_path(registry, lease.parent, _directory)
                        receipt = dict(intent, phase="transferred",
                                       intent_sha256=release.digest(intent_raw),
                                       runtime_dir_device=os.fstat(target_fd).st_dev,
                                       runtime_dir_inode=os.fstat(target_fd).st_ino,
                                       transferred_at=int(time.time()))
                        _write(lease.parent, vm_id + ".runtime-receipt.json", receipt)
                        _same_path(registry, lease.parent, _directory)
                        return receipt
                    finally:
                        os.close(disk_fd)
                finally:
                    os.close(target_fd)
            finally:
                os.close(parent_fd)
        finally:
            os.close(vm_fd)


def verify_transfer(source: Path, registry: Path, vm_parent: Path,
                    runtime_parent: Path, *, vm_id: str) -> dict:
    """Require unchanged transfer records and pristine named disk before seeding/launch."""
    release.require(os.geteuid() == 0, "root controller required")
    with ControllerLease(registry) as lease:
        creation_raw, made = _read_record(lease.parent, vm_id + ".creation-receipt.json")
        initial_raw, initial = _read_record(lease.parent, vm_id + ".creation-intent.json")
        intent_raw, intent = _read_record(lease.parent, vm_id + ".runtime-intent.json")
        receipt_raw, receipt = _read_record(lease.parent, vm_id + ".runtime-receipt.json")
        fields = {"schema", "phase", "vm_id", "creation_receipt_sha256",
                  "source_path", "target_path", "disk_device", "disk_inode",
                  "disk_bytes", "disk_sha256", "runtime_uid", "runtime_gid",
                  "runtime_account", "started_at", "qualified", "launch_authorized"}
        release.exact(intent, fields, "VM runtime intent")
        release.exact(receipt, fields | {"intent_sha256", "runtime_dir_device",
                                         "runtime_dir_inode", "transferred_at"},
                      "VM runtime receipt")
        source_dir = vm_parent / vm_id
        creation_module.validate_creation_records(initial_raw, initial, made,
                                                  source_dir, vm_id, int(time.time()))
        provenance = creation_module.verify_source(source)
        release.require(made["image"] == provenance,
                        "VM creation source changed after transfer")
        target_dir = runtime_parent / vm_id
        release.require(intent["schema"] == receipt["schema"] == SCHEMA
                        and intent["phase"] == "intent" and receipt["phase"] == "transferred"
                        and intent["vm_id"] == receipt["vm_id"] == vm_id
                        and intent["creation_receipt_sha256"] == release.digest(creation_raw)
                        and receipt["intent_sha256"] == release.digest(intent_raw)
                        and intent["source_path"] == made["disk_path"]
                        == str(source_dir / "disk.qcow2")
                        and intent["target_path"] == str(target_dir / "disk.qcow2")
                        and type(intent["disk_device"]) is int
                        and type(intent["disk_inode"]) is int
                        and type(intent["disk_bytes"]) is int
                        and type(intent["disk_sha256"]) is str
                        and (intent["disk_device"], intent["disk_inode"],
                             intent["disk_bytes"], intent["disk_sha256"])
                        == (made["disk_device"], made["disk_inode"],
                            made["disk_bytes"], made["disk_sha256"])
                        and type(intent["runtime_uid"]) is int
                        and type(intent["runtime_gid"]) is int
                        and intent["runtime_account"] == _identity(
                            vm_id, intent["runtime_uid"], intent["runtime_gid"])
                        and type(intent["started_at"]) is int
                        and type(receipt["transferred_at"]) is int
                        and 0 < intent["started_at"] <= receipt["transferred_at"]
                        and receipt["transferred_at"] <= int(time.time()) + 5
                        and intent["qualified"] is receipt["qualified"] is False
                        and intent["launch_authorized"] is receipt["launch_authorized"] is False
                        and all(receipt[field] == value for field, value in intent.items()
                                if field != "phase"),
                        "VM runtime records disagree")
        _backing_readable(Path(provenance["image_path"]))
        source_fd = _directory(source_dir)
        try:
            parent_fd = _runtime_parent(runtime_parent)
            try:
                target_fd = observer.open_vm_dir(target_dir, intent["runtime_uid"])
                try:
                    directory = os.fstat(target_fd)
                    release.require((directory.st_dev, directory.st_ino)
                                    == (receipt["runtime_dir_device"],
                                        receipt["runtime_dir_inode"]),
                                    "VM runtime directory differs")
                    disk_fd = os.open("disk.qcow2", os.O_RDONLY | os.O_NONBLOCK
                                      | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=target_fd)
                    try:
                        _named_disk(target_fd, disk_fd, intent["runtime_uid"],
                                    intent["runtime_gid"])
                        info = os.fstat(disk_fd)
                        release.require((info.st_dev, info.st_ino)
                                        == (intent["disk_device"], intent["disk_inode"])
                                        and _disk_digest(disk_fd)
                                        == (intent["disk_bytes"], intent["disk_sha256"]),
                                        "VM runtime pristine bytes differ")
                        # The exact held bytes were authenticated and parsed before
                        # custody transfer. Root must not parse this UID-writable path.
                        _named_disk(target_fd, disk_fd, intent["runtime_uid"],
                                    intent["runtime_gid"])
                        release.require(_disk_digest(disk_fd)
                                        == (intent["disk_bytes"], intent["disk_sha256"]),
                                        "VM runtime bytes changed during verification")
                    finally:
                        os.close(disk_fd)
                    _same_path(target_dir, target_fd,
                               lambda path: observer.open_vm_dir(path, intent["runtime_uid"]))
                finally:
                    os.close(target_fd)
                _same_path(source_dir, source_fd, _directory)
                _same_path(runtime_parent, parent_fd, _runtime_parent)
                _same_path(registry, lease.parent, _directory)
                release.require(_read_record(lease.parent, vm_id + ".creation-receipt.json")[0]
                                == creation_raw
                                and _read_record(lease.parent, vm_id + ".creation-intent.json")[0]
                                == initial_raw
                                and _read_record(lease.parent, vm_id + ".runtime-intent.json")[0]
                                == intent_raw
                                and _read_record(lease.parent, vm_id + ".runtime-receipt.json")[0]
                                == receipt_raw,
                                "VM runtime records changed during verification")
                return receipt
            finally:
                os.close(parent_fd)
        finally:
            os.close(source_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            record = verify_transfer(args.source, args.registry, args.vm_parent,
                                     args.runtime_parent, vm_id=args.vm_id)
            release.require((record["runtime_uid"], record["runtime_gid"])
                            == (args.uid, args.gid), "VM runtime identity differs")
        else:
            transfer(args.source, args.registry, args.vm_parent, args.runtime_parent,
                     vm_id=args.vm_id, uid=args.uid, gid=args.gid)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM runtime transfer refused or uncertain; retain all records and disks.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
