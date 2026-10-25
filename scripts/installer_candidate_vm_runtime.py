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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "registry", "vm-parent", "runtime-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--vm-id", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args()
    try:
        transfer(args.source, args.registry, args.vm_parent, args.runtime_parent,
                 vm_id=args.vm_id, uid=args.uid, gid=args.gid)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        parser.exit(1, "VM runtime transfer refused or uncertain; retain all records and disks.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
