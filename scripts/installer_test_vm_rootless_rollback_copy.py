#!/usr/bin/env python3
"""Prepare a distinct rollback-copy disk from a pending stopped snapshot.

The copy is never a checkpoint or package-install capability. A separate
controller must launch this new VM UUID, prove boot and baseline, then prove
cleanup before minting a stopped checkpoint. No CLI or live caller exists.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socket
import stat
import time
import uuid

from installer_candidate_controller import ControllerLease, _directory
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_runtime as runtime
import installer_candidate_vm_seed as seed_module
import installer_release as release
import installer_test_vm_restart as restart
import installer_test_vm_rootless_fixture as fixture
import installer_test_vm_rootless_stopped_snapshot as stopped

SCHEMA = "elevenid.installer-only-rootless-rollback-copy/v1"
INTENT_SUFFIX = ".rootless-rollback-copy-intent.json"
PREPARED_SUFFIX = ".rootless-rollback-copy-prepared.json"
CHUNK = 1024 * 1024
MAX_SEED = 16 * 1024 * 1024
INTENT_FIELDS = {"schema", "phase", "vm_id", "copy_vm_id",
                 "stop_intent_sha256", "pending_sha256",
                 "source_image_sha256", "source_manifest_sha256",
                 "source_signature_sha256", "source_keyring_sha256",
                 "creation_sha256", "transfer_sha256", "seed_sha256",
                 "launch_sha256", "launch_receipt_sha256",
                 "setup_readiness_sha256", "runtime_parent_device",
                 "runtime_parent_inode", "runtime_uid", "runtime_gid",
                 "copy_port", "snapshot_directory_device",
                 "snapshot_directory_inode", "snapshot_device",
                 "snapshot_inode", "snapshot_bytes", "snapshot_sha256",
                 "created_at", "rollback_qualified",
                 "package_install_authorized", "product_dispatch_authorized"}
PREPARED_FIELDS = {"schema", "phase", "vm_id", "copy_vm_id",
                   "intent_sha256", "pending_sha256", "copy_port",
                   "runtime_uid", "runtime_gid", "runtime_directory_device",
                   "runtime_directory_inode", "disk_device", "disk_inode",
                   "disk_bytes", "disk_sha256", "seed_device", "seed_inode",
                   "seed_bytes", "seed_sha256", "prepared_at",
                   "rollback_qualified", "package_install_authorized",
                   "product_dispatch_authorized"}


def _prelaunch_layout(directory: int) -> None:
    """A fresh copy has exactly the two producer-created files."""
    _closed_names(directory, {"disk.qcow2", "seed.iso"})
    try:
        os.stat("qmp.sock", dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("fixture rollback monitor path exists")


def _closed_names(directory: int, expected: set[str]) -> None:
    """Stream a tiny fixed directory census without unbounded allocation."""
    seen: set[str] = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            release.require(entry.name in expected and entry.name not in seen
                            and len(seen) < len(expected),
                            "fixture rollback directory has unexpected entries")
            seen.add(entry.name)
    release.require(seen == expected,
                    "fixture rollback directory has unexpected entries")


def _exact_pending(intent_raw: bytes, intent: dict,
                   pending_raw: bytes, pending: dict, vm_id: str) -> None:
    release.exact(intent, {"schema", "phase", "vm_id",
                           "setup_readiness_sha256", "launch_sha256", "pid",
                           "start_ticks", "boot_id", "runtime_uid", "runtime_gid",
                           "disk_device", "disk_inode", "qmp_device", "qmp_inode",
                           "requested_at", "stopped", "snapshot_qualified",
                           "package_install_authorized", "product_dispatch_authorized"},
                  "fixture stop intent")
    release.exact(pending, {"schema", "phase", "vm_id", "intent_sha256", "pid",
                            "start_ticks", "boot_id", "disk_device", "disk_inode",
                            "disk_bytes", "disk_sha256", "snapshot_bytes",
                            "snapshot_sha256", "snapshot_directory_device",
                            "snapshot_directory_inode", "snapshot_device",
                            "snapshot_inode", "observed_at", "stopped",
                            "snapshot_qualified", "package_install_authorized",
                            "product_dispatch_authorized"},
                  "fixture pending snapshot")
    release.require(intent["schema"] == pending["schema"] == stopped.SCHEMA
                    and intent["phase"] == "stop_intent"
                    and pending["phase"] == "snapshot_pending_rollback_test"
                    and intent["vm_id"] == pending["vm_id"] == vm_id
                    and pending["intent_sha256"] == release.digest(intent_raw)
                    and all(intent[key] == pending[key] for key in
                            ("pid", "start_ticks", "boot_id", "disk_device",
                             "disk_inode"))
                    and type(intent["pid"]) is int and intent["pid"] > 4
                    and type(intent["start_ticks"]) is str
                    and intent["start_ticks"].isascii()
                    and intent["start_ticks"].isdecimal()
                    and str(uuid.UUID(intent["boot_id"])) == intent["boot_id"]
                    and all(type(intent[key]) is int and intent[key] > 0 for key in
                            ("runtime_uid", "runtime_gid", "disk_device",
                             "disk_inode", "qmp_device", "qmp_inode",
                             "requested_at"))
                    and all(type(pending[key]) is int and pending[key] > 0 for key in
                            ("disk_bytes", "snapshot_bytes",
                             "snapshot_directory_device", "snapshot_directory_inode",
                             "snapshot_device", "snapshot_inode", "observed_at"))
                    and pending["disk_bytes"] == pending["snapshot_bytes"]
                    and pending["snapshot_bytes"]
                    <= restart.MAX_MUTABLE_DISK_BYTES
                    and pending["disk_sha256"] == pending["snapshot_sha256"]
                    and type(pending["disk_sha256"]) is str
                    and len(pending["disk_sha256"]) == 64
                    and all(c in "0123456789abcdef" for c in
                            pending["disk_sha256"])
                    and intent["stopped"] is False
                    and pending["stopped"] is True
                    and all(value is False for value in
                            (intent["snapshot_qualified"],
                             intent["package_install_authorized"],
                             intent["product_dispatch_authorized"],
                             pending["snapshot_qualified"],
                             pending["package_install_authorized"],
                             pending["product_dispatch_authorized"]))
                    and release.encode(intent) == intent_raw
                    and release.encode(pending) == pending_raw,
                    "fixture pending snapshot evidence invalid")


def _held_regular(parent: int, name: str, *, owner: int, group: int,
                  mode: int, device: int, inode: int, size: int) -> int:
    """Classify a named ordinary inode via O_PATH before content access."""
    pathfd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
    try:
        info = os.fstat(pathfd)
        release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and (info.st_uid, info.st_gid) == (owner, group)
                        and stat.S_IMODE(info.st_mode) == mode
                        and (info.st_dev, info.st_ino) == (device, inode)
                        and info.st_size == size,
                        "fixture source inode differs")
        opened = os.open(f"/proc/self/fd/{pathfd}",
                         os.O_RDONLY | os.O_CLOEXEC)
        try:
            now = os.fstat(opened)
            release.require((now.st_dev, now.st_ino, now.st_uid, now.st_gid,
                             stat.S_IMODE(now.st_mode), now.st_nlink,
                             now.st_size, now.st_mtime_ns, now.st_ctime_ns)
                            == (info.st_dev, info.st_ino, info.st_uid,
                                info.st_gid, mode, 1, size,
                                info.st_mtime_ns, info.st_ctime_ns),
                            "fixture source changed during reopen")
            return opened
        except BaseException:
            os.close(opened)
            raise
    finally:
        os.close(pathfd)


def _copy_exact(source_fd: int, target_fd: int, size: int,
                expected_sha256: str) -> None:
    release.require(type(size) is int and 0 < size <= restart.MAX_MUTABLE_DISK_BYTES,
                    "fixture copy size invalid")
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(source_fd, min(CHUNK, size - offset), offset)
        release.require(bool(block), "fixture copy source truncated")
        digest.update(block)
        view = memoryview(block)
        while view:
            written = os.write(target_fd, view)
            release.require(written > 0, "fixture copy stalled")
            view = view[written:]
        offset += len(block)
    release.require(os.pread(source_fd, 1, size) == b""
                    and digest.hexdigest() == expected_sha256,
                    "fixture copy source digest differs")
    os.fsync(target_fd)


def _snapshot(registry: Path, lease: ControllerLease, vm_id: str,
              pending: dict) -> tuple[int, int]:
    path = registry / (vm_id + stopped.SNAPSHOT_SUFFIX)
    held = _directory(path)
    try:
        info = os.fstat(held)
        release.require((info.st_dev, info.st_ino)
                        == (pending["snapshot_directory_device"],
                            pending["snapshot_directory_inode"]),
                        "fixture snapshot directory differs")
        _closed_names(held, {"disk.qcow2"})
        source = _held_regular(
            held, "disk.qcow2", owner=0, group=0, mode=0o600,
            device=pending["snapshot_device"],
            inode=pending["snapshot_inode"], size=pending["snapshot_bytes"])
        try:
            size, digest, _, _ = restart._mutable_digest(source)
            release.require((size, digest) == (pending["snapshot_bytes"],
                                               pending["snapshot_sha256"]),
                            "fixture named snapshot digest differs")
            create._rebind_directory(path, held)
            return held, source
        except BaseException:
            os.close(source)
            raise
    except BaseException:
        os.close(held)
        raise


def _copy_target(parent: int, copy_id: str, source_fd: int,
                 pending: dict, seed_fd: int, seed_bytes: int, seed_sha: str,
                 uid: int, gid: int) -> dict:
    os.mkdir(copy_id, 0o700, dir_fd=parent)
    os.fsync(parent)
    directory = os.open(copy_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=parent)
    try:
        disk = os.open("disk.qcow2", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                       os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            _copy_exact(source_fd, disk, pending["snapshot_bytes"],
                        pending["snapshot_sha256"])
            os.fchown(disk, uid, gid)
            os.fchmod(disk, 0o600)
            os.fsync(disk)
            disk_stamp = os.fstat(disk)
            release.require((disk_stamp.st_dev, disk_stamp.st_ino)
                            != (pending["snapshot_device"],
                                pending["snapshot_inode"]),
                            "fixture restore disk aliases original snapshot")
        finally:
            os.close(disk)
        seed = os.open("seed.iso", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                       os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            _copy_exact(seed_fd, seed, seed_bytes, seed_sha)
            os.fchown(seed, 0, gid)
            os.fchmod(seed, 0o440)
            os.fsync(seed)
            seed_stamp = os.fstat(seed)
        finally:
            os.close(seed)
        for name, stamp, owner, group, mode, size, digest in (
            ("disk.qcow2", disk_stamp, uid, gid, 0o600,
             pending["snapshot_bytes"], pending["snapshot_sha256"]),
            ("seed.iso", seed_stamp, 0, gid, 0o440,
             seed_bytes, seed_sha),
        ):
            reader = _held_regular(directory, name, owner=owner, group=group,
                                   mode=mode, device=stamp.st_dev,
                                   inode=stamp.st_ino, size=size)
            try:
                release.require(restart._mutable_digest(reader)[:2]
                                == (size, digest),
                                "fixture copied file digest differs")
            finally:
                os.close(reader)
        os.fchown(directory, uid, gid)
        os.fchmod(directory, 0o700)
        os.fsync(directory)
        os.fsync(parent)
        again = os.stat(copy_id, dir_fd=parent, follow_symlinks=False)
        release.require((again.st_dev, again.st_ino, again.st_uid, again.st_gid,
                         stat.S_IMODE(again.st_mode))
                        == (os.fstat(directory).st_dev, os.fstat(directory).st_ino,
                            uid, gid, 0o700),
                        "fixture restore directory changed")
        for name, inode, owner, group, mode in (
            ("disk.qcow2", disk_stamp, uid, gid, 0o600),
            ("seed.iso", seed_stamp, 0, gid, 0o440),
        ):
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            release.require((named.st_dev, named.st_ino, named.st_uid,
                             named.st_gid, stat.S_IMODE(named.st_mode),
                             named.st_nlink, named.st_size)
                            == (inode.st_dev, inode.st_ino, owner, group,
                                mode, 1, inode.st_size),
                            "fixture restore file changed")
        release.require(os.fstat(directory).st_dev == disk_stamp.st_dev,
                        "fixture restore disk mount differs")
        return {"runtime_directory_device": again.st_dev,
                "runtime_directory_inode": again.st_ino,
                "disk_device": disk_stamp.st_dev,
                "disk_inode": disk_stamp.st_ino,
                "disk_bytes": disk_stamp.st_size,
                "disk_sha256": pending["snapshot_sha256"],
                "seed_device": seed_stamp.st_dev,
                "seed_inode": seed_stamp.st_ino,
                "seed_bytes": seed_stamp.st_size,
                "seed_sha256": seed_sha}
    finally:
        os.close(directory)


def prepare_copy(*, source: Path, registry: Path, vm_parent: Path,
                 runtime_parent: Path, vm_id: str, copy_vm_id: str,
                 copy_port: int) -> dict:
    """Create an exclusive rollback-copy disk; return no installation authority."""
    fixture._uuid4(vm_id)
    fixture._uuid4(copy_vm_id)
    release.require(os.geteuid() == 0 and vm_id != copy_vm_id
                    and all(p.is_absolute() for p in
                            (source, registry, vm_parent, runtime_parent))
                    and type(copy_port) is int and 1024 <= copy_port <= 65535,
                    "fixture restore-copy request invalid")
    provenance = create.verify_source(source)
    with ControllerLease(registry) as lease:
        parent = _directory(vm_parent)
        runtime_parent_fd = runtime._runtime_parent(runtime_parent)
        try:
            create._rebind_directory(registry, lease.parent)
            fixture._fresh_uuid(lease.parent, parent, runtime_parent_fd,
                                copy_vm_id)
            intent_raw, intent = create._read_record(
                lease.parent, vm_id + stopped.INTENT_SUFFIX)
            pending_raw, pending = create._read_record(
                lease.parent, vm_id + stopped.PENDING_SUFFIX)
            _exact_pending(intent_raw, intent, pending_raw, pending, vm_id)
            release.require(launch._boot_id() == pending["boot_id"],
                            "fixture stopped epoch changed")
            creation_raw, creation = create._read_record(
                lease.parent, vm_id + ".creation-receipt.json")
            transfer_raw, transfer = create._read_record(
                lease.parent, vm_id + ".runtime-receipt.json")
            seed_raw, seeded = create._read_record(
                lease.parent, vm_id + ".seed-receipt.json")
            launch_raw, launched = create._read_record(
                lease.parent, vm_id + ".launch-intent.json")
            launch_receipt_raw, _ = create._read_record(
                lease.parent, vm_id + ".launch-receipt.json")
            readiness_raw, _ = create._read_record(
                lease.parent, vm_id + ".rootless-fixture-setup-readiness.json")
            release.require(creation["image"] == provenance
                            and (transfer["runtime_uid"], transfer["runtime_gid"])
                            == (intent["runtime_uid"], intent["runtime_gid"])
                            and (transfer["disk_device"], transfer["disk_inode"])
                            == (pending["disk_device"], pending["disk_inode"])
                            and launched["ssh_port"] != copy_port
                            and intent["launch_sha256"]
                            == release.digest(launch_receipt_raw)
                            and intent["setup_readiness_sha256"]
                            == release.digest(readiness_raw),
                            "fixture original source or copy port differs")
            runtime_dir = runtime_parent / vm_id
            restart._no_live_owner(intent["runtime_uid"], intent["pid"],
                                   intent["start_ticks"], intent["boot_id"],
                                   runtime_dir, launched["ssh_port"])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", copy_port))
            old_dir = observer.open_vm_dir(runtime_dir, intent["runtime_uid"])
            snapshot_dir = snapshot_fd = old_disk = old_seed = None
            try:
                old_disk = restart._disk_fd(
                    old_dir, intent["runtime_uid"], intent["runtime_gid"],
                    pending["disk_device"], pending["disk_inode"])
                release.require(restart._mutable_digest(old_disk)[:2]
                                == (pending["disk_bytes"], pending["disk_sha256"]),
                                "fixture original stopped disk differs")
                old_seed = _held_regular(
                    old_dir, "seed.iso", owner=0, group=intent["runtime_gid"],
                    mode=0o440, device=seeded["seed_device"],
                    inode=seeded["seed_inode"], size=seeded["seed_bytes"])
                seed_size, seed_sha, _, _ = restart._mutable_digest(old_seed)
                release.require(seed_size <= MAX_SEED
                                and seed_sha == seeded["seed_sha256"],
                                "fixture seed differs")
                snapshot_dir, snapshot_fd = _snapshot(registry, lease, vm_id,
                                                      pending)
                copy_intent = {"schema": SCHEMA, "phase": "copy_intent",
                               "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                               "stop_intent_sha256": release.digest(intent_raw),
                               "pending_sha256": release.digest(pending_raw),
                               "source_image_sha256": provenance["image_sha256"],
                               "source_manifest_sha256": provenance["manifest_sha256"],
                               "source_signature_sha256": provenance["signature_sha256"],
                               "source_keyring_sha256": provenance["keyring_sha256"],
                               "creation_sha256": release.digest(creation_raw),
                               "transfer_sha256": release.digest(transfer_raw),
                               "seed_sha256": release.digest(seed_raw),
                               "launch_sha256": release.digest(launch_raw),
                               "launch_receipt_sha256": release.digest(
                                   launch_receipt_raw),
                               "setup_readiness_sha256": release.digest(
                                   readiness_raw),
                               "runtime_parent_device": os.fstat(runtime_parent_fd).st_dev,
                               "runtime_parent_inode": os.fstat(runtime_parent_fd).st_ino,
                               "runtime_uid": intent["runtime_uid"],
                               "runtime_gid": intent["runtime_gid"],
                               "copy_port": copy_port,
                               "snapshot_directory_device": pending["snapshot_directory_device"],
                               "snapshot_directory_inode": pending["snapshot_directory_inode"],
                               "snapshot_device": pending["snapshot_device"],
                               "snapshot_inode": pending["snapshot_inode"],
                               "snapshot_bytes": pending["snapshot_bytes"],
                               "snapshot_sha256": pending["snapshot_sha256"],
                               "created_at": int(time.time()),
                               "rollback_qualified": False,
                               "package_install_authorized": False,
                               "product_dispatch_authorized": False}
                intent_bytes = create._write(
                    lease.parent, copy_vm_id + INTENT_SUFFIX, copy_intent)
                copied = _copy_target(
                    runtime_parent_fd, copy_vm_id, snapshot_fd, pending,
                    old_seed, seed_size, seed_sha,
                    intent["runtime_uid"], intent["runtime_gid"])
                release.require(restart._mutable_digest(old_disk)[:2]
                                == (pending["disk_bytes"], pending["disk_sha256"])
                                and restart._mutable_digest(old_seed)[:2]
                                == (seed_size, seed_sha),
                                "fixture original stopped files changed")
                create._rebind_directory(registry, lease.parent)
                runtime._same_path(runtime_parent, runtime_parent_fd,
                                   runtime._runtime_parent)
                create._rebind_directory(
                    registry / (vm_id + stopped.SNAPSHOT_SUFFIX),
                    snapshot_dir)
                release.require(create._read_record(
                    lease.parent, copy_vm_id + INTENT_SUFFIX)[0] == intent_bytes
                    and create._read_record(lease.parent,
                        vm_id + stopped.PENDING_SUFFIX)[0] == pending_raw
                    and create.verify_source(source) == provenance
                    and restart._mutable_digest(snapshot_fd)[:2]
                    == (pending["snapshot_bytes"], pending["snapshot_sha256"]),
                    "fixture restore-copy source changed")
                named_snapshot = _held_regular(
                    snapshot_dir, "disk.qcow2", owner=0, group=0, mode=0o600,
                    device=pending["snapshot_device"],
                    inode=pending["snapshot_inode"],
                    size=pending["snapshot_bytes"])
                try:
                    release.require(restart._mutable_digest(named_snapshot)[:2]
                                    == (pending["snapshot_bytes"],
                                        pending["snapshot_sha256"]),
                                    "fixture named snapshot changed after copy")
                finally:
                    os.close(named_snapshot)
                restart._no_live_owner(
                    intent["runtime_uid"], intent["pid"],
                    intent["start_ticks"], intent["boot_id"],
                    runtime_dir, launched["ssh_port"])
                result = {"schema": SCHEMA, "phase": "copy_prepared",
                          "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                          "intent_sha256": release.digest(intent_bytes),
                          "pending_sha256": release.digest(pending_raw),
                          "copy_port": copy_port,
                          "runtime_uid": intent["runtime_uid"],
                          "runtime_gid": intent["runtime_gid"],
                          **copied, "prepared_at": int(time.time()),
                          "rollback_qualified": False,
                          "package_install_authorized": False,
                          "product_dispatch_authorized": False}
                create._write(lease.parent, copy_vm_id + PREPARED_SUFFIX, result)
                return result
            finally:
                for held in (snapshot_fd, snapshot_dir, old_seed, old_disk):
                    if held is not None:
                        os.close(held)
                os.close(old_dir)
        finally:
            os.close(runtime_parent_fd)
            os.close(parent)


def bound_prepared_copy(*, source: Path, registry: Path,
                        runtime_parent: Path, vm_id: str,
                        copy_vm_id: str, _lease: ControllerLease | None = None) -> dict:
    """Reobserve exact prepared copy, original stopped state and snapshot.

    The returned private binding has no launch or package authority. A later
    launcher must repeat it under the same held registry lease before spawn.
    """
    from contextlib import nullcontext
    fixture._uuid4(vm_id)
    fixture._uuid4(copy_vm_id)
    release.require(os.geteuid() == 0 and vm_id != copy_vm_id
                    and all(p.is_absolute() for p in
                            (source, registry, runtime_parent)),
                    "fixture rollback-copy binding request invalid")
    provenance = create.verify_source(source)
    with (ControllerLease(registry) if _lease is None else nullcontext(_lease)) as lease:
        create._rebind_directory(registry, lease.parent)
        copy_intent_raw, copy_intent = create._read_record(
            lease.parent, copy_vm_id + INTENT_SUFFIX)
        prepared_raw, prepared = create._read_record(
            lease.parent, copy_vm_id + PREPARED_SUFFIX)
        stop_raw, stop_intent = create._read_record(
            lease.parent, vm_id + stopped.INTENT_SUFFIX)
        pending_raw, pending = create._read_record(
            lease.parent, vm_id + stopped.PENDING_SUFFIX)
        _exact_pending(stop_raw, stop_intent, pending_raw, pending, vm_id)
        release.exact(copy_intent, INTENT_FIELDS, "fixture rollback-copy intent")
        release.exact(prepared, PREPARED_FIELDS, "fixture rollback-copy prepared")
        release.require(copy_intent["schema"] == prepared["schema"] == SCHEMA
                        and copy_intent["phase"] == "copy_intent"
                        and prepared["phase"] == "copy_prepared"
                        and copy_intent["vm_id"] == prepared["vm_id"] == vm_id
                        and copy_intent["copy_vm_id"] == prepared["copy_vm_id"]
                        == copy_vm_id
                        and prepared["intent_sha256"]
                        == release.digest(copy_intent_raw)
                        and copy_intent["stop_intent_sha256"]
                        == release.digest(stop_raw)
                        and copy_intent["pending_sha256"]
                        == prepared["pending_sha256"] == release.digest(pending_raw)
                        and all(copy_intent["source_" + key] == provenance[key]
                                for key in ("image_sha256", "manifest_sha256",
                                            "signature_sha256", "keyring_sha256"))
                        and all(copy_intent[key] == pending[key] for key in
                                ("snapshot_directory_device",
                                 "snapshot_directory_inode", "snapshot_device",
                                 "snapshot_inode", "snapshot_bytes",
                                 "snapshot_sha256"))
                        and all(copy_intent[key] == prepared[key] for key in
                                ("runtime_uid", "runtime_gid", "copy_port"))
                        and prepared["disk_bytes"] == pending["snapshot_bytes"]
                        and prepared["disk_sha256"] == pending["snapshot_sha256"]
                        and all(value is False for value in
                                (copy_intent["rollback_qualified"],
                                 copy_intent["package_install_authorized"],
                                 copy_intent["product_dispatch_authorized"],
                                 prepared["rollback_qualified"],
                                 prepared["package_install_authorized"],
                                 prepared["product_dispatch_authorized"]))
                        and type(copy_intent["created_at"]) is int
                        and type(prepared["prepared_at"]) is int
                        and copy_intent["created_at"] > 0
                        and prepared["prepared_at"] >= copy_intent["created_at"]
                        and type(prepared["copy_port"]) is int
                        and 1024 <= prepared["copy_port"] <= 65535,
                        "fixture rollback-copy record chain invalid")
        original_launch_raw, original_launch = create._read_record(
            lease.parent, vm_id + ".launch-intent.json")
        creation_raw, creation = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        transfer_raw, transfer = create._read_record(
            lease.parent, vm_id + ".runtime-receipt.json")
        seed_raw, seed = create._read_record(
            lease.parent, vm_id + ".seed-receipt.json")
        launch_receipt_raw, _ = create._read_record(
            lease.parent, vm_id + ".launch-receipt.json")
        readiness_raw, _ = create._read_record(
            lease.parent, vm_id + ".rootless-fixture-setup-readiness.json")
        release.require(release.digest(original_launch_raw)
                        == copy_intent["launch_sha256"]
                        and release.digest(creation_raw)
                        == copy_intent["creation_sha256"]
                        and release.digest(transfer_raw)
                        == copy_intent["transfer_sha256"]
                        and release.digest(seed_raw)
                        == copy_intent["seed_sha256"]
                        and release.digest(launch_receipt_raw)
                        == copy_intent["launch_receipt_sha256"]
                        and release.digest(readiness_raw)
                        == copy_intent["setup_readiness_sha256"]
                        == stop_intent["setup_readiness_sha256"]
                        and creation["image"] == provenance
                        and transfer["runtime_uid"] == prepared["runtime_uid"]
                        and transfer["runtime_gid"] == prepared["runtime_gid"]
                        and (transfer["disk_device"], transfer["disk_inode"])
                        == (pending["disk_device"], pending["disk_inode"])
                        and seed["seed_sha256"] == prepared["seed_sha256"]
                        and prepared["runtime_uid"] == stop_intent["runtime_uid"]
                        and prepared["runtime_gid"] == stop_intent["runtime_gid"]
                        and original_launch["ssh_port"] != prepared["copy_port"]
                        and launch._boot_id() == pending["boot_id"],
                        "fixture original epoch or copy identity differs")
        original_dir = runtime_parent / vm_id
        restart._no_live_owner(stop_intent["runtime_uid"],
                               stop_intent["pid"], stop_intent["start_ticks"],
                               stop_intent["boot_id"], original_dir,
                               original_launch["ssh_port"])
        parent_fd = runtime._runtime_parent(runtime_parent)
        target_fd = snapshot_dir = snapshot_fd = disk_fd = seed_fd = control_fd = None
        try:
            release.require((os.fstat(parent_fd).st_dev,
                             os.fstat(parent_fd).st_ino)
                            == (copy_intent["runtime_parent_device"],
                                copy_intent["runtime_parent_inode"]),
                            "fixture rollback runtime parent differs")
            target_fd = observer.open_vm_dir(runtime_parent / copy_vm_id,
                                             prepared["runtime_uid"])
            release.require((os.fstat(target_fd).st_dev,
                             os.fstat(target_fd).st_ino)
                            == (prepared["runtime_directory_device"],
                                prepared["runtime_directory_inode"]),
                            "fixture rollback runtime directory differs")
            _prelaunch_layout(target_fd)
            disk_fd = _held_regular(
                target_fd, "disk.qcow2", owner=prepared["runtime_uid"],
                group=prepared["runtime_gid"], mode=0o600,
                device=prepared["disk_device"], inode=prepared["disk_inode"],
                size=prepared["disk_bytes"])
            seed_fd = _held_regular(
                target_fd, "seed.iso", owner=0,
                group=prepared["runtime_gid"], mode=0o440,
                device=prepared["seed_device"], inode=prepared["seed_inode"],
                size=prepared["seed_bytes"])
            snapshot_dir, snapshot_fd = _snapshot(registry, lease, vm_id, pending)
            control_dir = registry / (vm_id + ".control")
            control_fd = _directory(control_dir)
            release.require((os.fstat(control_fd).st_dev,
                             os.fstat(control_fd).st_ino)
                            == (seed["control_dir_device"],
                                seed["control_dir_inode"])
                            and release.digest(seed_module._bytes(
                                control_dir / "controller_ed25519", 8192))
                            == seed["controller_private_sha256"]
                            and release.digest(seed_module._bytes(
                                control_dir / "known_hosts", 4096))
                            == seed["known_hosts_sha256"],
                            "fixture rollback SSH control identity differs")
            release.require((prepared["disk_device"], prepared["disk_inode"])
                            != (pending["snapshot_device"], pending["snapshot_inode"])
                            and restart._mutable_digest(disk_fd)[:2]
                            == (prepared["disk_bytes"], prepared["disk_sha256"])
                            and restart._mutable_digest(seed_fd)[:2]
                            == (prepared["seed_bytes"], prepared["seed_sha256"])
                            and restart._mutable_digest(snapshot_fd)[:2]
                            == (pending["snapshot_bytes"],
                                pending["snapshot_sha256"]),
                            "fixture rollback-copy bytes differ")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", prepared["copy_port"]))
            runtime._same_path(runtime_parent, parent_fd,
                               runtime._runtime_parent)
            launch._same_path(
                runtime_parent / copy_vm_id, target_fd,
                lambda path: observer.open_vm_dir(path, prepared["runtime_uid"]))
            create._rebind_directory(
                registry / (vm_id + stopped.SNAPSHOT_SUFFIX), snapshot_dir)
            create._rebind_directory(control_dir, control_fd)
            create._rebind_directory(registry, lease.parent)
            release.require(create._read_record(
                            lease.parent, copy_vm_id + INTENT_SUFFIX)[0]
                            == copy_intent_raw
                            and create._read_record(
                            lease.parent, copy_vm_id + PREPARED_SUFFIX)[0]
                            == prepared_raw
                            and create._read_record(
                            lease.parent, vm_id + stopped.PENDING_SUFFIX)[0]
                            == pending_raw
                            and create.verify_source(source) == provenance,
                            "fixture rollback-copy source changed")
            return {"vm_id": vm_id, "copy_vm_id": copy_vm_id,
                    "runtime_uid": prepared["runtime_uid"],
                    "runtime_gid": prepared["runtime_gid"],
                    "runtime_dir": runtime_parent / copy_vm_id,
                    "runtime_directory_device": prepared["runtime_directory_device"],
                    "runtime_directory_inode": prepared["runtime_directory_inode"],
                    "disk_device": prepared["disk_device"],
                    "disk_inode": prepared["disk_inode"],
                    "disk_bytes": prepared["disk_bytes"],
                    "disk_sha256": prepared["disk_sha256"],
                    "seed_device": prepared["seed_device"],
                    "seed_inode": prepared["seed_inode"],
                    "seed_bytes": prepared["seed_bytes"],
                    "seed_sha256": prepared["seed_sha256"],
                    "copy_port": prepared["copy_port"],
                    "control_dir": control_dir,
                    "key_sha256": seed["controller_private_sha256"],
                    "known_hosts_sha256": seed["known_hosts_sha256"],
                    "prepared_sha256": release.digest(prepared_raw),
                    "pending_sha256": release.digest(pending_raw),
                    "package_install_authorized": False,
                    "product_dispatch_authorized": False}
        finally:
            for fd in (control_fd, seed_fd, disk_fd, snapshot_fd, snapshot_dir,
                       target_fd, parent_fd):
                if fd is not None:
                    os.close(fd)
