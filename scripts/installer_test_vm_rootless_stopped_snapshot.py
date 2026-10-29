#!/usr/bin/env python3
"""One-shot stop and pending snapshot evidence for a disposable setup guest.

This is test infrastructure, not a product entrypoint. It cannot mint a
VerifiedStoppedCheckpoint: a distinct restore-copy VM must boot the snapshot
and prove rollback before an offline package transaction is authorized.
There is no retry after an uncertain stop intent and no live caller here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import time

from installer_candidate_controller import ControllerLease
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_release as release
import installer_test_vm_restart as restart
import installer_test_vm_rootless_setup as setup

SCHEMA = "elevenid.installer-only-rootless-stopped-snapshot/v1"
INTENT_SUFFIX = ".rootless-stop-snapshot-intent.json"
PENDING_SUFFIX = ".rootless-stopped-snapshot-pending.json"
SNAPSHOT_SUFFIX = ".rootless-stopped-snapshot"
MAX_QMP_LINE = 65536
MAX_QMP_MESSAGES = 20
STOP_SECONDS = 120
COPY_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class StoppedSnapshotEvidence:
    """Historical pending record reference; never a checkpoint capability."""
    vm_id: str
    intent_sha256: str
    pending_sha256: str
    disk_sha256: str
    snapshot_sha256: str
    package_install_authorized: bool = False
    product_dispatch_authorized: bool = False


def _qmp_powerdown(path: Path, disk: Path, *, pid: int, uid: int,
                   socket_device: int, socket_inode: int) -> None:
    """Issue only system_powerdown to the exact live QEMU peer."""
    before = path.lstat()
    release.require(stat.S_ISSOCK(before.st_mode)
                    and before.st_uid == uid
                    and (before.st_dev, before.st_ino)
                    == (socket_device, socket_inode),
                    "fixture QMP socket changed")
    # The existing observer checks running state and exact writable qcow2.
    observer.qmp(path, disk, pid=pid, uid=uid)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        peer = struct.unpack("3i", connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        release.require(peer[:2] == (pid, uid), "fixture QMP peer changed")
        current = path.lstat()
        release.require((current.st_dev, current.st_ino, current.st_uid)
                        == (socket_device, socket_inode, uid),
                        "fixture QMP path changed")
        with connection.makefile("rwb") as stream:
            greeting = release.decode(stream.readline(MAX_QMP_LINE + 1))
            release.require(type(greeting) is dict and "QMP" in greeting,
                            "fixture QMP greeting invalid")
            for ident, command in ((1, "qmp_capabilities"),
                                   (2, "system_powerdown")):
                stream.write(release.encode({"execute": command, "id": ident}))
                stream.flush()
                for _ in range(MAX_QMP_MESSAGES):
                    line = stream.readline(MAX_QMP_LINE + 1)
                    release.require(0 < len(line) <= MAX_QMP_LINE,
                                    "fixture QMP response invalid")
                    value = release.decode(line)
                    if value.get("id") == ident:
                        release.require("return" in value and "error" not in value,
                                        "fixture QMP command failed")
                        break
                else:
                    raise ValueError("fixture QMP response unavailable")


def _wait_stopped(uid: int, pid: int, start: str, boot: str,
                  runtime_dir: Path, port: int) -> None:
    deadline = time.monotonic() + STOP_SECONDS
    while restart._original_still_live(pid, start, boot):
        release.require(time.monotonic() < deadline,
                        "fixture powerdown timed out; manual recovery required")
        time.sleep(0.2)
    restart._no_live_owner(uid, pid, start, boot, runtime_dir, port)


def _copy_snapshot(source_fd: int, parent: int, vm_id: str,
                   expected_size: int, expected_sha: str) -> tuple[int, str, int, int]:
    """Copy exact held stopped disk bytes to an exclusive private inode."""
    dirname = vm_id + SNAPSHOT_SUFFIX
    os.mkdir(dirname, 0o700, dir_fd=parent)
    os.fsync(parent)
    directory = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC, dir_fd=parent)
    try:
        directory_stat = os.fstat(directory)
        release.require(directory_stat.st_uid == 0
                        and stat.S_IMODE(directory_stat.st_mode) == 0o700,
                        "fixture snapshot directory invalid")
        target = os.open("disk.qcow2", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            digest = hashlib.sha256()
            left = expected_size
            offset = 0
            while left:
                block = os.pread(source_fd, min(left, COPY_CHUNK), offset)
                release.require(bool(block), "fixture stopped disk truncated")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(target, view)
                    release.require(written > 0, "fixture snapshot write stalled")
                    view = view[written:]
                offset += len(block)
                left -= len(block)
            release.require(digest.hexdigest() == expected_sha,
                            "fixture stopped disk changed during copy")
            os.fsync(target)
            saved = os.fstat(target)
            release.require(stat.S_ISREG(saved.st_mode) and saved.st_uid == 0
                            and saved.st_nlink == 1
                            and stat.S_IMODE(saved.st_mode) == 0o600
                            and saved.st_size == expected_size,
                            "fixture snapshot inode invalid")
        finally:
            os.close(target)
        os.fsync(directory)
        rebound = os.stat(dirname, dir_fd=parent, follow_symlinks=False)
        release.require((rebound.st_dev, rebound.st_ino, rebound.st_uid,
                         stat.S_IMODE(rebound.st_mode))
                        == (directory_stat.st_dev, directory_stat.st_ino, 0, 0o700),
                        "fixture snapshot directory changed")
        named = os.stat("disk.qcow2", dir_fd=directory, follow_symlinks=False)
        release.require((named.st_dev, named.st_ino, named.st_size,
                         named.st_mtime_ns, named.st_ctime_ns)
                        == (saved.st_dev, saved.st_ino, saved.st_size,
                            saved.st_mtime_ns, saved.st_ctime_ns),
                        "fixture snapshot name changed")
        reader = os.open("disk.qcow2", os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=directory)
        try:
            actual = hashlib.sha256()
            left = expected_size
            while left:
                block = os.read(reader, min(left, COPY_CHUNK))
                release.require(bool(block), "fixture snapshot truncated")
                actual.update(block)
                left -= len(block)
            release.require(os.read(reader, 1) == b""
                            and actual.hexdigest() == expected_sha,
                            "fixture snapshot digest differs")
            observed = os.fstat(reader)
            release.require((observed.st_dev, observed.st_ino, observed.st_size,
                             observed.st_mtime_ns, observed.st_ctime_ns)
                            == (saved.st_dev, saved.st_ino, saved.st_size,
                                saved.st_mtime_ns, saved.st_ctime_ns),
                            "fixture snapshot changed during rehash")
        finally:
            os.close(reader)
        return expected_size, expected_sha, saved.st_dev, saved.st_ino
    finally:
        os.close(directory)


def stop_and_snapshot(*, source: Path, registry: Path, vm_parent: Path,
                      runtime_parent: Path, vm_id: str) -> StoppedSnapshotEvidence:
    """Consume one stop intent and return pending, non-authoritative evidence.

    The future root-private caller must authenticate this source/import closure
    and separately authorize the setup guest shutdown. This operation never
    retries a prior intent or interprets a partial snapshot as complete.
    """
    release.require(os.geteuid() == 0
                    and all(path.is_absolute() for path in
                            (source, registry, vm_parent, runtime_parent)),
                    "fixture stop needs trusted controller")
    runtime_dir = runtime_parent / vm_id
    disk = runtime_dir / "disk.qcow2"
    with ControllerLease(registry) as lease:
        before = setup.bound_setup_fixture(
            source=source, registry=registry, vm_parent=vm_parent,
            runtime_parent=runtime_parent, vm_id=vm_id, _lease=lease)
        transfer_raw, transfer = create._read_record(lease.parent,
                                          vm_id + ".runtime-receipt.json")
        setup_raw, _ = create._read_record(lease.parent,
                                          vm_id + setup.SETUP_READINESS_SUFFIX)
        release.require(release.digest(setup_raw) == before["readiness_sha256"],
                        "fixture setup evidence changed")
        provenance = create.verify_source(source)
        uid, gid = transfer["runtime_uid"], transfer["runtime_gid"]
        sock = runtime_dir / "qmp.sock"
        socket_stat = sock.lstat()
        release.require(stat.S_ISSOCK(socket_stat.st_mode)
                        and socket_stat.st_uid == uid,
                        "fixture monitor socket invalid")
        release.require(restart._original_still_live(
                        before["pid"], before["start_ticks"], before["boot_id"]),
                        "fixture process not live")
        intent = {"schema": SCHEMA, "phase": "stop_intent", "vm_id": vm_id,
                  "setup_readiness_sha256": before["readiness_sha256"],
                  "launch_sha256": before["launch_sha256"],
                  "pid": before["pid"], "start_ticks": before["start_ticks"],
                  "boot_id": before["boot_id"], "runtime_uid": uid,
                  "runtime_gid": gid, "disk_device": before["disk_device"],
                  "disk_inode": before["disk_inode"],
                  "qmp_device": socket_stat.st_dev,
                  "qmp_inode": socket_stat.st_ino,
                  "requested_at": int(time.time()), "stopped": False,
                  "snapshot_qualified": False, "package_install_authorized": False,
                  "product_dispatch_authorized": False}
        intent_raw = create._write(lease.parent, vm_id + INTENT_SUFFIX, intent)
        # No action before the durable intent. Any exception from here onward
        # leaves that intent and refuses a second invocation.
        _qmp_powerdown(sock, disk, pid=before["pid"], uid=uid,
                       socket_device=socket_stat.st_dev,
                       socket_inode=socket_stat.st_ino)
        _wait_stopped(uid, before["pid"], before["start_ticks"],
                      before["boot_id"], runtime_dir, before["port"])
        runtime_fd = observer.open_vm_dir(runtime_dir, uid)
        try:
            disk_fd = restart._disk_fd(runtime_fd, uid, gid,
                                       before["disk_device"],
                                       before["disk_inode"])
            try:
                size, digest, mtime, ctime = restart._mutable_digest(disk_fd)
                copied = _copy_snapshot(disk_fd, lease.parent, vm_id,
                                        size, digest)
                release.require(restart._mutable_digest(disk_fd)
                                == (size, digest, mtime, ctime),
                                "fixture stopped disk changed")
            finally:
                os.close(disk_fd)
        finally:
            os.close(runtime_fd)
        _wait_stopped(uid, before["pid"], before["start_ticks"],
                      before["boot_id"], runtime_dir, before["port"])
        release.require(create._read_record(lease.parent,
                        vm_id + INTENT_SUFFIX)[0] == intent_raw,
                        "fixture stop intent changed")
        release.require(create._read_record(lease.parent,
                        vm_id + ".runtime-receipt.json")[0] == transfer_raw
                        and create._read_record(lease.parent,
                        vm_id + setup.SETUP_READINESS_SUFFIX)[0] == setup_raw
                        and create.verify_source(source) == provenance
                        and launch._boot_id() == before["boot_id"],
                        "fixture stop source or epoch changed")
        create._rebind_directory(registry, lease.parent)
        pending = {"schema": SCHEMA, "phase": "snapshot_pending_rollback_test",
                   "vm_id": vm_id, "intent_sha256": release.digest(intent_raw),
                   "pid": before["pid"], "start_ticks": before["start_ticks"],
                   "boot_id": before["boot_id"],
                   "disk_device": before["disk_device"],
                   "disk_inode": before["disk_inode"],
                   "disk_bytes": size, "disk_sha256": digest,
                   "snapshot_bytes": copied[0], "snapshot_sha256": copied[1],
                   "snapshot_device": copied[2], "snapshot_inode": copied[3],
                   "observed_at": int(time.time()), "stopped": True,
                   "snapshot_qualified": False,
                   "package_install_authorized": False,
                   "product_dispatch_authorized": False}
        pending_raw = create._write(lease.parent, vm_id + PENDING_SUFFIX, pending)
        return StoppedSnapshotEvidence(
            vm_id=vm_id, intent_sha256=release.digest(intent_raw),
            pending_sha256=release.digest(pending_raw), disk_sha256=digest,
            snapshot_sha256=copied[1])
