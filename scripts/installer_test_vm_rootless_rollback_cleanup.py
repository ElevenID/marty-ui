#!/usr/bin/env python3
"""One-shot exact owned cleanup of a rollback-copy guest after baseline proof.

This removes only the new disposable copy's two known files and directory.
It never removes the original VM, root-private snapshot or historical records.
Interrupted cleanup has no automatic retry; no checkpoint is minted here.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import time

from installer_candidate_controller import ControllerLease
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_runtime as runtime
import installer_release as release
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_rollback_launch as launched
import installer_test_vm_rootless_stopped_snapshot as stopped

SCHEMA = "elevenid.installer-only-rootless-rollback-cleanup/v1"
INTENT_SUFFIX = ".rootless-rollback-cleanup-intent.json"
STOPPED_SUFFIX = ".rootless-rollback-cleanup-stopped.json"
REMOVE_INTENT_SUFFIX = ".rootless-rollback-cleanup-remove-intent.json"
RESULT_SUFFIX = ".rootless-rollback-cleanup-result.json"


def _unused(parent: int, copy_id: str) -> None:
    for suffix in (INTENT_SUFFIX, STOPPED_SUFFIX,
                   REMOVE_INTENT_SUFFIX, RESULT_SUFFIX):
        try:
            os.stat(copy_id + suffix, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("fixture rollback cleanup already attempted")


def _baseline(lease: ControllerLease, before: dict,
              copy_id: str) -> tuple[bytes, dict]:
    raw, result = create._read_record(
        lease.parent, copy_id + launched.BASELINE_SUFFIX)
    release.exact(result, {"schema", "phase", "vm_id", "copy_vm_id",
                           "launch_sha256", "prepared_sha256",
                           "admission_result_sha256", "setup_engine_id",
                           "dpkg_status_sha256", "pid", "start_ticks",
                           "boot_id", "observed_at", "rollback_qualified",
                           "package_install_authorized",
                           "product_dispatch_authorized"},
                  "fixture rollback baseline")
    release.require(result["schema"] == launched.BASELINE_SCHEMA
                    and result["phase"] == "baseline_observed"
                    and result["vm_id"] == before["vm_id"]
                    and result["copy_vm_id"] == before["copy_vm_id"]
                    and result["launch_sha256"] == before["launch_sha256"]
                    and result["prepared_sha256"] == before["prepared_sha256"]
                    and result["setup_engine_id"] == before["setup_engine_id"]
                    and all(result[key] == before[key] for key in
                            ("pid", "start_ticks", "boot_id"))
                    and type(result["observed_at"]) is int
                    and result["observed_at"] > 0
                    and all(result[key] is False for key in
                            ("rollback_qualified",
                             "package_install_authorized",
                             "product_dispatch_authorized")),
                    "fixture rollback baseline record differs")
    return raw, result


def _require_absent(parent: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("fixture rollback removed entry reappeared")


def _same_named_file(parent: int, name: str, held: os.stat_result) -> None:
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    release.require(stat.S_ISREG(named.st_mode)
                    and (named.st_dev, named.st_ino, named.st_uid,
                         named.st_gid, stat.S_IMODE(named.st_mode),
                         named.st_nlink, named.st_size,
                         named.st_mtime_ns, named.st_ctime_ns)
                    == (held.st_dev, held.st_ino, held.st_uid,
                        held.st_gid, stat.S_IMODE(held.st_mode),
                        1, held.st_size, held.st_mtime_ns, held.st_ctime_ns),
                    "fixture rollback named file changed before unlink")


def cleanup_copy(*, source: Path, registry: Path, runtime_parent: Path,
                 vm_id: str, copy_vm_id: str) -> dict:
    """Stop exact copy QEMU, durably remove exact two files, record result."""
    release.require(os.geteuid() == 0,
                    "fixture rollback cleanup needs root controller")
    with ControllerLease(registry) as lease:
        before = launched.bound_live_copy(
            source=source, registry=registry, runtime_parent=runtime_parent,
            vm_id=vm_id, copy_vm_id=copy_vm_id, _lease=lease)
        baseline_raw, _ = _baseline(lease, before, copy_vm_id)
        _unused(lease.parent, copy_vm_id)
        directory_path = runtime_parent / copy_vm_id
        disk_path = directory_path / "disk.qcow2"
        qmp_path = directory_path / "qmp.sock"
        monitor = qmp_path.lstat()
        release.require(stat.S_ISSOCK(monitor.st_mode)
                        and monitor.st_uid == before["runtime_uid"],
                        "fixture rollback monitor differs")
        intent = {"schema": SCHEMA, "phase": "cleanup_intent",
                  "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                  "baseline_sha256": release.digest(baseline_raw),
                  "launch_sha256": before["launch_sha256"],
                  "pid": before["pid"],
                  "start_ticks": before["start_ticks"],
                  "boot_id": before["boot_id"],
                  "runtime_uid": before["runtime_uid"],
                  "runtime_gid": before["runtime_gid"],
                  "disk_device": before["disk_device"],
                  "disk_inode": before["disk_inode"],
                  "qmp_device": monitor.st_dev,
                  "qmp_inode": monitor.st_ino,
                  "port": before["port"],
                  "requested_at": int(time.time()),
                  "copy_removed": False, "rollback_qualified": False,
                  "package_install_authorized": False,
                  "product_dispatch_authorized": False}
        intent_raw = create._write(lease.parent,
                                   copy_vm_id + INTENT_SUFFIX, intent)
        # From here, failures leave a durable intent and require manual review.
        stopped._qmp_powerdown(
            qmp_path, disk_path, pid=before["pid"],
            uid=before["runtime_uid"],
            start_ticks=before["start_ticks"], boot_id=before["boot_id"],
            socket_device=monitor.st_dev, socket_inode=monitor.st_ino)
        stopped._wait_stopped(
            before["runtime_uid"], before["pid"], before["start_ticks"],
            before["boot_id"], directory_path, before["port"])
        parent_fd = runtime._runtime_parent(runtime_parent)
        directory = disk_fd = seed_fd = None
        try:
            directory = observer.open_vm_dir(directory_path,
                                             before["runtime_uid"])
            copy._closed_names(directory, {"disk.qcow2", "seed.iso"})
            disk_fd = launched._held_mutable_disk(
                directory, uid=before["runtime_uid"],
                gid=before["runtime_gid"],
                device=before["disk_device"],
                inode=before["disk_inode"])
            prepared_raw, prepared = create._read_record(
                lease.parent, copy_vm_id + copy.PREPARED_SUFFIX)
            release.require(release.digest(prepared_raw)
                            == before["prepared_sha256"],
                            "fixture rollback prepared copy changed")
            seed_fd = copy._held_regular(
                directory, "seed.iso", owner=0,
                group=before["runtime_gid"], mode=0o440,
                device=prepared["seed_device"],
                inode=prepared["seed_inode"], size=prepared["seed_bytes"])
            release.require(copy.restart._mutable_digest(seed_fd)[:2]
                            == (prepared["seed_bytes"],
                                prepared["seed_sha256"]),
                            "fixture rollback cleanup seed differs")
            held_dir = os.fstat(directory)
            disk_stamp = os.fstat(disk_fd)
            seed_stamp = os.fstat(seed_fd)
            create._rebind_directory(registry, lease.parent)
            release.require(create._read_record(
                            lease.parent, copy_vm_id + INTENT_SUFFIX)[0]
                            == intent_raw
                            and create._read_record(
                            lease.parent, copy_vm_id + launched.BASELINE_SUFFIX)[0]
                            == baseline_raw,
                            "fixture rollback cleanup inputs changed")
            stopped_record = {"schema": SCHEMA, "phase": "copy_stopped",
                              "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                              "intent_sha256": release.digest(intent_raw),
                              "pid": before["pid"],
                              "start_ticks": before["start_ticks"],
                              "boot_id": before["boot_id"],
                              "runtime_directory_device": held_dir.st_dev,
                              "runtime_directory_inode": held_dir.st_ino,
                              "disk_device": disk_stamp.st_dev,
                              "disk_inode": disk_stamp.st_ino,
                              "seed_device": seed_stamp.st_dev,
                              "seed_inode": seed_stamp.st_ino,
                              "observed_at": int(time.time()),
                              "copy_removed": False,
                              "rollback_qualified": False,
                              "package_install_authorized": False,
                              "product_dispatch_authorized": False}
            stopped_raw = create._write(
                lease.parent, copy_vm_id + STOPPED_SUFFIX, stopped_record)
            remove_intent = {"schema": SCHEMA, "phase": "remove_intent",
                             "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                             "cleanup_intent_sha256": release.digest(intent_raw),
                             "stopped_sha256": release.digest(stopped_raw),
                             "runtime_directory_device": held_dir.st_dev,
                             "runtime_directory_inode": held_dir.st_ino,
                             "disk_device": disk_stamp.st_dev,
                             "disk_inode": disk_stamp.st_ino,
                             "seed_device": seed_stamp.st_dev,
                             "seed_inode": seed_stamp.st_ino,
                             "requested_at": int(time.time()),
                             "copy_removed": False,
                             "rollback_qualified": False,
                             "package_install_authorized": False,
                             "product_dispatch_authorized": False}
            remove_raw = create._write(
                lease.parent, copy_vm_id + REMOVE_INTENT_SUFFIX,
                remove_intent)
            # Exact held inode/name checks precede each unlink. All absent or
            # partial states after this point remain manual-recovery only.
            _same_named_file(directory, "disk.qcow2", disk_stamp)
            os.unlink("disk.qcow2", dir_fd=directory)
            os.fsync(directory)
            _require_absent(directory, "disk.qcow2")
            _same_named_file(directory, "seed.iso", seed_stamp)
            os.unlink("seed.iso", dir_fd=directory)
            os.fsync(directory)
            _require_absent(directory, "seed.iso")
            current_dir = os.stat(copy_vm_id, dir_fd=parent_fd,
                                  follow_symlinks=False)
            release.require(stat.S_ISDIR(current_dir.st_mode)
                            and (current_dir.st_dev, current_dir.st_ino,
                                 current_dir.st_uid, current_dir.st_gid,
                                 stat.S_IMODE(current_dir.st_mode))
                            == (held_dir.st_dev, held_dir.st_ino,
                                held_dir.st_uid, held_dir.st_gid, 0o700),
                            "fixture rollback directory changed before removal")
            os.rmdir(copy_vm_id, dir_fd=parent_fd)
            os.fsync(parent_fd)
            _require_absent(parent_fd, copy_vm_id)
            create._rebind_directory(registry, lease.parent)
            release.require(create._read_record(
                            lease.parent, copy_vm_id + REMOVE_INTENT_SUFFIX)[0]
                            == remove_raw,
                            "fixture rollback removal intent changed")
            result = {"schema": SCHEMA, "phase": "copy_removed",
                      "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                      "cleanup_intent_sha256": release.digest(intent_raw),
                      "stopped_sha256": release.digest(stopped_raw),
                      "remove_intent_sha256": release.digest(remove_raw),
                      "baseline_sha256": release.digest(baseline_raw),
                      "removed_at": int(time.time()),
                      "copy_removed": True, "rollback_qualified": False,
                      "package_install_authorized": False,
                      "product_dispatch_authorized": False}
            create._write(lease.parent, copy_vm_id + RESULT_SUFFIX, result)
            return result
        finally:
            for fd in (seed_fd, disk_fd, directory, parent_fd):
                if fd is not None:
                    os.close(fd)
