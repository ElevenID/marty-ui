#!/usr/bin/env python3
"""Dedicated one-shot QEMU launch for a prepared rollback-copy disk.

This never invents pristine VM creation/transfer receipts. All output remains
test-infrastructure evidence, with package/product authority false. No live
caller or CLI exists; an intent-only or PID-only launch is not retried.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import time

from installer_candidate_controller import ControllerLease
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_release as release
import installer_test_vm_rootless_rollback_copy as copy

SCHEMA = "elevenid.installer-only-rootless-rollback-launch/v1"
PID_SCHEMA = "elevenid.installer-only-rootless-rollback-pid/v1"
INTENT_SUFFIX = ".rootless-rollback-launch-intent.json"
PID_SUFFIX = ".rootless-rollback-launch-pid.json"
RECEIPT_SUFFIX = ".rootless-rollback-launch-receipt.json"
OBSERVE_SECONDS = 45


def _unused(parent: int, copy_vm_id: str) -> None:
    for suffix in (INTENT_SUFFIX, PID_SUFFIX, RECEIPT_SUFFIX):
        try:
            os.stat(copy_vm_id + suffix, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("fixture rollback launch already attempted")


def launch_copy(*, source: Path, registry: Path, runtime_parent: Path,
                vm_id: str, copy_vm_id: str) -> dict:
    """Launch only a revalidated new copy inode; never the original snapshot."""
    release.require(os.geteuid() == 0, "fixture rollback launch needs root controller")
    with ControllerLease(registry) as lease:
        before = copy.bound_prepared_copy(
            source=source, registry=registry, runtime_parent=runtime_parent,
            vm_id=vm_id, copy_vm_id=copy_vm_id, _lease=lease)
        _unused(lease.parent, copy_vm_id)
        runtime_dir = before["runtime_dir"]
        disk_path = runtime_dir / "disk.qcow2"
        uid, gid = before["runtime_uid"], before["runtime_gid"]
        kvm_gid = launch._kvm_group()
        qemu_sha = launch._trusted_tool(launch.QEMU)
        setpriv_sha = launch._trusted_tool(launch.SETPRIV)
        launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        args = launch._arguments(runtime_dir, copy_vm_id,
                                 before["copy_port"],
                                 launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        # The source snapshot path never appears in these fixed QEMU arguments.
        release.require(str(disk_path) in args[args.index("-drive") + 1]
                        and all("rootless-stopped-snapshot" not in arg
                                for arg in args),
                        "fixture rollback QEMU disk selection differs")
        runtime_fd = observer.open_vm_dir(runtime_dir, uid)
        try:
            disk_fd = copy._held_regular(
                runtime_fd, "disk.qcow2", owner=uid, group=gid, mode=0o600,
                device=before["disk_device"], inode=before["disk_inode"],
                size=before["disk_bytes"])
            try:
                release.require(copy.restart._mutable_digest(disk_fd)[:2]
                                == (before["disk_bytes"],
                                    before["disk_sha256"]),
                                "fixture rollback disk changed before launch")
                launch._seed_media(runtime_fd, before, gid)
                boot = launch._boot_id()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                    reserved.bind(("127.0.0.1", before["copy_port"]))
                    current = copy.bound_prepared_copy(
                        source=source, registry=registry,
                        runtime_parent=runtime_parent, vm_id=vm_id,
                        copy_vm_id=copy_vm_id, _lease=lease)
                    release.require(current == before,
                                    "fixture rollback-copy binding changed")
                    intent = {"schema": SCHEMA, "phase": "launch_intent",
                              "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                              "prepared_sha256": before["prepared_sha256"],
                              "pending_sha256": before["pending_sha256"],
                              "runtime_uid": uid, "runtime_gid": gid,
                              "runtime_directory_device":
                                  before["runtime_directory_device"],
                              "runtime_directory_inode":
                                  before["runtime_directory_inode"],
                              "disk_device": before["disk_device"],
                              "disk_inode": before["disk_inode"],
                              "disk_sha256": before["disk_sha256"],
                              "seed_device": before["seed_device"],
                              "seed_inode": before["seed_inode"],
                              "seed_sha256": before["seed_sha256"],
                              "ssh_port": before["copy_port"],
                              "memory_mib": launch.ROOTLESS_FIXTURE_MEMORY_MIB,
                              "kvm_gid": kvm_gid, "args": args,
                              "qemu_sha256": qemu_sha,
                              "setpriv_sha256": setpriv_sha,
                              "controller_boot_id": boot,
                              "requested_at": int(time.time()),
                              "rollback_qualified": False,
                              "package_install_authorized": False,
                              "product_dispatch_authorized": False}
                    intent_raw = create._write(
                        lease.parent, copy_vm_id + INTENT_SUFFIX, intent)
                # Intent is durable before any guest process can start.
                current = copy.bound_prepared_copy(
                    source=source, registry=registry,
                    runtime_parent=runtime_parent, vm_id=vm_id,
                    copy_vm_id=copy_vm_id, _lease=lease)
                release.require(current == before
                                and launch._boot_id() == boot
                                and launch._trusted_tool(launch.QEMU) == qemu_sha
                                and launch._trusted_tool(launch.SETPRIV) == setpriv_sha,
                                "fixture rollback launch inputs changed")
                launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
                command = [str(launch.SETPRIV), "--reuid", str(uid),
                           "--regid", str(gid), "--groups", str(kvm_gid),
                           "--bounding-set=-all", "--inh-caps=-all",
                           "--ambient-caps=-all", "--no-new-privs", "--", *args]
                process = subprocess.Popen(
                    command, cwd="/", env=launch.ENV,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True,
                    close_fds=True)
                # No automatic kill/retry if observation or receipt fails.
                start_ticks = launch._start_ticks(process.pid)
                pid_raw = create._write(lease.parent, copy_vm_id + PID_SUFFIX,
                    {"schema": PID_SCHEMA, "phase": "spawned",
                     "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                     "intent_sha256": release.digest(intent_raw),
                     "pid": process.pid, "start_ticks": start_ticks,
                     "controller_boot_id": boot,
                     "spawned_at": int(time.time())})
                live = None
                deadline = time.monotonic() + OBSERVE_SECONDS
                while time.monotonic() < deadline:
                    release.require(process.poll() is None,
                                    "fixture rollback QEMU exited before observation")
                    try:
                        live = launch._live(
                            process.pid, args, uid, gid, kvm_gid,
                            disk_path, before["disk_device"],
                            before["disk_inode"], qemu_sha)
                        break
                    except (FileNotFoundError, ConnectionRefusedError,
                            socket.timeout, observer.DiskNotOpenedYet):
                        time.sleep(0.25)
                release.require(live is not None
                                and live["start_ticks"] == start_ticks,
                                "fixture rollback QEMU observation timed out")
                release.require(launch._live(
                                process.pid, args, uid, gid, kvm_gid,
                                disk_path, before["disk_device"],
                                before["disk_inode"], qemu_sha) == live
                                and create._read_record(
                                    lease.parent, copy_vm_id + INTENT_SUFFIX)[0]
                                    == intent_raw
                                and create._read_record(
                                    lease.parent, copy_vm_id + PID_SUFFIX)[0]
                                    == pid_raw,
                                "fixture rollback QEMU changed before receipt")
                receipt = {**intent, "phase": "launched",
                           "intent_sha256": release.digest(intent_raw),
                           "pid_record_sha256": release.digest(pid_raw),
                           "pid": process.pid, "start_ticks": start_ticks,
                           "disk_fd": live["disk_fd"],
                           "observed_at": int(time.time())}
                create._write(lease.parent, copy_vm_id + RECEIPT_SUFFIX,
                              receipt)
                return receipt
            finally:
                os.close(disk_fd)
        finally:
            os.close(runtime_fd)
