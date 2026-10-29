#!/usr/bin/env python3
"""Dormant one-shot resume of an exact stopped fixture checkpoint.

This is test infrastructure only. It never grants guest package or product
authority; no CLI or live caller exists. An uncertain intent is never retried.
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
import installer_candidate_vm_runtime as runtime
import installer_release as release
import installer_test_vm_restart as restart
import installer_test_vm_rootless_checkpoint as checkpoint
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_rollback_proof as proof

SCHEMA = "elevenid.installer-only-rootless-checkpoint-resume/v1"
PID_SCHEMA = "elevenid.installer-only-rootless-checkpoint-resume-pid/v1"
INTENT_SUFFIX = ".rootless-checkpoint-resume-intent.json"
PID_SUFFIX = ".rootless-checkpoint-resume-pid.json"
RECEIPT_SUFFIX = ".rootless-checkpoint-resume-receipt.json"
OBSERVE_SECONDS = 45


def _checkpoint(parent: int, vm_id: str, proof_value: dict) -> tuple[bytes, dict]:
    raw, record = create._read_record(parent, vm_id + checkpoint.SUFFIX)
    release.exact(record,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "controller_boot_id", "stopped_pid",
                   "stopped_start_ticks", "disk_device", "disk_inode",
                   "disk_sha256", "snapshot_sha256", "snapshot_bytes",
                   "rollback_test_sha256", "admission_result_sha256",
                   "stage_recheck_sha256", "source_module_sha256",
                   "source_controller_sha256", "created_at", "stopped",
                   "package_install_authorized", "product_dispatch_authorized"},
                  "fixture checkpoint resume record")
    release.require(record["schema"] == checkpoint.SCHEMA
                    and record["phase"] == "historical_rollback_observed"
                    and record["vm_id"] == vm_id
                    and record["copy_vm_id"] == proof_value["copy_vm_id"]
                    and record["controller_boot_id"] == launch._boot_id()
                    and record["disk_sha256"] == proof_value["disk_sha256"]
                    and record["snapshot_sha256"]
                    == proof_value["snapshot_sha256"]
                    and record["rollback_test_sha256"]
                    == proof_value["cleanup_result_sha256"]
                    and record["admission_result_sha256"]
                    == proof_value["admission_result_sha256"]
                    and record["stopped"] is True
                    and record["package_install_authorized"] is False
                    and record["product_dispatch_authorized"] is False,
                    "fixture checkpoint resume evidence differs")
    return raw, record


def _unused(parent: int, vm_id: str) -> None:
    for suffix in (INTENT_SUFFIX, PID_SUFFIX, RECEIPT_SUFFIX):
        try:
            os.stat(vm_id + suffix, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError("fixture checkpoint resume already attempted")


def resume(*, source: Path, registry: Path, runtime_parent: Path,
           vm_id: str, copy_vm_id: str) -> dict:
    """Spawn fixed QEMU from the original stopped inode, once."""
    release.require(os.geteuid() == 0
                    and all(path.is_absolute() for path in
                            (source, registry, runtime_parent)),
                    "fixture checkpoint resume needs trusted controller")
    with ControllerLease(registry) as lease:
        prior = proof.inspect_proof(
            source=source, registry=registry, runtime_parent=runtime_parent,
            vm_id=vm_id, copy_vm_id=copy_vm_id, _lease=lease)
        checkpoint_raw, checked = _checkpoint(lease.parent, vm_id, prior)
        _unused(lease.parent, vm_id)
        stop_raw, stop = create._read_record(
            lease.parent, vm_id + proof.stopped.INTENT_SUFFIX)
        pending_raw, pending = create._read_record(
            lease.parent, vm_id + proof.stopped.PENDING_SUFFIX)
        launch_raw, original_launch = create._read_record(
            lease.parent, vm_id + ".launch-intent.json")
        creation_raw, creation = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        seed_raw, seed = create._read_record(
            lease.parent, vm_id + ".seed-receipt.json")
        release.require(release.digest(pending_raw) == prior["pending_sha256"]
                        and pending["intent_sha256"] == release.digest(stop_raw)
                        and checked["stopped_pid"] == stop["pid"]
                        and checked["stopped_start_ticks"]
                        == stop["start_ticks"]
                        and (checked["disk_device"], checked["disk_inode"])
                        == (pending["disk_device"], pending["disk_inode"])
                        and checked["snapshot_bytes"]
                        == pending["snapshot_bytes"]
                        and stop["launch_sha256"]
                        == release.digest(create._read_record(
                            lease.parent, vm_id + ".launch-receipt.json")[0])
                        and original_launch["ssh_port"] == seed["ssh_port"]
                        and creation["image"] == create.verify_source(source),
                        "fixture checkpoint resume original chain differs")
        runtime_dir = runtime_parent / vm_id
        disk_path = runtime_dir / "disk.qcow2"
        uid, gid = stop["runtime_uid"], stop["runtime_gid"]
        qemu_sha = launch._trusted_tool(launch.QEMU)
        setpriv_sha = launch._trusted_tool(launch.SETPRIV)
        kvm_gid = launch._kvm_group()
        launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        args = launch._arguments(runtime_dir, vm_id, seed["ssh_port"],
                                 launch.ROOTLESS_FIXTURE_MEMORY_MIB)
        release.require(args == original_launch["args"],
                        "fixture checkpoint QEMU arguments differ")
        runtime_fd = observer.open_vm_dir(runtime_dir, uid)
        disk_fd = None
        try:
            copy._closed_names(runtime_fd, {"disk.qcow2", "seed.iso"})
            disk_fd = restart._disk_fd(runtime_fd, uid, gid,
                                       pending["disk_device"], pending["disk_inode"])
            release.require(restart._mutable_digest(disk_fd)[:2]
                            == (pending["disk_bytes"], pending["disk_sha256"]),
                            "fixture checkpoint disk differs before resume")
            restart._mutable_image_info(
                disk_path, disk_fd, uid, gid,
                creation["image"]["image_path"], creation["virtual_gib"] * 1024**3)
            release.require(restart._mutable_digest(disk_fd)[:2]
                            == (pending["disk_bytes"], pending["disk_sha256"]),
                            "fixture checkpoint disk changed during image inspection")
            launch._seed_media(runtime_fd, seed, gid)
            launch._same_path(runtime_dir, runtime_fd,
                              lambda path: observer.open_vm_dir(path, uid))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", seed["ssh_port"]))
                current = proof.inspect_proof(
                    source=source, registry=registry,
                    runtime_parent=runtime_parent, vm_id=vm_id,
                    copy_vm_id=copy_vm_id, _lease=lease)
                release.require(current == prior,
                                "fixture checkpoint proof changed before intent")
                boot = launch._boot_id()
                intent = {"schema": SCHEMA, "phase": "resume_intent",
                          "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                          "checkpoint_sha256": release.digest(checkpoint_raw),
                          "pending_sha256": release.digest(pending_raw),
                          "creation_sha256": release.digest(creation_raw),
                          "seed_sha256": release.digest(seed_raw),
                          "controller_boot_id": boot,
                          "prior_pid": stop["pid"],
                          "prior_start_ticks": stop["start_ticks"],
                          "runtime_uid": uid, "runtime_gid": gid,
                          "runtime_directory_device": os.fstat(runtime_fd).st_dev,
                          "runtime_directory_inode": os.fstat(runtime_fd).st_ino,
                          "disk_device": pending["disk_device"],
                          "disk_inode": pending["disk_inode"],
                          "disk_sha256": pending["disk_sha256"],
                          "ssh_port": seed["ssh_port"],
                          "memory_mib": launch.ROOTLESS_FIXTURE_MEMORY_MIB,
                          "kvm_gid": kvm_gid, "args": args,
                          "qemu_sha256": qemu_sha,
                          "setpriv_sha256": setpriv_sha,
                          "requested_at": int(time.time()),
                          "package_install_authorized": False,
                          "product_dispatch_authorized": False}
                intent_raw = create._write(
                    lease.parent, vm_id + INTENT_SUFFIX, intent)
            # Every failure past this point retains a durable intent. No retry.
            release.require(proof.inspect_proof(
                            source=source, registry=registry,
                            runtime_parent=runtime_parent, vm_id=vm_id,
                            copy_vm_id=copy_vm_id, _lease=lease) == prior
                            and create._read_record(
                                lease.parent, vm_id + INTENT_SUFFIX)[0] == intent_raw
                            and launch._trusted_tool(launch.QEMU) == qemu_sha
                            and launch._trusted_tool(launch.SETPRIV) == setpriv_sha
                            and launch._boot_id() == boot,
                            "fixture checkpoint changed before spawn")
            launch._host_headroom(launch.ROOTLESS_FIXTURE_MEMORY_MIB)
            process = subprocess.Popen(
                [str(launch.SETPRIV), "--reuid", str(uid), "--regid", str(gid),
                 "--groups", str(kvm_gid), "--bounding-set=-all",
                 "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
                 "--", *args], cwd="/", env=launch.ENV,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
                close_fds=True)
            ticks = launch._start_ticks(process.pid)
            pid_raw = create._write(lease.parent, vm_id + PID_SUFFIX,
                {"schema": PID_SCHEMA, "phase": "spawned", "vm_id": vm_id,
                 "intent_sha256": release.digest(intent_raw),
                 "controller_boot_id": boot, "pid": process.pid,
                 "start_ticks": ticks, "spawned_at": int(time.time())})
            live = None
            deadline = time.monotonic() + OBSERVE_SECONDS
            while time.monotonic() < deadline:
                release.require(process.poll() is None,
                                "fixture checkpoint QEMU exited")
                try:
                    live = launch._live(
                        process.pid, args, uid, gid, kvm_gid,
                        disk_path, pending["disk_device"],
                        pending["disk_inode"], qemu_sha)
                    break
                except (FileNotFoundError, ConnectionRefusedError,
                        socket.timeout, observer.DiskNotOpenedYet):
                    time.sleep(0.25)
            release.require(live is not None and live["start_ticks"] == ticks
                            and launch._live(process.pid, args, uid, gid,
                                             kvm_gid, disk_path,
                                             pending["disk_device"],
                                             pending["disk_inode"], qemu_sha)
                            == live
                            and create._read_record(
                                lease.parent, vm_id + INTENT_SUFFIX)[0]
                            == intent_raw
                            and create._read_record(
                                lease.parent, vm_id + PID_SUFFIX)[0]
                            == pid_raw,
                            "fixture checkpoint live QEMU differs")
            receipt = {**intent, "phase": "resumed",
                       "intent_sha256": release.digest(intent_raw),
                       "pid_record_sha256": release.digest(pid_raw),
                       "pid": process.pid, "start_ticks": ticks,
                       "disk_fd": live["disk_fd"],
                       "observed_at": int(time.time())}
            create._write(lease.parent, vm_id + RECEIPT_SUFFIX, receipt)
            return receipt
        finally:
            for fd in (disk_fd, runtime_fd):
                if fd is not None:
                    os.close(fd)
