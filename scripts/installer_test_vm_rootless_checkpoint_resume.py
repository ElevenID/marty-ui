#!/usr/bin/env python3
"""Dormant one-shot resume of an exact stopped fixture checkpoint.

This is test infrastructure only. It never grants guest package or product
authority; no CLI or live caller exists. An uncertain intent is never retried.
"""
from __future__ import annotations

from contextlib import nullcontext
import json
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
import installer_candidate_vm_seed as seed_module
import installer_release as release
import installer_test_vm_restart as restart
import installer_test_vm_rootless_package_admission as archive
import installer_test_vm_rootless_package_admission_controller as admission
import installer_test_vm_rootless_checkpoint as checkpoint
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_rollback_proof as proof
import installer_test_vm_rootless_setup as setup

SCHEMA = "elevenid.installer-only-rootless-checkpoint-resume/v1"
PID_SCHEMA = "elevenid.installer-only-rootless-checkpoint-resume-pid/v1"
INTENT_SUFFIX = ".rootless-checkpoint-resume-intent.json"
PID_SUFFIX = ".rootless-checkpoint-resume-pid.json"
RECEIPT_SUFFIX = ".rootless-checkpoint-resume-receipt.json"
READINESS_SUFFIX = ".rootless-checkpoint-resume-readiness.json"
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
        setup_raw, setup_record = create._read_record(
            lease.parent, vm_id + setup.SETUP_READINESS_SUFFIX)
        release.exact(setup_record,
                      {"schema", "phase", "vm_id", "launch_sha256",
                       "seed_sha256", "pid", "start_ticks", "boot_id",
                       "setup_engine_id", "ordinary_uid", "ordinary_gid",
                       "ordinary_home", "setup_uid", "setup_gid", "setup_home",
                       "setup_principal_distinct",
                       "ordinary_no_sudo_or_docker_group",
                       "setup_socket_denied_to_installer",
                       "setup_engine_stopped", "rootless_engine_observed",
                       "rootless_ready", "qualified",
                       "product_dispatch_authorized", "observed_at"},
                      "fixture resumed historical setup")
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


def bound_resumed(*, source: Path, registry: Path, runtime_parent: Path,
                  vm_id: str, copy_vm_id: str,
                  _lease: ControllerLease | None = None) -> dict:
    """Reobserve only the new live QEMU epoch and retained snapshot."""
    release.require(os.geteuid() == 0 and all(path.is_absolute() for path in
                    (source, registry, runtime_parent)),
                    "fixture resumed binding needs trusted controller")
    with (ControllerLease(registry) if _lease is None
          else nullcontext(_lease)) as lease:
        historical = proof._records(lease.parent, vm_id, copy_vm_id)
        proof._exact_chain(historical, vm_id, copy_vm_id)
        h = {key: value[1] for key, value in historical.items()}
        historical_value = {
            "copy_vm_id": copy_vm_id,
            "disk_sha256": h["pending"]["disk_sha256"],
            "snapshot_sha256": h["pending"]["snapshot_sha256"],
            "cleanup_result_sha256": release.digest(
                historical["cleanup_result"][0]),
            "admission_result_sha256": release.digest(
                historical["admission_result"][0])}
        checked_raw, checked = _checkpoint(lease.parent, vm_id,
                                           historical_value)
        intent_raw, intent = create._read_record(
            lease.parent, vm_id + INTENT_SUFFIX)
        pid_raw, spawned = create._read_record(
            lease.parent, vm_id + PID_SUFFIX)
        receipt_raw, receipt = create._read_record(
            lease.parent, vm_id + RECEIPT_SUFFIX)
        intent_fields = {"schema", "phase", "vm_id", "copy_vm_id",
                         "checkpoint_sha256", "pending_sha256",
                         "creation_sha256", "seed_sha256",
                         "controller_boot_id", "prior_pid",
                         "prior_start_ticks", "runtime_uid", "runtime_gid",
                         "runtime_directory_device", "runtime_directory_inode",
                         "disk_device", "disk_inode", "disk_sha256",
                         "ssh_port", "memory_mib", "kvm_gid", "args",
                         "qemu_sha256", "setpriv_sha256", "requested_at",
                         "package_install_authorized",
                         "product_dispatch_authorized"}
        release.exact(intent, intent_fields, "fixture checkpoint resume intent")
        release.exact(spawned,
                      {"schema", "phase", "vm_id", "intent_sha256",
                       "controller_boot_id", "pid", "start_ticks",
                       "spawned_at"}, "fixture checkpoint resume PID")
        release.exact(receipt,
                      intent_fields | {"intent_sha256", "pid_record_sha256",
                                       "pid", "start_ticks", "disk_fd",
                                       "observed_at"},
                      "fixture checkpoint resume receipt")
        release.require(intent["schema"] == receipt["schema"] == SCHEMA
                        and spawned["schema"] == PID_SCHEMA
                        and [intent["phase"], spawned["phase"], receipt["phase"]]
                        == ["resume_intent", "spawned", "resumed"]
                        and all(receipt[key] == value for key, value in
                                intent.items() if key != "phase")
                        and intent["vm_id"] == spawned["vm_id"]
                        == receipt["vm_id"] == vm_id
                        and intent["copy_vm_id"] == copy_vm_id
                        and intent["checkpoint_sha256"]
                        == release.digest(checked_raw)
                        and intent["pending_sha256"]
                        == release.digest(historical["pending"][0])
                        and spawned["intent_sha256"]
                        == receipt["intent_sha256"]
                        == release.digest(intent_raw)
                        and receipt["pid_record_sha256"]
                        == release.digest(pid_raw)
                        and receipt["pid"] == spawned["pid"]
                        and receipt["start_ticks"] == spawned["start_ticks"]
                        and type(spawned["pid"]) is int and spawned["pid"] > 4
                        and type(spawned["start_ticks"]) is str
                        and spawned["start_ticks"].isascii()
                        and spawned["start_ticks"].isdecimal()
                        and intent["controller_boot_id"]
                        == spawned["controller_boot_id"] == launch._boot_id()
                        and intent["prior_pid"] == h["stop"]["pid"]
                        and intent["prior_start_ticks"]
                        == h["stop"]["start_ticks"]
                        and intent["disk_sha256"]
                        == h["pending"]["disk_sha256"]
                        and (intent["disk_device"], intent["disk_inode"])
                        == (h["pending"]["disk_device"],
                            h["pending"]["disk_inode"])
                        and (intent["runtime_uid"], intent["runtime_gid"])
                        == (h["stop"]["runtime_uid"],
                            h["stop"]["runtime_gid"])
                        and intent["memory_mib"]
                        == launch.ROOTLESS_FIXTURE_MEMORY_MIB
                        and intent["package_install_authorized"] is False
                        and intent["product_dispatch_authorized"] is False,
                        "fixture checkpoint resume record chain differs")
        creation_raw, creation = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        seed_raw, seed = create._read_record(
            lease.parent, vm_id + ".seed-receipt.json")
        original_launch_raw, original_launch = create._read_record(
            lease.parent, vm_id + ".launch-intent.json")
        setup_raw, setup_record = create._read_record(
            lease.parent, vm_id + setup.SETUP_READINESS_SUFFIX)
        release.exact(setup_record,
                      {"schema", "phase", "vm_id", "launch_sha256",
                       "seed_sha256", "pid", "start_ticks", "boot_id",
                       "setup_engine_id", "ordinary_uid", "ordinary_gid",
                       "ordinary_home", "setup_uid", "setup_gid", "setup_home",
                       "setup_principal_distinct",
                       "ordinary_no_sudo_or_docker_group",
                       "setup_socket_denied_to_installer",
                       "setup_engine_stopped", "rootless_engine_observed",
                       "rootless_ready", "qualified",
                       "product_dispatch_authorized", "observed_at"},
                      "fixture resumed historical setup")
        provenance = create.verify_source(source)
        runtime_dir = runtime_parent / vm_id
        release.require(creation["image"] == provenance
                        and intent["creation_sha256"]
                        == release.digest(creation_raw)
                        == h["copy_intent"]["creation_sha256"]
                        and intent["seed_sha256"]
                        == release.digest(seed_raw)
                        == h["copy_intent"]["seed_sha256"]
                        and release.digest(original_launch_raw)
                        == h["copy_intent"]["launch_sha256"]
                        and release.digest(setup_raw)
                        == h["copy_intent"]["setup_readiness_sha256"]
                        == h["stop"]["setup_readiness_sha256"]
                        and setup_record["schema"]
                        == setup.SETUP_READINESS_SCHEMA
                        and setup_record["phase"] == "setup_engine_observed"
                        and setup_record["vm_id"] == vm_id
                        and type(setup_record["ordinary_uid"]) is int
                        and setup_record["ordinary_uid"] > 0
                        and setup_record["ordinary_home"] == "/home/installer"
                        and setup_record["setup_principal_distinct"] is True
                        and setup_record["ordinary_no_sudo_or_docker_group"] is True
                        and setup_record["setup_socket_denied_to_installer"] is True
                        and setup_record["setup_engine_stopped"] is False
                        and setup_record["rootless_engine_observed"] is False
                        and setup_record["rootless_ready"] is False
                        and setup_record["qualified"] is False
                        and setup_record["product_dispatch_authorized"] is False
                        and setup_record["setup_engine_id"]
                        == h["admission_result"]["engine_id"]
                        and checked["stopped_pid"] == h["stop"]["pid"]
                        and checked["stopped_start_ticks"]
                        == h["stop"]["start_ticks"]
                        and checked["source_module_sha256"]
                        == h["admission_result"]["module_sha256"]
                        and checked["source_controller_sha256"]
                        == h["admission_result"]["controller_sha256"]
                        and seed["ssh_port"] == intent["ssh_port"]
                        and intent["args"] == original_launch["args"]
                        == launch._arguments(runtime_dir, vm_id,
                                             intent["ssh_port"],
                                             launch.ROOTLESS_FIXTURE_MEMORY_MIB)
                        and intent["qemu_sha256"]
                        == launch._trusted_tool(launch.QEMU)
                        and intent["setpriv_sha256"]
                        == launch._trusted_tool(launch.SETPRIV)
                        and intent["kvm_gid"] == launch._kvm_group(),
                        "fixture checkpoint resume source differs")
        parent_fd = runtime._runtime_parent(runtime_parent)
        held = disk_fd = seed_fd = snapshot_dir = snapshot_file = control_fd = None
        try:
            release.require((os.fstat(parent_fd).st_dev,
                             os.fstat(parent_fd).st_ino)
                            == (h["copy_intent"]["runtime_parent_device"],
                                h["copy_intent"]["runtime_parent_inode"]),
                            "fixture resumed runtime parent differs")
            held = observer.open_vm_dir(runtime_dir, intent["runtime_uid"])
            release.require((os.fstat(held).st_dev, os.fstat(held).st_ino)
                            == (intent["runtime_directory_device"],
                                intent["runtime_directory_inode"]),
                            "fixture checkpoint resumed directory differs")
            copy._closed_names(held, {"disk.qcow2", "seed.iso", "qmp.sock"})
            disk_fd = proof.launched._held_mutable_disk(
                held, uid=intent["runtime_uid"], gid=intent["runtime_gid"],
                device=intent["disk_device"], inode=intent["disk_inode"])
            seed_fd = copy._held_regular(
                held, "seed.iso", owner=0, group=intent["runtime_gid"],
                mode=0o440, device=seed["seed_device"],
                inode=seed["seed_inode"], size=seed["seed_bytes"])
            release.require(restart._mutable_digest(seed_fd)[:2]
                            == (seed["seed_bytes"], seed["seed_sha256"]),
                            "fixture resumed seed differs")
            snapshot_dir, snapshot_file = copy._snapshot(
                registry, lease, vm_id, h["pending"])
            live = launch._live(
                receipt["pid"], intent["args"], intent["runtime_uid"],
                intent["runtime_gid"], intent["kvm_gid"],
                runtime_dir / "disk.qcow2", intent["disk_device"],
                intent["disk_inode"], intent["qemu_sha256"])
            release.require(live == {"pid": receipt["pid"],
                                     "start_ticks": receipt["start_ticks"],
                                     "disk_fd": receipt["disk_fd"]},
                            "fixture resumed live QEMU differs")
            control_dir = registry / (vm_id + ".control")
            control_fd = copy._directory(control_dir)
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
                            "fixture resumed SSH control differs")
            launch._same_path(runtime_dir, held,
                              lambda path: observer.open_vm_dir(
                                  path, intent["runtime_uid"]))
            runtime._same_path(runtime_parent, parent_fd,
                               runtime._runtime_parent)
            create._rebind_directory(control_dir, control_fd)
            create._rebind_directory(registry, lease.parent)
            release.require(proof._records(lease.parent, vm_id, copy_vm_id)
                            == historical
                            and all(create._read_record(lease.parent,
                                vm_id + suffix)[0] == original for suffix,
                                original in ((INTENT_SUFFIX, intent_raw),
                                             (PID_SUFFIX, pid_raw),
                                             (RECEIPT_SUFFIX, receipt_raw),
                                             (".creation-receipt.json",
                                              creation_raw),
                                             (".seed-receipt.json", seed_raw),
                                             (setup.SETUP_READINESS_SUFFIX,
                                              setup_raw),
                                             (".launch-intent.json",
                                              original_launch_raw)))
                            and create.verify_source(source) == provenance
                            and launch._live(
                                receipt["pid"], intent["args"],
                                intent["runtime_uid"], intent["runtime_gid"],
                                intent["kvm_gid"], runtime_dir / "disk.qcow2",
                                intent["disk_device"], intent["disk_inode"],
                                intent["qemu_sha256"]) == live,
                            "fixture resumed epoch changed")
            return {"vm_id": vm_id, "copy_vm_id": copy_vm_id,
                    "pid": receipt["pid"],
                    "start_ticks": receipt["start_ticks"],
                    "boot_id": intent["controller_boot_id"],
                    "runtime_uid": intent["runtime_uid"],
                    "runtime_gid": intent["runtime_gid"],
                    "port": intent["ssh_port"],
                    "control_dir": control_dir,
                    "key_sha256": seed["controller_private_sha256"],
                    "known_hosts_sha256": seed["known_hosts_sha256"],
                    "guest_uid": setup_record["ordinary_uid"],
                    "historical_engine_id":
                        h["admission_result"]["engine_id"],
                    "checkpoint_sha256": release.digest(checked_raw),
                    "resume_receipt_sha256": release.digest(receipt_raw),
                    "package_install_authorized": False,
                    "product_dispatch_authorized": False}
        finally:
            for fd in (control_fd, snapshot_file, snapshot_dir,
                       seed_fd, disk_fd, held, parent_fd):
                if fd is not None:
                    os.close(fd)


def observe_current_readiness(*, source: Path, registry: Path,
                              runtime_parent: Path, vm_id: str,
                              copy_vm_id: str) -> dict:
    """Observe current resumed guest principals, Engine and dpkg, read-only."""
    release.require(os.geteuid() == 0,
                    "fixture resume readiness needs trusted controller")
    with ControllerLease(registry) as lease:
        try:
            os.stat(vm_id + READINESS_SUFFIX, dir_fd=lease.parent,
                    follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("fixture resume readiness already attempted")
        before = bound_resumed(source=source, registry=registry,
                               runtime_parent=runtime_parent, vm_id=vm_id,
                               copy_vm_id=copy_vm_id, _lease=lease)
        admission_raw, admitted = create._read_record(
            lease.parent, vm_id + admission.RESULT_SUFFIX)
        release.require(release.digest(admission_raw)
                        == create._read_record(
                            lease.parent, vm_id + checkpoint.SUFFIX)[1]
                            ["admission_result_sha256"],
                        "fixture resumed admission result differs")
        ordinary_raw = setup._ssh_as(
            before, "installer", setup._installer_command(), limit=2048)
        ordinary = setup._decode_installer(ordinary_raw)
        admin_raw = setup._ssh_as(
            before, "fixture-admin", setup._admin_identity_command(),
            limit=512)
        admin = setup._decode_admin(admin_raw, ordinary["uid"])
        engine_raw = setup._ssh_as(
            before, "fixture-admin", setup.SETUP_ENGINE_COMMAND,
            limit=256)
        engine = json.loads(engine_raw)
        status = admission._guest_status(before)
        release.require(ordinary["uid"] == before["guest_uid"]
                        and admin["uid"] != ordinary["uid"]
                        and engine == before["historical_engine_id"]
                        == admitted["engine_id"]
                        and archive.sha(status)
                        == admitted["dpkg_status_sha256"],
                        "fixture resumed guest baseline differs")
        after = bound_resumed(source=source, registry=registry,
                              runtime_parent=runtime_parent, vm_id=vm_id,
                              copy_vm_id=copy_vm_id, _lease=lease)
        release.require(after == before
                        and setup._ssh_as(
                            after, "installer", setup._installer_command(),
                            limit=2048) == ordinary_raw
                        and setup._ssh_as(
                            after, "fixture-admin", setup._admin_identity_command(),
                            limit=512) == admin_raw
                        and setup._ssh_as(
                            after, "fixture-admin", setup.SETUP_ENGINE_COMMAND,
                            limit=256) == engine_raw
                        and admission._guest_status(after) == status
                        and create._read_record(
                            lease.parent, vm_id + admission.RESULT_SUFFIX)[0]
                        == admission_raw,
                        "fixture resumed guest changed during observation")
        record = {"schema": SCHEMA, "phase": "current_readiness_observed",
                  "vm_id": vm_id, "copy_vm_id": copy_vm_id,
                  "resume_receipt_sha256": before["resume_receipt_sha256"],
                  "checkpoint_sha256": before["checkpoint_sha256"],
                  "admission_result_sha256": release.digest(admission_raw),
                  "pid": before["pid"], "start_ticks": before["start_ticks"],
                  "boot_id": before["boot_id"],
                  "ordinary_uid": ordinary["uid"],
                  "setup_uid": admin["uid"],
                  "setup_engine_id": engine,
                  "dpkg_status_sha256": archive.sha(status),
                  "observed_at": int(time.time()),
                  "package_install_authorized": False,
                  "product_dispatch_authorized": False}
        create._write(lease.parent, vm_id + READINESS_SUFFIX, record)
        return record
