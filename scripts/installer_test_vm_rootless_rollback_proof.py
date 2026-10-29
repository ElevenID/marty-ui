#!/usr/bin/env python3
"""Read-only, false-authority proof of one disposable rollback-copy trial.

This checks historical records and current stopped disk/snapshot custody. It
does not mint the package executor's caller-constructible checkpoint type.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket

from installer_candidate_controller import ControllerLease
import installer_candidate_qemu_observe as observer
import installer_candidate_vm_create as create
import installer_candidate_vm_launch as launch
import installer_candidate_vm_runtime as runtime
import installer_release as release
import installer_test_vm_restart as restart
import installer_test_vm_rootless_package_admission_controller as admission
import installer_test_vm_rootless_rollback_cleanup as cleanup
import installer_test_vm_rootless_rollback_copy as copy
import installer_test_vm_rootless_rollback_launch as launched
import installer_test_vm_rootless_stopped_snapshot as stopped


def _records(parent: int, vm_id: str, copy_id: str) -> dict[str, tuple[bytes, dict]]:
    names = {
        "stop": vm_id + stopped.INTENT_SUFFIX,
        "pending": vm_id + stopped.PENDING_SUFFIX,
        "copy_intent": copy_id + copy.INTENT_SUFFIX,
        "prepared": copy_id + copy.PREPARED_SUFFIX,
        "launch_intent": copy_id + launched.INTENT_SUFFIX,
        "launch_pid": copy_id + launched.PID_SUFFIX,
        "launch_receipt": copy_id + launched.RECEIPT_SUFFIX,
        "admission_intent": vm_id + admission.INTENT_SUFFIX,
        "admission_result": vm_id + admission.RESULT_SUFFIX,
        "baseline": copy_id + launched.BASELINE_SUFFIX,
        "cleanup_intent": copy_id + cleanup.INTENT_SUFFIX,
        "copy_stopped": copy_id + cleanup.STOPPED_SUFFIX,
        "remove_intent": copy_id + cleanup.REMOVE_INTENT_SUFFIX,
        "cleanup_result": copy_id + cleanup.RESULT_SUFFIX,
    }
    return {key: create._read_record(parent, name) for key, name in names.items()}


def _exact_chain(records: dict[str, tuple[bytes, dict]], vm_id: str,
                 copy_id: str) -> None:
    """Reject partial, altered or authority-bearing local record chains."""
    raw = {key: pair[0] for key, pair in records.items()}
    row = {key: pair[1] for key, pair in records.items()}
    release.require(set(row) == {
        "stop", "pending", "copy_intent", "prepared", "launch_intent",
        "launch_pid", "launch_receipt", "admission_intent",
        "admission_result", "baseline", "cleanup_intent", "copy_stopped",
        "remove_intent", "cleanup_result"},
        "fixture rollback proof record set incomplete")
    copy._exact_pending(raw["stop"], row["stop"], raw["pending"],
                        row["pending"], vm_id)
    release.exact(row["admission_intent"],
                  {"schema", "phase", "vm_id", "observation_id", "engine_id",
                   "readiness_sha256", "pid", "start_ticks",
                   "dpkg_status_sha256", "module_sha256",
                   "controller_sha256", "purpose",
                   "package_actions_authorized", "installation_authorized"},
                  "fixture rollback proof admission intent")
    release.exact(row["admission_result"],
                  {"schema", "phase", "vm_id", "observation_id",
                   "intent_sha256", "engine_id", "readiness_sha256",
                   "dpkg_status_sha256", "module_sha256",
                   "controller_sha256", "private_stage", "packages",
                   "archive_releases", "new_package_actions",
                   "transaction_simulated",
                   "rootful_docker_package_simulated_change",
                   "package_actions_authorized", "installation_authorized",
                   "account_or_subids_allocated",
                   "daemon_start_attempted_by_probe", "rootless_ready",
                   "qualified", "application_deployment_authorized",
                   "observed_at"},
                  "fixture rollback proof admission result")
    release.exact(row["copy_intent"], copy.INTENT_FIELDS,
                  "fixture rollback proof copy intent")
    release.exact(row["prepared"], copy.PREPARED_FIELDS,
                  "fixture rollback proof prepared copy")
    release.require(row["copy_intent"]["schema"] == copy.SCHEMA
                    and row["copy_intent"]["phase"] == "copy_intent"
                    and row["prepared"]["schema"] == copy.SCHEMA
                    and row["prepared"]["phase"] == "copy_prepared"
                    and row["copy_intent"]["vm_id"]
                    == row["prepared"]["vm_id"] == vm_id
                    and row["copy_intent"]["copy_vm_id"]
                    == row["prepared"]["copy_vm_id"] == copy_id
                    and row["copy_intent"]["stop_intent_sha256"]
                    == release.digest(raw["stop"])
                    and row["copy_intent"]["pending_sha256"]
                    == row["prepared"]["pending_sha256"]
                    == release.digest(raw["pending"])
                    and row["prepared"]["intent_sha256"]
                    == release.digest(raw["copy_intent"])
                    and row["prepared"]["disk_sha256"]
                    == row["pending"]["snapshot_sha256"]
                    and row["prepared"]["disk_bytes"]
                    == row["pending"]["snapshot_bytes"]
                    and all(row["copy_intent"][key] is False for key in
                            ("rollback_qualified", "package_install_authorized",
                             "product_dispatch_authorized"))
                    and all(row["prepared"][key] is False for key in
                            ("rollback_qualified", "package_install_authorized",
                             "product_dispatch_authorized"))
                    and all(row["copy_intent"][key] == row["pending"][key]
                            for key in ("snapshot_device", "snapshot_inode",
                                        "snapshot_bytes", "snapshot_sha256",
                                        "snapshot_directory_device",
                                        "snapshot_directory_inode")),
                    "fixture rollback proof copy chain differs")
    launch_intent, pid, receipt = (row[key] for key in
                                   ("launch_intent", "launch_pid",
                                    "launch_receipt"))
    launch_fields = {"schema", "phase", "vm_id", "copy_vm_id",
                     "prepared_sha256", "pending_sha256", "runtime_uid",
                     "runtime_gid", "runtime_directory_device",
                     "runtime_directory_inode", "disk_device", "disk_inode",
                     "disk_sha256", "seed_device", "seed_inode", "seed_sha256",
                     "ssh_port", "memory_mib", "kvm_gid", "args",
                     "qemu_sha256", "setpriv_sha256", "controller_boot_id",
                     "requested_at", "rollback_qualified",
                     "package_install_authorized", "product_dispatch_authorized"}
    release.exact(launch_intent, launch_fields,
                  "fixture rollback proof launch intent")
    release.exact(pid, {"schema", "phase", "vm_id", "copy_vm_id",
                        "intent_sha256", "pid", "start_ticks",
                        "controller_boot_id", "spawned_at"},
                  "fixture rollback proof launch PID")
    release.exact(receipt, launch_fields | {"intent_sha256",
                                           "pid_record_sha256", "pid",
                                           "start_ticks", "disk_fd",
                                           "observed_at"},
                  "fixture rollback proof launch receipt")
    release.require(launch_intent["schema"] == receipt["schema"]
                    == launched.SCHEMA and pid["schema"] == launched.PID_SCHEMA
                    and launch_intent["phase"] == "launch_intent"
                    and pid["phase"] == "spawned"
                    and receipt["phase"] == "launched"
                    and all(receipt[key] == value for key, value in
                            launch_intent.items() if key != "phase")
                    and launch_intent["vm_id"] == pid["vm_id"]
                    == receipt["vm_id"] == vm_id
                    and launch_intent["copy_vm_id"] == pid["copy_vm_id"]
                    == receipt["copy_vm_id"] == copy_id
                    and launch_intent["prepared_sha256"]
                    == release.digest(raw["prepared"])
                    and launch_intent["pending_sha256"]
                    == release.digest(raw["pending"])
                    and pid["intent_sha256"] == receipt["intent_sha256"]
                    == release.digest(raw["launch_intent"])
                    and receipt["pid_record_sha256"]
                    == release.digest(raw["launch_pid"])
                    and all(receipt[key] == pid[key] for key in
                            ("pid", "start_ticks"))
                    and receipt["controller_boot_id"]
                    == pid["controller_boot_id"]
                    and all(launch_intent[key] == row["prepared"][key]
                            for key in ("runtime_uid", "runtime_gid",
                                        "runtime_directory_device",
                                        "runtime_directory_inode", "disk_device",
                                        "disk_inode", "disk_sha256", "seed_device",
                                        "seed_inode", "seed_sha256")),
                    "fixture rollback proof launch chain differs")
    ai, ar = row["admission_intent"], row["admission_result"]
    release.require(ai["schema"] == ar["schema"] == admission.SCHEMA
                    and ai["phase"] == "intent" and ar["phase"] == "observed"
                    and ai["vm_id"] == ar["vm_id"] == vm_id
                    and ar["intent_sha256"]
                    == release.digest(raw["admission_intent"])
                    and ai["observation_id"] == ar["observation_id"]
                    and ai["purpose"]
                    == "disposable_fixture_setup_package_admission"
                    and all(ai[key] == ar[key] for key in
                            ("engine_id", "readiness_sha256",
                             "dpkg_status_sha256", "module_sha256",
                             "controller_sha256"))
                    and ai["package_actions_authorized"] is False
                    and ai["installation_authorized"] is False
                    and ar["transaction_simulated"] is True
                    and all(ar[key] is False for key in
                            ("rootful_docker_package_simulated_change",
                             "package_actions_authorized",
                             "installation_authorized",
                             "account_or_subids_allocated",
                             "daemon_start_attempted_by_probe",
                             "rootless_ready", "qualified",
                             "application_deployment_authorized")),
                    "fixture rollback proof admission chain differs")
    baseline = row["baseline"]
    release.exact(baseline,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "launch_sha256", "prepared_sha256",
                   "admission_result_sha256", "setup_engine_id",
                   "dpkg_status_sha256", "pid", "start_ticks", "boot_id",
                   "observed_at", "rollback_qualified",
                   "package_install_authorized", "product_dispatch_authorized"},
                  "fixture rollback proof baseline")
    release.require(baseline["schema"] == launched.BASELINE_SCHEMA
                    and baseline["phase"] == "baseline_observed"
                    and baseline["vm_id"] == vm_id
                    and baseline["copy_vm_id"] == copy_id
                    and baseline["launch_sha256"]
                    == release.digest(raw["launch_receipt"])
                    and baseline["prepared_sha256"]
                    == release.digest(raw["prepared"])
                    and baseline["admission_result_sha256"]
                    == release.digest(raw["admission_result"])
                    and baseline["setup_engine_id"] == ar["engine_id"]
                    and baseline["dpkg_status_sha256"]
                    == ar["dpkg_status_sha256"]
                    and all(baseline[key] == receipt[key] for key in
                            ("pid", "start_ticks"))
                    and baseline["boot_id"]
                    == launch_intent["controller_boot_id"],
                    "fixture rollback proof baseline differs")
    ci, stopped_copy, ri, result = (row[key] for key in
                                    ("cleanup_intent", "copy_stopped",
                                     "remove_intent", "cleanup_result"))
    release.exact(ci,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "baseline_sha256", "launch_sha256", "pid",
                   "start_ticks", "boot_id", "runtime_uid", "runtime_gid",
                   "disk_device", "disk_inode", "qmp_device", "qmp_inode",
                   "port", "requested_at", "copy_removed",
                   "rollback_qualified", "package_install_authorized",
                   "product_dispatch_authorized"},
                  "fixture rollback proof cleanup intent")
    release.exact(stopped_copy,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "intent_sha256", "pid", "start_ticks", "boot_id",
                   "runtime_directory_device", "runtime_directory_inode",
                   "disk_device", "disk_inode", "seed_device", "seed_inode",
                   "observed_at", "copy_removed", "rollback_qualified",
                   "package_install_authorized", "product_dispatch_authorized"},
                  "fixture rollback proof stopped copy")
    release.exact(ri,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "cleanup_intent_sha256", "stopped_sha256",
                   "runtime_directory_device", "runtime_directory_inode",
                   "disk_device", "disk_inode", "seed_device", "seed_inode",
                   "requested_at", "copy_removed", "rollback_qualified",
                   "package_install_authorized", "product_dispatch_authorized"},
                  "fixture rollback proof removal intent")
    release.exact(result,
                  {"schema", "phase", "vm_id", "copy_vm_id",
                   "cleanup_intent_sha256", "stopped_sha256",
                   "remove_intent_sha256", "baseline_sha256", "removed_at",
                   "copy_removed", "rollback_qualified",
                   "package_install_authorized", "product_dispatch_authorized"},
                  "fixture rollback proof cleanup result")
    release.require(all(value["schema"] == cleanup.SCHEMA for value in
                        (ci, stopped_copy, ri, result))
                    and [value["phase"] for value in
                         (ci, stopped_copy, ri, result)]
                    == ["cleanup_intent", "copy_stopped", "remove_intent",
                        "copy_removed"]
                    and all(value["vm_id"] == vm_id
                            and value["copy_vm_id"] == copy_id for value in
                            (ci, stopped_copy, ri, result))
                    and ci["baseline_sha256"]
                    == result["baseline_sha256"]
                    == release.digest(raw["baseline"])
                    and ci["launch_sha256"]
                    == release.digest(raw["launch_receipt"])
                    and stopped_copy["intent_sha256"]
                    == release.digest(raw["cleanup_intent"])
                    and ri["cleanup_intent_sha256"]
                    == result["cleanup_intent_sha256"]
                    == release.digest(raw["cleanup_intent"])
                    and ri["stopped_sha256"] == result["stopped_sha256"]
                    == release.digest(raw["copy_stopped"])
                    and result["remove_intent_sha256"]
                    == release.digest(raw["remove_intent"])
                    and ci["pid"] == stopped_copy["pid"]
                    == receipt["pid"]
                    and ci["start_ticks"] == stopped_copy["start_ticks"]
                    == receipt["start_ticks"]
                    and ci["boot_id"] == stopped_copy["boot_id"]
                    == baseline["boot_id"]
                    and ci["runtime_uid"] == launch_intent["runtime_uid"]
                    and ci["runtime_gid"] == launch_intent["runtime_gid"]
                    and ci["disk_device"] == stopped_copy["disk_device"]
                    == ri["disk_device"] == launch_intent["disk_device"]
                    and ci["disk_inode"] == stopped_copy["disk_inode"]
                    == ri["disk_inode"] == launch_intent["disk_inode"]
                    and stopped_copy["runtime_directory_device"]
                    == ri["runtime_directory_device"]
                    == launch_intent["runtime_directory_device"]
                    and stopped_copy["runtime_directory_inode"]
                    == ri["runtime_directory_inode"]
                    == launch_intent["runtime_directory_inode"]
                    and stopped_copy["seed_device"] == ri["seed_device"]
                    == launch_intent["seed_device"]
                    and stopped_copy["seed_inode"] == ri["seed_inode"]
                    == launch_intent["seed_inode"]
                    and ci["port"] == launch_intent["ssh_port"]
                    and all(value[key] is False for value in
                            (launch_intent, receipt, baseline, ci,
                             stopped_copy, ri, result,
                             row["copy_intent"], row["prepared"])
                            for key in ("rollback_qualified",
                                        "package_install_authorized",
                                        "product_dispatch_authorized"))
                    and all(value["copy_removed"] is False for value in
                            (ci, stopped_copy, ri))
                    and result["copy_removed"] is True,
                    "fixture rollback proof cleanup chain differs")


def inspect_proof(*, source: Path, registry: Path, runtime_parent: Path,
                  vm_id: str, copy_vm_id: str) -> dict:
    """Return private historical evidence only after exact current rechecks."""
    copy.fixture._uuid4(vm_id)
    copy.fixture._uuid4(copy_vm_id)
    release.require(os.geteuid() == 0 and vm_id != copy_vm_id
                    and all(path.is_absolute() for path in
                            (source, registry, runtime_parent)),
                    "fixture rollback proof request invalid")
    with ControllerLease(registry) as lease:
        provenance = create.verify_source(source)
        before = _records(lease.parent, vm_id, copy_vm_id)
        _exact_chain(before, vm_id, copy_vm_id)
        row = {key: pair[1] for key, pair in before.items()}
        pending = row["pending"]
        intent = row["stop"]
        ci = row["copy_intent"]
        release.require(all(ci["source_" + key] == provenance[key]
                            for key in ("image_sha256", "manifest_sha256",
                                        "signature_sha256", "keyring_sha256"))
                        and launch._boot_id() == pending["boot_id"]
                        and row["launch_intent"]["controller_boot_id"]
                        == pending["boot_id"],
                        "fixture rollback proof source or epoch differs")
        original_dir = runtime_parent / vm_id
        original_launch_raw, original_launch = create._read_record(
            lease.parent, vm_id + ".launch-intent.json")
        original_creation_raw, original_creation = create._read_record(
            lease.parent, vm_id + ".creation-receipt.json")
        original_transfer_raw, original_transfer = create._read_record(
            lease.parent, vm_id + ".runtime-receipt.json")
        original_seed_raw, _ = create._read_record(
            lease.parent, vm_id + ".seed-receipt.json")
        original_launch_receipt_raw, _ = create._read_record(
            lease.parent, vm_id + ".launch-receipt.json")
        setup_raw, setup_record = create._read_record(
            lease.parent, vm_id + launched.setup.SETUP_READINESS_SUFFIX)
        release.require(release.digest(original_launch_raw)
                        == ci["launch_sha256"]
                        and release.digest(original_creation_raw)
                        == ci["creation_sha256"]
                        and release.digest(original_transfer_raw)
                        == ci["transfer_sha256"]
                        and release.digest(original_seed_raw)
                        == ci["seed_sha256"]
                        and release.digest(original_launch_receipt_raw)
                        == ci["launch_receipt_sha256"]
                        == intent["launch_sha256"]
                        and release.digest(setup_raw)
                        == ci["setup_readiness_sha256"]
                        == intent["setup_readiness_sha256"]
                        and original_creation["image"] == provenance
                        and original_transfer["runtime_uid"]
                        == intent["runtime_uid"]
                        and original_transfer["runtime_gid"]
                        == intent["runtime_gid"]
                        and setup_record["setup_engine_id"]
                        == row["baseline"]["setup_engine_id"]
                        and original_launch["ssh_port"] != ci["copy_port"],
                        "fixture rollback proof original source changed")
        restart._no_live_owner(intent["runtime_uid"], intent["pid"],
                               intent["start_ticks"], intent["boot_id"],
                               original_dir, original_launch["ssh_port"])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", ci["copy_port"]))
        parent = runtime._runtime_parent(runtime_parent)
        original = disk = snapshot_dir = snapshot_file = None
        try:
            release.require((os.fstat(parent).st_dev, os.fstat(parent).st_ino)
                            == (ci["runtime_parent_device"],
                                ci["runtime_parent_inode"]),
                            "fixture rollback proof runtime parent changed")
            cleanup._require_absent(parent, copy_vm_id)
            original = observer.open_vm_dir(original_dir, intent["runtime_uid"])
            disk = restart._disk_fd(original, intent["runtime_uid"],
                                    intent["runtime_gid"],
                                    pending["disk_device"],
                                    pending["disk_inode"])
            release.require(restart._mutable_digest(disk)[:2]
                            == (pending["disk_bytes"], pending["disk_sha256"]),
                            "fixture rollback proof original disk differs")
            snapshot_dir, snapshot_file = copy._snapshot(
                registry, lease, vm_id, pending)
            release.require(restart._mutable_digest(snapshot_file)[:2]
                            == (pending["snapshot_bytes"],
                                pending["snapshot_sha256"]),
                            "fixture rollback proof snapshot differs")
            create._rebind_directory(registry, lease.parent)
            runtime._same_path(runtime_parent, parent,
                               runtime._runtime_parent)
            create._rebind_directory(
                registry / (vm_id + stopped.SNAPSHOT_SUFFIX), snapshot_dir)
            release.require(_records(lease.parent, vm_id, copy_vm_id) == before
                            and create.verify_source(source) == provenance
                            and all(create._read_record(lease.parent, name)[0]
                                    == prior for name, prior in (
                                        (vm_id + ".creation-receipt.json",
                                         original_creation_raw),
                                        (vm_id + ".runtime-receipt.json",
                                         original_transfer_raw),
                                        (vm_id + ".seed-receipt.json",
                                         original_seed_raw),
                                        (vm_id + ".launch-intent.json",
                                         original_launch_raw),
                                        (vm_id + ".launch-receipt.json",
                                         original_launch_receipt_raw),
                                        (vm_id + launched.setup.SETUP_READINESS_SUFFIX,
                                         setup_raw)))
                            and restart._mutable_digest(disk)[:2]
                            == (pending["disk_bytes"], pending["disk_sha256"])
                            and restart._mutable_digest(snapshot_file)[:2]
                            == (pending["snapshot_bytes"],
                                pending["snapshot_sha256"]),
                            "fixture rollback proof observation changed")
            return {"vm_id": vm_id, "copy_vm_id": copy_vm_id,
                    "pending_sha256": release.digest(before["pending"][0]),
                    "snapshot_sha256": pending["snapshot_sha256"],
                    "disk_sha256": pending["disk_sha256"],
                    "admission_result_sha256": release.digest(
                        before["admission_result"][0]),
                    "baseline_sha256": release.digest(before["baseline"][0]),
                    "cleanup_result_sha256": release.digest(
                        before["cleanup_result"][0]),
                    "rollback_qualified": False,
                    "package_install_authorized": False,
                    "product_dispatch_authorized": False}
        finally:
            for fd in (snapshot_file, snapshot_dir, disk, original, parent):
                if fd is not None:
                    os.close(fd)
