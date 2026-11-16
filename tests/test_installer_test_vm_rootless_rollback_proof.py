"""Synthetic exact-record proof checks; no VM or package action."""
from __future__ import annotations

import copy as clone
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_rollback_proof as proof  # noqa: E402

VM = "11111111-2222-4333-8444-555555555555"
COPY = "33333333-4444-4555-8666-777777777777"
BOOT = "22222222-3333-4444-8555-666666666666"


def _fixture():
    rows = {}
    def put(key, value):
        rows[key] = (proof.release.encode(value), value)
    stop = {"schema": proof.stopped.SCHEMA, "phase": "stop_intent",
            "vm_id": VM, "setup_readiness_sha256": "a" * 64,
            "launch_sha256": "b" * 64, "pid": 1777, "start_ticks": "17",
            "boot_id": BOOT, "runtime_uid": 994, "runtime_gid": 994,
            "disk_device": 4, "disk_inode": 5, "qmp_device": 4,
            "qmp_inode": 7, "requested_at": 10, "stopped": False,
            "snapshot_qualified": False, "package_install_authorized": False,
            "product_dispatch_authorized": False}
    put("stop", stop)
    pending = {"schema": proof.stopped.SCHEMA,
               "phase": "snapshot_pending_rollback_test", "vm_id": VM,
               "intent_sha256": proof.release.digest(rows["stop"][0]),
               "pid": 1777, "start_ticks": "17", "boot_id": BOOT,
               "disk_device": 4, "disk_inode": 5, "disk_bytes": 32,
               "disk_sha256": "c" * 64, "snapshot_bytes": 32,
               "snapshot_sha256": "c" * 64,
               "snapshot_directory_device": 4,
               "snapshot_directory_inode": 8,
               "snapshot_device": 4, "snapshot_inode": 9,
               "observed_at": 11, "stopped": True,
               "snapshot_qualified": False,
               "package_install_authorized": False,
               "product_dispatch_authorized": False}
    put("pending", pending)
    common = {"vm_id": VM, "copy_vm_id": COPY,
              "rollback_qualified": False,
              "package_install_authorized": False,
              "product_dispatch_authorized": False}
    ci = dict.fromkeys(proof.copy.INTENT_FIELDS, 1)
    ci.update(common)
    ci.update({"schema": proof.copy.SCHEMA, "phase": "copy_intent",
               "stop_intent_sha256": proof.release.digest(rows["stop"][0]),
               "pending_sha256": proof.release.digest(rows["pending"][0]),
               "snapshot_sha256": "c" * 64, "snapshot_bytes": 32,
               "snapshot_directory_device": 4,
               "snapshot_directory_inode": 8,
               "snapshot_device": 4, "snapshot_inode": 9})
    put("copy_intent", ci)
    prepared = dict.fromkeys(proof.copy.PREPARED_FIELDS, 1)
    prepared.update(common)
    prepared.update({"schema": proof.copy.SCHEMA, "phase": "copy_prepared",
                     "intent_sha256": proof.release.digest(rows["copy_intent"][0]),
                     "pending_sha256": proof.release.digest(rows["pending"][0]),
                     "disk_bytes": 32, "disk_sha256": "c" * 64})
    put("prepared", prepared)
    launch_fields = {"schema", "phase", "vm_id", "copy_vm_id",
                     "prepared_sha256", "pending_sha256", "runtime_uid",
                     "runtime_gid", "runtime_directory_device",
                     "runtime_directory_inode", "disk_device", "disk_inode",
                     "disk_sha256", "seed_device", "seed_inode", "seed_sha256",
                     "ssh_port", "memory_mib", "kvm_gid", "args",
                     "qemu_sha256", "setpriv_sha256", "controller_boot_id",
                     "requested_at", "rollback_qualified",
                     "package_install_authorized", "product_dispatch_authorized"}
    li = dict.fromkeys(launch_fields, 1)
    li.update(common)
    li.update({"schema": proof.launched.SCHEMA, "phase": "launch_intent",
               "prepared_sha256": proof.release.digest(rows["prepared"][0]),
               "pending_sha256": proof.release.digest(rows["pending"][0]),
               "controller_boot_id": BOOT})
    for key in ("runtime_uid", "runtime_gid", "runtime_directory_device",
                "runtime_directory_inode", "disk_device", "disk_inode",
                "disk_sha256", "seed_device", "seed_inode", "seed_sha256"):
        li[key] = prepared[key]
    put("launch_intent", li)
    pid = {"schema": proof.launched.PID_SCHEMA, "phase": "spawned",
           "vm_id": VM, "copy_vm_id": COPY,
           "intent_sha256": proof.release.digest(rows["launch_intent"][0]),
           "pid": 1888, "start_ticks": "18", "controller_boot_id": BOOT,
           "spawned_at": 12}
    put("launch_pid", pid)
    receipt = {**li, "phase": "launched",
               "intent_sha256": proof.release.digest(rows["launch_intent"][0]),
               "pid_record_sha256": proof.release.digest(rows["launch_pid"][0]),
               "pid": 1888, "start_ticks": "18", "disk_fd": 12,
               "observed_at": 13}
    put("launch_receipt", receipt)
    ai = {"schema": proof.admission.SCHEMA, "phase": "intent",
          "vm_id": VM, "observation_id": COPY,
          "engine_id": "e" * 64, "readiness_sha256": "a" * 64,
          "pid": 1777, "start_ticks": "17",
          "dpkg_status_sha256": "f" * 64,
          "module_sha256": "1" * 64,
          "controller_sha256": "2" * 64,
          "purpose": "disposable_fixture_setup_package_admission",
          "package_actions_authorized": False,
          "installation_authorized": False}
    put("admission_intent", ai)
    ar = {"schema": proof.admission.SCHEMA, "phase": "observed",
          "vm_id": VM, "observation_id": COPY,
          "intent_sha256": proof.release.digest(rows["admission_intent"][0]),
          "engine_id": "e" * 64, "dpkg_status_sha256": "f" * 64,
          "readiness_sha256": "a" * 64,
          "module_sha256": "1" * 64,
          "controller_sha256": "2" * 64,
          "private_stage": "/private/stage", "packages": [],
          "archive_releases": [], "new_package_actions": [],
          "transaction_simulated": True,
          "rootful_docker_package_simulated_change": False,
          "package_actions_authorized": False,
          "installation_authorized": False,
          "account_or_subids_allocated": False,
          "daemon_start_attempted_by_probe": False,
          "rootless_ready": False,
          "qualified": False, "application_deployment_authorized": False}
    ar["observed_at"] = 14
    put("admission_result", ar)
    baseline = {**common, "schema": proof.launched.BASELINE_SCHEMA,
                "phase": "baseline_observed",
                "launch_sha256": proof.release.digest(rows["launch_receipt"][0]),
                "prepared_sha256": proof.release.digest(rows["prepared"][0]),
                "admission_result_sha256": proof.release.digest(
                    rows["admission_result"][0]),
                "setup_engine_id": "e" * 64,
                "dpkg_status_sha256": "f" * 64,
                "pid": 1888, "start_ticks": "18", "boot_id": BOOT,
                "observed_at": 15}
    put("baseline", baseline)
    cleanup = {**common, "schema": proof.cleanup.SCHEMA,
               "phase": "cleanup_intent",
               "baseline_sha256": proof.release.digest(rows["baseline"][0]),
               "launch_sha256": proof.release.digest(rows["launch_receipt"][0]),
               "pid": 1888, "start_ticks": "18", "boot_id": BOOT,
               "runtime_uid": 1, "runtime_gid": 1,
               "disk_device": 1, "disk_inode": 1,
               "qmp_device": 1, "qmp_inode": 1,
               "port": 1, "requested_at": 16,
               "copy_removed": False}
    put("cleanup_intent", cleanup)
    stopped = {**common, "schema": proof.cleanup.SCHEMA,
               "phase": "copy_stopped",
               "intent_sha256": proof.release.digest(rows["cleanup_intent"][0]),
               "pid": 1888, "start_ticks": "18", "boot_id": BOOT,
               "runtime_directory_device": 1,
               "runtime_directory_inode": 1,
               "disk_device": 1, "disk_inode": 1,
               "seed_device": 1, "seed_inode": 1,
               "observed_at": 17,
               "copy_removed": False}
    put("copy_stopped", stopped)
    remove = {**common, "schema": proof.cleanup.SCHEMA,
              "phase": "remove_intent",
              "cleanup_intent_sha256": proof.release.digest(rows["cleanup_intent"][0]),
              "stopped_sha256": proof.release.digest(rows["copy_stopped"][0]),
              "runtime_directory_device": 1,
              "runtime_directory_inode": 1,
              "disk_device": 1, "disk_inode": 1,
              "seed_device": 1, "seed_inode": 1,
              "requested_at": 18,
              "copy_removed": False}
    put("remove_intent", remove)
    result = {**common, "schema": proof.cleanup.SCHEMA,
              "phase": "copy_removed",
              "cleanup_intent_sha256": proof.release.digest(rows["cleanup_intent"][0]),
              "stopped_sha256": proof.release.digest(rows["copy_stopped"][0]),
              "remove_intent_sha256": proof.release.digest(rows["remove_intent"][0]),
              "baseline_sha256": proof.release.digest(rows["baseline"][0]),
              "removed_at": 19,
              "copy_removed": True}
    put("cleanup_result", result)
    return rows


def test_exact_full_record_chain_and_cleanup_digest():
    proof._exact_chain(_fixture(), VM, COPY)


@pytest.mark.parametrize("key,field,value", [
    ("baseline", "admission_result_sha256", "0" * 64),
    ("cleanup_result", "copy_removed", False),
    ("cleanup_result", "remove_intent_sha256", "0" * 64),
    ("launch_receipt", "pid", 1999),
    ("pending", "snapshot_sha256", "0" * 64),
    ("admission_intent", "readiness_sha256", "0" * 64),
    ("admission_intent", "pid", 1999),
])
def test_chain_refuses_changed_record(key, field, value):
    rows = clone.deepcopy(_fixture())
    changed = {**rows[key][1], field: value}
    rows[key] = (proof.release.encode(changed), changed)
    with pytest.raises((ValueError, KeyError)):
        proof._exact_chain(rows, VM, COPY)


@pytest.mark.parametrize("field,value", [
    ("readiness_sha256", "0" * 64), ("pid", 1999),
])
def test_rehashed_admission_still_must_match_stopped_incarnation(field, value):
    rows = _fixture()
    def update(key, **changes):
        record = {**rows[key][1], **changes}
        rows[key] = (proof.release.encode(record), record)
    update("admission_intent", **{field: value})
    update("admission_result",
           intent_sha256=proof.release.digest(rows["admission_intent"][0]),
           **({field: value} if field == "readiness_sha256" else {}))
    update("baseline", admission_result_sha256=proof.release.digest(
        rows["admission_result"][0]))
    update("cleanup_intent", baseline_sha256=proof.release.digest(
        rows["baseline"][0]))
    update("copy_stopped", intent_sha256=proof.release.digest(
        rows["cleanup_intent"][0]))
    update("remove_intent",
           cleanup_intent_sha256=proof.release.digest(rows["cleanup_intent"][0]),
           stopped_sha256=proof.release.digest(rows["copy_stopped"][0]))
    update("cleanup_result",
           baseline_sha256=proof.release.digest(rows["baseline"][0]),
           cleanup_intent_sha256=proof.release.digest(rows["cleanup_intent"][0]),
           stopped_sha256=proof.release.digest(rows["copy_stopped"][0]),
           remove_intent_sha256=proof.release.digest(rows["remove_intent"][0]))
    with pytest.raises(ValueError, match="admission chain differs"):
        proof._exact_chain(rows, VM, COPY)


def test_named_snapshot_rebind_refuses_replaced_name(tmp_path):
    path = tmp_path / "disk.qcow2"
    path.write_bytes(b"synthetic snapshot")
    path.chmod(0o600)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    held = os.open(path, os.O_RDONLY)
    actual_stat, actual_fstat = os.stat, os.fstat
    def root_owned(value):
        fields = ("st_mode", "st_dev", "st_ino", "st_nlink", "st_size",
                  "st_mtime_ns", "st_ctime_ns")
        return SimpleNamespace(**{key: getattr(value, key) for key in fields},
                               st_uid=0, st_gid=0)
    try:
        with mock.patch.object(proof.os, "stat", side_effect=lambda *a, **kw:
                               root_owned(actual_stat(*a, **kw))), \
             mock.patch.object(proof.os, "fstat", side_effect=lambda *a, **kw:
                               root_owned(actual_fstat(*a, **kw))):
            proof._named_snapshot(directory, held)
            path.unlink()
            path.write_bytes(b"synthetic snapshot")
            path.chmod(0o600)
            with pytest.raises(ValueError, match="named snapshot changed"):
                proof._named_snapshot(directory, held)
    finally:
        os.close(held)
        os.close(directory)
