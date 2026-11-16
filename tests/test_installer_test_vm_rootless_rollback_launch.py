"""Synthetic rollback launch ordering; no QEMU or guest process is started."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import installer_test_vm_rootless_rollback_launch as launched  # noqa: E402

VM = "11111111-2222-4333-8444-555555555555"
COPY = "33333333-4444-4555-8666-777777777777"


def test_old_launch_output_refuses_before_spawn(tmp_path):
    registry = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        (tmp_path / (COPY + launched.PID_SUFFIX)).write_bytes(b"old")
        with pytest.raises(ValueError, match="already attempted"):
            launched._unused(registry, COPY)
    finally:
        os.close(registry)


def test_live_disk_binding_accepts_growth_on_same_inode_and_rejects_link(tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"initial qcow2 fixture")
    disk.chmod(0o600)
    original = disk.stat()
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        disk.write_bytes(b"initial qcow2 fixture" * 20)
        held = launched._held_mutable_disk(
            directory, uid=os.getuid(), gid=os.getgid(),
            device=original.st_dev, inode=original.st_ino)
        os.close(held)
        disk.unlink()
        disk.symlink_to("missing")
        with pytest.raises(ValueError, match="live disk identity differs"):
            launched._held_mutable_disk(
                directory, uid=os.getuid(), gid=os.getgid(),
                device=original.st_dev, inode=original.st_ino)
    finally:
        os.close(directory)


def test_exact_copy_intent_precedes_fixed_unprivileged_spawn(tmp_path):
    registry = tmp_path / "registry"
    runtime = tmp_path / "runtime"
    copy_dir = runtime / COPY
    registry.mkdir()
    copy_dir.mkdir(parents=True)
    disk = copy_dir / "synthetic"
    disk.write_bytes(b"copy")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    binding = {"vm_id": VM, "copy_vm_id": COPY,
               "runtime_dir": copy_dir, "runtime_uid": 994,
               "runtime_gid": 994, "copy_port": port,
               "runtime_directory_device": 1,
               "runtime_directory_inode": 2,
               "disk_device": 3, "disk_inode": 4,
               "disk_bytes": 4, "disk_sha256": "a" * 64,
               "seed_device": 5, "seed_inode": 6,
               "seed_bytes": 7, "seed_sha256": "b" * 64,
               "prepared_sha256": "c" * 64,
               "pending_sha256": "d" * 64,
               "control_dir": registry / "control",
               "key_sha256": "e" * 64,
               "known_hosts_sha256": "f" * 64,
               "package_install_authorized": False,
               "product_dispatch_authorized": False}
    events = []
    records = {}
    class Lease:
        def __enter__(self):
            self.parent = os.open(registry, os.O_RDONLY | os.O_DIRECTORY)
            return self
        def __exit__(self, *_):
            os.close(self.parent)
    class Process:
        pid = 1699
        def poll(self):
            return None
    def write(_parent, name, value):
        events.append(("write", name))
        raw = launched.release.encode(value)
        records[name] = raw
        return raw
    def spawn(argv, **opts):
        events.append(("spawn", argv, opts))
        return Process()
    def read(_parent, name):
        return records[name], {}
    def held_file(*_args, **_kwargs):
        return os.open(disk, os.O_RDONLY)
    with mock.patch.object(launched.os, "geteuid", return_value=0), \
         mock.patch.object(launched, "ControllerLease", return_value=Lease()), \
         mock.patch.object(launched.copy, "bound_prepared_copy",
                           return_value=binding), \
         mock.patch.object(launched.launch, "_kvm_group", return_value=999), \
         mock.patch.object(launched.launch, "_trusted_tool",
                           return_value="9" * 64), \
         mock.patch.object(launched.launch, "_host_headroom"), \
         mock.patch.object(launched.launch, "_seed_media"), \
         mock.patch.object(launched.launch, "_boot_id",
                           return_value="22222222-3333-4444-8555-666666666666"), \
         mock.patch.object(launched.launch, "_start_ticks",
                           return_value="12345"), \
         mock.patch.object(launched.launch, "_live",
                           return_value={"pid": 1699,
                                         "start_ticks": "12345", "disk_fd": 12}), \
         mock.patch.object(launched.copy, "_held_regular", side_effect=held_file), \
         mock.patch.object(launched.copy.restart, "_mutable_digest",
                           return_value=(4, "a" * 64, 1, 1)), \
         mock.patch.object(launched.observer, "open_vm_dir",
                           side_effect=lambda *_: os.open(copy_dir, os.O_RDONLY)), \
         mock.patch.object(launched.create, "_write", side_effect=write), \
         mock.patch.object(launched.create, "_read_record", side_effect=read), \
         mock.patch.object(launched.subprocess, "Popen", side_effect=spawn):
        receipt = launched.launch_copy(
            source=tmp_path / "source", registry=registry,
            runtime_parent=runtime, vm_id=VM, copy_vm_id=COPY)
    assert [entry[0] for entry in events] == ["write", "spawn", "write", "write"]
    assert events[0][1] == COPY + launched.INTENT_SUFFIX
    assert events[2][1] == COPY + launched.PID_SUFFIX
    assert events[3][1] == COPY + launched.RECEIPT_SUFFIX
    argv, opts = events[1][1:]
    assert argv[:12] == ["/usr/bin/setpriv", "--reuid", "994", "--regid",
                         "994", "--groups", "999", "--bounding-set=-all",
                         "--inh-caps=-all", "--ambient-caps=-all",
                         "--no-new-privs", "--"]
    assert opts["close_fds"] is True and opts["start_new_session"] is True
    assert receipt["package_install_authorized"] is False
    assert receipt["product_dispatch_authorized"] is False


def test_baseline_observes_only_fixed_principals_engine_and_status(tmp_path):
    registry = tmp_path / "registry"
    registry.mkdir()
    engine = "6c3ab358-4b21-4979-b2ff-916bbd32d891"
    status = b"Package: synthetic\nStatus: install ok installed\n"
    binding = {"vm_id": VM, "copy_vm_id": COPY, "pid": 1699,
               "start_ticks": "12345",
               "boot_id": "22222222-3333-4444-8555-666666666666",
               "ordinary_uid": 1000, "setup_uid": 1002,
               "setup_engine_id": engine, "launch_sha256": "a" * 64,
               "prepared_sha256": "b" * 64,
               "setup_readiness_sha256": "e" * 64}
    admission_intent = {"schema": launched.admission_controller.SCHEMA,
                        "phase": "intent", "vm_id": VM,
                        "observation_id": "44444444-5555-4666-8777-888888888888",
                        "engine_id": engine,
                        "readiness_sha256": binding["setup_readiness_sha256"],
                        "pid": 1699, "start_ticks": "12345",
                        "dpkg_status_sha256": launched.release.digest(status),
                        "module_sha256": "1" * 64,
                        "controller_sha256": "2" * 64,
                        "purpose": "disposable_fixture_setup_package_admission",
                        "package_actions_authorized": False,
                        "installation_authorized": False}
    admission_intent_raw = launched.release.encode(admission_intent)
    admission = {"schema": launched.admission_controller.SCHEMA,
                 "phase": "observed", "vm_id": VM,
                 "observation_id": "44444444-5555-4666-8777-888888888888",
                 "intent_sha256": launched.release.digest(admission_intent_raw),
                 "engine_id": engine,
                 "readiness_sha256": binding["setup_readiness_sha256"],
                 "dpkg_status_sha256": launched.release.digest(status),
                 "module_sha256": "1" * 64, "controller_sha256": "2" * 64,
                 "private_stage": "/private/stage", "packages": [],
                 "archive_releases": [], "new_package_actions": [],
                 "transaction_simulated": True,
                 "rootful_docker_package_simulated_change": False,
                 "package_actions_authorized": False,
                 "installation_authorized": False,
                 "account_or_subids_allocated": False,
                 "daemon_start_attempted_by_probe": False,
                 "rootless_ready": False, "qualified": False,
                 "application_deployment_authorized": False,
                 "observed_at": 1000}
    admission_raw = launched.release.encode(admission)
    def records(_parent, name):
        return ((admission_intent_raw, admission_intent)
                if name.endswith(launched.admission_controller.INTENT_SUFFIX)
                else (admission_raw, admission))
    ordinary = launched.release.encode({
        "schema": "elevenid.fixture-installer-account/v1",
        "uid": 1000, "gid": 1001, "home": "/home/installer",
        "docker_group": False, "sudo_group": False,
        "setup_socket_denied": True, "no_new_privs": True,
        "effective_caps_zero": True})
    admin = launched.release.encode({
        "schema": "elevenid.fixture-admin-identity/v1",
        "uid": 1002, "gid": 1002, "home": "/home/fixture-admin"})
    def ssh(_binding, _user, script, **_kwargs):
        if script == launched.setup._installer_command():
            return ordinary
        if script == launched.setup._admin_identity_command():
            return admin
        assert script == launched.setup.SETUP_ENGINE_COMMAND
        return ('"' + engine + '"\n').encode()
    class Lease:
        parent = 20
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
    with mock.patch.object(launched, "ControllerLease", return_value=Lease()), \
         mock.patch.object(launched, "bound_live_copy", return_value=binding), \
         mock.patch.object(launched.setup, "_ssh_as", side_effect=ssh), \
         mock.patch.object(launched.probe, "_ssh", return_value=status) as read, \
         mock.patch.object(launched.create, "_read_record", side_effect=records), \
         mock.patch.object(launched.create, "_write") as write:
        result = launched.observe_baseline(
            source=tmp_path / "source", registry=registry,
            runtime_parent=tmp_path / "runtime", vm_id=VM, copy_vm_id=COPY,
            expected_engine_id=engine,
            expected_status_sha256=launched.release.digest(status))
    assert read.call_count == 2
    assert write.call_count == 1
    assert result["dpkg_status_sha256"] == launched.release.digest(status)
    assert result["admission_result_sha256"] == launched.release.digest(
        admission_raw)
    assert status not in str(result).encode()
    assert result["rollback_qualified"] is False
    assert result["package_install_authorized"] is False
    assert result["product_dispatch_authorized"] is False
    admission["package_actions_authorized"] = True
    with mock.patch.object(launched, "ControllerLease", return_value=Lease()), \
         mock.patch.object(launched, "bound_live_copy", return_value=binding), \
         mock.patch.object(launched.create, "_read_record",
                           side_effect=lambda _p, name:
                           (admission_intent_raw, admission_intent)
                           if name.endswith(
                               launched.admission_controller.INTENT_SUFFIX)
                           else (launched.release.encode(admission), admission)), \
         mock.patch.object(launched.setup, "_ssh_as") as ssh, \
         mock.patch.object(launched.create, "_write") as write:
        with pytest.raises(ValueError, match="admission observation differs"):
            launched.observe_baseline(
                source=tmp_path / "source", registry=registry,
                runtime_parent=tmp_path / "runtime", vm_id=VM, copy_vm_id=COPY,
                expected_engine_id=engine,
                expected_status_sha256=launched.release.digest(status))
    ssh.assert_not_called()
    write.assert_not_called()


def test_baseline_wrong_engine_refuses_without_record(tmp_path):
    binding = {"ordinary_uid": 1000, "setup_uid": 1002,
               "setup_engine_id": "6c3ab358-4b21-4979-b2ff-916bbd32d891",
               "setup_readiness_sha256": "e" * 64}
    admission_intent = {"schema": launched.admission_controller.SCHEMA,
                        "phase": "intent", "vm_id": VM,
                        "observation_id": "44444444-5555-4666-8777-888888888888",
                        "engine_id": binding["setup_engine_id"],
                        "readiness_sha256": binding["setup_readiness_sha256"],
                        "pid": 1699, "start_ticks": "12345",
                        "dpkg_status_sha256": "c" * 64,
                        "module_sha256": "1" * 64,
                        "controller_sha256": "2" * 64,
                        "purpose": "disposable_fixture_setup_package_admission",
                        "package_actions_authorized": False,
                        "installation_authorized": False}
    admission_intent_raw = launched.release.encode(admission_intent)
    admission = {"schema": launched.admission_controller.SCHEMA,
                 "phase": "observed", "vm_id": VM,
                 "observation_id": "44444444-5555-4666-8777-888888888888",
                 "intent_sha256": launched.release.digest(admission_intent_raw),
                 "engine_id": binding["setup_engine_id"],
                 "readiness_sha256": binding["setup_readiness_sha256"],
                 "dpkg_status_sha256": "c" * 64,
                 "module_sha256": "1" * 64, "controller_sha256": "2" * 64,
                 "private_stage": "/private/stage", "packages": [],
                 "archive_releases": [], "new_package_actions": [],
                 "transaction_simulated": True,
                 "rootful_docker_package_simulated_change": False,
                 "package_actions_authorized": False,
                 "installation_authorized": False,
                 "account_or_subids_allocated": False,
                 "daemon_start_attempted_by_probe": False,
                 "rootless_ready": False, "qualified": False,
                 "application_deployment_authorized": False,
                 "observed_at": 1000}
    admission_raw = launched.release.encode(admission)
    def records(_parent, name):
        return ((admission_intent_raw, admission_intent)
                if name.endswith(launched.admission_controller.INTENT_SUFFIX)
                else (admission_raw, admission))
    ordinary = launched.release.encode({
        "schema": "elevenid.fixture-installer-account/v1",
        "uid": 1000, "gid": 1001, "home": "/home/installer",
        "docker_group": False, "sudo_group": False,
        "setup_socket_denied": True, "no_new_privs": True,
        "effective_caps_zero": True})
    admin = launched.release.encode({
        "schema": "elevenid.fixture-admin-identity/v1",
        "uid": 1002, "gid": 1002, "home": "/home/fixture-admin"})
    def ssh(_binding, _user, script, **_kwargs):
        if script == launched.setup._installer_command():
            return ordinary
        if script == launched.setup._admin_identity_command():
            return admin
        return b'"7c3ab358-4b21-4979-b2ff-916bbd32d891"\n'
    class Lease:
        parent = 20
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
    with mock.patch.object(launched, "ControllerLease", return_value=Lease()), \
         mock.patch.object(launched, "bound_live_copy", return_value=binding), \
         mock.patch.object(launched.setup, "_ssh_as", side_effect=ssh), \
         mock.patch.object(launched.create, "_read_record", side_effect=records), \
         mock.patch.object(launched.probe, "_ssh") as status, \
         mock.patch.object(launched.create, "_write") as write:
        with pytest.raises(ValueError, match="Engine differs"):
            launched.observe_baseline(
                source=tmp_path / "source", registry=tmp_path / "registry",
                runtime_parent=tmp_path / "runtime", vm_id=VM,
                copy_vm_id=COPY,
                expected_engine_id=binding["setup_engine_id"],
                expected_status_sha256="c" * 64)
    status.assert_not_called()
    write.assert_not_called()
