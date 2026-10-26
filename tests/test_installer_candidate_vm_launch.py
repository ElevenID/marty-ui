"""Root-only transition tests for the single-use engineering VM launcher."""

import json
import os
import socket

from pathlib import Path
import subprocess
import sys
import time

import pytest

if sys.platform != "linux":
    pytest.skip("VM launch requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_launch as launch
import installer_candidate_vm_seed as seed
from test_installer_candidate_vm_seed import _transferred
from test_installer_candidate_vm_create import root_trial as root_trial
from test_installer_candidate_vm_runtime import runtime_parent as runtime_parent
from test_installer_candidate_vm_runtime import VM_ID


def _seeded(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _transferred(root_trial, runtime_parent, monkeypatch)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    seed.prepare(source, registry, parent, runtime_parent, vm_id=VM_ID, ssh_port=port)
    monkeypatch.setattr(launch, "_trusted_tool", lambda _path: "a" * 64)
    monkeypatch.setattr(launch, "_kvm_group", lambda: 993)
    monkeypatch.setattr(launch, "_host_headroom", lambda: 8 * 1024**3)
    monkeypatch.setattr(
        launch, "_boot_id", lambda: "11111111-1111-4111-8111-111111111111"
    )
    monkeypatch.setattr(launch, "_start_ticks", lambda _pid: "123")
    return source, registry, parent


def test_launch_refuses_active_runtime_identity_before_intent(
    root_trial, runtime_parent, monkeypatch
):
    source, registry, parent = _seeded(root_trial, runtime_parent, monkeypatch)

    def active(_uid):
        raise ValueError("VM runtime identity has an existing process")

    monkeypatch.setattr(launch, "_idle_uid", active)
    with pytest.raises(ValueError, match="existing process"):
        launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    assert not (registry / f"{VM_ID}.launch-intent.json").exists()


def test_spawn_failure_retains_launch_intent_and_no_receipt(
    root_trial, runtime_parent, monkeypatch
):
    source, registry, parent = _seeded(root_trial, runtime_parent, monkeypatch)
    monkeypatch.setattr(launch, "_idle_uid", lambda _uid: None)

    def refuse_spawn(*_args, **_kwargs):
        raise OSError("injected QEMU spawn failure")

    monkeypatch.setattr(launch.subprocess, "Popen", refuse_spawn)
    with pytest.raises(OSError, match="spawn failure"):
        launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    assert (registry / f"{VM_ID}.launch-intent.json").exists()
    assert not (registry / f"{VM_ID}.launch-pid.json").exists()
    assert not (registry / f"{VM_ID}.launch-receipt.json").exists()
    with pytest.raises(FileExistsError):
        launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)


def test_launch_arguments_are_loopback_and_owned_runtime_only():
    directory = Path(
        "/var/tmp/marty-runtime-test/vms/a1c2d3e4-4444-4444-8444-1234567890ab"
    )
    args = launch._arguments(directory, VM_ID, 22022)
    assert args[0] == str(launch.QEMU)
    assert "q35,accel=kvm" in args
    assert "user,id=net0,hostfwd=tcp:127.0.0.1:22022-:22" in args
    assert "unix:" + str(directory / "qmp.sock") + ",server=on,wait=off" in args
    assert (
        "file="
        + str(directory / "seed.iso")
        + ",if=virtio,media=cdrom,format=raw,readonly=on"
        in args
    )
    assert not any("0.0.0.0" in arg for arg in args)


def test_launch_rejects_qemu_option_delimiters_in_runtime_path():
    with pytest.raises(ValueError, match="unsafe"):
        launch._arguments(Path("/var/tmp/guest,format=raw"), VM_ID, 22022)
    with pytest.raises(ValueError, match="unsafe"):
        launch._arguments(Path("/var/tmp/guest\nunsafe"), VM_ID, 22022)


@pytest.mark.skipif(os.geteuid() != 0, reason="root controller trial required")
def test_privilege_drop_observation_is_real():
    command = [
        str(launch.SETPRIV),
        "--reuid",
        "60000",
        "--regid",
        "60000",
        "--groups",
        "60001",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
        "/usr/bin/sleep",
        "5",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 2
        while Path(f"/proc/{process.pid}/exe").resolve() != Path("/usr/bin/sleep"):
            assert process.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        launch._process_credentials(process.pid, 60000, 60000, 60001)
    finally:
        process.terminate()
        process.wait(timeout=5)


@pytest.mark.parametrize("disk_open_delay", [False, True])
def test_mocked_live_launch_records_exact_process(
    root_trial, runtime_parent, monkeypatch, disk_open_delay
):
    source, registry, parent = _seeded(root_trial, runtime_parent, monkeypatch)
    monkeypatch.setattr(launch, "_idle_uid", lambda _uid: None)

    class FakeProcess:
        pid = 12345

        def poll(self):
            return None

    monkeypatch.setattr(launch.subprocess, "Popen", lambda *_a, **_k: FakeProcess())
    actual_readlink = launch.os.readlink
    monkeypatch.setattr(
        launch.os,
        "readlink",
        lambda path: (
            str(launch.QEMU)
            if str(path) == "/proc/12345/exe"
            else actual_readlink(path)
        ),
    )
    live = {"pid": 12345, "start_ticks": "123", "disk_fd": 7}
    calls = 0

    def observe(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if disk_open_delay and calls == 1:
            raise launch.observer.DiskNotOpenedYet("VM writable disk descriptor not open yet")
        return live

    monkeypatch.setattr(launch, "_live", observe)
    monkeypatch.setattr(launch.time, "sleep", lambda _seconds: None)
    receipt = launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    assert calls == (3 if disk_open_delay else 2)
    assert receipt["phase"] == "launched" and receipt["pid"] == 12345
    assert receipt["qualified"] is False and receipt["dispatch_authorized"] is False
    assert (registry / f"{VM_ID}.launch-pid.json").is_file()
    assert (registry / f"{VM_ID}.launch-receipt.json").is_file()


@pytest.mark.parametrize("legacy", [False, True])
def test_post_spawn_failure_keeps_pid_and_recovers_same_process(
    root_trial, runtime_parent, monkeypatch, legacy
):
    source, registry, parent = _seeded(root_trial, runtime_parent, monkeypatch)
    monkeypatch.setattr(launch, "_idle_uid", lambda _uid: None)

    class FakeProcess:
        pid = 12345

        def poll(self):
            return None

    monkeypatch.setattr(launch.subprocess, "Popen", lambda *_a, **_k: FakeProcess())
    actual_readlink = launch.os.readlink
    monkeypatch.setattr(
        launch.os,
        "readlink",
        lambda path: (
            str(launch.QEMU)
            if str(path) == "/proc/12345/exe"
            else actual_readlink(path)
        ),
    )

    def refuse_live(*_args, **_kwargs):
        raise ValueError("injected QMP failure")

    monkeypatch.setattr(launch, "_live", refuse_live)
    with pytest.raises(ValueError, match="QMP failure"):
        launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    assert (registry / f"{VM_ID}.launch-intent.json").is_file()
    assert (registry / f"{VM_ID}.launch-pid.json").is_file()
    assert not (registry / f"{VM_ID}.launch-receipt.json").exists()
    with pytest.raises(FileExistsError):
        launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    pid_record = json.loads((registry / f"{VM_ID}.launch-pid.json").read_text())
    monkeypatch.setattr(launch, "_spawn_time", lambda _pid: pid_record["spawned_at"])
    monkeypatch.setattr(
        launch,
        "_live",
        lambda *_a, **_k: {"pid": 12345, "start_ticks": "123", "disk_fd": 7},
    )
    pid_path = registry / f"{VM_ID}.launch-pid.json"
    intent_path = registry / f"{VM_ID}.launch-intent.json"
    pid_original = pid_path.read_bytes()
    intent_original = intent_path.read_bytes()

    with monkeypatch.context() as changed:
        changed.setattr(
            launch, "_boot_id", lambda: "22222222-2222-4222-8222-222222222222"
        )
        with pytest.raises(ValueError, match="records disagree"):
            launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
    with monkeypatch.context() as changed:
        changed.setattr(
            launch, "_spawn_time", lambda _pid: pid_record["spawned_at"] + 30
        )
        with pytest.raises(ValueError, match="PID start differs"):
            launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)

    broken_pid = dict(pid_record, intent_sha256="0" * 64)
    pid_path.write_bytes(launch.release.encode(broken_pid))
    with pytest.raises(ValueError, match="records disagree"):
        launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
    pid_path.write_bytes(pid_original)

    broken_intent = json.loads(intent_original)
    broken_intent["seed_receipt_sha256"] = "0" * 64
    intent_path.write_bytes(launch.release.encode(broken_intent))
    linked_pid = dict(
        pid_record, intent_sha256=launch.release.digest(intent_path.read_bytes())
    )
    pid_path.write_bytes(launch.release.encode(linked_pid))
    with pytest.raises(ValueError, match="records disagree"):
        launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
    intent_path.write_bytes(intent_original)
    pid_path.write_bytes(pid_original)

    broken_pid = dict(pid_record, start_ticks="124")
    pid_path.write_bytes(launch.release.encode(broken_pid))
    with pytest.raises(ValueError, match="exact PID identity differs"):
        launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
    pid_path.write_bytes(pid_original)
    assert not (registry / f"{VM_ID}.launch-receipt.json").exists()
    if legacy:
        legacy_pid = dict(pid_record, schema=launch.SCHEMA)
        legacy_pid.pop("start_ticks")
        legacy_pid.pop("controller_boot_id")
        pid_path.write_bytes(launch.release.encode(legacy_pid))
    receipt = launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
    assert receipt["observation_route"] == "existing" and receipt["pid"] == 12345
    assert receipt["pid_authentication"] == (
        "bounded_seconds_engineering_only" if legacy else "exact_boot_and_start_ticks"
    )
    with pytest.raises(ValueError, match="already observed"):
        launch.observe_existing(registry, runtime_parent, vm_id=VM_ID)
