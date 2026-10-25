"""Root-owned diagnostic observation of an already launched VM."""
import json
from pathlib import Path
import sys

import pytest

if sys.platform != "linux":
    pytest.skip("live VM observer requires Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_launch as launch
import installer_candidate_vm_live_observe as live
from test_installer_candidate_vm_launch import _seeded
from test_installer_candidate_vm_create import root_trial as root_trial
from test_installer_candidate_vm_runtime import runtime_parent as runtime_parent
from test_installer_candidate_vm_runtime import VM_ID


def _launched(root_trial, runtime_parent, monkeypatch):
    source, registry, parent = _seeded(root_trial, runtime_parent, monkeypatch)
    monkeypatch.setattr(launch, "_idle_uid", lambda _uid: None)

    class FakeProcess:
        pid = 12345

        def poll(self):
            return None

    monkeypatch.setattr(launch.subprocess, "Popen", lambda *_a, **_k: FakeProcess())
    original = launch.os.readlink
    monkeypatch.setattr(
        launch.os, "readlink",
        lambda path: str(launch.QEMU) if str(path) == "/proc/12345/exe"
        else original(path),
    )
    observed = {"pid": 12345, "start_ticks": "123", "disk_fd": 7}
    monkeypatch.setattr(launch, "_live", lambda *_a, **_k: observed)
    launch.launch(source, registry, parent, runtime_parent, vm_id=VM_ID)
    return registry


def test_exact_live_observation_is_diagnostic_only(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    record = live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert record["schema"] == live.SCHEMA
    assert record["phase"] == "process-observed"
    assert record["process_pid"] == 12345
    assert record["qualified"] is False
    assert record["dispatch_authorized"] is False
    assert len(record["record_sha256"]) == 9
    output = registry / f"{VM_ID}.live-process-observation.json"
    before = output.read_bytes()
    with pytest.raises(FileExistsError):
        live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert output.read_bytes() == before


def test_legacy_launch_cannot_gain_live_candidate_evidence(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    path = registry / f"{VM_ID}.launch-receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt["pid_authentication"] = "bounded_seconds_engineering_only"
    path.write_bytes(launch.release.encode(receipt))
    with pytest.raises(ValueError, match="exact launch chain"):
        live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert not (registry / f"{VM_ID}.live-process-observation.json").exists()


def test_process_replacement_refuses_diagnostic_write(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    monkeypatch.setattr(
        launch, "_live", lambda *_a, **_k:
        {"pid": 12345, "start_ticks": "124", "disk_fd": 7},
    )
    with pytest.raises(ValueError, match="process differs"):
        live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert not (registry / f"{VM_ID}.live-process-observation.json").exists()


def test_changed_control_material_refuses_diagnostic_write(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    known_hosts = registry / f"{VM_ID}.control" / "known_hosts"
    known_hosts.write_bytes(b"[127.0.0.1]:22 wrong-key\n")
    with pytest.raises(ValueError, match="control material differs"):
        live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert not (registry / f"{VM_ID}.live-process-observation.json").exists()


def test_changed_root_record_refuses_diagnostic_write(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    path = registry / f"{VM_ID}.runtime-receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt["runtime_dir_inode"] += 1
    path.write_bytes(launch.release.encode(receipt))
    with pytest.raises(ValueError, match="provisioning chain invalid"):
        live.observe(registry, runtime_parent, vm_id=VM_ID)
    assert not (registry / f"{VM_ID}.live-process-observation.json").exists()


def test_guest_readiness_remains_diagnostic_under_same_lease(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    calls = []

    def pinned(_control, *, port, user, packages, key_sha256,
               known_hosts_sha256):
        calls.append((port, user, packages, key_sha256, known_hosts_sha256))
        return {"guest_uid": 1000, "docker_initially_empty": True}

    monkeypatch.setattr(live, "pinned_guest", pinned)
    record = live.observe(registry, runtime_parent, vm_id=VM_ID,
                          guest_readiness=True)
    assert record["schema"] == live.GUEST_SCHEMA
    assert record["phase"] == "guest-ready"
    assert record["guest"]["docker_initially_empty"] is True
    assert record["qualified"] is False
    assert record["dispatch_authorized"] is False
    assert len(calls) == 1
    assert (registry / f"{VM_ID}.guest-readiness.json").is_file()


def test_failed_guest_probe_retains_process_without_readiness_record(
    root_trial, runtime_parent, monkeypatch
):
    registry = _launched(root_trial, runtime_parent, monkeypatch)

    def refuse(*_args, **_kwargs):
        raise ValueError("injected guest host key mismatch")

    monkeypatch.setattr(live, "pinned_guest", refuse)
    with pytest.raises(ValueError, match="host key mismatch"):
        live.observe(registry, runtime_parent, vm_id=VM_ID,
                     guest_readiness=True)
    assert not (registry / f"{VM_ID}.guest-readiness.json").exists()
    assert (registry / f"{VM_ID}.launch-receipt.json").is_file()
