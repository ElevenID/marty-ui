"""Exact v2 VM target binding remains diagnostic until candidate admission."""
from pathlib import Path
import sys
import time

import pytest

if sys.platform != "linux":
    pytest.skip("root VM target fixtures require Linux", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import installer_candidate_vm_live_observe as live
import installer_candidate_vm_target as target
from installer_candidate_vm_launch_evidence import bind_provisioned_launch
import installer_release as release
from test_installer_candidate_vm_live_observe import _launched
from test_installer_candidate_vm_create import root_trial as root_trial
from test_installer_candidate_vm_runtime import runtime_parent as runtime_parent
from test_installer_candidate_vm_runtime import VM_ID

OBSERVATION_ID = "77777777-7777-4777-8777-777777777777"
INSTALLATION_ID = "88888888-8888-4888-8888-888888888888"


def _evidence(root_trial, runtime_parent, monkeypatch):
    registry = _launched(root_trial, runtime_parent, monkeypatch)
    records = {name.replace("-", "_"): (
        registry / f"{VM_ID}.{name}.json").read_bytes()
        for name in live.RECORDS}
    seed = release.decode(records["seed_receipt"])
    monkeypatch.setattr(live, "pinned_guest", lambda *_a, **_k: {
        "guest_uid": 1000, "guest_user": seed["guest_user"],
        "packages": seed["packages"], "cloud_init_status": "done",
        "docker_engine_id": "engine-12345678",
        "docker_initially_empty": True, "guest_architecture": "x86_64"})
    initial = live.observe(registry, runtime_parent, vm_id=VM_ID,
                           guest_readiness=True)
    current = live.observe(registry, runtime_parent, vm_id=VM_ID,
                           pre_dispatch_id=OBSERVATION_ID)
    return records, release.encode(initial), current


def test_exact_v2_target_derives_ssh_and_disk_from_provisioning(
    root_trial, runtime_parent, monkeypatch
):
    records, initial, current = _evidence(root_trial, runtime_parent,
                                          monkeypatch)
    bound = target.bind_target(records, initial, current,
                               observation_id=OBSERVATION_ID,
                               installation_id=INSTALLATION_ID,
                               now=int(time.time()))
    seed = release.decode(records["seed_receipt"])
    assert bound["target"]["guest_id"] == VM_ID
    assert bound["target"]["engine_id"] == "engine-12345678"
    assert bound["ssh"]["host"] == "127.0.0.1"
    assert bound["ssh"]["port"] == seed["ssh_port"]
    assert bound["ssh"]["control_dir"] == seed["control_dir"]
    assert bound["qualified"] is False
    assert bound["dispatch_authorized"] is False


@pytest.mark.parametrize("mutation", ["guest", "record", "initial", "pid"])
def test_v2_target_refuses_substitution(
    root_trial, runtime_parent, monkeypatch, mutation
):
    records, initial, current = _evidence(root_trial, runtime_parent,
                                          monkeypatch)
    if mutation == "guest":
        current["guest"] = dict(current["guest"], docker_engine_id="other-engine")
    elif mutation == "record":
        record = release.decode(records["seed_receipt"])
        record["known_hosts_sha256"] = "0" * 64
        records["seed_receipt"] = release.encode(record)
    elif mutation == "initial":
        record = release.decode(initial)
        record["record_sha256"]["launch_receipt_sha256"] = "0" * 64
        initial = release.encode(record)
    else:
        record = release.decode(records["launch_receipt"])
        record["pid_authentication"] = "bounded_seconds_engineering_only"
        records["launch_receipt"] = release.encode(record)
    with pytest.raises(ValueError):
        target.bind_target(records, initial, current,
                           observation_id=OBSERVATION_ID,
                           installation_id=INSTALLATION_ID,
                           now=int(time.time()))


@pytest.mark.parametrize("field", ["process_pid", "disk_device",
                                   "runtime_dir_inode", "process_disk_fd"])
def test_v2_target_refuses_numerically_equal_inexact_identity(
    root_trial, runtime_parent, monkeypatch, field
):
    records, initial_raw, current = _evidence(root_trial, runtime_parent,
                                               monkeypatch)
    initial = release.decode(initial_raw)
    initial[field] = float(initial[field])
    current[field] = initial[field]
    changed = release.encode(initial)
    current["initial_guest_readiness_sha256"] = release.digest(changed)
    with pytest.raises(ValueError, match="live target differs"):
        target.bind_target(records, changed, current,
                           observation_id=OBSERVATION_ID,
                           installation_id=INSTALLATION_ID,
                           now=int(time.time()))


def test_v2_target_refuses_boolean_equal_to_provisioned_integer(
    root_trial, runtime_parent, monkeypatch
):
    records, initial_raw, current = _evidence(root_trial, runtime_parent,
                                               monkeypatch)
    receipt = release.decode(records["launch_receipt"])
    receipt["disk_fd"] = 1
    records["launch_receipt"] = release.encode(receipt)
    initial = release.decode(initial_raw)
    initial["record_sha256"] = bind_provisioned_launch(
        **records, boot_id=initial["controller_boot_id"])
    initial["process_disk_fd"] = True
    current["process_disk_fd"] = True
    current["record_sha256"] = initial["record_sha256"]
    changed = release.encode(initial)
    current["initial_guest_readiness_sha256"] = release.digest(changed)
    with pytest.raises(ValueError, match="live target differs"):
        target.bind_target(records, changed, current,
                           observation_id=OBSERVATION_ID,
                           installation_id=INSTALLATION_ID,
                           now=int(time.time()))
