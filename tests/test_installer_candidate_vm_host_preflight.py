"""Signed input, held-lease VM and raw host admission orchestration."""
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux" or os.geteuid() != 0:
    pytest.skip("root VM preflight requires Linux root", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_candidate_controller import ControllerLease
from installer_candidate_vm_create import _write
import installer_candidate_vm_host_preflight as preflight
import installer_release as release
from test_installer_acceptance_runner import host

VM_ID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
FIRST_ID = "33333333-3333-4333-8333-333333333333"
FINAL_ID = "44444444-4444-4444-8444-444444444444"


@pytest.fixture
def arranged(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    with ControllerLease(registry) as lease:
        _write(lease.parent, VM_ID + ".guest-readiness.json", {})
        for name in preflight.RECORDS:
            _write(lease.parent, VM_ID + "." + name + ".json", {})
    expected = dict(source_sha="a" * 40, release_tag="v1.2.3",
                    operator_sha256="b" * 64, phase="staged", nonce="c" * 64,
                    harness_source_sha="d" * 40, run_id=7, run_attempt=1)
    calls = []
    monkeypatch.setattr(preflight.uploader, "authenticate",
                        lambda *_a, **_k: (b'{}', b'{}'))
    monkeypatch.setattr(preflight.release, "bind_candidate_authorization",
                        lambda *_a, **_k: calls.append("signed") or ({}, {}))
    monkeypatch.setattr(preflight.dispatch, "verified_harness_script",
                        lambda *_a, **_k: "print('{}')")
    def observe(*_a, **kwargs):
        calls.append("observe:" + kwargs["pre_dispatch_id"])
        return {"id": kwargs["pre_dispatch_id"]}
    monkeypatch.setattr(preflight, "observe", observe)
    engine = "test-engine-12345678"
    def bind(_records, _initial, current, **_kwargs):
        return dict(target=dict(guest_id=VM_ID, disk_id="e" * 64,
                                engine_id=engine, installation_id=INSTALLATION_ID),
                    ssh=dict(host="127.0.0.1", port=2222, user="installer",
                             control_dir="/root/control",
                             controller_key_sha256="f" * 64,
                             known_hosts_sha256="0" * 64),
                    provisioning_sha256={"creation_intent_sha256": "1" * 64},
                    initial_guest_readiness_sha256="2" * 64,
                    pre_dispatch_sha256=release.digest(release.encode(current)))
    monkeypatch.setattr(preflight, "bind_target", bind)
    observed = release.encode(host())
    def probe(_binding, _source):
        calls.append("probe")
        return observed
    args = dict(registry=registry, runtime_parent=runtime, vm_id=VM_ID,
                installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
                final_observation_id=FINAL_ID,
                authorization=tmp_path / "authorization.json",
                assets=tmp_path / "assets", expected=expected,
                gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                clock=lambda: 100000, guest_probe=probe)
    return args, calls, observed, monkeypatch


def test_preflight_preserves_raw_host_bytes_without_consuming_nonce(arranged):
    args, calls, raw, _ = arranged
    with ControllerLease(args["registry"]) as lease:
        result = preflight.preflight(lease, **args)
        assert lease.parent is not None
    assert result["host_admission_passed"] is True
    assert result["nonce_consumed"] is False
    assert result["qualified"] is False
    assert result["host_observation_sha256"] == release.digest(raw)
    raw_path = args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json"
    assert raw_path.read_bytes() == raw
    assert calls == ["signed", "observe:" + FIRST_ID, "probe", "signed",
                     "observe:" + FINAL_ID, "signed"]
    assert not (args["registry"] / (args["expected"]["nonce"] + ".json")).exists()


def test_preflight_rejects_dirty_host_but_retains_raw_evidence(arranged):
    args, _, _, _ = arranged
    dirty = host()
    dirty["predicates"]["initial_docker_clean"] = False
    args["guest_probe"] = lambda *_a: release.encode(dirty)
    with ControllerLease(args["registry"]) as lease:
        with pytest.raises(ValueError, match="guest pre-pull state differs"):
            preflight.preflight(lease, **args)
    assert (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json").is_file()
    assert not (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-preflight.json").exists()


def test_preflight_rejects_changed_signed_inputs_after_probe(arranged):
    args, _, _, monkeypatch = arranged
    count = 0
    def authenticate(*_a, **_k):
        nonlocal count
        count += 1
        return (b'{}' if count == 1 else b'{"changed":true}', b'{}')
    monkeypatch.setattr(preflight.uploader, "authenticate", authenticate)
    with ControllerLease(args["registry"]) as lease:
        with pytest.raises(ValueError, match="signed candidate inputs changed"):
            preflight.preflight(lease, **args)
    assert not (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-preflight.json").exists()


def test_preflight_rejects_changed_vm_after_probe(arranged):
    args, _, _, monkeypatch = arranged
    original = preflight.bind_target
    count = 0
    def changed(*a, **k):
        nonlocal count
        count += 1
        record = original(*a, **k)
        if count == 2:
            record["target"]["engine_id"] = "other-engine-12345"
        return record
    monkeypatch.setattr(preflight, "bind_target", changed)
    with ControllerLease(args["registry"]) as lease:
        with pytest.raises(ValueError, match="VM target changed"):
            preflight.preflight(lease, **args)
    assert not (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-preflight.json").exists()


def test_preflight_probe_failure_never_writes_admission(arranged):
    args, _, _, _ = arranged
    def refuse(*_a):
        raise ValueError("synthetic pinned SSH failure")
    args["guest_probe"] = refuse
    with ControllerLease(args["registry"]) as lease:
        with pytest.raises(ValueError, match="pinned SSH failure"):
            preflight.preflight(lease, **args)
    assert not (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json").exists()


def test_preflight_refuses_stale_measurement_after_reauthentication(arranged):
    args, _, _, monkeypatch = arranged
    tick = [100000]
    count = 0
    def authenticate(*_a, **_k):
        nonlocal count
        count += 1
        if count == 2:
            tick[0] += 61
        return b'{}', b'{}'
    monkeypatch.setattr(preflight.uploader, "authenticate", authenticate)
    args["clock"] = lambda: tick[0]
    with ControllerLease(args["registry"]) as lease:
        with pytest.raises(ValueError, match="measurement is stale"):
            preflight.preflight(lease, **args)
    assert (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json").is_file()
    assert not (args["registry"] / f"{VM_ID}.{FIRST_ID}.host-preflight.json").exists()


def test_raw_evidence_replacement_with_fifo_cannot_block(arranged):
    args, _, _, monkeypatch = arranged
    name = "synthetic.host-observation.json"
    raw = b'{}\n'
    with ControllerLease(args["registry"]) as lease:
        preflight._raw_at(lease.parent, name, raw)
        original_stat = os.stat
        swapped = [False]
        def stat(path, *a, **k):
            info = original_stat(path, *a, **k)
            if (path == name and k.get("dir_fd") == lease.parent
                    and not swapped[0]):
                swapped[0] = True
                os.rename(name, name + ".old", src_dir_fd=lease.parent,
                          dst_dir_fd=lease.parent)
                os.mkfifo(name, 0o600, dir_fd=lease.parent)
            return info
        monkeypatch.setattr(preflight.os, "stat", stat)
        with pytest.raises(ValueError, match="raw host evidence changed"):
            preflight._unchanged_raw(lease.parent, name, raw)
        assert swapped[0]
