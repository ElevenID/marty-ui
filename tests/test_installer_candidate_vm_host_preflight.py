"""Signed input, held-lease VM and raw host admission orchestration."""
import os
import json
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

REAL_BIND_CANDIDATE = release.bind_candidate_authorization

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
        observed = {"vm_id": VM_ID, "observation_id": kwargs["pre_dispatch_id"],
                    "observed_at": 100000}
        _write(kwargs["lease"].parent,
               VM_ID + ".pre-dispatch-" + kwargs["pre_dispatch_id"] + ".json",
               observed)
        return observed
    monkeypatch.setattr(preflight, "observe", observe)
    engine = "test-engine-12345678"
    def bind(_records, initial, current, **_kwargs):
        return dict(target=dict(guest_id=VM_ID, disk_id="e" * 64,
                                engine_id=engine, installation_id=INSTALLATION_ID),
                    ssh=dict(host="127.0.0.1", port=2222, user="installer",
                             control_dir="/root/control",
                             controller_key_sha256="f" * 64,
                             known_hosts_sha256="0" * 64),
                    provisioning_sha256={"creation_intent_sha256": "1" * 64},
                    initial_guest_readiness_sha256=release.digest(initial),
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


def test_consume_reobserves_same_vm_under_held_lease(arranged):
    args, calls, _, monkeypatch = arranged
    now = [100000]
    args["clock"] = lambda: now[0]
    original_write = preflight._write
    def advance_after_intent(parent, name, record):
        result = original_write(parent, name, record)
        if name.endswith(".vm-consumption-intent.json"):
            now[0] += 1
        return result
    monkeypatch.setattr(preflight, "_write", advance_after_intent)
    consumed = []
    def consume(_self, a, i, **kwargs):
        consumed.append((a, i, kwargs))
        return b"durable receipt"
    monkeypatch.setattr(ControllerLease, "consume", consume)
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        result = preflight.consume_preflight(
            lease, args["registry"], args["runtime_parent"], vm_id=VM_ID,
            installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
            consumption_observation_id="55555555-5555-4555-8555-555555555555",
            preflight_record=record, authorization=args["authorization"],
            assets=args["assets"], expected=args["expected"], gh=args["gh"],
            cosign=args["cosign"], clock=args["clock"])
        assert lease.parent is not None
    assert result == b"durable receipt"
    assert len(consumed) == 1
    assert consumed[0][2]["guest_id"] == VM_ID
    assert consumed[0][2]["installation_id"] == INSTALLATION_ID
    assert consumed[0][2]["consumed_at"] == 100000
    assert consumed[0][2]["now"] == 100001
    assert calls[-2:] == ["signed", "observe:55555555-5555-4555-8555-555555555555"]


def test_consume_rejects_changed_host_bytes_before_nonce(arranged):
    args, _, _, monkeypatch = arranged
    monkeypatch.setattr(ControllerLease, "consume", lambda *_a, **_k:
                        pytest.fail("nonce consumed after host evidence changed"))
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        raw_path = args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json"
        raw_path.write_bytes(release.encode({}))
        with pytest.raises(ValueError, match="host evidence differs"):
            preflight.consume_preflight(
                lease, args["registry"], args["runtime_parent"], vm_id=VM_ID,
                installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
                consumption_observation_id="55555555-5555-4555-8555-555555555555",
                preflight_record=record, authorization=args["authorization"],
                assets=args["assets"], expected=args["expected"], gh=args["gh"],
                cosign=args["cosign"], clock=args["clock"])


def test_consume_preserves_noncanonical_raw_host_json(arranged):
    args, _, raw, monkeypatch = arranged
    args["guest_probe"] = lambda *_a: b" " + raw
    monkeypatch.setattr(ControllerLease, "consume", lambda *_a, **_k: b"receipt")
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        result = preflight.consume_preflight(
            lease, args["registry"], args["runtime_parent"], vm_id=VM_ID,
            installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
            consumption_observation_id="55555555-5555-4555-8555-555555555555",
            preflight_record=record, authorization=args["authorization"],
            assets=args["assets"], expected=args["expected"], gh=args["gh"],
            cosign=args["cosign"], clock=args["clock"])
    assert result == b"receipt"


def test_consume_rejects_replaced_vm_target_before_nonce(arranged):
    args, _, _, monkeypatch = arranged
    monkeypatch.setattr(ControllerLease, "consume", lambda *_a, **_k:
                        pytest.fail("nonce consumed after VM changed"))
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        original = preflight.bind_target
        def changed(*a, **k):
            bound = original(*a, **k)
            bound["target"]["engine_id"] = "replacement-engine-12345678"
            return bound
        monkeypatch.setattr(preflight, "bind_target", changed)
        with pytest.raises(ValueError, match="VM target changed"):
            preflight.consume_preflight(
                lease, args["registry"], args["runtime_parent"], vm_id=VM_ID,
                installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
                consumption_observation_id="55555555-5555-4555-8555-555555555555",
                preflight_record=record, authorization=args["authorization"],
                assets=args["assets"], expected=args["expected"], gh=args["gh"],
                cosign=args["cosign"], clock=args["clock"])


@pytest.mark.parametrize("purpose", [preflight.QUALIFICATION, preflight.ENGINEERING])
def test_real_held_lease_consumes_exact_nonce_once(arranged, purpose):
    args, _, _, monkeypatch = arranged
    args["purpose"] = purpose
    fixture = json.loads((Path(__file__).resolve().parents[1]
                          / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json")
                         .read_text())
    authorization = fixture["authorization"].encode()
    inventory = fixture["inventory"].encode()
    grant = release.decode(authorization)
    args["expected"] = {key: grant[key] for key in release.CONTEXT_FIELDS}
    monkeypatch.setattr(preflight.uploader, "authenticate",
                        lambda *_a, **_k: (authorization, inventory))
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        monkeypatch.setattr(release, "bind_candidate_authorization", REAL_BIND_CANDIDATE)
        common = dict(vm_id=VM_ID, installation_id=INSTALLATION_ID,
                      observation_id=FIRST_ID, preflight_record=record,
                      authorization=args["authorization"], assets=args["assets"],
                      expected=args["expected"], gh=args["gh"], cosign=args["cosign"],
                      clock=args["clock"], purpose=purpose)
        other = (preflight.QUALIFICATION if purpose == preflight.ENGINEERING
                 else preflight.ENGINEERING)
        with pytest.raises(ValueError, match="preflight purpose differs"):
            preflight.consume_preflight(
                lease, args["registry"], args["runtime_parent"],
                consumption_observation_id="55555555-5555-4555-8555-555555555555",
                **dict(common, purpose=other))
        receipt = preflight.consume_preflight(
            lease, args["registry"], args["runtime_parent"],
            consumption_observation_id="55555555-5555-4555-8555-555555555555",
            **common)
        ledger = args["registry"] / (grant["nonce"] + ".json")
        assert ledger.read_bytes() == receipt
        intent_path = args["registry"] / (grant["nonce"] + ".vm-consumption-intent.json")
        intent_bytes = intent_path.read_bytes()
        intent = release.decode(intent_bytes)
        preflight_raw = (args["registry"] /
                         f"{VM_ID}.{FIRST_ID}.host-preflight.json").read_bytes()
        observation_raw = (args["registry"] /
            f"{VM_ID}.pre-dispatch-55555555-5555-4555-8555-555555555555.json").read_bytes()
        assert intent["preflight_sha256"] == release.digest(preflight_raw)
        assert intent["consumption_observation_sha256"] == release.digest(observation_raw)
        assert intent["target"] == record["target"]
        assert intent["nonce"] == grant["nonce"]
        assert intent["preflight_observation_id"] == FIRST_ID
        assert intent["consumption_observation_id"] == "55555555-5555-4555-8555-555555555555"
        assert intent["nonce_consumed"] is False
        assert intent["dispatch_authorized"] is False
        checked = preflight.verify_consumed_intent(
            lease, args["registry"], authorization=args["authorization"],
            assets=args["assets"], expected=args["expected"], gh=args["gh"],
            cosign=args["cosign"], clock=args["clock"], purpose=purpose)
        assert checked["receipt_sha256"] == release.digest(receipt)
        assert checked["intent_sha256"] == release.digest(intent_bytes)
        assert checked["target"] == record["target"]
        with pytest.raises(ValueError):
            preflight.verify_consumed_intent(
                lease, args["registry"], authorization=args["authorization"],
                assets=args["assets"], expected=args["expected"], gh=args["gh"],
                cosign=args["cosign"], clock=args["clock"], purpose=other)
        if purpose == preflight.ENGINEERING:
            assert intent["purpose"] == preflight.ENGINEERING
            assert intent["qualification_eligible"] is False
            assert "host_admission_passed" not in record
        original_bind_consumption = release.bind_controller_consumption
        evidence_paths = (
            args["registry"] / f"{VM_ID}.{FIRST_ID}.host-preflight.json",
            args["registry"] / f"{VM_ID}.pre-dispatch-55555555-5555-4555-8555-555555555555.json",
            args["registry"] / f"{VM_ID}.{FIRST_ID}.host-observation.json",
        )
        for evidence_path in evidence_paths:
            original_bytes = evidence_path.read_bytes()
            def mutate_during_ledger_binding(*a, **k):
                bound = original_bind_consumption(*a, **k)
                evidence_path.write_bytes(release.encode({}))
                return bound
            monkeypatch.setattr(release, "bind_controller_consumption",
                                mutate_during_ledger_binding)
            try:
                with pytest.raises(ValueError, match="VM consumed nonce evidence changed"):
                    preflight.verify_consumed_intent(
                        lease, args["registry"], authorization=args["authorization"],
                        assets=args["assets"], expected=args["expected"],
                        gh=args["gh"], cosign=args["cosign"], clock=args["clock"],
                        purpose=purpose)
            finally:
                evidence_path.write_bytes(original_bytes)
                monkeypatch.setattr(release, "bind_controller_consumption",
                                    original_bind_consumption)
        bound = release.bind_controller_consumption(
            receipt, authorization, inventory, expected=args["expected"],
            expected_engine=record["target"]["engine_id"], now=100000)
        assert all(bound[key] == value for key, value in record["target"].items())
        with pytest.raises(FileExistsError):
            preflight.consume_preflight(
                lease, args["registry"], args["runtime_parent"],
                consumption_observation_id="66666666-6666-4666-8666-666666666666",
                **common)
        assert ledger.read_bytes() == receipt
        assert intent_path.read_bytes() == intent_bytes
        assert lease.parent is not None
        with pytest.raises(BlockingIOError):
            with ControllerLease(args["registry"]):
                pass


@pytest.mark.parametrize("purpose", [preflight.QUALIFICATION, preflight.ENGINEERING])
def test_small_vm_preflight_retains_failed_production_capacity(arranged, purpose):
    args, _, _, _ = arranged
    value = host()
    value.update(docker_memory_bytes=4 * 1024**3, guest_memory_bytes=4 * 1024**3)
    value["predicates"]["capacity"] = False
    raw = release.encode(value)
    args.update(purpose=purpose, guest_probe=lambda *_args: raw)
    with ControllerLease(args["registry"]) as lease:
        if purpose == preflight.QUALIFICATION:
            with pytest.raises(ValueError, match="qualification RAM unavailable"):
                preflight.preflight(lease, **args)
        else:
            record = preflight.preflight(lease, **args)
            assert record["schema"] == preflight.ENGINEERING_SCHEMA
            assert record["engineering_admission_passed"] is True
            assert record["qualification_eligible"] is False
            assert record["production_capacity_passed"] is False
            assert "host_admission_passed" not in record
        assert preflight._raw_bytes_at(
            lease.parent, f"{VM_ID}.{FIRST_ID}.host-observation.json") == raw


def test_slow_intent_persistence_cannot_consume_stale_evidence(arranged):
    args, _, _, monkeypatch = arranged
    now = [100000]
    args["clock"] = lambda: now[0]
    original_write = preflight._write
    def slow_write(parent, name, record):
        result = original_write(parent, name, record)
        if name.endswith(".vm-consumption-intent.json"):
            now[0] = 100061
        return result
    monkeypatch.setattr(preflight, "_write", slow_write)
    monkeypatch.setattr(ControllerLease, "consume", lambda *_a, **_k:
                        pytest.fail("stale evidence consumed nonce"))
    with ControllerLease(args["registry"]) as lease:
        record = preflight.preflight(lease, **args)
        with pytest.raises(ValueError, match="consumption evidence is stale"):
            preflight.consume_preflight(
                lease, args["registry"], args["runtime_parent"], vm_id=VM_ID,
                installation_id=INSTALLATION_ID, observation_id=FIRST_ID,
                consumption_observation_id="55555555-5555-4555-8555-555555555555",
                preflight_record=record, authorization=args["authorization"],
                assets=args["assets"], expected=args["expected"], gh=args["gh"],
                cosign=args["cosign"], clock=args["clock"])
        assert (args["registry"] /
                (args["expected"]["nonce"] + ".vm-consumption-intent.json")).exists()
        assert not (args["registry"] /
                    (args["expected"]["nonce"] + ".json")).exists()


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
