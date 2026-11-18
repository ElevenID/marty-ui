"""Fixed engineering scope and one-attempt controller ordering."""
import json
import os
from pathlib import Path
import sys

import pytest

if sys.platform != "linux" or os.geteuid() != 0:
    pytest.skip("engineering controller requires Linux root", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_installer_engineering_trial as trial
from installer_candidate_controller import ControllerLease
import installer_release as release


@pytest.fixture
def arranged(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    registry = tmp_path / "registry"
    registry.mkdir(mode=0o700)
    context = tmp_path / "context.json"
    fixture = json.loads((Path(__file__).resolve().parents[1]
                          / "rust/crates/deployment-catalog/tests/fixtures/installer-candidate-records.json")
                         .read_text())
    grant = release.decode(fixture["authorization"].encode())
    expected = {key: grant[key] for key in release.CONTEXT_FIELDS}
    context.write_bytes(release.encode(expected))
    context.chmod(0o600)
    calls = []

    def preflight(lease, *_args, **kwargs):
        assert lease.parent is not None and kwargs["purpose"] == trial.ENGINEERING
        calls.append("preflight")
        return {"synthetic": "engineering preflight"}

    def consume(lease, *_args, **kwargs):
        assert lease.parent is not None and kwargs["purpose"] == trial.ENGINEERING
        calls.append("consume")
        trial._write(lease.parent, expected["nonce"] + ".vm-consumption-intent.json",
                     dict(purpose=trial.ENGINEERING, qualification_eligible=False))
        return b"synthetic receipt"

    def exchange(**kwargs):
        assert kwargs["purpose"] == trial.ENGINEERING
        with ControllerLease(registry):
            pass
        calls.append("exchange")
        return dict(purpose=trial.ENGINEERING, qualification_eligible=False)

    def dispatch(**kwargs):
        assert kwargs["purpose"] == trial.ENGINEERING
        assert (registry / (expected["nonce"] + ".engineering-exchange.json")).is_file()
        assert kwargs["exchange_result"]["qualification_eligible"] is False
        calls.append("dispatch")
        return dict(purpose=trial.ENGINEERING, qualification_eligible=False,
                    acceptance=False, installation_ready=False)

    for name, value in (("preflight", preflight), ("consume_preflight", consume),
                        ("exchange", exchange), ("dispatch_once", dispatch)):
        monkeypatch.setattr(trial, name, value)
    args = dict(client=object(), registry=registry, runtime_parent=tmp_path / "runtime",
                vm_id="11111111-1111-4111-8111-111111111111",
                installation_id="22222222-2222-4222-8222-222222222222",
                context=context, authorization=tmp_path / "authorization.json",
                assets=tmp_path / "assets", descriptor=tmp_path / "descriptor.json",
                gh=tmp_path / "gh", cosign=tmp_path / "cosign",
                ssh=Path("/usr/bin/ssh"), scp=Path("/usr/bin/scp"),
                controller_user_id=7076785, clock=lambda: 100000)
    return args, calls


def test_engineering_trial_orders_one_attempt_and_refuses_replay(arranged):
    args, calls = arranged
    result = trial.run(**args)
    assert result["acceptance"] is False
    assert calls == ["preflight", "consume", "exchange", "dispatch"]
    with pytest.raises(FileExistsError):
        trial.run(**args)
    assert calls == ["preflight", "consume", "exchange", "dispatch", "preflight", "consume"]


@pytest.mark.parametrize("stage", ["consume_preflight", "exchange", "dispatch_once"])
def test_engineering_failure_never_repeats_a_mutating_stage(arranged, monkeypatch, stage):
    args, calls = arranged

    def fail(*_args, **_kwargs):
        calls.append("failed:" + stage)
        raise ValueError("synthetic uncertain result")

    monkeypatch.setattr(trial, stage, fail)
    with pytest.raises(ValueError, match="uncertain result"):
        trial.run(**args)
    assert calls.count("failed:" + stage) == 1
    assert "dispatch" not in calls
    if stage != "consume_preflight":
        nonce = release.decode(args["context"].read_bytes())["nonce"]
        assert (args["registry"] / (nonce + ".vm-consumption-intent.json")).is_file()


def test_context_change_after_preflight_cannot_consume(arranged, monkeypatch):
    args, calls = arranged
    original = trial.preflight

    def changed(*pos, **kwargs):
        result = original(*pos, **kwargs)
        args["context"].write_bytes(release.encode({}))
        return result

    monkeypatch.setattr(trial, "preflight", changed)
    with pytest.raises(ValueError, match="context changed"):
        trial.run(**args)
    assert calls == ["preflight"]


def test_engineering_coordinator_refuses_false_readiness(arranged, monkeypatch):
    args, _ = arranged
    monkeypatch.setattr(trial, "dispatch_once", lambda **_kwargs:
                        dict(purpose=trial.ENGINEERING, qualification_eligible=False,
                             acceptance=False, installation_ready=True))
    with pytest.raises(ValueError, match="falsely claims qualification"):
        trial.run(**args)
