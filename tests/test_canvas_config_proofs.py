"""Bounded evidence checks for the early, image-free Canvas configuration cases."""

import hashlib
import json
import runpy
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci/run-canvas-config-proofs.py"


@pytest.fixture
def proof(monkeypatch, tmp_path):
    module = runpy.run_path(str(SCRIPT))
    for name, value in (
        ("RUNNER_TEMP", str(tmp_path)),
        ("GITHUB_RUN_ID", "123"),
        ("GITHUB_RUN_ATTEMPT", "2"),
        ("GITHUB_JOB", "test-rust-services"),
        ("GITHUB_SHA", "a" * 40),
        ("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
        ("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST", "1"),
    ):
        monkeypatch.setenv(name, value)
    executable = tmp_path / "composition-executable"
    executable.write_bytes(b"synthetic unique executable")
    return SimpleNamespace(
        module=module,
        executable=executable,
        evidence=tmp_path / "canvas-config-proofs.json",
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-list",
        "duplicate-list",
        "missing-marker",
        "duplicate-marker",
        "ignored",
        "failed",
        "nonzero",
    ],
)
def test_early_proof_requires_exact_discovery_and_actual_success(
    proof, monkeypatch, mutation
):
    names = [name for name, _ in proof.module["CASES"]]
    markers = dict(proof.module["CASES"])
    calls = []

    def fake_run(arguments, _timeout):
        calls.append(arguments)
        if arguments[1] == "--list":
            assert _timeout == 30
            listing = [f"{name}: test" for name in names]
            if mutation == "missing-list":
                listing.pop()
            if mutation == "duplicate-list":
                listing.append(listing[-1])
            return SimpleNamespace(stdout="\n".join(listing), stderr="", returncode=0)
        name = arguments[1]
        assert _timeout == 600
        marker = markers[name]
        if mutation == "missing-marker":
            marker = ""
        elif mutation == "duplicate-marker":
            marker *= 2
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored;"
        if mutation == "ignored":
            summary = "test result: ok. 0 passed; 0 failed; 1 ignored;"
        elif mutation == "failed":
            summary = "test result: FAILED. 0 passed; 1 failed; 0 ignored;"
        return SimpleNamespace(
            stdout=f"{marker}\n{summary}\n",
            stderr="",
            returncode=1 if mutation == "nonzero" else 0,
        )

    monkeypatch.setitem(proof.module["run"].__globals__, "run_case", fake_run)
    with pytest.raises(ValueError):
        proof.module["run"](proof.executable)
    assert not proof.evidence.exists()
    assert calls[0] == [str(proof.executable), "--list"]


def test_verified_proof_is_bound_to_executable_source_run_and_tier(proof, monkeypatch):
    cases = proof.module["CASES"]
    calls = []

    def fake_run(arguments, _timeout):
        calls.append(arguments)
        if arguments[1] == "--list":
            assert _timeout == 30
            return SimpleNamespace(
                stdout="\n".join(f"{name}: test" for name, _ in cases),
                stderr="",
                returncode=0,
            )
        marker = dict(cases)[arguments[1]]
        assert _timeout == 600
        return SimpleNamespace(
            stdout=f"test {arguments[1]} ... {marker}\nok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setitem(proof.module["run"].__globals__, "run_case", fake_run)
    proof.module["run"](proof.executable)
    assert proof.module["verify"](proof.executable)
    assert len(calls) == 3
    assert all("--exact" in call and "--test-threads=1" in call for call in calls[1:])
    record = json.loads(proof.evidence.read_text(encoding="ascii"))
    assert (
        record["composition_sha256"]
        == hashlib.sha256(proof.executable.read_bytes()).hexdigest()
    )
    for name, changed in (
        ("GITHUB_RUN_ID", "other"),
        ("GITHUB_RUN_ATTEMPT", "3"),
        ("GITHUB_JOB", "other-job"),
        ("GITHUB_SHA", "b" * 40),
        ("MARTY_CANVAS_FULL_QUALIFICATION", "1"),
    ):
        with monkeypatch.context() as temporary:
            temporary.setenv(name, changed)
            assert not proof.module["verify"](proof.executable)
    proof.executable.write_bytes(b"different executable")
    assert not proof.module["verify"](proof.executable)
    proof.executable.write_bytes(b"synthetic unique executable")
    for invalid in ("{}", "not-json", json.dumps({**record, "cases": []})):
        proof.evidence.write_text(invalid, encoding="ascii")
        assert not proof.module["verify"](proof.executable)
    proof.evidence.write_text(json.dumps({**record, "schema": True}), encoding="ascii")
    assert not proof.module["verify"](proof.executable)


def test_failed_rerun_removes_prior_evidence(proof, monkeypatch):
    proof.evidence.write_text("stale", encoding="ascii")
    monkeypatch.setitem(
        proof.module["run"].__globals__,
        "run_case",
        lambda *_args: SimpleNamespace(stdout="", stderr="", returncode=0),
    )
    with pytest.raises(ValueError):
        proof.module["run"](proof.executable)
    assert not proof.evidence.exists()


def test_opt_in_is_required_before_any_child_can_claim_completion(proof, monkeypatch):
    monkeypatch.delenv("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST")
    with pytest.raises(ValueError, match="opt-in is required"):
        proof.module["run"](proof.executable)
    assert not proof.evidence.exists()


@pytest.mark.parametrize("timeout", [False, True])
def test_whole_child_is_reaped_and_timeout_never_records_proof(
    proof, monkeypatch, timeout
):
    events = []

    class FakeOwnedProcess:
        def __init__(self, command, *, stdout, stderr):
            assert command == [str(proof.executable), "--list"]
            assert stderr == subprocess.STDOUT
            self.output = stdout
            events.append("start")

        def wait(self, *, timeout):
            assert timeout == 30
            events.append("wait")
            if timeout_case:
                raise subprocess.TimeoutExpired("owned child", timeout)
            self.output.write(b"one: test\n")
            return 0

        def cleanup(self, *, timeout):
            assert timeout == 10
            events.append("cleanup")

    timeout_case = timeout
    monkeypatch.setattr(proof.module["sys"], "platform", "linux")
    monkeypatch.setitem(
        proof.module["run_case"].__globals__, "OwnedProcess", FakeOwnedProcess
    )
    if timeout:
        with pytest.raises(ValueError, match="deadline"):
            proof.module["run_case"]([str(proof.executable), "--list"], 30)
    else:
        result = proof.module["run_case"]([str(proof.executable), "--list"], 30)
        assert result.stdout == "one: test\n"
        assert result.returncode == 0
    assert events == ["start", "wait", "cleanup"]
    assert not proof.evidence.exists()


@pytest.mark.parametrize(
    "mutation", ["duplicate", "harness", "other-package", "missing"]
)
def test_artifact_selector_requires_one_real_composition_test(
    proof, tmp_path, mutation
):
    artifact = {
        "reason": "compiler-artifact",
        "package_id": "path+file:///checkout/rust/crates/canvas-acceptance#marty-canvas-acceptance@0.1.0",
        "target": {"name": "canvas_published_schema_contract", "kind": ["test"]},
        "profile": {"test": True},
        "executable": str(proof.executable),
    }
    artifacts = tmp_path / "artifacts.json"
    if mutation == "duplicate":
        rows = [artifact, artifact]
    elif mutation == "harness":
        rows = [{**artifact, "profile": {"test": False}}]
    elif mutation == "other-package":
        rows = [{**artifact, "package_id": "#other@0.1.0"}]
    elif mutation == "missing":
        rows = [{**artifact, "executable": str(tmp_path / "missing")}]
    artifacts.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    with pytest.raises(ValueError):
        proof.module["executable_from_artifacts"](artifacts)
    artifacts.write_text(json.dumps(artifact), encoding="utf-8")
    assert proof.module["executable_from_artifacts"](artifacts) == proof.executable
