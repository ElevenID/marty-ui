"""Transport controls for immediate qualification; Rust owns outcome acceptance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts import official_review_gate as gate

SOURCE = "a" * 40
HARNESS = "b" * 40
RUN = 17
LANES = ["oid4vci-issuer", "oid4vp-final", "oid4vp-url-query", "oid4vp-mdoc", "haip", "w3c-v2", "eudi"]


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class Fixture:
    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.args = argparse.Namespace(
            validator=Path("validator-unit-fixture"), manifest=directory / "manifest.json",
            snapshot=directory / "snapshot", output=directory / "gate.json",
            source=SOURCE, harness=HARNESS, run_id=RUN, current_attempt=1,
        )
        self.args.manifest.write_bytes(b"transport-unit-fixture-manifest\n")
        self.args.snapshot.mkdir()
        (self.args.snapshot / "stack-manifest.json").write_bytes(self.args.manifest.read_bytes())
        (self.args.snapshot / "origin-attempt.txt").write_bytes(b"1\n")
        self.set_plan(1)
        self.clock = Clock()
        self.mains = [SOURCE]
        self.api_calls: list[str] = []
        self.validator_calls: list[tuple[list[str], dict]] = []
        self.branch_error: Exception | None = None
        self.validator_error: Exception | None = None
        self.branch_mutator = lambda value: None
        self.gate_mutator = lambda value: None
        self.after_validation = lambda: None
        owner = self

        class GitHub:
            def api(self, path: str) -> bytes:
                assert path == "branches/main", "qualification must never request a review record"
                owner.api_calls.append(path)
                if owner.branch_error is not None:
                    raise owner.branch_error
                main = owner.mains.pop(0) if len(owner.mains) > 1 else owner.mains[0]
                value = {"name": "main", "protected": True, "commit": {"sha": main}}
                owner.branch_mutator(value)
                return encoded(value)

            def review_record(self, *_args, **_kwargs):
                raise AssertionError("manual review records must never be read")

            def fetch_main(self, *_args, **_kwargs):
                raise AssertionError("qualification needs no review-history fetch")

        self.github = GitHub()
        for key, value in {
            "GITHUB_REPOSITORY": gate.REPOSITORY, "GITHUB_REPOSITORY_ID": gate.REPOSITORY_ID,
            "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": SOURCE,
            "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_dispatch",
        }.items():
            monkeypatch.setenv(key, value)
        monkeypatch.setattr(gate, "command", self.validator)
        monkeypatch.setattr(gate.time, "sleep", lambda *_args: pytest.fail("qualification must not wait for a person"))

    def set_plan(self, count: int) -> None:
        self.plan = encoded({"pending": [{"transport_fixture_only": index} for index in range(count)],
                             "release_qualified": False})
        (self.args.snapshot / "assessment.json").write_bytes(self.plan)

    def result(self) -> bytes:
        value = {"schema": "marty.official-release-gate/v2", "source_sha": SOURCE,
                 "harness_sha": HARNESS, "manifest_sha256": digest(self.args.manifest.read_bytes()),
                 "run_id": RUN, "qualification_context": "PRE_PUBLICATION_CANDIDATE",
                 "lanes": [{"lane": lane, "summary_sha256": "sha256:" + "e" * 64} for lane in LANES],
                 "automated_qualification": {
                     "schema": "marty.automated-official-qualification/v1",
                     "policy": "marty.official-verifier-outcome/v1", "evidence_run_attempt": 1,
                     "request_sha256": digest(self.plan), "automated_cases": len(json.loads(self.plan)["pending"]),
                     "original_official_results_unchanged": True,
                 }}
        self.gate_mutator(value)
        return encoded(value)

    def validator(self, arguments: list[str], **kwargs) -> bytes:
        self.validator_calls.append((arguments, kwargs))
        assert arguments[0] == "validator-unit-fixture"
        assert arguments[-2:] == ["1", str(self.args.snapshot / "official-summaries")]
        assert 0 < kwargs["timeout"] <= min(120, gate.QUALIFICATION_TIMEOUT_SECONDS - self.clock.now)
        if arguments[1] == "--prepare-review":
            return self.plan
        assert arguments[1] == "--automated"
        if self.validator_error is not None:
            raise self.validator_error
        self.after_validation()
        return self.result()

    def qualify(self) -> None:
        gate.qualify(self.args, self.github, clock=self.clock)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    return Fixture(tmp_path, monkeypatch)


@pytest.mark.parametrize("pending", [0, 1, 13])
def test_qualification_is_immediate_and_keeps_the_original_source(fixture, pending) -> None:
    fixture.set_plan(pending)
    fixture.qualify()
    assert fixture.args.output.read_bytes() == fixture.result()
    assert fixture.args.output.stat().st_mode & 0o777 == 0o600
    assert fixture.api_calls == ["branches/main", "branches/main"]
    assert [arguments[1] for arguments, _ in fixture.validator_calls] == ["--prepare-review", "--automated"]
    assert fixture.clock.now == 0
    receipt = json.loads(fixture.args.output.read_bytes())
    assert receipt["source_sha"] == SOURCE
    assert "review_disposition" not in receipt


def test_local_review_record_cannot_authorize_or_change_the_result(fixture, tmp_path) -> None:
    legacy = tmp_path / "official-review-authorization"
    legacy.mkdir()
    record = legacy / "record.json"
    record.write_bytes(b'{"verdict":"accepted","reviewer":{"kind":"human"}}')
    before = record.read_bytes()
    fixture.validator_error = ValueError("unsupported automated obligation")
    with pytest.raises(ValueError, match="unsupported automated obligation"):
        fixture.qualify()
    assert not fixture.args.output.exists()
    assert record.read_bytes() == before
    assert fixture.api_calls == ["branches/main"]


@pytest.mark.parametrize("manual", [False, True])
def test_historical_v1_receipts_cannot_enter_automated_production(fixture, manual) -> None:
    def legacy(value):
        value["schema"] = "marty.official-release-gate/v1"
        value.pop("automated_qualification")
        if manual:
            value["review_disposition"] = {"verdict": "accepted"}
    fixture.gate_mutator = legacy
    with pytest.raises(ValueError, match="automated v2"):
        fixture.qualify()
    assert not fixture.args.output.exists()


@pytest.mark.parametrize("changed", ["before", "after"])
def test_protected_main_cannot_move_during_qualification(fixture, changed) -> None:
    fixture.mains = ["c" * 40] if changed == "before" else [SOURCE, "c" * 40]
    with pytest.raises(ValueError, match="protected main"):
        fixture.qualify()
    assert not fixture.args.output.exists()
    assert len(fixture.validator_calls) == (1 if changed == "before" else 2)


@pytest.mark.parametrize("protected", [False, None, "true"])
def test_unprotected_main_fails_before_automated_validation(fixture, protected) -> None:
    fixture.branch_mutator = lambda value: value.update(protected=protected)
    with pytest.raises(ValueError, match="protected main"):
        fixture.qualify()
    assert fixture.api_calls == ["branches/main"]
    assert len(fixture.validator_calls) == 1
    assert not fixture.args.output.exists()


def test_api_failure_is_an_immediate_failure(fixture) -> None:
    fixture.branch_error = ValueError("transport unavailable")
    with pytest.raises(ValueError, match="transport unavailable"):
        fixture.qualify()
    assert fixture.api_calls == ["branches/main"]
    assert not fixture.args.output.exists()


def test_expiration_during_validation_refuses_output_and_final_api(fixture) -> None:
    fixture.after_validation = lambda: setattr(fixture.clock, "now", gate.QUALIFICATION_TIMEOUT_SECONDS)
    with pytest.raises(ValueError, match="deadline"):
        fixture.qualify()
    assert fixture.api_calls == ["branches/main"]
    assert not fixture.args.output.exists()


def test_later_attempt_refuses_before_any_api_or_validation(fixture, monkeypatch) -> None:
    fixture.args.current_attempt = 2
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    with pytest.raises(ValueError, match="original protected-main dispatch attempt"):
        fixture.qualify()
    assert not fixture.api_calls and not fixture.validator_calls


@pytest.mark.parametrize("key,value", [
    ("GITHUB_REPOSITORY", "other/repository"), ("GITHUB_REPOSITORY_ID", "1"),
    ("GITHUB_REF", "refs/heads/other"), ("GITHUB_SHA", "c" * 40),
    ("GITHUB_EVENT_NAME", "pull_request"),
])
def test_foreign_dispatch_context_refuses_before_work(fixture, monkeypatch, key, value) -> None:
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        fixture.qualify()
    assert not fixture.api_calls and not fixture.validator_calls


def test_preexisting_output_is_never_overwritten(fixture) -> None:
    fixture.args.output.write_bytes(b"existing")
    with pytest.raises(ValueError, match="already exists"):
        fixture.qualify()
    assert fixture.args.output.read_bytes() == b"existing"
    assert not fixture.api_calls and not fixture.validator_calls


@pytest.mark.parametrize("field,value", [
    ("source_sha", "c" * 40), ("harness_sha", "c" * 40),
    ("manifest_sha256", "sha256:" + "f" * 64), ("run_id", RUN + 1),
])
def test_returned_candidate_identity_must_match(fixture, field, value) -> None:
    fixture.gate_mutator = lambda receipt: receipt.update({field: value})
    with pytest.raises(ValueError):
        fixture.qualify()
    assert not fixture.args.output.exists()


@pytest.mark.parametrize("field,value", [
    ("policy", "other-policy"), ("request_sha256", "sha256:" + "f" * 64),
    ("automated_cases", 0), ("automated_cases", True), ("evidence_run_attempt", 2),
    ("original_official_results_unchanged", False),
])
def test_returned_assessment_must_match_the_complete_frozen_input(fixture, field, value) -> None:
    fixture.gate_mutator = lambda receipt: receipt["automated_qualification"].update({field: value})
    with pytest.raises(ValueError):
        fixture.qualify()
    assert not fixture.args.output.exists()


def test_remaining_time_caps_each_transport_command(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(gate, "command", lambda arguments, **kwargs: calls.append((arguments, kwargs)) or b"{}")
    github = gate.GitHub()
    github.deadline, github.clock = 8, lambda: 5
    github.api("branches/main")
    assert calls[0][1] == {"timeout": 3}
    github.clock = lambda: 8
    with pytest.raises(ValueError, match="deadline"):
        github.api("branches/main")
    assert len(calls) == 1


def test_process_error_details_are_not_exposed(monkeypatch) -> None:
    monkeypatch.setattr(gate.subprocess, "run", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 1, b"private-response", b"private-token"))
    with pytest.raises(ValueError, match="^official evidence transport or Rust validation failed$"):
        gate.command(["unit-fixture"])


@pytest.mark.parametrize("timeout", [0, -1, True, "1", float("nan"), float("inf")])
def test_invalid_command_deadlines_refuse_before_spawn(monkeypatch, timeout) -> None:
    monkeypatch.setattr(gate.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("must not spawn"))
    with pytest.raises(ValueError, match="remaining time"):
        gate.completed(["unit-fixture"], timeout=timeout)
