"""Guard the reviewed native REST replay inputs, not historical capture."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_input_pins,
    normalized_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts/canvas-worker-rest-current-inputs.json"
INPUTS = frozenset(
    {
        "contracts/canvas-issued-review-scenarios.json",
        "contracts/canvas-worker-rest-oracle.json",
        "contracts/canvas-worker-rest-scenarios.json",
        "contracts/fixtures/canvas_worker_test_trust.py",
        "rust/services/issuance/tests/support/canvas_worker_rest_replay.rs",
        "rust/services/issuance/tests/support/remote_integration_secret.rs",
        "scripts/canvas_worker_https_fixture.py",
        "scripts/prepare_canvas_published_schema.py",
        "scripts/test_canvas_lti_https.py",
        "scripts/test_canvas_worker_rest_https.py",
    }
)


def _assert_native_rest_inputs(evidence: dict, root: Path) -> None:
    assert_current_input_pins(
        evidence,
        root,
        schema="marty.canvas-worker-rest-current-inputs/v2",
        label="REST",
        disclaimer="native REST replay",
        expected_inputs=INPUTS,
    )
    scenarios = json.loads(
        (root / "contracts/canvas-worker-rest-scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    assert scenarios["shared_seed"] == "canvas-issued-review-scenarios.json", (
        "REST shared seed needs input review"
    )
    assert [stage["name"] for stage in scenarios["stages"]] == [
        "initial_permit",
        "deny_after_issue",
        "duplicate_deny",
        "rate_limit_preserves_evidence",
    ]


def test_native_rest_replay_inputs_match_explicit_hashes() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    _assert_native_rest_inputs(evidence, ROOT)


@pytest.mark.parametrize("name", sorted(INPUTS))
def test_each_rest_input_change_invalidates_evidence(tmp_path: Path, name: str) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in INPUTS:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="REST input drift"):
        _assert_native_rest_inputs(evidence, tmp_path)


def test_unreviewed_or_missing_rest_pin_is_rejected() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    evidence["sha256"].pop(next(iter(INPUTS)))
    with pytest.raises(AssertionError, match="REST input set needs review"):
        _assert_native_rest_inputs(evidence, ROOT)
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    evidence["sha256"]["scripts/unreviewed.py"] = "a" * 64
    with pytest.raises(AssertionError, match="REST input set needs review"):
        _assert_native_rest_inputs(evidence, ROOT)


def test_shared_seed_change_requires_review(tmp_path: Path) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in INPUTS:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    scenario = tmp_path / "contracts/canvas-worker-rest-scenarios.json"
    data = json.loads(scenario.read_text(encoding="utf-8"))
    data["shared_seed"] = "canvas-worker-startup-scenarios.json"
    scenario.write_text(json.dumps(data), encoding="utf-8")
    evidence["sha256"]["contracts/canvas-worker-rest-scenarios.json"] = normalized_sha256(
        scenario
    )
    with pytest.raises(AssertionError, match="REST shared seed needs input review"):
        _assert_native_rest_inputs(evidence, tmp_path)
