"""Guard current Retry-After capture inputs without authenticating the frozen corpus."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_inputs,
    normalized_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-retry-after-current-inputs.json"
RETRY_AFTER = "run_canvas_worker_retry_after_oracle.py"


def _inputs() -> tuple[dict, dict]:
    return (
        json.loads(EVIDENCE.read_text(encoding="utf-8")),
        json.loads(GRAPH.read_text(encoding="utf-8")),
    )


def _assert_retry_after_inputs(evidence: dict, graph: dict, root: Path) -> None:
    assert_current_inputs(
        evidence,
        graph,
        root,
        entrypoint=RETRY_AFTER,
        schema="marty.canvas-worker-retry-after-current-inputs/v1",
        label="Retry-After",
        disclaimer="do not attest the historical Retry-After corpus",
    )
    retry_after = json.loads(
        (root / "contracts/canvas-worker-retry-after-scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    assert retry_after["reference_scenario"] == "canvas-worker-rest-scenarios.json", (
        "Retry-After reference scenario changed; review the selected capture input"
    )
    rest = json.loads(
        (root / "contracts/canvas-worker-rest-scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    assert rest["shared_seed"] == "canvas-issued-review-scenarios.json", (
        "Retry-After shared seed changed; review the selected capture input"
    )


def _copy_inputs(tmp_path: Path, evidence: dict) -> None:
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())


def test_current_retry_after_inputs_match_exact_closure() -> None:
    evidence, graph = _inputs()
    _assert_retry_after_inputs(evidence, graph, ROOT)
    assert len(evidence["sha256"]) == 10
    assert graph["scenario_literals"][RETRY_AFTER] == [
        "canvas-worker-retry-after-scenarios.json"
    ]


@pytest.mark.parametrize("name", json.loads(EVIDENCE.read_text())["sha256"])
def test_each_input_change_invalidates_evidence(tmp_path: Path, name: str) -> None:
    evidence, graph = _inputs()
    _copy_inputs(tmp_path, evidence)
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="Retry-After input drift"):
        _assert_retry_after_inputs(evidence, graph, tmp_path)


@pytest.mark.parametrize("field", ["reference_scenario", "shared_seed"])
def test_transitive_reference_change_requires_review(
    tmp_path: Path, field: str
) -> None:
    evidence, graph = _inputs()
    _copy_inputs(tmp_path, evidence)
    source = (
        "canvas-worker-retry-after-scenarios.json"
        if field == "reference_scenario"
        else "canvas-worker-rest-scenarios.json"
    )
    scenario = tmp_path / "contracts" / source
    data = json.loads(scenario.read_text(encoding="utf-8"))
    data[field] = "canvas-worker-new-scenarios.json"
    scenario.write_text(json.dumps(data), encoding="utf-8")
    # Even after a reviewed hash update, the new transitive input is missing.
    evidence["sha256"][f"contracts/{source}"] = normalized_sha256(scenario)
    with pytest.raises(AssertionError, match="Missing capture scenario input"):
        _assert_retry_after_inputs(evidence, graph, tmp_path)


def test_new_local_helper_requires_input_review() -> None:
    evidence, graph = _inputs()
    graph["direct_imports"][RETRY_AFTER].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        _assert_retry_after_inputs(evidence, graph, ROOT)


def test_new_process_child_requires_input_review() -> None:
    evidence, graph = _inputs()
    graph["launched_scripts"][RETRY_AFTER] = ["new_child.py"]
    graph["direct_imports"]["new_child.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        _assert_retry_after_inputs(evidence, graph, ROOT)


def test_existing_pinned_reference_swap_still_requires_review(tmp_path: Path) -> None:
    evidence, graph = _inputs()
    _copy_inputs(tmp_path, evidence)
    scenario = tmp_path / "contracts/canvas-worker-retry-after-scenarios.json"
    data = json.loads(scenario.read_text(encoding="utf-8"))
    data["reference_scenario"] = "canvas-worker-startup-scenarios.json"
    scenario.write_text(json.dumps(data), encoding="utf-8")
    evidence["sha256"]["contracts/canvas-worker-retry-after-scenarios.json"] = (
        normalized_sha256(scenario)
    )
    with pytest.raises(AssertionError, match="Retry-After reference scenario changed"):
        _assert_retry_after_inputs(evidence, graph, tmp_path)


def test_new_scenario_requires_input_review() -> None:
    evidence, graph = _inputs()
    graph["scenario_literals"][RETRY_AFTER].append("canvas-worker-new-scenarios.json")
    with pytest.raises(AssertionError, match="Missing capture scenario input"):
        _assert_retry_after_inputs(evidence, graph, ROOT)
