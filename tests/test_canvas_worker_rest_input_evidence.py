"""Guard current shared REST capture inputs, not historical qualification."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_inputs,
    normalized_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-rest-current-inputs.json"
REST = "run_canvas_worker_rest_oracle.py"
MOUNTED_INPUTS = frozenset(
    {
        "scripts/prepare_canvas_published_schema.py",
        "contracts/fixtures/canvas_worker_test_trust.py",
    }
)


def _assert_rest_inputs(evidence: dict, graph: dict, root: Path) -> None:
    assert_current_inputs(
        evidence,
        graph,
        root,
        entrypoint=REST,
        schema="marty.canvas-worker-rest-current-inputs/v1",
        label="REST",
        disclaimer="do not attest historical REST or downstream corpora",
        additional_inputs=MOUNTED_INPUTS,
    )


def test_current_rest_capture_inputs_match_explicit_hashes() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    _assert_rest_inputs(evidence, graph, ROOT)
    assert len(evidence["sha256"]) == 10
    assert MOUNTED_INPUTS <= set(evidence["sha256"])
    assert graph["direct_imports"][REST] == [
        "canvas_worker_https_fixture.py",
        "run_canvas_worker_startup_oracle.py",
    ]


@pytest.mark.parametrize(
    "name",
    json.loads(EVIDENCE.read_text(encoding="utf-8"))["sha256"],
)
def test_each_rest_input_change_invalidates_evidence(tmp_path: Path, name: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="REST input drift"):
        _assert_rest_inputs(evidence, graph, tmp_path)


@pytest.mark.parametrize("name", sorted(MOUNTED_INPUTS))
def test_mounted_rest_runtime_pin_cannot_disappear(name: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    del evidence["sha256"][name]
    with pytest.raises(AssertionError, match="need input review"):
        _assert_rest_inputs(evidence, graph, ROOT)


def test_new_rest_helper_requires_input_review() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["direct_imports"][REST].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        _assert_rest_inputs(evidence, graph, ROOT)


def test_new_rest_scenario_requires_input_review() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["scenario_literals"][REST].append("canvas-worker-new-scenarios.json")
    with pytest.raises(AssertionError, match="Missing capture scenario input"):
        _assert_rest_inputs(evidence, graph, ROOT)


def test_default_rest_shared_seed_change_requires_input_review(tmp_path: Path) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    scenario = tmp_path / "contracts/canvas-worker-rest-scenarios.json"
    data = json.loads(scenario.read_text(encoding="utf-8"))
    assert data["shared_seed"] == "canvas-issued-review-scenarios.json"
    data["shared_seed"] = "canvas-worker-startup-scenarios.json"
    scenario.write_text(json.dumps(data), encoding="utf-8")
    # Simulate a reviewed byte-pin update: the changed dependency graph must
    # still reject removal of the previously pinned shared seed.
    evidence["sha256"]["contracts/canvas-worker-rest-scenarios.json"] = (
        normalized_sha256(scenario)
    )
    with pytest.raises(AssertionError, match="need input review"):
        _assert_rest_inputs(evidence, graph, tmp_path)


def test_dynamic_scenario_path_requires_review() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["scenario_templates"][REST] = ["canvas-worker-{kind}-scenarios.json"]
    with pytest.raises(AssertionError, match="Review dynamic capture scenario paths"):
        _assert_rest_inputs(evidence, graph, ROOT)
