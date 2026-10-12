"""Guard current REST-dependent capture inputs, not historical observations."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import assert_current_inputs


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-rest-dependent-current-inputs.json"
REST_EVIDENCE = ROOT / "contracts/canvas-worker-rest-current-inputs.json"
PRODUCERS = (
    "run_canvas_worker_provider_signals_oracle.py",
    "run_canvas_worker_roster_failure_oracle.py",
    "run_canvas_worker_validation_oracle.py",
)
SCENARIOS = (
    "canvas-worker-provider-signals-scenarios.json",
    "canvas-worker-roster-failure-scenarios.json",
    "canvas-worker-validation-scenarios.json",
)
MOUNTED_INPUTS = frozenset(
    {
        "scripts/prepare_canvas_published_schema.py",
        "contracts/fixtures/canvas_worker_test_trust.py",
    }
)


def check_inputs(evidence: dict, rest: dict, graph: dict, root: Path) -> None:
    assert set(evidence) == {
        "schema", "purpose", "normalization", "inherited_inputs", "sha256"
    }
    assert evidence["inherited_inputs"] == "contracts/canvas-worker-rest-current-inputs.json"
    assert evidence["normalization"] == rest["normalization"]
    assert set(evidence["sha256"]) == {
        *(f"contracts/{scenario}" for scenario in SCENARIOS),
        "contracts/canvas-worker-retry-scenarios.json",
        *(f"scripts/{producer}" for producer in PRODUCERS),
    }
    assert not (set(evidence["sha256"]) & set(rest["sha256"]))
    assert_current_inputs(
        rest,
        graph,
        root,
        entrypoint="run_canvas_worker_rest_oracle.py",
        schema="marty.canvas-worker-rest-current-inputs/v1",
        label="REST",
        disclaimer="do not attest historical REST or downstream corpora",
        additional_inputs=MOUNTED_INPUTS,
    )
    combined = {key: evidence[key] for key in ("schema", "purpose", "normalization")}
    combined["sha256"] = rest["sha256"] | evidence["sha256"]
    assert_current_inputs(
        combined,
        graph,
        root,
        entrypoint=PRODUCERS,
        schema="marty.canvas-worker-rest-dependent-current-inputs/v1",
        label="REST-dependent producers",
        disclaimer="do not attest historical corpora",
        additional_inputs=MOUNTED_INPUTS,
    )


def test_current_rest_dependent_capture_inputs_match_explicit_hashes() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rest = json.loads(REST_EVIDENCE.read_text(encoding="utf-8"))
    check_inputs(evidence, rest, graph, ROOT)
    assert len(rest["sha256"]) == 10
    assert len(evidence["sha256"]) == 7
    for producer, scenario in zip(PRODUCERS, SCENARIOS, strict=True):
        assert graph["direct_imports"][producer] == [
            "canvas_worker_https_fixture.py",
            "run_canvas_worker_rest_oracle.py",
            "run_canvas_worker_startup_oracle.py",
        ]
        assert graph["scenario_literals"][producer] == [scenario]


@pytest.mark.parametrize("name", json.loads(EVIDENCE.read_text(encoding="utf-8"))["sha256"])
def test_each_dependent_input_change_invalidates_evidence(tmp_path: Path, name: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rest = json.loads(REST_EVIDENCE.read_text(encoding="utf-8"))
    for source in rest["sha256"] | evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="REST-dependent producers input drift"):
        check_inputs(evidence, rest, graph, tmp_path)


def test_inherited_rest_change_invalidates_dependent_evidence(tmp_path: Path) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rest = json.loads(REST_EVIDENCE.read_text(encoding="utf-8"))
    for source in rest["sha256"] | evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / "scripts/run_canvas_worker_rest_oracle.py"
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="REST input drift"):
        check_inputs(evidence, rest, graph, tmp_path)


@pytest.mark.parametrize("producer", PRODUCERS)
def test_new_dependent_helper_requires_input_review(producer: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rest = json.loads(REST_EVIDENCE.read_text(encoding="utf-8"))
    graph["direct_imports"][producer].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        check_inputs(evidence, rest, graph, ROOT)


@pytest.mark.parametrize("producer", PRODUCERS)
def test_new_dependent_scenario_requires_input_review(producer: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rest = json.loads(REST_EVIDENCE.read_text(encoding="utf-8"))
    graph["scenario_literals"][producer].append("canvas-worker-other-scenarios.json")
    with pytest.raises(AssertionError):
        check_inputs(evidence, rest, graph, ROOT)
