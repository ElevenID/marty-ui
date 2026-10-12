"""Guard current timeout capture inputs, not historical observations."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import assert_current_inputs


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-timeout-current-inputs.json"
PRODUCERS = (
    "run_canvas_worker_timeout_oracle.py",
    "run_canvas_worker_body_timeout_oracle.py",
)
MOUNTED_INPUTS = frozenset(
    {
        "scripts/prepare_canvas_published_schema.py",
        "contracts/fixtures/canvas_worker_test_trust.py",
    }
)


def check_inputs(evidence: dict, graph: dict, root: Path) -> None:
    assert_current_inputs(
        evidence,
        graph,
        root,
        entrypoint=PRODUCERS,
        schema="marty.canvas-worker-timeout-current-inputs/v1",
        label="timeout producers",
        disclaimer="do not attest historical corpora",
        additional_inputs=MOUNTED_INPUTS,
    )


def test_current_timeout_capture_inputs_match_explicit_hashes() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    check_inputs(evidence, graph, ROOT)
    assert len(evidence["sha256"]) == 27
    assert MOUNTED_INPUTS <= set(evidence["sha256"])
    assert graph["scenario_literals"][PRODUCERS[0]] == [
        "canvas-worker-timeout-scenarios.json"
    ]
    assert (
        "canvas-worker-body-timeout-scenarios.json"
        in graph["scenario_literals"][PRODUCERS[1]]
    )


@pytest.mark.parametrize(
    "name", json.loads(EVIDENCE.read_text(encoding="utf-8"))["sha256"]
)
def test_each_timeout_input_change_invalidates_evidence(
    tmp_path: Path, name: str
) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="timeout producers input drift"):
        check_inputs(evidence, graph, tmp_path)


@pytest.mark.parametrize("producer", PRODUCERS)
def test_new_timeout_helper_requires_input_review(producer: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["direct_imports"][producer].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        check_inputs(evidence, graph, ROOT)


@pytest.mark.parametrize("producer", PRODUCERS)
def test_new_timeout_scenario_requires_input_review(producer: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["scenario_literals"][producer].append("canvas-worker-new-scenarios.json")
    with pytest.raises(AssertionError, match="Missing capture scenario input"):
        check_inputs(evidence, graph, ROOT)


def test_mounted_timeout_input_cannot_disappear() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    del evidence["sha256"]["scripts/prepare_canvas_published_schema.py"]
    with pytest.raises(AssertionError, match="need input review"):
        check_inputs(evidence, graph, ROOT)
