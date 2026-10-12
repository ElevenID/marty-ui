"""Guard current provider-signals capture inputs after Rust-only retirement."""

import json
from pathlib import Path

import pytest

from scripts.ci.canvas_oracle_current_inputs import assert_current_inputs


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-provider-signals-current-inputs.json"
PRODUCER = "run_canvas_worker_provider_signals_oracle.py"
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
        entrypoint=PRODUCER,
        schema="marty.canvas-worker-provider-signals-current-inputs/v1",
        label="provider-signals",
        disclaimer="do not attest historical corpora",
        additional_inputs=MOUNTED_INPUTS,
    )


def test_current_provider_signals_inputs_match_exact_closure() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    check_inputs(evidence, graph, ROOT)
    assert len(evidence["sha256"]) == 12
    assert graph["direct_imports"][PRODUCER] == [
        "canvas_worker_https_fixture.py",
        "run_canvas_worker_rest_oracle.py",
        "run_canvas_worker_startup_oracle.py",
    ]
    assert graph["scenario_literals"][PRODUCER] == [
        "canvas-worker-provider-signals-scenarios.json"
    ]


def test_provider_signals_source_drift_fails(tmp_path: Path) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / "scripts/run_canvas_worker_provider_signals_oracle.py"
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="provider-signals input drift"):
        check_inputs(evidence, graph, tmp_path)


def test_new_provider_signals_helper_needs_review() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["direct_imports"][PRODUCER].append("new_local_helper.py")
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        check_inputs(evidence, graph, ROOT)


def test_new_provider_signals_scenario_needs_review() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["scenario_literals"][PRODUCER].append("new-scenarios.json")
    with pytest.raises(AssertionError, match="Missing capture scenario input"):
        check_inputs(evidence, graph, ROOT)
