"""Bind current startup capture inputs, without claiming historical qualification."""

import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-startup-current-inputs.json"
STARTUP = "run_canvas_worker_startup_oracle.py"


def _startup_inputs(graph: dict) -> set[str]:
    """Expand the bounded #1121 source graph from the startup capture entrypoint."""
    pending = [STARTUP]
    scripts = set()
    while pending:
        script = pending.pop()
        if script in scripts:
            continue
        assert script in graph["direct_imports"], f"Unreviewed startup script: {script}"
        scripts.add(script)
        pending.extend(graph["direct_imports"][script])
        pending.extend(graph["launched_scripts"].get(script, []))
    scenarios = {
        scenario
        for script in scripts
        for scenario in graph["scenario_literals"].get(script, [])
    }
    assert not any(script in graph["scenario_templates"] for script in scripts), (
        "Review dynamic startup scenario paths"
    )
    return {f"scripts/{script}" for script in scripts} | {
        f"contracts/{scenario}" for scenario in scenarios
    }


def _normalized_sha256(path: Path) -> str:
    normalized = path.read_text(encoding="utf-8").replace("\r\n", "\n").replace(
        "\r", "\n"
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _assert_current_inputs(evidence: dict, graph: dict, root: Path) -> None:
    assert evidence["schema"] == "marty.canvas-worker-startup-current-inputs/v1"
    assert set(evidence) == {"schema", "purpose", "normalization", "sha256"}
    assert "not attest the historical startup corpus" in evidence["purpose"]
    assert evidence["normalization"] == (
        "UTF-8 text with CRLF and CR converted to LF before SHA-256"
    )
    expected = _startup_inputs(graph)
    assert set(evidence["sha256"]) == expected, (
        "Startup script, local imports, children, and scenarios need input review"
    )
    for name, pinned in evidence["sha256"].items():
        assert Path(name).as_posix() == name and ".." not in Path(name).parts
        assert len(pinned) == 64 and all(c in "0123456789abcdef" for c in pinned)
        assert _normalized_sha256(root / name) == pinned, f"Startup input drift: {name}"


def test_current_startup_capture_inputs_match_explicit_hashes() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    _assert_current_inputs(evidence, graph, ROOT)
    assert graph["direct_imports"][STARTUP] == [], (
        "New directly imported helpers require hash evidence"
    )


@pytest.mark.parametrize(
    "name",
    [
        "scripts/run_canvas_worker_startup_oracle.py",
        "scripts/run_canvas_worker_single_cycle.py",
        "contracts/canvas-worker-startup-scenarios.json",
    ],
)
def test_each_startup_input_change_invalidates_evidence(tmp_path: Path, name: str) -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="Startup input drift"):
        _assert_current_inputs(evidence, graph, tmp_path)


def test_new_direct_helper_requires_input_evidence() -> None:
    graph = json.loads(GRAPH.read_text(encoding="utf-8"))
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    graph["direct_imports"][STARTUP] = ["new_local_helper.py"]
    graph["direct_imports"]["new_local_helper.py"] = []
    with pytest.raises(AssertionError, match="need input review"):
        _assert_current_inputs(evidence, graph, ROOT)


def test_text_hash_is_independent_of_checkout_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "line-endings.txt"
    path.write_bytes(b"first\nsecond\n")
    expected = _normalized_sha256(path)
    path.write_bytes(b"first\r\nsecond\r\n")
    assert _normalized_sha256(path) == expected
    path.write_bytes(b"first\rsecond\r")
    assert _normalized_sha256(path) == expected
