"""Bind current startup capture inputs, without claiming historical qualification."""

import json
from pathlib import Path

import pytest
import yaml

from scripts.ci.canvas_oracle_current_inputs import (
    assert_current_inputs,
    normalized_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
GRAPH = ROOT / "contracts/canvas-worker-oracle-script-imports.json"
EVIDENCE = ROOT / "contracts/canvas-worker-startup-current-inputs.json"
STARTUP = "run_canvas_worker_startup_oracle.py"


def _assert_current_inputs(evidence: dict, graph: dict, root: Path) -> None:
    assert_current_inputs(
        evidence,
        graph,
        root,
        entrypoint=STARTUP,
        schema="marty.canvas-worker-startup-current-inputs/v1",
        label="Startup",
        disclaimer="not attest the historical startup corpus",
    )


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
def test_each_startup_input_change_invalidates_evidence(
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
    expected = normalized_sha256(path)
    path.write_bytes(b"first\r\nsecond\r\n")
    assert normalized_sha256(path) == expected
    path.write_bytes(b"first\rsecond\r")
    assert normalized_sha256(path) == expected


def test_fresh_attestation_upload_requires_successful_full_main_canvas_job() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["test-rust-services"]["steps"]
    uploads = [
        step
        for step in steps
        if step.get("name") == "Preserve fresh full-main startup attestation"
    ]
    assert len(uploads) == 1
    upload = uploads[0]
    assert upload["if"] == (
        "success() && matrix.lane == 'canvas' && "
        "env.MARTY_CANVAS_FULL_QUALIFICATION == '1' && github.ref == 'refs/heads/main'"
    )
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["retention-days"] == 14
    assert "${{ github.run_id }}-${{ github.run_attempt }}" in upload["with"]["name"]
    source = (
        ROOT / "rust/crates/canvas-acceptance/tests/canvas_published_worker_contract.rs"
    ).read_text(encoding="utf-8")
    startup_test = source.split(
        "async fn worker_startup_matches_published_process_and_idle_heartbeat()", 1
    )[1].split("\n}\n", 1)[0]
    assert "canvas_worker_process_signals::worker_executable()" in startup_test
    assert startup_test.index("worker_binary_before") < startup_test.index("::replay(")
    assert startup_test.index("assert_eq!(") < startup_test.index("::replay(")
    assert startup_test.index("::replay(") < startup_test.index(
        "owned.close().unwrap();"
    )
    assert startup_test.index("owned.close().unwrap();") < startup_test.index(
        "emit_after_startup_pass("
    )
    attester = (
        ROOT
        / "rust/crates/canvas-acceptance/tests/support/canvas_startup_attestation.rs"
    ).read_text(encoding="utf-8")
    assert '"worker_binary_sha256": worker_binary_sha' in attester
    assert (
        "verified_worker_binary_sha(worker_binary, worker_binary_before, &resolved)"
        in attester
    )
    assert "persist_verified_evidence(root, &output, &run, || {" in attester
    verified_write = attester.split("fn persist_verified_evidence(", 1)[1].split(
        "\nfn persist_evidence(", 1
    )[0]
    assert verified_write.index("verify_checkout_identity(root, run);") < verified_write.index(
        "persist_evidence(output, &evidence());"
    )
