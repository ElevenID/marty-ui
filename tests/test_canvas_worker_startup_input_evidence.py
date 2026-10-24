"""Bind current startup capture inputs, without claiming historical qualification."""

import json
from pathlib import Path

import pytest
import yaml

from scripts.ci.canvas_oracle_current_inputs import normalized_sha256

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts/canvas-worker-startup-current-inputs.json"
INPUTS = {
    "contracts/canvas-worker-startup-expected.json",
    "contracts/canvas-worker-startup-scenarios.json",
    "rust/services/issuance/tests/support/canvas_worker_startup_replay.rs",
}


def _assert_current_inputs(evidence: dict, root: Path) -> None:
    assert evidence["schema"] == "marty.canvas-worker-startup-current-inputs/v2"
    assert "native startup replay" in evidence["purpose"]
    assert set(evidence["sha256"]) == INPUTS
    for name, pinned in evidence["sha256"].items():
        assert normalized_sha256(root / name) == pinned, f"Startup input drift: {name}"


def test_current_startup_capture_inputs_match_explicit_hashes() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    _assert_current_inputs(evidence, ROOT)


@pytest.mark.parametrize(
    "name",
    [
        "contracts/canvas-worker-startup-expected.json",
        "rust/services/issuance/tests/support/canvas_worker_startup_replay.rs",
        "contracts/canvas-worker-startup-scenarios.json",
    ],
)
def test_each_startup_input_change_invalidates_evidence(
    tmp_path: Path, name: str
) -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for source in evidence["sha256"]:
        target = tmp_path / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / source).read_bytes())
    target = tmp_path / name
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    with pytest.raises(AssertionError, match="Startup input drift"):
        _assert_current_inputs(evidence, tmp_path)


def test_extra_input_pin_requires_review() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    evidence["sha256"]["scripts/unreviewed.py"] = "0" * 64
    with pytest.raises(AssertionError):
        _assert_current_inputs(evidence, ROOT)


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
        ROOT / "rust/crates/canvas-worker-acceptance/tests/canvas_published_worker_contract.rs"
    ).read_text(encoding="utf-8")
    startup_test = source.split(
        "async fn worker_startup_matches_published_process_and_idle_heartbeat()", 1
    )[1].split("\n}\n", 1)[0]
    assert "canvas_worker_process_signals::worker_executable()" in startup_test
    assert "PublishedDatabase::start()" in startup_test
    assert "start_with_worker_startup" not in startup_test
    assert "canvas-worker-startup-oracle.json" not in startup_test
    assert startup_test.index("worker_binary_before") < startup_test.index("::replay(")
    assert startup_test.index("::replay(") < startup_test.index(
        "owned.close().unwrap();"
    )
    assert startup_test.index("owned.close().unwrap();") < startup_test.index(
        "emit_after_startup_pass("
    )
    attester = (
        ROOT
        / "rust/crates/canvas-worker-acceptance/tests/support/canvas_startup_attestation.rs"
    ).read_text(encoding="utf-8")
    assert '"marty.canvas-worker-startup-fresh-run/v2"' in attester
    assert "observed_python" not in attester
    assert "canvas-worker-startup-oracle.json" not in attester
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
