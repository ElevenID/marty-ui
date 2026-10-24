"""Frozen logging corpus and its native Rust owner."""

import json
from pathlib import Path


def test_frozen_logging_corpus_has_native_owner_and_all_declared_inputs():
    root = Path(__file__).resolve().parents[1]
    contracts = root / "contracts"
    reference = json.loads(
        (contracts / "canvas-worker-logging-oracle.json").read_text()
    )
    scenarios = json.loads(
        (contracts / "canvas-worker-logging-scenarios.json").read_text()
    )
    startup = json.loads((contracts / "canvas-worker-startup-oracle.json").read_text())
    assert reference["source_sha256"] == startup["source_sha256"]["issuance.canvas_worker"]
    assert [case["input"] for case in reference["cases"]] == scenarios["levels"]
    assert len(reference["cases"]) == 16
    assert sum("error_class" in case["observed"] for case in reference["cases"]) == 7
    worker = (root / "rust/services/issuance/src/bin/canvas_sync_worker.rs").read_text()
    process = (
        root / "rust/services/issuance/tests/support/canvas_worker_logging_contract.rs"
    ).read_text()
    assert "fn deployed_log_level_matches_frozen_published_thresholds()" in worker
    assert "contracts/canvas-worker-logging-oracle.json" in worker
    assert "fn invalid_log_level_process_failure_does_not_echo_operator_value()" in process
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "python3 scripts/test_canvas_worker_logging_reference.py" not in workflow
    assert "cargo test --locked --workspace" in workflow
    dockerfile = (root / "rust/services/Dockerfile.ci").read_text(encoding="utf-8")
    issuance = dockerfile.split("FROM runtime AS issuance\n", 1)[1].split(
        "FROM runtime AS gateway\n", 1
    )[0]
    assert "RUST_LOG=" not in issuance, "image defaults must not mask deployed LOG_LEVEL"
    assert "RUST_LOG=" not in (root / "services/Dockerfile").read_text(encoding="utf-8")
