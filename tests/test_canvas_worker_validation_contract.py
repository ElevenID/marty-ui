"""Coverage accounting for the actual-process validation corpus, not runtime proof."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_every_validation_error_is_covered_or_explicitly_remaining():
    spec = json.loads(
        (ROOT / "contracts/canvas-worker-validation-scenarios.json").read_text()
    )
    contract = json.loads(
        (ROOT / "contracts/issuance-canvas-sync-worker.json").read_text()
    )
    # Find the normative validation block rather than maintain a second code list.
    blocks = [
        value
        for value in contract.values()
        if isinstance(value, dict) and "errors" in value
    ]
    validation = next(
        block
        for block in blocks
        if any(
            error.get("code") == "canvas_sync_target_incomplete"
            for error in block["errors"]
        )
    )
    required = {error["code"] for error in validation["errors"]}
    covered = {case["code"] for case in spec["cases"]}
    remaining = set(spec["remaining_validation_errors"])
    assert not covered & remaining
    assert covered | remaining == required
    assert len(spec["cases"]) == len({case["name"] for case in spec["cases"]}) == 11
    assert (
        sum(case["code"] == "canvas_sync_target_inactive" for case in spec["cases"])
        == 5
    )
    for case in spec["cases"]:
        assert case["seed"]
        for statement in case["seed"]:
            assert statement.startswith(
                ("UPDATE issuance_service.", "INSERT INTO issuance_service.")
            )
            assert all(
                word not in statement.upper()
                for word in ("ALTER ", "DROP ", "TRUNCATE ", "DELETE ")
            )
            assert "canvas_evidence_sync_jobs" not in statement
    assert spec["initial_job_seed"].startswith(
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs "
    )
