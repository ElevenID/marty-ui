"""Coverage accounting for the actual-process validation corpus, not runtime proof."""

import json
import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_native_validation_matrix_uses_separate_children_and_no_expected_reads(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-native-executable", "validation")
    assert len(calls) == len({call[4]["name"] for call in calls}) == 13
    for executable, scenario, spec, reference, case in calls:
        assert executable == "synthetic-native-executable" and scenario == "validation"
        assert len(spec["stages"]) == len(reference["observations"]) == 1
        assert (
            spec["stages"][0]["name"]
            == reference["observations"][0]["name"]
            == case["name"]
        )
        assert reference["observations"][0]["requests"] == []
        assert (
            reference["observations"][0]["jobs"][0]["last_error_code"] == case["code"]
        )
        assert reference["target"]["enabled"] is False
        if "reference_race" in case:
            assert spec["stages"][0]["reference_race"] == case["reference_race"]
            assert reference["observations"][0]["reference_race"] == {
                "blocked_before_release": True,
                "referenced_row_absent": True,
            }


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
    assert len(spec["cases"]) == len({case["name"] for case in spec["cases"]}) == 13
    assert remaining == set()
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


def test_reference_races_remove_only_exact_fixture_rows_without_weakening_constraints():
    spec = json.loads(
        (ROOT / "contracts/canvas-worker-validation-scenarios.json").read_text()
    )
    races = [case for case in spec["cases"] if "reference_race" in case]
    assert len(races) == 2
    for case, table, column, identity in zip(
        races,
        ["applications", "canvas_award_candidates"],
        ["application_id", "candidate_id"],
        ["application-race", "candidate-race"],
        strict=True,
    ):
        race = case["reference_race"]
        assert (
            race["barrier_sql"]
            == f"LOCK TABLE issuance_service.{table} IN ACCESS EXCLUSIVE MODE"
        )
        assert "wait_event_type='Lock'" in race["blocked_sql"]
        assert f"%SELECT%FROM issuance_service.{table}%" in race["blocked_sql"]
        assert race["release_sql"] == [
            f"UPDATE issuance_service.canvas_evidence_sync_targets SET {column}=NULL WHERE id='target-review'",
            f"DELETE FROM issuance_service.{table} WHERE id='{identity}' AND organization_id='org-review'",
        ]
        assert (
            race["absent_sql"]
            == f"SELECT NOT EXISTS (SELECT 1 FROM issuance_service.{table} WHERE id='{identity}')"
        )
