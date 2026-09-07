"""Coverage accounting for the actual-process validation corpus, not runtime proof."""

import json
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_global_processor_inventory_is_disjoint_exhaustive_and_reference_backed():
    def read(name):
        return json.loads((ROOT / "contracts" / name).read_text())

    audit = read("canvas-worker-processor-coverage.json")
    contract = read(audit["normative_contract"])
    required = {
        item["code"]: item["retryable"]
        for item in contract["processor_dispatch"]["stable_outcomes"]
    }
    assert len(required) == 17
    observed = {}
    owners = {}

    def record(job, *, corpus, code, retryable):
        assert job["last_error_code"] == code
        # A corpus can exercise several inputs for the same outcome; categories
        # must remain disjoint and every repeated outcome must agree on status.
        assert owners.get(code, corpus) == corpus
        assert observed.get(code, job["status"]) == job["status"]
        assert isinstance(retryable, bool)
        assert required[code] in (retryable, "provider-defined")
        assert job["status"] == ("retry" if retryable else "dead_letter")
        observed[code] = job["status"]
        owners[code] = corpus

    validation = audit["actual_process"]["validation"]
    reference = read(validation["reference"])
    for case in read(validation["scenarios"])["cases"]:
        if case.get("boundary") != validation["boundary"]:
            continue
        observation = reference[case["name"]]["observations"][0]
        assert observation["name"] == case["name"]
        assert observation["requests"] == []
        assert len(observation["jobs"]) == 1
        job = observation["jobs"][0]
        record(
            job,
            corpus="validation",
            code=case["code"],
            retryable=required[case["code"]],
        )
    assert len(observed) == 5

    retry = audit["actual_process"]["retry"]
    stages = {item["name"]: item for item in read(retry["reference"])["observations"]}
    assert len(retry["stages"]) == 2
    for name in retry["stages"]:
        stage = stages[name]
        assert stage["requests"]
        job = stage["jobs"][-1]
        code = job["last_error_code"]
        record(job, corpus="retry", code=code, retryable=required[code])
    assert len(observed) == 7

    roster = audit["actual_process"]["roster_failure"]
    reference = read(roster["reference"])
    additional = []
    for case in read(roster["scenarios"])["cases"]:
        result = reference[case["name"]]
        assert len(result["observations"]) == 1
        observation = result["observations"][0]
        assert observation["name"] == case["name"]
        assert len(observation["requests"]) == case["expected_requests"]
        assert len(observation["jobs"]) == 1
        job = observation["jobs"][0]
        if case["code"] == roster["additional_worker_code"]:
            assert case["code"] not in required
            assert job["last_error_code"] == case["code"]
            assert job["status"] == "retry" and case["retryable"] is True
            additional.append(case["code"])
        else:
            record(
                job,
                corpus="roster_failure",
                code=case["code"],
                retryable=case["retryable"],
            )
    assert additional == [roster["additional_worker_code"]]
    assert len(observed) == 11

    groups = [set(observed)]
    for name, count in [
        ("controlled_worker_cycle", 1),
        ("typed_dispatch_reconciliation", 2),
        ("remaining_composed_outcomes", 3),
    ]:
        group = set(audit[name])
        assert len(group) == len(audit[name]) == count
        assert all(not group & earlier for earlier in groups)
        groups.append(group)
    assert set.union(*groups) == set(required)
    assert audit["controlled_worker_cycle"] == ["canvas_background_signing_forbidden"]
    assert audit["typed_dispatch_reconciliation"] == [
        "canvas_sync_processor_unavailable",
        "canvas_sync_processor_contract_invalid",
    ]
    # This only protects test registration; hosted execution is separate evidence.
    registered = (
        ROOT / "rust/services/issuance/tests/canvas_sync_worker_postgres_contract.rs"
    ).read_text()
    assert (
        "canvas_worker_signing_guard::assert_signing_guard(&pool).await;" in registered
    )


def test_native_validation_matrix_uses_separate_children_and_no_expected_reads(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-native-executable", "validation")
    assert len(calls) == len({call[4]["name"] for call in calls}) == 20
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
        assert spec["stages"][0].get("environment", {}) == case.get("environment", {})
        if "reference_race" in case:
            assert spec["stages"][0]["reference_race"] == case["reference_race"]
            assert reference["observations"][0]["reference_race"] == {
                "blocked_before_release": True,
                "referenced_row_absent": True,
            }


@pytest.mark.parametrize(
    ("boundary", "remaining_key", "errors_key"),
    [
        ("target_validation", "remaining_validation_errors", "errors"),
        ("processor_dispatch", "remaining_processor_errors", "stable_outcomes"),
    ],
)
def test_every_error_is_covered_or_explicitly_remaining(
    boundary, remaining_key, errors_key
):
    spec = json.loads(
        (ROOT / "contracts/canvas-worker-validation-scenarios.json").read_text()
    )
    contract = json.loads(
        (ROOT / "contracts/issuance-canvas-sync-worker.json").read_text()
    )
    required = {error["code"] for error in contract[boundary][errors_key]}
    covered = {
        case["code"]
        for case in spec["cases"]
        if case.get("boundary", "target_validation") == boundary
    }
    remaining = set(spec[remaining_key])
    assert not covered & remaining
    assert covered | remaining == required
    assert len(spec["cases"]) == len({case["name"] for case in spec["cases"]}) == 20
    assert len(remaining) == (0 if boundary == "target_validation" else 12)
    assert all(
        case.get("boundary", "target_validation")
        in {"target_validation", "processor_dispatch"}
        for case in spec["cases"]
    )
    assert (
        sum(case["code"] == "canvas_sync_target_inactive" for case in spec["cases"])
        == 5
    )
    for case in spec["cases"]:
        assert set(case.get("environment", {})) <= {
            "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE",
            "CANVAS_BACKGROUND_ROSTER_MAX_SIZE",
        }
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
    assert len(races) == 3
    for case, table, update, identity in zip(
        races,
        ["application_templates", "applications", "canvas_award_candidates"],
        [
            "UPDATE issuance_service.applications SET application_template_id='template-review' WHERE id='application-review'",
            "UPDATE issuance_service.canvas_evidence_sync_targets SET application_id=NULL WHERE id='target-review'",
            "UPDATE issuance_service.canvas_evidence_sync_targets SET candidate_id=NULL WHERE id='target-review'",
        ],
        ["template-race", "application-race", "candidate-race"],
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
            update,
            f"DELETE FROM issuance_service.{table} WHERE id='{identity}' AND organization_id='org-review'",
        ]
        assert (
            race["absent_sql"]
            == f"SELECT NOT EXISTS (SELECT 1 FROM issuance_service.{table} WHERE id='{identity}')"
        )
