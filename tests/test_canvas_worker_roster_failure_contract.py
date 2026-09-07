"""Fixture/registration controls; actual native Linux execution is a separate gate."""

import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def read(suffix):
    return json.loads(
        (ROOT / f"contracts/canvas-worker-roster-failure-{suffix}.json").read_text()
    )


def test_frozen_roster_failures_keep_distinct_side_effects():
    spec, reference = read("scenarios"), read("oracle")
    assert len(spec["cases"]) == len(reference) == 5
    assert {case["name"] for case in spec["cases"]} == set(reference)
    for case in spec["cases"]:
        result = reference[case["name"]]
        assert result["schema"] == "marty.canvas-worker-roster-failure-oracle/v1"
        assert len(result["observations"]) == 1
        observation = result["observations"][0]
        assert observation["name"] == case["name"]
        assert len(observation["requests"]) == case["expected_requests"]
        assert observation["facts"] == []
        assert observation["exit_code_after_interrupt"] == -2
        assert len(observation["jobs"]) == 1
        job = observation["jobs"][0]
        assert job["last_error_code"] == case["code"]
        assert job["status"] == ("retry" if case["retryable"] else "dead_letter")
        assert job["attempt_count"] == 1
        assert job["max_attempts"] == (8 if case["retryable"] else 1)
        assert not job["lease_owner_present"] and not job["lease_expires_present"]
        assert job["result"] == {}
        if case["retryable"]:
            assert job["retry_delay_within_backoff_bounds"] and job["retry_scheduled"]
        assert result["target"] == {
            "candidate_count": 0,
            "config_version": 1,
            "enabled": case["retryable"],
            "heartbeat_timestamp_present": True,
            "last_success_present": False,
            "metadata": {
                "roster_cursor": 1,
                "synthetic_marker": "preserve",
                "worker_id": "worker-rest",
            },
        }
        # The published AGS-only path looks up OAuth even with no NRPS URL.
        assert observation["oauth"]["secret_used"] == (
            case["name"] != "roster_oauth_unavailable"
        )
    assert reference["nrps_context_unavailable"]["observations"][0]["requests"] == []
    assert (
        reference["roster_http_status_failed"]["observations"][0]["jobs"][0][
            "last_error_summary"
        ]
        == "Canvas synchronization failed (HTTPException)"
    )


def test_roster_qualification_is_exact_head_and_keeps_unrelated_gates_open():
    audit = json.loads(
        (ROOT / "contracts/canvas-worker-processor-coverage.json").read_text()
    )
    roster = audit["actual_process"]["roster_failure"]
    assert "roster_failure" not in audit["pending_process_qualification"]
    assert roster["scenarios"] == "canvas-worker-roster-failure-scenarios.json"
    assert roster["reference"] == "canvas-worker-roster-failure-oracle.json"
    # Protect the recorded hosted evidence, not a claim of runtime execution here.
    assert roster["qualification"] == {
        "commit": "5dde6b69adbca467d7fefaa1b43bc2b77ac4aa19",
        "ci_run_id": 34085691302,
        "runtime_job_id": 101629197299,
        "configured_tests": 109,
        "configured_duration_seconds": 2361.53,
        "configured_result_timestamp_utc": "2026-09-07T05:56:08Z",
        "worker_postgres_tests": 4,
        "worker_postgres_duration_seconds": 96.28,
    }
    codes = {case["code"] for case in read("scenarios")["cases"]}
    assert roster["additional_worker_code"] == "canvas_sync_unexpected_error"
    assert roster["additional_worker_code"] in codes
    assert len(codes - {roster["additional_worker_code"]}) == 4
    assert not codes & set(audit["remaining_composed_outcomes"])
    assert set(audit["remaining_composed_outcomes"]) == {
        "canvas_platform_reconfigured",
        "canvas_application_unavailable",
        "canvas_sync_resources_unavailable",
    }


def test_native_roster_matrix_retains_declared_responses_and_separate_children(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-native-executable", "roster-failure")
    assert len(calls) == len({call[4]["name"] for call in calls}) == 5
    for executable, scenario, spec, reference, case in calls:
        assert executable == "synthetic-native-executable"
        assert scenario == "roster-failure"
        assert spec["stages"] == [case]
        assert reference["observations"][0]["name"] == case["name"]
    assert calls[2][2]["stages"][0]["body"] == [
        {"id": "11"},
        {"id": "12"},
        {"id": "13"},
    ]
    assert calls[-1][2]["stages"][0]["status"] == 503


def test_roster_fixture_only_changes_exact_initial_rows():
    spec = read("scenarios")
    assert len(spec["seed"]) == 2
    assert "'worker-roster-failure-job'" in spec["seed"][1]
    for statement in [
        spec["seed"][0],
        *(s for case in spec["cases"] for s in case["seed"]),
    ]:
        assert statement.startswith("UPDATE issuance_service.")
        assert any(
            statement.endswith(f"WHERE id='{identity}'")
            for identity in (
                "target-review",
                "worker-rest-connection",
                "binding-review",
            )
        )
        assert "canvas_evidence_sync_jobs" not in statement
        assert all(
            word not in statement.upper()
            for word in (
                "ALTER ",
                "DROP ",
                "DELETE ",
                "TRUNCATE ",
                "LEASE_",
                "CLOCK_TIMESTAMP",
            )
        )


@pytest.mark.parametrize("scenario", ["unknown-roster", "roster-failure/unknown"])
def test_native_matrix_rejects_unknown_scenarios_before_start(monkeypatch, scenario):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    with pytest.raises(AssertionError):
        native.run("must-not-start", scenario)
