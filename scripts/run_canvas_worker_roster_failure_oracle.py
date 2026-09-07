"""Actual published worker roster failures, sharing the REST process owner."""

import json
from pathlib import Path

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_rest_oracle import run_scenarios
from run_canvas_worker_startup_oracle import DATABASE


def run(case_name):
    contracts = Path("/verification/contracts")
    spec = json.loads(
        (contracts / "canvas-worker-roster-failure-scenarios.json").read_text()
    )
    matching = [case for case in spec["cases"] if case["name"] == case_name]
    assert len(matching) == 1
    case = matching[0]
    base = json.loads((contracts / spec["reference_scenario"]).read_text())
    retry = json.loads((contracts / spec["retry_scenario"]).read_text())
    shared = json.loads((contracts / base["shared_seed"]).read_text())
    prepared = {
        **base,
        "jobs_sql": retry["jobs_sql"],
        "post_oauth_seed": [*spec["seed"], *case["seed"]],
        "stages": [case],
        "oracle_schema": "marty.canvas-worker-roster-failure-oracle/v1",
    }
    with WorkerHttpsFixture() as https:
        result = run_scenarios(prepared, shared, https)
    observation = result["observations"][0]
    assert len(observation["requests"]) == case["expected_requests"]
    assert observation["facts"] == []
    assert len(observation["jobs"]) == 1
    job = observation["jobs"][0]
    assert job["attempt_count"] == 1
    assert job["status"] == ("retry" if case["retryable"] else "dead_letter")
    assert job["last_error_code"] == case["code"]
    assert not job["lease_owner_present"] and not job["lease_expires_present"]
    if case["retryable"]:
        assert job["retry_scheduled"] and job["retry_delay_within_backoff_bounds"]
    engine = create_engine(DATABASE, hide_parameters=True)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT id FROM issuance_service.canvas_evidence_sync_jobs")
                ).scalar_one()
                == "worker-roster-failure-job"
            )
            result["target"] = connection.execute(text(spec["target_sql"])).scalar_one()
        assert result["target"]["enabled"] == case["retryable"]
        assert result["target"]["metadata"] == {
            "roster_cursor": 1,
            "synthetic_marker": "preserve",
            "worker_id": "worker-rest",
        }
        assert result["target"]["heartbeat_timestamp_present"] is True
        assert result["target"]["candidate_count"] == 0
        assert result["target"]["last_success_present"] is False
        return result
    finally:
        engine.dispose()
