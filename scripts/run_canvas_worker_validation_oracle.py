"""Actual worker validation/processor failures and owned reference-removal races."""

import json
from pathlib import Path

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_rest_oracle import run_scenarios
from run_canvas_worker_startup_oracle import DATABASE


def run(case_name):
    contracts = Path("/verification/contracts")
    spec = json.loads(
        (contracts / "canvas-worker-validation-scenarios.json").read_text()
    )
    cases = [case for case in spec["cases"] if case["name"] == case_name]
    assert len(cases) == 1
    case = cases[0]
    base = json.loads((contracts / spec["reference_scenario"]).read_text())
    shared = json.loads((contracts / base["shared_seed"]).read_text())
    shared["seed"] = [*shared["seed"], *case["seed"], spec["initial_job_seed"]]
    prepared = {
        **base,
        "stages": [{**case, "status": 500, "body": {}}],
        "oracle_schema": "marty.canvas-worker-validation-oracle/v1",
    }
    with WorkerHttpsFixture() as https:
        result = run_scenarios(prepared, shared, https)
        observation = result["observations"][0]
        assert observation["requests"] == observation["facts"] == []
        assert len(observation["jobs"]) == 1
        job = observation["jobs"][0]
        assert job["attempt_count"] == 1 and job["status"] == "dead_letter"
        assert job["last_error_code"] == case["code"]
        assert observation["oauth"]["secret_used"] is False
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            with engine.connect() as connection:
                assert (
                    connection.execute(
                        text(
                            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs"
                        )
                    ).scalar_one()
                    == "worker-validation-job"
                )
                result["target"] = connection.execute(
                    text(
                        "SELECT jsonb_build_object('enabled',enabled,'config_version',config_version) "
                        "FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'"
                    )
                ).scalar_one()
            assert "synthetic-prohibited-material" not in json.dumps(result)
            return result
        finally:
            engine.dispose()
