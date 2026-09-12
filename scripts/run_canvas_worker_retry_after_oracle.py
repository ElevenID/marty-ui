"""Actual provider Retry-After parsing carried through durable job scheduling."""

from email.utils import parsedate_to_datetime
import json
from pathlib import Path

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_rest_oracle import run_scenarios
from run_canvas_worker_startup_oracle import DATABASE


def run(case_name):
    contracts = Path("/verification/contracts")
    spec = json.loads(
        (contracts / "canvas-worker-retry-after-scenarios.json").read_text()
    )
    matches = [case for case in spec["cases"] if case["name"] == case_name]
    assert len(matches) == 1
    case = matches[0]
    base = json.loads((contracts / spec["reference_scenario"]).read_text())
    stage = {**case, "status": 429, "body": {"error": "synthetic-rate-limit"}}
    prepared = {
        **base,
        "stages": [stage],
        "oracle_schema": "marty.canvas-worker-retry-after-oracle/v1",
    }
    shared = json.loads((contracts / base["shared_seed"]).read_text())
    with WorkerHttpsFixture() as https:
        result = run_scenarios(prepared, shared, https)
        observation = result["observations"][0]
        assert len(observation["requests"]) == len(observation["jobs"]) == 1
        assert observation["jobs"][0]["status"] == "retry"
        assert observation["jobs"][0]["attempt_count"] == 1
        assert observation["facts"] == []
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            with engine.connect() as connection:
                if case["timing"] == "http_date":
                    assert len(https.retry_after_dates) == 1
                    retry_at = parsedate_to_datetime(https.retry_after_dates[0])
                    valid = connection.execute(
                        text(
                            "SELECT abs(extract(epoch FROM available_at-:retry_at))<=1.1 "
                            "FROM issuance_service.canvas_evidence_sync_jobs"
                        ),
                        {"retry_at": retry_at},
                    ).scalar_one()
                else:
                    assert case["timing"] == "bounds"
                    minimum, maximum = case["delay_bounds"]
                    assert type(minimum) is int and type(maximum) is int
                    assert 0 <= minimum <= maximum <= 86400
                    valid = connection.execute(
                        text(
                            "SELECT extract(epoch FROM available_at-updated_at) BETWEEN :minimum AND :maximum "
                            "FROM issuance_service.canvas_evidence_sync_jobs"
                        ),
                        {"minimum": minimum - 0.1, "maximum": maximum + 0.1},
                    ).scalar_one()
                assert valid, f"Persisted Retry-After timing mismatch: {case_name}"
            result["retry_timing"] = {"kind": case["timing"], "matches": True}
            return result
        finally:
            engine.dispose()
