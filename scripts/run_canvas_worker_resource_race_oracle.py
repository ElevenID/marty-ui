"""Published resource changes during actual provider I/O; no running-job edits."""

import json
from pathlib import Path
import signal

from sqlalchemy import create_engine

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_provider_recovery_oracle import scalar, wait_for
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix = json.loads(
        (contracts / "canvas-worker-resource-race-scenarios.json").read_text()
    )
    matching = [case for case in matrix["cases"] if case["name"] == case_name]
    assert len(matching) == 1
    case = matching[0]
    spec = json.loads((contracts / matrix["reference_scenario"]).read_text())
    spec["jobs_sql"] = json.loads((contracts / matrix["retry_scenario"]).read_text())[
        "jobs_sql"
    ]
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    child = None
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)

            def observe():
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                return state

            https.stage = {**matrix["response"], "hold_response": True}
            child = start_worker(worker_case(https.origin, https.cert), "worker-rest")
            wait_for(
                https.received.is_set,
                15,
                "actual resource-race provider request",
                child,
            )
            before = observe()
            original = scalar(engine, matrix["job_row_sql"])
            assert len(before["jobs"]) == 1 and original["attempt_count"] == 1
            assert original["status"] == "leased" and before["facts"] == []
            with engine.begin() as connection:
                for statement in case["mutation"]:
                    assert connection.exec_driver_sql(statement).rowcount == 1
            changed_resources = scalar(engine, matrix["resource_sql"])
            assert scalar(engine, matrix["job_row_sql"]) == original
            https.release.set()

            def completed():
                state = observe()
                if state["heartbeat"]["metadata"]["phase"] == "idle" and state["jobs"][
                    0
                ]["status"] in {"retry", "dead_letter"}:
                    return state
                return None

            after = wait_for(completed, 20, "durable resource-race outcome", child)
            job = after["jobs"][0]
            assert len(after["jobs"]) == 1 and job["attempt_count"] == 1
            assert job["last_error_code"] == case["code"]
            assert job["status"] == ("retry" if case["retryable"] else "dead_letter")
            assert after["facts"] == [] and len(https.requests) == 1
            final_resources = scalar(engine, matrix["resource_sql"])
            terminal = scalar(engine, matrix["job_row_sql"])
            assert terminal["id"] == original["id"]
            child.send_signal(signal.SIGINT)
            exit_code = child.wait(timeout=10)
            assert observe() == after
            assert scalar(engine, matrix["job_row_sql"]) == terminal
            assert scalar(engine, matrix["resource_sql"]) == final_resources
            return {
                "schema": "marty.canvas-worker-resource-race-oracle/v1",
                "source_sha256": worker_source_sha256(),
                "case": case_name,
                "before": before,
                "changed_resources": changed_resources,
                "after": after,
                "final_resources": final_resources,
                "same_job": True,
                "unchanged_after_exit": True,
                "requests": list(https.requests),
                "exit_code_after_interrupt": exit_code,
            }
        finally:
            https.release.set()
            if child is not None:
                finish_worker(child)
            engine.dispose()
