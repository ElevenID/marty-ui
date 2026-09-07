"""Actual terminal completion/reclaimer overlap; retain published differences."""

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
    finish_workers,
    start_worker,
    worker_source_sha256,
)


def run():
    contracts = Path("/verification/contracts")
    case = json.loads(
        (contracts / "canvas-worker-provider-completion-scenarios.json").read_text()
    )
    spec = json.loads((contracts / case["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    history = json.loads((contracts / case["history_scenario"]).read_text())
    workers = {}
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            with engine.begin() as connection:
                connection.exec_driver_sql(history["initial_job_seed"])
                for statement in case["setup"]:
                    connection.exec_driver_sql(statement)
            worker_input = worker_case(
                https.origin,
                https.cert,
                {"CANVAS_SYNC_WORKER_LEASE_SECONDS": str(case["lease_seconds"])},
            )
            https.stage = {**spec["stages"][0], "hold_response": True}

            def all_alive():
                assert all(child.poll() is None for child in workers.values())

            def observe():
                all_alive()
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                return state

            with engine.begin() as barrier:
                barrier.exec_driver_sql(case["barrier_sql"])
                workers["worker-rest"] = start_worker(worker_input, "worker-rest")
                child = workers["worker-rest"]
                wait_for(https.received.is_set, 15, "actual provider request", child)
                before = observe()
                original = scalar(engine, case["job_row_sql"])
                assert before["jobs"][0]["status"] == "leased"
                assert original["attempt_count"] == 8
                assert before["facts"] == []
                https.release.set()
                wait_for(
                    lambda: scalar(engine, case["terminal_wait_sql"]),
                    15,
                    "actual terminal write barrier",
                    child,
                )
                pending = observe()
                assert pending["jobs"] == before["jobs"]
                assert len(pending["facts"]) == 1
                assert scalar(engine, case["journal_sql"]) == []
                wait_for(
                    lambda: scalar(
                        engine,
                        "SELECT lease_expires_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id='worker-final-job'",
                    ),
                    35,
                    "real lease expiry",
                    child,
                )
                # A distinct synthetic database identity prevents the owner's
                # concurrent renewal query from impersonating this reclaimer.
                assert not scalar(engine, case["reclaimer_wait_sql"])
                reclaimer_input = {
                    **worker_input,
                    "environment": {
                        **worker_input["environment"],
                        "DATABASE_URL": DATABASE.replace(
                            "postgresql:", "postgresql+asyncpg:", 1
                        ).replace(
                            "oracle:synthetic-local-only@",
                            "synthetic_reclaimer:synthetic-reclaimer-local-only@",
                            1,
                        ),
                    },
                }
                workers["worker-contender"] = start_worker(
                    reclaimer_input, "worker-contender"
                )
                wait_for(
                    lambda: scalar(engine, case["reclaimer_wait_sql"]),
                    15,
                    "actual published reclaimer blocked by completion",
                    workers["worker-contender"],
                )
                all_alive()
                assert observe() == pending
                assert scalar(engine, case["journal_sql"]) == []

            def both_idle():
                all_alive()
                return scalar(
                    engine,
                    "SELECT count(*)=2 AND bool_and(metadata->>'phase'='idle') FROM issuance_service.canvas_worker_heartbeats",
                )

            wait_for(both_idle, 20, "both actual workers idle")
            completed = observe()
            terminal = scalar(engine, case["job_row_sql"])
            target = scalar(engine, case["target_row_sql"])
            journal = scalar(engine, case["journal_sql"])
            assert journal == ["succeeded"]
            assert terminal["status"] == "succeeded"
            assert terminal["attempt_count"] == 8
            for key in ("id", "started_at", "created_at"):
                assert terminal[key] == original[key]
            assert len(https.requests) == 1
            exits = []
            for child in workers.values():
                child.send_signal(signal.SIGINT)
                exits.append(child.wait(timeout=10))
            assert exits == [-2, -2]
            assert scalar(engine, case["job_row_sql"]) == terminal
            assert scalar(engine, case["target_row_sql"]) == target
            assert scalar(engine, case["journal_sql"]) == journal
            return {
                "schema": "marty.canvas-worker-provider-completion-oracle/v1",
                "case": "completion",
                "before": before,
                "terminal_pending": pending,
                "completed": completed,
                "reclaimer_blocked_by_completion": True,
                "terminal_journal": journal,
                "target_enabled": target["enabled"],
                "target_success_timestamp_present": target["last_succeeded_at"]
                is not None,
                "same_job_and_original_start": True,
                "both_workers_alive_after_completion": True,
                "exit_codes_after_interrupt": exits,
                "rows_unchanged_after_exit": True,
                "requests": list(https.requests),
                "source_sha256": worker_source_sha256(),
            }
        finally:
            try:
                finish_workers(workers)
            finally:
                engine.dispose()
