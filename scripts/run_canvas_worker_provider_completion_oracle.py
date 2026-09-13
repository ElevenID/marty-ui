"""Actual terminal completion/reclaimer overlap; retain published differences."""

import json
from pathlib import Path
import signal

from sqlalchemy import create_engine, text

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


def run(scenario="canvas-worker-provider-completion-scenarios.json"):
    contracts = Path("/verification/contracts")
    case = json.loads((contracts / scenario).read_text())
    if "extends" in case:
        case = {**json.loads((contracts / case["extends"]).read_text()), **case}
    assert case["case"] in {"completion", "recovery_first"}
    recovery_first = case["case"] == "recovery_first"
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

            def wait_expiry():
                wait_for(
                    lambda: scalar(
                        engine,
                        "SELECT lease_expires_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id='worker-final-job'",
                    ),
                    35,
                    "real lease expiry",
                    workers["worker-rest"],
                )

            def start_contender():
                # Identity excludes the original worker's blocked renewal.
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

            extra = {}

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
                if recovery_first:
                    with engine.begin() as owner_barrier:
                        owner_barrier.exec_driver_sql(case["owner_barrier_sql"])
                        with engine.begin() as connection:
                            for statement in case["owner_barrier_setup"]:
                                connection.exec_driver_sql(statement)
                        https.release.set()
                        wait_for(
                            lambda: scalar(engine, case["owner_statement_wait_sql"]),
                            15,
                            "actual owner statement barrier",
                            child,
                        )
                        # Prove the statement barrier does not own the job row.
                        with engine.begin() as probe:
                            assert (
                                probe.execute(
                                    text(
                                        "SELECT id FROM issuance_service.canvas_evidence_sync_jobs WHERE id='worker-final-job' FOR UPDATE NOWAIT"
                                    )
                                ).scalar_one()
                                == "worker-final-job"
                            )
                        pending = observe()
                        assert pending["jobs"] == before["jobs"]
                        assert len(pending["facts"]) == 1
                        wait_expiry()
                        start_contender()
                        wait_for(
                            lambda: scalar(engine, case["terminal_wait_sql"]),
                            15,
                            "actual recovery terminal write",
                            workers["worker-contender"],
                        )
                        assert observe() == pending
                        assert scalar(engine, case["journal_sql"]) == []
                    owner_wait_sql = case["reclaimer_wait_sql"].replace(
                        "a.usename='synthetic_reclaimer'", "a.usename='oracle'"
                    )

                    def stale_owner_path():
                        if scalar(engine, owner_wait_sql):
                            return "blocked"
                        if scalar(
                            engine,
                            "SELECT metadata->>'phase'='idle' FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'",
                        ):
                            return "idle"
                        return None

                    path = wait_for(
                        stale_owner_path, 15, "actual stale owner path", child
                    )
                    extra = {
                        "owner_statement_blocked_before_row_lock": True,
                        "stale_owner_path": path,
                        "contending": observe(),
                    }
                else:
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
                    wait_expiry()
                    start_contender()
                    wait_for(
                        lambda: scalar(engine, case["reclaimer_wait_sql"]),
                        15,
                        "actual published reclaimer blocked by completion",
                        workers["worker-contender"],
                    )
                    assert observe() == pending
                all_alive()
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
            expected_status = "dead_letter" if recovery_first else "succeeded"
            assert journal == [expected_status]
            assert terminal["status"] == expected_status
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
                "case": case["case"],
                "before": before,
                "terminal_pending": pending,
                "completed": completed,
                "reclaimer_blocked_by_completion": not recovery_first,
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
                **extra,
            }
        finally:
            try:
                finish_workers(workers)
            finally:
                engine.dispose()
