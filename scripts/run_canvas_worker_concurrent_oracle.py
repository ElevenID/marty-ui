"""Two actual schedulers contend on the owned schema, not a repository mock."""

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
    finish_worker,
    start_worker,
    worker_source_sha256,
)


def run():
    contracts = Path("/verification/contracts")
    cases = json.loads(
        (contracts / "canvas-worker-concurrent-scenarios.json").read_text()
    )
    spec = json.loads((contracts / cases["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    assert cases["worker_ids"] == ["worker-rest", "worker-contender"]
    workers = {}
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            https.stage = {**spec["stages"][0], "hold_response": True}

            def all_alive():
                assert len(workers) == 2
                assert all(child.poll() is None for child in workers.values())

            def observe():
                all_alive()
                state, current, encrypted = snapshot(
                    engine, spec, shared, heartbeat_sql=cases["heartbeats_sql"]
                )
                assert (current, encrypted) == preserved
                return state

            # Only this fresh fixture database is locked. Release on success or
            # exception; no application clock, query or job state is patched.
            with engine.begin() as barrier:
                barrier.exec_driver_sql(cases["barrier_sql"])
                for worker_id in cases["worker_ids"]:
                    workers[worker_id] = start_worker(
                        worker_case(https.origin, https.cert), worker_id
                    )

                def both_blocked():
                    all_alive()
                    return scalar(engine, cases["blocked_schedulers_sql"]) == 2

                wait_for(
                    both_blocked,
                    20,
                    "both actual schedulers blocked at database barrier",
                )
                assert not https.received.is_set()
                assert (
                    scalar(
                        engine,
                        "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs",
                    )
                    == 0
                )

            wait_for(https.received.is_set, 15, "actual provider request")

            def phase_state(phases, status):
                state = observe()
                if (
                    [entry["metadata"]["phase"] for entry in state["heartbeat"]]
                    == phases
                    and len(state["jobs"]) == 1
                    and state["jobs"][0]["status"] == status
                ):
                    return state
                return None

            before = wait_for(
                lambda: phase_state(["idle", "processing"], "leased"),
                10,
                "one owner and one idle contender",
            )
            with engine.connect() as connection:
                original = dict(
                    connection.execute(
                        text(
                            "SELECT id,lease_owner,started_at FROM issuance_service.canvas_evidence_sync_jobs"
                        )
                    )
                    .mappings()
                    .one()
                )
            assert original["lease_owner"] in workers
            assert before["jobs"][0]["attempt_count"] == 1
            assert before["facts"] == []
            assert len(https.requests) == 1
            assert not https.release.is_set()
            https.release.set()
            completed = wait_for(
                lambda: phase_state(["idle", "idle"], "succeeded"),
                25,
                "both workers idle after one successful job",
            )
            with engine.connect() as connection:
                final = dict(
                    connection.execute(
                        text(
                            "SELECT id,started_at FROM issuance_service.canvas_evidence_sync_jobs"
                        )
                    )
                    .mappings()
                    .one()
                )
            assert final == {key: original[key] for key in ["id", "started_at"]}
            assert completed["jobs"][0]["attempt_count"] == 1
            assert len(https.requests) == 1
            exit_codes = []
            for child in workers.values():
                child.send_signal(signal.SIGINT)
                exit_codes.append(child.wait(timeout=10))
            assert exit_codes == [-2, -2]
            return {
                "schema": "marty.canvas-worker-concurrent-oracle/v1",
                "both_schedulers_blocked": True,
                "both_workers_alive_after_completion": True,
                "before": before,
                "completed": completed,
                "same_job_and_original_start": True,
                "exit_codes_after_interrupt": exit_codes,
                "requests": list(https.requests),
                "source_sha256": worker_source_sha256(),
            }
        finally:
            for child in workers.values():
                finish_worker(child)
            engine.dispose()
