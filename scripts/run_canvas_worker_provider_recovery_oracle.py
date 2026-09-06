"""Actual lease renewal and process-loss recovery, without clock/lease mutation."""

import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import time

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import DATABASE, finish_worker, start_worker


def wait_for(predicate, timeout, description, child=None):
    deadline = time.monotonic() + timeout
    while True:
        if child is not None:
            assert child.poll() is None, "Published worker exited before observation"
        value = predicate()
        if value:
            return value
        assert time.monotonic() < deadline, f"Timed out waiting for {description}"
        time.sleep(0.025)


def scalar(engine, query, parameters=None):
    with engine.connect() as connection:
        return connection.execute(text(query), parameters or {}).scalar_one()


def generation(engine):
    with engine.connect() as connection:
        return dict(
            connection.execute(
                text(
                    "SELECT j.id,j.attempt_count,j.lease_owner,j.lease_expires_at,j.started_at,"
                    "h.last_heartbeat_at AS worker_heartbeat,"
                    "t.metadata->>'worker_heartbeat_at' AS target_heartbeat "
                    "FROM issuance_service.canvas_evidence_sync_jobs j "
                    "JOIN issuance_service.canvas_evidence_sync_targets t ON t.id=j.target_id "
                    "JOIN issuance_service.canvas_worker_heartbeats h ON h.worker_id='worker-rest'"
                )
            )
            .mappings()
            .one()
        )


def run(case_name, scenario="canvas-worker-provider-recovery-scenarios.json"):
    contracts = Path("/verification/contracts")
    cases = json.loads((contracts / scenario).read_text())
    assert case_name in cases["cases"]
    spec = json.loads((contracts / cases["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        child = None
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            if "initial_job_seed" in cases:
                # Historical fixture state is inserted before any worker starts;
                # running attempt/lease/outcome state is never edited.
                assert (
                    scalar(
                        engine,
                        "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs",
                    )
                    == 0
                )
                with engine.begin() as connection:
                    connection.exec_driver_sql(cases["initial_job_seed"])
            worker_input = worker_case(
                https.origin,
                https.cert,
                {
                    "CANVAS_SYNC_WORKER_LEASE_SECONDS": str(cases["lease_seconds"]),
                },
            )
            https.stage = {**spec["stages"][0], "hold_response": True}

            def observe():
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                return state

            def idle_outcome(status, attempt, since):
                state = observe()
                fresh = scalar(
                    engine,
                    "SELECT last_heartbeat_at>=:since FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'",
                    {"since": since},
                )
                if (
                    fresh
                    and state["heartbeat"]["metadata"]["phase"] == "idle"
                    and len(state["jobs"]) == 1
                    and state["jobs"][0]["status"] == status
                    and state["jobs"][0]["attempt_count"] == attempt
                ):
                    return state
                return None

            def start():
                since = scalar(engine, "SELECT clock_timestamp()")
                return start_worker(worker_input, "worker-rest"), since

            child, started = start()
            wait_for(https.received.is_set, 15, "actual provider request", child)
            before = observe()
            first = generation(engine)
            assert before["jobs"][0]["status"] == "leased"
            assert before["facts"] == []

            def renewed():
                current = generation(engine)
                if (
                    current["lease_expires_at"] > first["lease_expires_at"]
                    and current["worker_heartbeat"] > first["worker_heartbeat"]
                    and current["target_heartbeat"] > first["target_heartbeat"]
                ):
                    return current
                return None

            advanced = wait_for(renewed, 13, "lease and both heartbeat renewal", child)
            for key in ["id", "attempt_count", "lease_owner", "started_at"]:
                assert advanced[key] == first[key]
            renewed_state = observe()
            assert renewed_state == before
            assert not https.release.is_set()
            result = {
                "schema": "marty.canvas-worker-provider-recovery-oracle/v1",
                "case": case_name,
                "before": before,
                "renewed": renewed_state,
                "lease_and_both_heartbeats_advanced": True,
                "generation_preserved_during_renewal": True,
            }
            if case_name in {"recovery", "final"}:
                child.send_signal(signal.SIGKILL)
                result["crash_exit_code"] = child.wait(timeout=10)
                result["after_crash"] = observe()
                assert result["after_crash"] == renewed_state
                https.release.set()
                wait_for(
                    lambda: scalar(
                        engine,
                        "SELECT lease_expires_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=:id",
                        {"id": first["id"]},
                    ),
                    35,
                    "real lease expiry",
                )
                child, started = start()
            if case_name == "recovery":
                restarted = started
                result["reclaimed"] = wait_for(
                    lambda: idle_outcome("retry", 1, restarted),
                    15,
                    "durable recovery retry",
                    child,
                )
                assert len(https.requests) == 1, (
                    "Recovery must not bypass retry eligibility"
                )
                result["recovery_backoff_in_range"] = scalar(
                    engine,
                    "SELECT extract(epoch FROM available_at-updated_at) BETWEEN 14.9 AND 20.1 FROM issuance_service.canvas_evidence_sync_jobs WHERE id=:id",
                    {"id": first["id"]},
                )
                assert result["recovery_backoff_in_range"]
                child.send_signal(signal.SIGINT)
                result["reclaimer_exit_code"] = child.wait(timeout=10)
                wait_for(
                    lambda: scalar(
                        engine,
                        "SELECT status='retry' AND available_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=:id",
                        {"id": first["id"]},
                    ),
                    25,
                    "real recovered retry eligibility",
                )
                child, started = start()
            else:
                https.release.set()
            result["completed"] = wait_for(
                lambda: idle_outcome(
                    "dead_letter" if case_name == "final" else "succeeded",
                    {"renewal": 1, "recovery": 2, "final": 8}[case_name],
                    started,
                ),
                25,
                "terminal actual worker outcome",
                child,
            )
            child.send_signal(signal.SIGINT)
            result["exit_code_after_interrupt"] = child.wait(timeout=10)
            final = generation(engine)
            assert final["id"] == first["id"]
            assert final["started_at"] == first["started_at"]
            result["same_job_and_original_start"] = True
            result["requests"] = list(https.requests)
            assert len(https.requests) == (2 if case_name == "recovery" else 1)
            if case_name == "final":
                result["target_enabled"] = scalar(
                    engine,
                    "SELECT enabled FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'",
                )
                assert result["target_enabled"] is False
                assert result["completed"]["facts"] == []
            result["source_sha256"] = {
                name: hashlib.sha256(
                    Path(importlib.util.find_spec(name).origin)
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest()
                for name in [
                    "issuance.canvas_worker",
                    "issuance.infrastructure.api.canvas_routes",
                ]
            }
            return result
        finally:
            if child is not None:
                finish_worker(child)
            engine.dispose()
