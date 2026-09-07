"""Actual published worker dispatch with explicit synthetic callable shapes."""

import copy
import hashlib
import importlib.util
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

CASE_NAMES = {
    "missing_processor",
    "nonawaitable_result",
    "nonmapping_result",
    "valid_mapping",
    "rollout_closed_missing",
}
HOOKS = {"nonawaitable_result", "nonmapping_result", "valid_mapping"}


class DispatchObservedAsyncRequiredSummary(AssertionError):
    pass


class DispatchObservedInvalidResultSummary(AssertionError):
    pass


class DispatchObservedMissingProcessorSummary(AssertionError):
    pass


class DispatchObservedAbsentSummary(AssertionError):
    pass


class DispatchObservedUnknownSummary(AssertionError):
    pass


def assert_summary(actual, expected):
    if actual != expected:
        # The outer immutable-image probe reports classes, never messages.
        # Only fixed known summaries receive distinct classes; arbitrary
        # processor/provider strings never enter the diagnostic channel.
        failure = {
            "Canvas synchronization processor must be asynchronous": DispatchObservedAsyncRequiredSummary,
            "Canvas synchronization processor returned an invalid result": DispatchObservedInvalidResultSummary,
            "Authoritative Canvas synchronization processor is not configured": DispatchObservedMissingProcessorSummary,
            None: DispatchObservedAbsentSummary,
        }.get(actual, DispatchObservedUnknownSummary)
        raise failure


def select_case(matrix, name):
    assert matrix["schema"] == "marty.canvas-worker-dispatch-scenarios/v1"
    names = [case["name"] for case in matrix["cases"]]
    assert len(names) == len(set(names)) == 5 and set(names) == CASE_NAMES
    assert name in names
    assert matrix["hook_module"] == "canvas_worker_dispatch_hooks"
    case = next(case for case in matrix["cases"] if case["name"] == name)
    assert case["hook"] is None or case["hook"] in HOOKS
    assert type(case["rollout_enabled"]) is bool
    assert case["processor_configured"] is (case["hook"] is not None)
    return case


def dispatch_input(origin, cert, matrix, case):
    selected = "" if case["hook"] is None else f"{matrix['hook_module']}:{case['hook']}"
    supplied = worker_case(
        origin,
        cert,
        {
            "CANVAS_SYNC_PROCESSOR": selected,
            "CANVAS_PORTABLE_INTEGRATION_ENABLED": str(case["rollout_enabled"]).lower(),
        },
    )
    # Keep the existing TLS trust hook; expose only this mounted synthetic
    # module through the loader's existing configured Python import path.
    supplied["environment"]["PYTHONPATH"] += ":/verification/scripts"
    return supplied


def assert_outcome(state, case):
    jobs = state["jobs"]
    assert len(jobs) == 1
    job = jobs[0]
    assert job["status"] == case["status"]
    assert job["attempt_count"] == 1
    # Published fail_canvas_sync_job exhausts a forced-terminal job's budget
    # without changing its attempt-count lease fence. Retained validation
    # captures independently show this exact max_attempts=1 shape.
    assert job["max_attempts"] == (1 if case["retryable"] is False else 8)
    assert job["result"] == case["result"]
    assert job["last_error_code"] == case["code"]
    assert_summary(job["last_error_summary"], case["summary"])
    assert job["started"] is True
    assert job["completed"] is (case["status"] != "retry")
    assert job["lease_owner_present"] is job["lease_expires_present"] is False
    assert job["retry_scheduled"] is (True if case["status"] == "retry" else None)
    assert state["heartbeat"] == {
        "role": "canvas_sync",
        "metadata": {
            "phase": "idle",
            "leased_jobs": 0,
            "process": "standalone",
            "processor_configured": case["processor_configured"],
        },
    }
    assert state["facts"] == []
    assert state["oauth"] == {
        "status": "connected",
        "reauthorization_required": False,
        "refresh_lease_owner_present": False,
        "secret_enabled": True,
        "secret_used": False,
    }


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix = json.loads(
        (contracts / "canvas-worker-dispatch-scenarios.json").read_text()
    )
    case = select_case(matrix, case_name)
    spec = json.loads((contracts / matrix["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    queued = json.loads((contracts / matrix["queued_job_scenario"]).read_text())
    child = None
    with WorkerHttpsFixture() as https:
        https.stage = {"status": 500, "body": {}}
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            with engine.begin() as connection:
                assert (
                    connection.exec_driver_sql(queued["initial_job_seed"]).rowcount == 1
                )
            initial = scalar(engine, matrix["job_row_sql"])
            assert (
                initial["id"] == "worker-validation-job"
                and initial["status"] == "queued"
            )

            def observe():
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                return state

            child = start_worker(
                dispatch_input(https.origin, https.cert, matrix, case), "worker-rest"
            )

            def completed():
                assert not https.failures and not https.requests
                jobs = scalar(engine, spec["jobs_sql"])
                assert len(jobs) == 1
                idle = scalar(
                    engine,
                    "SELECT EXISTS(SELECT 1 FROM issuance_service.canvas_worker_heartbeats "
                    "WHERE worker_id='worker-rest' AND metadata->>'phase'='idle')",
                )
                if idle and jobs[0]["status"] in {"retry", "dead_letter", "succeeded"}:
                    return observe()
                return None

            state = wait_for(completed, 25, "actual dispatch outcome", child)
            assert_outcome(state, case)
            target = scalar(engine, matrix["target_sql"])
            target_row = scalar(engine, matrix["target_row_sql"])
            terminal = scalar(engine, matrix["job_row_sql"])
            assert terminal["id"] == initial["id"]
            assert "synthetic-operational-result-tripwire" not in json.dumps(
                [terminal, target_row, state]
            )
            child.send_signal(signal.SIGINT)
            assert child.wait(timeout=10) == -2
            child = None
            assert observe() == state
            assert scalar(engine, matrix["job_row_sql"]) == terminal
            assert scalar(engine, matrix["target_sql"]) == target
            assert scalar(engine, matrix["target_row_sql"]) == target_row
            source = worker_source_sha256()
            dispatch_source = Path(
                importlib.util.find_spec(
                    "issuance.application.canvas_sync_service"
                ).origin
            )
            source["issuance.application.canvas_sync_service"] = hashlib.sha256(
                dispatch_source.read_text(encoding="utf-8").encode()
            ).hexdigest()
            result = {
                "schema": "marty.canvas-worker-dispatch-oracle/v1",
                "case": case_name,
                "source_sha256": source,
                "hook_sha256": hashlib.sha256(
                    Path(__file__)
                    .with_name("canvas_worker_dispatch_hooks.py")
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest(),
                "scope": "Actual published worker and durable dispatch with controlled synthetic hooks; not provider or signing qualification",
                "state": state,
                "target": target,
                "requests": copy.deepcopy(https.requests),
                "same_job": True,
                "issued_rows_transactions_ciphertext_preserved": True,
                "synthetic_result_detail_not_retained": True,
                "unchanged_after_exit": True,
                "exit_code_after_interrupt": -2,
            }
        finally:
            try:
                if child is not None:
                    finish_worker(child)
            finally:
                engine.dispose()
    # Keep the tripwire live until all owned request handlers have joined.
    assert not https.failures and https.requests == result["requests"] == []
    return result
