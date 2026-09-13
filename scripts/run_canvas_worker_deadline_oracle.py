"""Actual published worker deadline across three legitimate ordered HTTPS reads."""

from contextlib import ExitStack
import copy
import hashlib
import json
import math
from pathlib import Path
import signal
import tempfile
import time

from sqlalchemy import create_engine

from canvas_worker_deadline_https_fixture import DeadlineHttpsFixture
import canvas_worker_output_capture as output_capture
from run_canvas_worker_provider_recovery_oracle import generation, scalar, wait_for
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)

CASE_NAMES = ["early_release", "deadline_cancel"]


class DeadlineClockDisagreement(AssertionError):
    """Only derived elapsed seconds; no message, row, ID or absolute timestamp."""

    def __init__(self, database_elapsed, monotonic_lower, monotonic_upper):
        super().__init__()
        self.timing_diagnostics = {
            "database_elapsed_seconds": database_elapsed,
            "monotonic_lower_seconds": monotonic_lower,
            "monotonic_upper_seconds": monotonic_upper,
        }


def assert_fact_count(state, expected):
    actual = len(state["facts"])
    if actual != expected:
        # The immutable-image probe exposes classes, never fact payloads.
        error = type(
            f"DeadlineObservedFacts{actual}Expected{expected}", (AssertionError,), {}
        )
        raise error


def load_case(contracts, name):
    matrix = json.loads(
        (contracts / "canvas-worker-deadline-scenarios.json").read_text()
    )
    assert matrix["schema"] == "marty.canvas-worker-deadline-scenarios/v1"
    assert [case["name"] for case in matrix["cases"]] == CASE_NAMES
    assert name in CASE_NAMES
    assert matrix["environment"] == {
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "30",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS": "30",
        "CANVAS_SYNC_WORKER_POLL_SECONDS": "60",
        "LOG_LEVEL": "WARNING",
    }
    assert matrix["completed_response_delay_seconds"] == 11
    assert matrix["completed_response_latest_seconds"] == 14
    assert matrix["published_http_timeout_seconds"] == 15
    assert matrix["native_http_timeout_seconds"] == 20
    assert matrix["post_response_observation_margin_seconds"] == 2
    assert matrix["timing_bounds"] == {
        "initial_job_age_max_seconds": 2,
        "query_latency_max_seconds": 1,
        "deadline_job_age_min_seconds": 29.5,
        "deadline_job_age_max_seconds": 33,
        "clock_agreement_max_seconds": 0.5,
    }
    case = next(case for case in matrix["cases"] if case["name"] == name)
    extension = json.loads((contracts / matrix["reference_scenario"]).read_text())
    spec = {**json.loads((contracts / extension["extends"]).read_text()), **extension}
    requirements = {
        requirement["requirement_id"]: requirement
        for requirement in spec["requirements"]
    }
    assert matrix["requirement_ids"] == ["assignment", "quiz", "module"]
    spec["requirements"] = [requirements[key] for key in matrix["requirement_ids"]]
    stage = next(
        stage for stage in spec["stages"] if stage["name"] == matrix["response_stage"]
    )
    responses = {path: stage["responses"][path] for path in matrix["request_paths"]}
    assert len(responses) == 3 and all(
        response["status"] == 200 for response in responses.values()
    )
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    queued = json.loads((contracts / matrix["queued_job_scenario"]).read_text())
    return matrix, case, spec, shared, queued, responses


def read_job_age(engine, matrix):
    before = time.monotonic()
    row = scalar(engine, matrix["job_age_sql"])
    after = time.monotonic()
    return {"row": row, "before": before, "after": after}


def assert_job_timing(sample, bounds, initial=None, *, deadline=False):
    row = sample["row"]
    assert isinstance(row, dict)
    assert isinstance(row.get("started_at"), str) and row["started_at"]
    assert row.get("id") == "worker-validation-job"
    assert type(row.get("attempt_count")) is int and row["attempt_count"] == 1
    values = (row.get("age_seconds"), sample.get("before"), sample.get("after"))
    assert all(type(value) in (int, float) and math.isfinite(value) for value in values)
    age, before, after = values
    assert age >= 0
    assert 0 <= after - before <= bounds["query_latency_max_seconds"], (
        "Owned timing query exceeded fixture latency budget"
    )
    if initial is None:
        assert age <= bounds["initial_job_age_max_seconds"], (
            "Owned first-request setup exceeded fixture age budget"
        )
        return
    assert tuple(row[key] for key in ("id", "attempt_count", "started_at")) == tuple(
        initial["row"][key] for key in ("id", "attempt_count", "started_at")
    )
    delta = age - initial["row"]["age_seconds"]
    # Each DB clock sample lies within its own monotonic query bracket. Do not
    # silently convert a clock jump or slow observer into runtime timer evidence.
    agreement = bounds["clock_agreement_max_seconds"]
    lower = before - initial["after"] - agreement
    upper = after - initial["before"] + agreement
    assert all(math.isfinite(value) for value in (delta, lower, upper)), (
        "Invalid derived timing comparison"
    )
    if not lower <= delta <= upper:
        # Bounds already include the unchanged 0.5-second agreement tolerance.
        # The probe independently validates this exact class and closed payload.
        raise DeadlineClockDisagreement(delta, lower, upper)
    if deadline:
        assert (
            bounds["deadline_job_age_min_seconds"]
            <= age
            <= bounds["deadline_job_age_max_seconds"]
        ), "Actual deadline outcome is outside declared fixture timing bounds"


def assert_requests(https, matrix, token, count=3):
    assert not https.failures, "Owned deadline transport failed"
    expected = [
        {
            "method": "GET",
            "path": path,
            "authorization": f"Bearer {token}",
            "accept": "application/json",
        }
        for path in matrix["request_paths"][:count]
    ]
    assert https.requests == expected, (
        "Deadline transport differs from exact ordered-read contract"
    )


def assert_outcome(state, case):
    assert len(state["jobs"]) == 1
    job = state["jobs"][0]
    assert job["status"] == case["status"]
    assert job["attempt_count"] == 1 and job["max_attempts"] == 8
    assert job["lease_owner_present"] is job["lease_expires_present"] is False
    assert job["started"] is True
    assert_fact_count(state, case["facts"])
    if case["name"] == "deadline_cancel":
        assert job["last_error_code"] == "canvas_sync_deadline_exceeded"
        assert (
            job["last_error_summary"]
            == "Canvas synchronization exceeded its wall-clock deadline"
        )
        assert job["result"] == {}
        assert job["completed"] is False and job["retry_scheduled"] is True
    else:
        assert job["last_error_code"] is job["last_error_summary"] is None
        assert job["completed"] is True
    assert state["heartbeat"]["metadata"]["phase"] == "idle"
    assert state["heartbeat"]["metadata"]["leased_jobs"] == 0
    assert state["target"] == {
        "enabled": True,
        "config_version": 1,
        "last_success_present": case["name"] == "early_release",
        "worker_id": "worker-rest",
        "worker_id_present": True,
        "worker_heartbeat_present": True,
    }


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix, case, spec, shared, queued, responses = load_case(contracts, case_name)
    child = None
    with (
        DeadlineHttpsFixture(matrix["request_paths"], responses) as https,
        ExitStack() as output_owner,
    ):
        # Handler/certificate cleanup precedes the final output observation.
        # Keep open output files under a separate owner on every platform.
        log_directory = output_owner.enter_context(
            tempfile.TemporaryDirectory(prefix="canvas-worker-deadline-output-")
        )
        (stdout_writer, stdout), (stderr_writer, stderr) = [
            output_capture.owned_log_streams(output_owner, log_directory)
            for _ in range(2)
        ]
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            with engine.begin() as connection:
                assert (
                    connection.exec_driver_sql(queued["initial_job_seed"]).rowcount == 1
                )

            def observe():
                state, current, ciphertext = snapshot(engine, spec, shared)
                assert (current, ciphertext) == preserved
                state["target"] = scalar(engine, matrix["target_sql"])
                return state

            def effects():
                return scalar(engine, matrix["effect_rows_sql"])

            def operational():
                return scalar(engine, matrix["operational_rows_sql"])

            def guard():
                assert child.poll() is None, (
                    "Published worker exited during deadline case"
                )
                assert not https.failures

            child = start_worker(
                worker_case(https.origin, https.cert, matrix["environment"]),
                "worker-rest",
                stdout=stdout_writer,
                stderr=stderr_writer,
            )
            wait_for(
                https.request_received[0].is_set,
                15,
                "first actual provider read",
                child,
            )
            initial_lease = generation(engine)
            initial_age = read_job_age(engine, matrix)
            assert_job_timing(initial_age, matrix["timing_bounds"])
            assert (
                initial_lease["lease_owner"] == "worker-rest"
                and initial_lease["attempt_count"] == 1
            )
            before_first_release = observe()
            assert before_first_release["facts"] == []

            def renewed_after(previous):
                guard()
                current = generation(engine)
                assert (
                    current["id"],
                    current["attempt_count"],
                    current["lease_owner"],
                ) == (initial_lease["id"], 1, "worker-rest")
                if current["lease_expires_at"] > previous["lease_expires_at"]:
                    return current
                return None

            last_live_lease = initial_lease
            completed_read_states = []
            prior_fact_rows = []
            for index in range(2):
                previous = last_live_lease
                last_live_lease = wait_for(
                    lambda: renewed_after(previous),
                    14,
                    f"real lease renewal during provider read {index}",
                    child,
                )
                wait_for(
                    lambda: (
                        time.monotonic() - https.received_at[index]
                        >= matrix["completed_response_delay_seconds"]
                    ),
                    12,
                    "completed response delay",
                    child,
                )
                assert (
                    time.monotonic() - https.received_at[index]
                    < matrix["completed_response_latest_seconds"]
                )
                https.response_release[index].set()
                wait_for(
                    https.request_received[index + 1].is_set,
                    8,
                    "next actual provider read",
                    child,
                )
                assert_requests(https, matrix, spec["token"], count=index + 2)
                state = observe()
                assert state["jobs"][0]["status"] == "leased"
                assert_fact_count(state, index + 1)
                assert [fact["fact_type"] for fact in state["facts"]] == [
                    "canvas.assignment_score",
                    "canvas.quiz_score",
                ][: index + 1]
                completed_read_states.append(state)
                current_fact_rows = effects()["facts"]
                assert all(row in current_fact_rows for row in prior_fact_rows), (
                    "An earlier immutable fact changed"
                )
                prior_fact_rows = current_fact_rows
            committed_effect_rows = effects()
            assert not https.response_release[2].is_set()
            if case_name == "early_release":
                assert time.monotonic() - https.received_at[0] < 27
                https.response_release[2].set()

            def completed():
                guard()
                jobs = scalar(engine, spec["jobs_sql"])
                idle = scalar(
                    engine,
                    "SELECT EXISTS(SELECT 1 FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest' AND metadata->>'phase'='idle')",
                )
                if (
                    len(jobs) == 1
                    and idle
                    and jobs[0]["status"] in {"succeeded", "retry", "dead_letter"}
                ):
                    return observe()
                return None

            outcome = wait_for(completed, 20, "actual complete worker outcome", child)
            terminal_age = read_job_age(engine, matrix)
            assert_job_timing(
                terminal_age,
                matrix["timing_bounds"],
                initial_age,
                deadline=case_name == "deadline_cancel",
            )
            assert_outcome(outcome, case)
            assert last_live_lease["lease_expires_at"] > scalar(
                engine, "SELECT clock_timestamp()"
            )
            if case_name == "deadline_cancel":
                assert not https.response_release[2].is_set()
                assert (
                    time.monotonic() - https.received_at[2]
                    < matrix["published_http_timeout_seconds"]
                )
                assert effects() == committed_effect_rows, (
                    "Cancellation lost or added committed prefix effects"
                )
                https.response_release[2].set()
            after_outcome = (effects(), operational())
            logs = output_capture.observed_log_profile(stdout, stderr, spec["token"])

            # Keep the same worker and listener alive beyond the pending read's
            # original HTTP timeout. No retry is due to be polled in this window.
            late_window_end = (
                https.received_at[2]
                + max(
                    matrix["published_http_timeout_seconds"],
                    matrix["native_http_timeout_seconds"],
                )
                + matrix["post_response_observation_margin_seconds"]
            )
            while time.monotonic() < late_window_end:
                guard()
                assert_requests(https, matrix, spec["token"])
                assert (effects(), operational()) == after_outcome
                time.sleep(0.025)
            assert all(event.is_set() for event in https.response_unblocked)
            https.close()  # joins actual handlers, including canceled-client writes
            assert_requests(https, matrix, spec["token"])
            assert (effects(), operational()) == after_outcome
            assert observe() == outcome
            assert (
                output_capture.observed_log_profile(stdout, stderr, spec["token"])
                == logs
            )
            guard()
            child.send_signal(signal.SIGINT)
            assert child.wait(timeout=10) == -2
            child = None
            assert (effects(), operational()) == after_outcome
            assert observe() == outcome
            return {
                "schema": "marty.canvas-worker-deadline-observation/v1",
                "case": case_name,
                "before_first_release": before_first_release,
                "completed_read_states": completed_read_states,
                "outcome": outcome,
                "requests": copy.deepcopy(https.requests),
                "completed_reads_released_before_published_http_timeout": 2,
                "renewals_observed_while_reads_pending": 2,
                "last_renewed_lease_still_current_at_outcome": True,
                "timing_bounds": matrix["timing_bounds"],
                "first_request_setup_within_age_budget": True,
                "timing_query_latency_within_budget": True,
                "database_and_monotonic_elapsed_agree": True,
                "deadline_outcome_within_declared_age_bounds": True
                if case_name == "deadline_cancel"
                else None,
                "third_response_released_after_deadline_outcome": case_name
                == "deadline_cancel",
                "committed_prefix_preserved_on_deadline": True
                if case_name == "deadline_cancel"
                else None,
                "stable_after_release_and_handler_join": True,
                "worker_live_and_idle_after_late_response_window": True,
                "stable_after_interrupt": True,
                "exit_code_after_interrupt": -2,
                "logs_before_interrupt": logs,
                "source_sha256": worker_source_sha256(),
                "log_source_sha256": output_capture.published_log_source_sha256(),
                "fixture_sha256": hashlib.sha256(
                    Path(__file__)
                    .with_name("canvas_worker_deadline_https_fixture.py")
                    .read_text()
                    .encode()
                ).hexdigest(),
            }
        finally:
            if child is not None:
                finish_worker(child)
            engine.dispose()
