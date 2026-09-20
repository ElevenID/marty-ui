"""Regenerate the frozen published worker's four delayed-header controls."""

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

from canvas_worker_timeout_https_fixture import TimeoutHttpsFixture
from canvas_worker_output_capture import (
    observed_log_profile,
    owned_log_streams,
    published_log_source_sha256,
)
from run_canvas_worker_provider_recovery_oracle import generation, scalar, wait_for
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)

CASE_LAYOUT = [
    ("application_prompt", "learner_application", False, "succeeded"),
    ("application_delayed_headers", "learner_application", True, "retry"),
    ("roster_prompt", "background_roster", False, "succeeded"),
    ("roster_delayed_headers", "background_roster", True, "succeeded"),
]
ENVIRONMENT = {
    "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
    "CANVAS_SYNC_WORKER_LEASE_SECONDS": "90",
    "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
    "LOG_LEVEL": "WARNING",
}
TIMING = {
    "delay_seconds": 17,
    "release_min_seconds": 16.5,
    "release_max_seconds": 18,
    "prompt_max_seconds": 2,
    "outcome_max_seconds": 25,
    "application_timeout_min_seconds": 14.5,
    "application_timeout_max_seconds": 16.5,
    "observe_until_seconds": 22,
    "after_outcome_seconds": 2,
}


def load_case(contracts, name):
    def read(filename):
        return json.loads((contracts / filename).read_text(encoding="utf-8"))

    matrix = read("canvas-worker-timeout-scenarios.json")
    assert matrix["schema"] == "marty.canvas-worker-timeout-scenarios/v1"
    assert matrix["environment"] == ENVIRONMENT and matrix["timing"] == TIMING
    assert [
        (case["name"], case["target_type"], case["delayed"], case["expected_status"])
        for case in matrix["cases"]
    ] == CASE_LAYOUT, "Timeout matrix must retain all four exact controls"
    assert all(type(case["delayed"]) is bool for case in matrix["cases"])
    matches = [case for case in matrix["cases"] if case["name"] == name]
    assert len(matches) == 1, "Unknown timeout case"
    case = matches[0]
    states = read(matrix["state_scenario"])
    for key in ("effect_rows_sql", "operational_rows_sql"):
        matrix[key] = states[key]
    spec = read(matrix["reference_scenario"])
    shared = read(spec["shared_seed"])
    spec["jobs_sql"] = read(matrix["retry_scenario"])["jobs_sql"]
    if case["target_type"] == "background_roster":
        spec["post_oauth_seed"] = read(matrix["roster_scenario"])["seed"]
        response = {"status": 200, "body": []}
        job_id = "worker-roster-failure-job"
    else:
        spec["post_oauth_seed"] = [
            matrix["application_seed"],
            read(matrix["queued_scenario"])["initial_job_seed"],
        ]
        response = next(
            stage for stage in spec["stages"] if stage["name"] == "initial_permit"
        )
        job_id = "worker-validation-job"
    request = {
        "method": "GET",
        "path": matrix["request_paths"][case["target_type"]],
        "authorization": f"Bearer {spec['token']}",
        "accept": "application/json",
    }
    return matrix, case, spec, shared, response, request, job_id


def assert_release_timing(https, case, timing):
    assert https.received_at is not None and https.released_at is not None
    elapsed = https.released_at - https.received_at
    if case["delayed"]:
        assert (
            timing["release_min_seconds"] <= elapsed <= timing["release_max_seconds"]
        ), "Owned delayed-header release missed its safe timing band"
    else:
        assert 0 <= elapsed < timing["prompt_max_seconds"], (
            "Owned prompt response missed its timing bound"
        )
    return True


def assert_outcome_order(outcome_at, released_at, case):
    assert released_at is not None
    before_release = outcome_at < released_at
    assert before_release is (case["expected_status"] == "retry"), (
        "Worker outcome did not occur on the required side of release"
    )
    return before_release


def assert_outcome_timing(received_at, outcome_at, case, timing):
    assert all(
        type(value) in (int, float) and math.isfinite(value)
        for value in (received_at, outcome_at)
    ), "Invalid owned response timing sample"
    elapsed = outcome_at - received_at
    assert 0 <= elapsed <= timing["outcome_max_seconds"], (
        "Worker outcome exceeded the response observation budget"
    )
    if case["name"] == "application_delayed_headers":
        # Retry-before-release alone would also accept an incorrect 5s/10s
        # timeout. These declared fixture tolerances surround the source's 15s
        # read boundary; they are not a new runtime SLA or a frozen observation.
        assert (
            timing["application_timeout_min_seconds"]
            <= elapsed
            <= timing["application_timeout_max_seconds"]
        ), "Application timeout differs from the declared source timing window"
    return True


def assert_outcome(state, case, initial_effects, completed_effects):
    assert len(state["jobs"]) == 1, "Timeout case must retain exactly one job"
    job = state["jobs"][0]
    assert job["status"] == case["expected_status"], (
        "Source-derived worker status differs"
    )
    assert job["attempt_count"] == 1 and job["max_attempts"] == 8
    assert not job["lease_owner_present"] and not job["lease_expires_present"]
    assert job["started"] is True
    assert state["heartbeat"]["metadata"]["phase"] == "idle"
    assert state["heartbeat"]["metadata"]["leased_jobs"] == 0
    assert state["oauth"] == {
        "status": "connected",
        "reauthorization_required": False,
        "refresh_lease_owner_present": False,
        "secret_enabled": True,
        "secret_used": True,
    }
    target = state["target"]
    assert target["target_type"] == case["target_type"]
    assert target["enabled"] and target["config_version"] == 1
    # The successful roster owner saves its pre-touch target metadata. Its
    # initial snapshot has neither heartbeat key; application reads do not
    # overwrite that metadata. This is also retained by the mixed-roster corpus.
    assert target["worker_heartbeat_present"] is (
        case["target_type"] == "learner_application"
    )
    assert target["last_success_present"] is (job["status"] == "succeeded")
    assert target["candidate_count"] == target["observation_count"] == 0
    if job["status"] == "retry":
        assert job["last_error_code"] == "canvas_authoritative_reads_failed"
        assert (
            job["last_error_summary"]
            == "No authoritative Canvas evidence requirement could be read"
        )
        assert job["result"] == {} and not job["completed"]
        assert job["retry_scheduled"] and job["retry_delay_within_backoff_bounds"]
        # Validation-state changes are legitimate; unavailable reads are not
        # verified evidence and must not manufacture business observations.
        for key in (
            "facts",
            "heads",
            "reviews",
            "events",
            "candidates",
            "observations",
        ):
            assert completed_effects[key] == initial_effects[key], (
                "Unavailable read changed business evidence"
            )
        assert state["facts"] == []
    else:
        assert job["last_error_code"] is job["last_error_summary"] is None
        assert job["completed"] is True
        if case["target_type"] == "learner_application":
            assert len(state["facts"]) == 1
            assert job["result"]["facts_created"] == 1
            assert job["result"]["requirements_checked"] == 1
            assert job["result"]["policy_allowed"] is True
        else:
            assert state["facts"] == []
            assert job["result"] == {
                "candidates_seen": 0,
                "pending_claim": 0,
                "identity_link_required": 0,
                "observations_written": 0,
            }
            assert target["metadata"]["roster_cursor"] == 0
            assert target["metadata"]["roster_size"] == 0
            assert target["metadata"]["synthetic_marker"] == "preserve"
            assert target["roster_cycle_completed_at_present"]


def await_outcome(observe, guard, received_at, timeout):
    def completed():
        guard()
        state = observe()
        assert len(state["jobs"]) == 1
        if (
            state["jobs"][0]["status"] in {"succeeded", "retry", "dead_letter"}
            and state["heartbeat"]["metadata"]["phase"] == "idle"
        ):
            return state, time.monotonic()
        return None

    remaining = received_at + timeout - time.monotonic()
    assert remaining > 0, "Timeout outcome observation budget exhausted"
    return wait_for(completed, remaining, "first actual timeout outcome")


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix, case, spec, shared, response, request, job_id = load_case(
        contracts, case_name
    )
    sources = worker_source_sha256()
    assert sources == matrix["source_sha256"], "Unexpected installed worker source"
    assert published_log_source_sha256() == matrix["log_source_sha256"]
    assert (
        hashlib.sha256(
            Path(
                "/app/services/issuance/application/canvas_lti_services.py"
            ).read_bytes()
        ).hexdigest()
        == matrix["http_source_sha256"]
    )
    child = None
    timing = matrix["timing"]
    with (
        TimeoutHttpsFixture(
            request,
            response,
            delay_seconds=timing["delay_seconds"] if case["delayed"] else 0,
        ) as https,
        ExitStack() as output_owner,
    ):
        log_directory = output_owner.enter_context(
            tempfile.TemporaryDirectory(prefix="canvas-worker-timeout-output-")
        )
        stdout_writer, stdout = owned_log_streams(output_owner, log_directory)
        stderr_writer, stderr = owned_log_streams(output_owner, log_directory)
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)

            def observe():
                state, rows, ciphertext = snapshot(engine, spec, shared)
                assert (rows, ciphertext) == preserved, (
                    "Issued rows or ciphertext changed"
                )
                state["target"] = scalar(engine, matrix["target_sql"])
                return state

            def effects():
                return scalar(engine, matrix["effect_rows_sql"])

            def operational():
                return scalar(engine, matrix["operational_rows_sql"])

            def guard():
                assert child.poll() is None, "Owned worker exited before observation"
                https.assert_requests()

            initial_effects = effects()
            child = start_worker(
                worker_case(https.origin, https.cert, matrix["environment"]),
                "worker-rest",
                stdout=stdout_writer,
                stderr=stderr_writer,
            )
            wait_for(
                https.request_started.is_set, 30, "actual timeout provider I/O", child
            )
            guard()
            lease = generation(engine)
            database_now = scalar(engine, "SELECT clock_timestamp()")
            lease_current = lease["lease_expires_at"] > database_now
            assert lease_current and lease["lease_owner"] == "worker-rest"
            assert lease["id"] == job_id and lease["attempt_count"] == 1
            before = observe()
            assert before["jobs"][0]["status"] == "leased" and before["facts"] == []
            assert before["target"]["worker_heartbeat_present"] is True
            assert not https.release.is_set(), (
                "Response released before initial leased snapshot"
            )
            https.prompt_ready.set()
            outcome, outcome_at = await_outcome(
                observe, guard, https.received_at, timing["outcome_max_seconds"]
            )
            outcome_in_band = assert_outcome_timing(
                https.received_at, outcome_at, case, timing
            )
            outcome_rows = (effects(), operational())
            assert_outcome(outcome, case, initial_effects, outcome_rows[0])
            # Independent release runs even if the application timed out first.
            wait_for(https.release.is_set, 20, "independent response release", child)
            release_in_band = assert_release_timing(https, case, timing)
            before_release = assert_outcome_order(outcome_at, https.released_at, case)
            lease_current_at_outcome = lease["lease_expires_at"] > scalar(
                engine, "SELECT clock_timestamp()"
            )
            assert lease_current_at_outcome, "Lease expiry masked the provider boundary"
            logs = observed_log_profile(stdout, stderr, spec["token"])
            stop_at = max(
                https.received_at + timing["observe_until_seconds"],
                outcome_at + timing["after_outcome_seconds"],
            )
            while time.monotonic() < stop_at:
                guard()
                assert (effects(), operational()) == outcome_rows, (
                    "Late response changed durable rows"
                )
                time.sleep(0.025)
            wait_for(
                https.response_unblocked.is_set,
                2,
                "owned response handler release",
                child,
            )
            https.close()
            guard()
            assert (effects(), operational()) == outcome_rows
            assert observe() == outcome
            assert observed_log_profile(stdout, stderr, spec["token"]) == logs
            child.send_signal(signal.SIGINT)
            exit_code = child.wait(timeout=10)
            assert exit_code == -2, "Unexpected owned Python worker shutdown"
            child = None
            assert (effects(), operational()) == outcome_rows and observe() == outcome
            return {
                "schema": "marty.canvas-worker-timeout-observation/v1",
                "case": case_name,
                "before_release": before,
                "outcome": outcome,
                "requests": copy.deepcopy(https.requests),
                "timing": {
                    "outcome_within_declared_source_window": outcome_in_band,
                    "release_within_declared_band": release_in_band,
                    "outcome_before_release": before_release,
                    "lease_current_while_response_held": lease_current,
                    "original_lease_current_after_outcome": lease_current_at_outcome,
                },
                "stable_after_release_handler_join_and_interrupt": True,
                "exit_code_after_interrupt": exit_code,
                "logs_before_interrupt": logs,
                "source_sha256": sources,
                "http_source_sha256": matrix["http_source_sha256"],
                "log_source_sha256": matrix["log_source_sha256"],
                "fixture_sha256": hashlib.sha256(
                    Path(__file__)
                    .with_name("canvas_worker_timeout_https_fixture.py")
                    .read_bytes()
                ).hexdigest(),
            }
        finally:
            https.cancel_controller.set()
            https.release.set()
            try:
                if child is not None:
                    finish_worker(child)
            finally:
                engine.dispose()
