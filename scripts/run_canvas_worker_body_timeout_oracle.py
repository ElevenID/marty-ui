"""Capture unchanged published-worker body progress and inactivity outcomes.

Expectations are declared before capture, not observations. The only post-start
stimulus is the owned HTTPS handler's outcome-independent byte schedule.
"""

from contextlib import ExitStack
import copy
from datetime import datetime
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path
import signal
import sys
import tempfile
import time

from sqlalchemy import create_engine, text

from canvas_worker_body_timeout_https_fixture import BodyTimeoutHttpsFixture
from canvas_worker_output_capture import (
    observed_log_profile,
    owned_log_streams,
    published_log_source_sha256,
)
from run_canvas_worker_provider_recovery_oracle import scalar
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)


CASE_LAYOUT = [
    ("application_body_prompt", "learner_application", "prompt", "succeeded"),
    ("roster_body_prompt", "background_roster", "prompt", "succeeded"),
    ("application_body_progress", "learner_application", "progress", "succeeded"),
    ("roster_body_progress", "background_roster", "progress", "succeeded"),
    ("application_body_stall", "learner_application", "stall", "retry"),
    ("roster_body_stall", "background_roster", "stall", "retry"),
]
ENVIRONMENT = {
    "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
    "CANVAS_SYNC_WORKER_LEASE_SECONDS": "90",
    "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
    "LOG_LEVEL": "WARNING",
}
SCHEDULES = {"prompt": [0, 0.05], "progress": [0, 8, 16, 24], "stall": [0, 8, 31]}
TIMING = {
    "initial_response_max_seconds": 2,
    "query_max_seconds": 0.5,
    "write_lateness_max_seconds": 0.5,
    "success_transition_early_uncertainty_seconds": 0.5,
    "success_transition_after_flush_max_seconds": 2,
    "application_inactivity_min_seconds": 14.5,
    "application_inactivity_max_seconds": 16.5,
    "roster_inactivity_min_seconds": 19.5,
    "roster_inactivity_max_seconds": 21.5,
    "prompt_outcome_max_seconds": 2,
    "progress_outcome_max_seconds": 26,
    "stall_outcome_max_seconds": 30,
    "after_final_attempt_seconds": 2,
    "after_outcome_seconds": 2,
    "after_read_budget_seconds": 2,
}
SOURCE_SHA256 = {
    "issuance.canvas_worker": "c5a7a692af7a808486b0a42d379699222bdf01f3995181c16da9d3466666e90a",
    "issuance.infrastructure.api.canvas_routes": "f3ea0cd0f94da4b08d071f03cad47afddf1ff2a587210c6a442b0b2f2a331943",
}
HTTP_SOURCE_SHA256 = "ab5b5a6de0e1c3ed45838e6ca0c1df1c84f3eb311de41060a60754769d7ac6b3"
LOG_SOURCE_SHA256 = "2b6d2eb7cec34bb4596ef9b758d8af02a3172337e89bad3b5d26b558d0dd00b7"
RUNTIME_VERSIONS = {"httpx": "0.26.0", "httpcore": "1.0.9"}
REFERENCE_IMAGE = "ghcr.io/elevenid/marty-credentials-issuance@sha256:9f15b64bc0ec7a693339cada3142b2952a575d2b50ee89230aabe078d0026176"
SCENARIO = "canvas-worker-body-timeout-scenarios.json"
CONTRACT_FILES = {
    "reference_scenario": "canvas-worker-rest-scenarios.json",
    "retry_scenario": "canvas-worker-retry-scenarios.json",
    "queued_scenario": "canvas-worker-validation-scenarios.json",
    "roster_scenario": "canvas-worker-roster-failure-scenarios.json",
    "state_scenario": "canvas-worker-deadline-scenarios.json",
}
SHARED_SEED = "canvas-issued-review-scenarios.json"
JOB_FIELDS = {
    "id",
    "organization_id",
    "target_id",
    "attempt_count",
    "status",
    "lease_owner",
    "lease_expires_at",
    "started_at",
    "result",
}
TERMINAL = {"succeeded", "retry", "dead_letter"}
ERRORS = {
    "learner_application": (
        "canvas_authoritative_reads_failed",
        "No authoritative Canvas evidence requirement could be read",
    ),
    # Pinned routes.py:1381-1501 catches HTTPError around streaming collection
    # JSON and wraps CanvasLtiServiceError; the roster dispatcher maps this.
    "background_roster": (
        "canvas_authoritative_read_failed",
        "Canvas background evidence could not be read",
    ),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def load_case(contracts, name):
    def read(filename):
        return json.loads((contracts / filename).read_text(encoding="utf-8"))

    matrix = read(SCENARIO)
    require(
        matrix["schema"] == "marty.canvas-worker-body-timeout-scenarios/v1",
        "Unexpected body scenario schema",
    )
    require(
        matrix["environment"] == ENVIRONMENT and matrix["timing"] == TIMING,
        "Body timing or worker configuration drifted",
    )
    require(matrix["schedules"] == SCHEDULES, "Body schedules drifted")
    require(
        all(finite_number(value) for value in matrix["timing"].values())
        and all(
            finite_number(value)
            for offsets in matrix["schedules"].values()
            for value in offsets
        ),
        "Body timing and schedule inputs must be finite plain numbers",
    )
    require(
        all(matrix[key] == value for key, value in CONTRACT_FILES.items()),
        "Body shared contract ownership drifted",
    )
    require(
        all(
            type(case) is dict
            and set(case) == {"name", "target_type", "mode", "expected_status"}
            for case in matrix["cases"]
        ),
        "Unexpected body case shape",
    )
    require(
        [
            (case["name"], case["target_type"], case["mode"], case["expected_status"])
            for case in matrix["cases"]
        ]
        == CASE_LAYOUT,
        "Body matrix must retain all six exact controls",
    )
    require(
        matrix["source_sha256"] == SOURCE_SHA256
        and matrix["http_source_sha256"] == HTTP_SOURCE_SHA256
        and matrix["log_source_sha256"] == LOG_SOURCE_SHA256
        and matrix["runtime_versions"] == RUNTIME_VERSIONS
        and matrix["reference_image"] == REFERENCE_IMAGE,
        "Body source authority drifted",
    )
    matches = [case for case in matrix["cases"] if case["name"] == name]
    require(len(matches) == 1, "Unknown body case")
    case = matches[0]
    states = read(matrix["state_scenario"])
    for key in ("effect_rows_sql", "operational_rows_sql"):
        matrix[key] = states[key]
    spec = read(matrix["reference_scenario"])
    require(spec["shared_seed"] == SHARED_SEED, "Body shared seed ownership drifted")
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
        stage = next(
            stage for stage in spec["stages"] if stage["name"] == "initial_permit"
        )
        response = {key: stage[key] for key in ("status", "body")}
        job_id = "worker-validation-job"
    request = {
        "method": "GET",
        "path": matrix["request_paths"][case["target_type"]],
        "authorization": f"Bearer {spec['token']}",
        "accept": "application/json",
    }
    return matrix, case, spec, shared, response, request, job_id


def capture_input_sha256(path):
    # Local capture inputs are Git text, whose checkout line endings can differ
    # between Windows and Linux. Universal-newline UTF-8 reading matches the
    # worker_source_sha256 convention: CRLF/CR become LF before UTF-8 hashing.
    # Do not parse/reserialize JSON (90.0 must remain 90.0), alter other text,
    # normalize raw observations, or apply this rule to pinned image bytes.
    return hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()


def verify_sources(matrix, contracts):
    require(
        worker_source_sha256() == SOURCE_SHA256 == matrix["source_sha256"],
        "Unexpected installed worker source",
    )
    require(
        published_log_source_sha256() == LOG_SOURCE_SHA256,
        "Unexpected published log source",
    )
    factory = Path("/app/services/issuance/application/canvas_lti_services.py")
    require(
        hashlib.sha256(factory.read_bytes()).hexdigest() == HTTP_SOURCE_SHA256,
        "Unexpected published HTTP factory",
    )
    require(
        {name: version(name) for name in RUNTIME_VERSIONS} == RUNTIME_VERSIONS,
        "Unexpected installed HTTP dependencies",
    )
    scripts = Path(__file__).parent
    files = {
        name: scripts / name
        for name in (
            Path(__file__).name,
            "canvas_worker_body_timeout_https_fixture.py",
            "canvas_worker_https_fixture.py",
            "canvas_worker_output_capture.py",
            "run_canvas_worker_rest_oracle.py",
            "run_canvas_worker_startup_oracle.py",
            "run_canvas_worker_provider_signals_oracle.py",
            "run_canvas_worker_provider_recovery_oracle.py",
        )
    }
    for name in (SCENARIO, SHARED_SEED, *CONTRACT_FILES.values()):
        files[name] = contracts / name
    return {name: capture_input_sha256(path) for name, path in files.items()}


def read_job(engine, job_id):
    with engine.connect() as connection:
        return dict(
            connection.execute(
                text(
                    "SELECT id,organization_id,target_id,attempt_count,status,lease_owner,"
                    "lease_expires_at,started_at,result FROM issuance_service.canvas_evidence_sync_jobs "
                    "WHERE id=:job_id AND organization_id='org-review' AND target_id='target-review'"
                ),
                {"job_id": job_id},
            )
            .mappings()
            .one()
        )


def sample_job(read):
    started = time.monotonic()
    job = read()
    ended = time.monotonic()
    require(
        0 <= ended - started <= TIMING["query_max_seconds"],
        "Body job observation exceeded its query budget",
    )
    return job, started, ended


def assert_same_generation(current, initial, *, leased):
    require(
        type(current) is dict
        and type(initial) is dict
        and set(current) == JOB_FIELDS
        and set(initial) == JOB_FIELDS,
        "Unexpected body job observation shape",
    )
    require(
        initial["id"] in {"worker-validation-job", "worker-roster-failure-job"}
        and initial["organization_id"] == "org-review"
        and initial["target_id"] == "target-review"
        and type(initial["attempt_count"]) is int
        and initial["attempt_count"] == 1
        and initial["status"] == "leased"
        and initial["lease_owner"] == "worker-rest"
        and initial["result"] == {}
        and isinstance(initial["started_at"], datetime)
        and isinstance(initial["lease_expires_at"], datetime)
        and initial["started_at"].tzinfo is not None
        and initial["lease_expires_at"].tzinfo is not None
        and initial["lease_expires_at"] > initial["started_at"],
        "Invalid original published body lease",
    )
    require(
        all(
            current[key] == initial[key]
            for key in (
                "id",
                "organization_id",
                "target_id",
                "attempt_count",
                "started_at",
            )
        )
        and type(current["attempt_count"]) is int,
        "Body job generation changed",
    )
    if leased:
        require(
            current["status"] == "leased"
            and current["lease_owner"] == initial["lease_owner"]
            and current["lease_expires_at"] == initial["lease_expires_at"]
            and current["result"] == {},
            "Original published body lease changed",
        )
    else:
        require(
            current["status"] in TERMINAL
            and current["lease_owner"] is None
            and current["lease_expires_at"] is None,
            "Body terminal job did not release its lease",
        )


def assert_target_generation(target):
    require(
        type(target["config_version"]) is int
        and target["config_version"] == 1
        and target["enabled"] is True,
        "Body target generation or enabled state changed",
    )


def await_terminal(read, guard, initial, body_started_at, timeout):
    original, lower, initial_end = initial
    assert_same_generation(original, original, leased=True)
    require(
        all(
            finite_number(value)
            for value in (lower, initial_end, body_started_at, timeout)
        )
        and lower <= initial_end <= body_started_at
        and 0 < timeout <= 60,
        "Invalid body transition observation origin",
    )
    deadline = body_started_at + timeout
    while True:
        guard()
        require(
            time.monotonic() <= deadline,
            "Body terminal observation exceeded its budget",
        )
        current, query_start, query_end = sample_job(read)
        require(query_end <= deadline, "Body terminal query returned after its budget")
        if current["status"] == "leased":
            assert_same_generation(current, original, leased=True)
            lower = query_start
        else:
            assert_same_generation(current, original, leased=False)
            return current, lower, query_end
        time.sleep(0.025)


def inactivity_bounds(case, timing):
    family = "application" if case["target_type"] == "learner_application" else "roster"
    return timing[f"{family}_inactivity_min_seconds"], timing[
        f"{family}_inactivity_max_seconds"
    ]


def assert_transition_timing(lower_at, upper_at, flush, case, timing):
    samples = (
        lower_at,
        upper_at,
        flush["write_started_at"],
        flush["write_completed_at"],
    )
    require(
        all(finite_number(value) for value in samples)
        and lower_at <= upper_at
        and flush["write_started_at"] <= flush["write_completed_at"],
        "Invalid body transition timing samples",
    )
    if case["mode"] == "stall":
        lower = lower_at - flush["write_completed_at"]
        upper = upper_at - flush["write_started_at"]
        minimum, maximum = inactivity_bounds(case, timing)
        require(
            minimum <= lower <= upper <= maximum,
            "Body durable transition differs from declared inactivity window",
        )
    else:
        # Incomplete JSON cannot establish successful evidence before the final
        # slot. Do not let a later idle snapshot hide a wholly early terminal
        # interval. A valid query interval may straddle the final flush.
        require(
            flush["write_started_at"]
            - timing["success_transition_early_uncertainty_seconds"]
            <= lower_at
            <= upper_at
            <= flush["write_completed_at"]
            + timing["success_transition_after_flush_max_seconds"]
            and upper_at >= flush["write_started_at"],
            "Successful body terminal interval differs from its final-write window",
        )
    return True


def assert_outcome_timing(
    received_at, body_started_at, outcome_at, flush, case, timing
):
    require(
        all(
            finite_number(value) for value in (received_at, body_started_at, outcome_at)
        )
        and 0 <= body_started_at - received_at < timing["initial_response_max_seconds"],
        "Body response setup exceeded its request-relative budget",
    )
    budget = timing[f"{case['mode']}_outcome_max_seconds"]
    require(
        0 <= outcome_at - body_started_at <= budget
        and outcome_at - received_at < budget + timing["initial_response_max_seconds"],
        "Body idle outcome exceeded its observation budget",
    )
    if case["mode"] == "stall":
        minimum, maximum = inactivity_bounds(case, timing)
        require(
            all(
                finite_number(flush[key])
                for key in ("write_started_at", "write_completed_at")
            )
            and flush["write_started_at"] <= flush["write_completed_at"]
            and minimum <= outcome_at - flush["write_completed_at"]
            and outcome_at - flush["write_started_at"] <= maximum,
            "Body idle outcome differs from declared inactivity window",
        )
    return True


def assert_schedule(https, case, timing):
    observations = https.observations()
    offsets = SCHEDULES[case["mode"]]
    require(
        len(observations) == len(offsets)
        and https.schedule_completed.is_set()
        and https.handler_finished.is_set(),
        "Body schedule did not finish all declared attempts",
    )
    require(
        finite_number(https.received_at)
        and finite_number(https.body_started_at)
        and 0
        <= https.body_started_at - https.received_at
        < timing["initial_response_max_seconds"],
        "Body schedule origin differs",
    )
    projected = []
    for index, (observation, offset, chunk) in enumerate(
        zip(observations, offsets, https.chunks, strict=True)
    ):
        require(
            set(observation)
            == {
                "index",
                "scheduled_offset_seconds",
                "write_started_seconds",
                "write_completed_seconds",
                "byte_count",
                "flushed_byte_count",
                "outcome",
                "disconnect_category",
            },
            "Unexpected body flush observation shape",
        )
        started, ended = (
            observation["write_started_seconds"],
            observation["write_completed_seconds"],
        )
        require(
            type(observation["index"]) is int
            and observation["index"] == index
            and finite_number(observation["scheduled_offset_seconds"])
            and observation["scheduled_offset_seconds"] == offset
            and finite_number(started)
            and finite_number(ended)
            and offset
            <= started
            <= ended
            <= offset + timing["write_lateness_max_seconds"],
            "Body write missed its declared schedule band",
        )
        require(
            type(observation["byte_count"]) is int
            and observation["byte_count"] == len(chunk) > 0,
            "Body attempted byte count differs",
        )
        if observation["outcome"] == "flushed":
            require(
                type(observation["flushed_byte_count"]) is int
                and observation["flushed_byte_count"] == len(chunk)
                and observation["disconnect_category"] is None,
                "Body successful flush evidence differs",
            )
        else:
            require(
                case["mode"] == "stall"
                and index == len(offsets) - 1
                and observation["outcome"] == "peer_closed"
                and observation["flushed_byte_count"] is None
                and observation["disconnect_category"]
                in {"broken_pipe", "connection_reset", "tls_eof", "tls_closed"},
                "Unexpected body disconnect or failed progress",
            )
        projected.append(
            {
                key: copy.deepcopy(observation[key])
                for key in (
                    "index",
                    "scheduled_offset_seconds",
                    "byte_count",
                    "flushed_byte_count",
                    "outcome",
                    "disconnect_category",
                )
            }
            | {"write_within_declared_band": True}
        )
    return projected


def assert_outcome(state, case, initial_effects, completed_effects):
    require(len(state["jobs"]) == 1, "Body case must retain exactly one job")
    job, target = state["jobs"][0], state["target"]
    assert_target_generation(target)
    require(
        job["status"] == case["expected_status"]
        and job["attempt_count"] == 1
        and job["max_attempts"] == 8
        and job["started"] is True
        and job["lease_owner_present"] is False
        and job["lease_expires_present"] is False,
        "Body job outcome differs",
    )
    require(
        state["heartbeat"]["metadata"]["phase"] == "idle"
        and state["heartbeat"]["metadata"]["leased_jobs"] == 0,
        "Body worker did not become idle",
    )
    require(
        state["oauth"]
        == {
            "status": "connected",
            "reauthorization_required": False,
            "refresh_lease_owner_present": False,
            "secret_enabled": True,
            "secret_used": True,
        },
        "Body OAuth projection differs",
    )
    require(
        target["target_type"] == case["target_type"]
        and target["candidate_count"] == 0
        and target["observation_count"] == 0,
        "Body target or candidate projection differs",
    )
    roster = case["target_type"] == "background_roster"
    retry = job["status"] == "retry"
    require(
        target["worker_heartbeat_present"] is (retry or not roster)
        and target["last_success_present"] is (not retry),
        "Body target heartbeat/success projection differs",
    )
    if not roster:
        require(
            target["metadata"] == {"worker_id": "worker-rest"}
            and target["roster_cycle_completed_at_present"] is False,
            "Application body target metadata changed",
        )
    if retry:
        require(
            (job["last_error_code"], job["last_error_summary"])
            == ERRORS[case["target_type"]]
            and job["result"] == {}
            and job["completed"] is False
            and job["retry_scheduled"] is True
            and job["retry_delay_within_backoff_bounds"] is True,
            "Body retry classification differs",
        )
        require(state["facts"] == [], "Unavailable body created facts")
        # Application validation state may change; partial JSON is not evidence.
        require(
            all(
                completed_effects[key] == initial_effects[key]
                for key in (
                    "facts",
                    "heads",
                    "reviews",
                    "events",
                    "candidates",
                    "observations",
                )
            ),
            "Unavailable body changed business evidence",
        )
        if roster:
            require(
                target["metadata"]
                == {
                    "roster_cursor": 1,
                    "synthetic_marker": "preserve",
                    "worker_id": "worker-rest",
                }
                and target["roster_cycle_completed_at_present"] is False,
                "Failed roster body lost its cursor or metadata",
            )
    else:
        require(
            job["last_error_code"] is None
            and job["last_error_summary"] is None
            and job["completed"] is True,
            "Successful body retained a failure",
        )
        if roster:
            require(
                state["facts"] == []
                and job["result"]
                == {
                    "candidates_seen": 0,
                    "pending_claim": 0,
                    "identity_link_required": 0,
                    "observations_written": 0,
                },
                "Empty roster body result differs",
            )
            require(
                target["metadata"]
                == {
                    "roster_cursor": 0,
                    "roster_size": 0,
                    "synthetic_marker": "preserve",
                }
                and target["roster_cycle_completed_at_present"] is True,
                "Successful roster body did not wrap its cursor",
            )
        else:
            require(
                len(state["facts"]) == 1
                and job["result"]["facts_created"] == 1
                and job["result"]["requirements_checked"] == 1
                and job["result"]["policy_allowed"] is True,
                "Successful application body did not create its evidence",
            )


def wait_until(predicate, timeout, message, guard=lambda: None):
    require(finite_number(timeout) and timeout > 0, "Invalid body wait budget")
    deadline = time.monotonic() + timeout
    while True:
        guard()
        require(time.monotonic() <= deadline, message)
        value = predicate()
        require(time.monotonic() <= deadline, message)
        if value:
            return value
        time.sleep(0.025)


def cleanup(child, https, engine):
    """Attempt every owned cleanup; never replace an active private-safe failure."""
    original = sys.exception()
    failures = 0
    for action in (
        https.cancel_schedule.set,
        https.initial_ready.set,
        (lambda: finish_worker(child)) if child is not None else (lambda: None),
        https.close,
        engine.dispose if engine is not None else (lambda: None),
    ):
        try:
            action()
        except BaseException:
            failures += 1
    if failures:
        if original is not None:
            original.add_note(
                "Owned body cleanup also failed; all owners were attempted"
            )
        else:
            raise AssertionError(
                "Owned body cleanup failed; all owners were attempted"
            ) from None


def flush_interval(https, index):
    observations = https.observations()
    require(
        len(observations) > index
        and observations[index]["index"] == index
        and observations[index]["outcome"] == "flushed",
        "Required body progress was not successfully flushed",
    )
    observation = observations[index]
    require(
        all(
            finite_number(observation[key])
            for key in (
                "write_started_seconds",
                "write_completed_seconds",
            )
        )
        and finite_number(https.body_started_at),
        "Invalid actual body flush timing",
    )
    return {
        "write_started_at": https.body_started_at
        + observation["write_started_seconds"],
        "write_completed_at": https.body_started_at
        + observation["write_completed_seconds"],
    }


def late_window_end(https, outcome_at, case, timing):
    observations = https.observations()
    require(
        observations
        and finite_number(https.body_started_at)
        and finite_number(outcome_at),
        "Invalid body late-window origin",
    )
    require(
        all(
            finite_number(item["write_completed_seconds"])
            and item["write_completed_seconds"] >= 0
            for item in observations
        ),
        "Invalid body late-write timing",
    )
    successful = [item for item in observations if item["outcome"] == "flushed"]
    require(successful, "Body late window has no successful progress")
    final_completed_at = (
        https.body_started_at + observations[-1]["write_completed_seconds"]
    )
    last_success_at = https.body_started_at + successful[-1]["write_completed_seconds"]
    read_budget = 15 if case["target_type"] == "learner_application" else 20
    return max(
        final_completed_at + timing["after_final_attempt_seconds"],
        outcome_at + timing["after_outcome_seconds"],
        last_success_at + read_budget + timing["after_read_budget_seconds"],
    )


def finish_and_verify_output(child, stdout, stderr, token):
    child.send_signal(signal.SIGINT)
    exit_code = child.wait(timeout=10)
    require(exit_code == -2, "Unexpected owned Python body worker shutdown")
    # Start strict: legitimate additional shutdown output must first receive
    # separate source review; it cannot silently disappear with the owned files.
    # This neither manufactures native log equivalence nor widens the existing
    # pre-interrupt classifier.
    return exit_code, observed_log_profile(stdout, stderr, token)


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix, case, spec, shared, response, request, job_id = load_case(
        contracts, case_name
    )
    provenance = verify_sources(matrix, contracts)
    timing, offsets = matrix["timing"], matrix["schedules"][case["mode"]]
    https = BodyTimeoutHttpsFixture(
        request,
        response,
        chunk_offsets=offsets,
        late_disconnect_from_index=len(offsets) - 1
        if case["mode"] == "stall"
        else None,
    )
    child = engine = None
    with ExitStack() as output_owner:
        try:
            https.__enter__()
            directory = output_owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-worker-body-output-")
            )
            stdout_writer, stdout = owned_log_streams(output_owner, directory)
            stderr_writer, stderr = owned_log_streams(output_owner, directory)
            # A session-local statement budget bounds observation SQL only. It
            # changes no worker, database clock, durable row or schema setting.
            engine = create_engine(
                DATABASE,
                hide_parameters=True,
                connect_args={"options": "-c statement_timeout=1000"},
            )
            preserved = seed_worker_database(engine, https.origin, spec, shared)

            def observe():
                state, rows, ciphertext = snapshot(engine, spec, shared)
                require(
                    (rows, ciphertext) == preserved,
                    "Body capture changed issued rows or ciphertext",
                )
                state["target"] = scalar(engine, matrix["target_sql"])
                assert_target_generation(state["target"])
                return state

            def effects():
                return scalar(engine, matrix["effect_rows_sql"])

            def operational():
                return scalar(engine, matrix["operational_rows_sql"])

            def guard():
                require(
                    child.poll() is None, "Owned body worker exited before observation"
                )
                https.assert_requests()

            initial_effects = effects()
            child = start_worker(
                worker_case(https.origin, https.cert, matrix["environment"]),
                "worker-rest",
                stdout=stdout_writer,
                stderr=stderr_writer,
            )
            wait_until(
                https.request_started.is_set,
                30,
                "Body provider request was not received",
                lambda: require(
                    child.poll() is None, "Owned body worker exited before request"
                ),
            )
            guard()
            before = observe()
            require(
                len(before["jobs"]) == 1
                and before["jobs"][0]["status"] == "leased"
                and before["facts"] == []
                and before["target"]["worker_heartbeat_present"] is True,
                "Initial held body state differs",
            )
            initial = sample_job(lambda: read_job(engine, job_id))
            original = initial[0]
            assert_same_generation(original, original, leased=True)
            require(original["id"] == job_id, "Body seed retained the wrong job")

            def original_lease_current():
                require(
                    original["lease_expires_at"]
                    > scalar(engine, "SELECT clock_timestamp()"),
                    "Original body lease expired during observation",
                )
                return True

            original_lease_current()
            require(
                not https.body_started.is_set(), "Body started before held snapshot"
            )
            https.initial_ready.set()
            wait_until(
                https.body_started.is_set,
                timing["initial_response_max_seconds"],
                "Body stream did not start promptly",
                guard,
            )
            require(
                0
                <= https.body_started_at - https.received_at
                < timing["initial_response_max_seconds"],
                "Body held snapshot exceeded setup budget",
            )
            budget = timing[f"{case['mode']}_outcome_max_seconds"]
            terminal, lower_at, upper_at = await_terminal(
                lambda: read_job(engine, job_id),
                guard,
                initial,
                https.body_started_at,
                budget,
            )
            # The first terminal job is already frozen. Idle/snapshots may not
            # redefine its timestamp or conceal an earlier terminal transition.
            require(
                terminal["status"] == case["expected_status"],
                "First body terminal outcome differs",
            )

            def idle():
                state = observe()
                require(
                    len(state["jobs"]) == 1
                    and state["jobs"][0]["status"] == terminal["status"]
                    and state["jobs"][0]["result"] == terminal["result"],
                    "Body terminal job changed before idle",
                )
                if state["heartbeat"]["metadata"]["phase"] == "idle":
                    return state, time.monotonic()
                return None

            outcome, outcome_at = wait_until(
                idle,
                https.body_started_at + budget - time.monotonic(),
                "Body idle outcome exceeded its budget",
                guard,
            )
            progress_index = 1 if case["mode"] == "stall" else len(offsets) - 1
            flush = flush_interval(https, progress_index)
            require(
                https.received_at <= lower_at <= upper_at <= outcome_at,
                "Body terminal interval is not ordered within actual observations",
            )
            assert_transition_timing(lower_at, upper_at, flush, case, timing)
            assert_outcome_timing(
                https.received_at,
                https.body_started_at,
                outcome_at,
                flush,
                case,
                timing,
            )
            outcome_rows = effects(), operational()
            assert_outcome(outcome, case, initial_effects, outcome_rows[0])
            original_lease_current()
            logs = observed_log_profile(stdout, stderr, spec["token"])

            def stable():
                guard()
                require(
                    (effects(), operational()) == outcome_rows,
                    "Late body traffic changed durable rows",
                )

            # Prompt writes may already be complete before idle bookkeeping.
            # Their actual ledger still has to meet every declared flush bound.
            if not https.schedule_completed.is_set():
                wait_until(
                    https.schedule_completed.is_set,
                    https.body_started_at
                    + offsets[-1]
                    + timing["write_lateness_max_seconds"]
                    + 1
                    - time.monotonic(),
                    "Independent final body attempt did not finish",
                    stable,
                )
            chunks = assert_schedule(https, case, timing)
            final = https.observations()[-1]
            final_started_at = https.body_started_at + final["write_started_seconds"]
            final_completed_at = (
                https.body_started_at + final["write_completed_seconds"]
            )
            outcome_before_final = outcome_at < final_started_at
            if case["mode"] == "stall":
                require(
                    upper_at < final_started_at and outcome_before_final,
                    "Stalled body outcome was not established before independent final attempt",
                )
            else:
                # Preserve observed-outcome-after-flush; do not pretend the
                # conservative query lower bound measures client byte receipt.
                require(
                    outcome_at >= final_completed_at,
                    "Successful body outcome preceded the complete response",
                )
            stop_at = late_window_end(https, outcome_at, case, timing)
            while time.monotonic() < stop_at:
                stable()
                time.sleep(0.025)
            https.close()  # Joins actual handlers; writer-finished alone is insufficient.
            stable()
            require(
                assert_schedule(https, case, timing) == chunks and observe() == outcome,
                "Joined body handler changed transport or business state",
            )
            require(
                observed_log_profile(stdout, stderr, spec["token"]) == logs,
                "Body worker output changed before interruption",
            )
            original_lease_current()
            exit_code, shutdown_logs = finish_and_verify_output(
                child, stdout, stderr, spec["token"]
            )
            child = None
            https.assert_requests()
            require(
                (effects(), operational()) == outcome_rows
                and observe() == outcome
                and assert_schedule(https, case, timing) == chunks,
                "Body state changed after worker exit",
            )
            require(
                verify_sources(matrix, contracts) == provenance,
                "Body capture inputs changed while worker ran",
            )
            return {
                "schema": "marty.canvas-worker-body-timeout-observation/v1",
                "case": case_name,
                "before_release": before,
                "outcome": outcome,
                "requests": copy.deepcopy(https.requests),
                "chunks": chunks,
                "timing": {
                    "initial_response_within_request_budget": True,
                    "first_terminal_interval_within_declared_window": True,
                    "idle_outcome_within_declared_window": True,
                    "all_attempts_within_declared_schedule": True,
                    "outcome_before_final_attempt": outcome_before_final,
                    "original_lease_current_through_join": True,
                    "late_window_completed": True,
                },
                "stable_after_final_attempt_handler_join_and_interrupt": True,
                "exit_code_after_interrupt": exit_code,
                "logs_before_interrupt": logs,
                "logs_after_interrupt": shutdown_logs,
                "source_sha256": copy.deepcopy(SOURCE_SHA256),
                "http_source_sha256": HTTP_SOURCE_SHA256,
                "log_source_sha256": LOG_SOURCE_SHA256,
                "runtime_versions": copy.deepcopy(RUNTIME_VERSIONS),
                "capture_source_sha256": provenance,
            }
        finally:
            cleanup(child, https, engine)
