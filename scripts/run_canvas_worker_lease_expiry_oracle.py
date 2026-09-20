"""Reference-only live HTTPS/blocked-renewal observations, never native parity.

An owned row lock spans either a current or naturally expired original lease.
Post-unblock renewal and effects are observations, not preselected failures.
Existing worker, SQL clock, provider, source-pinned fixture and guards are intact.
"""

from contextlib import ExitStack
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time

from sqlalchemy import create_engine, text

from canvas_worker_body_timeout_https_fixture import BodyTimeoutHttpsFixture
from canvas_worker_output_capture import observed_log_profile, owned_log_streams
import run_canvas_worker_body_timeout_oracle as body
from run_canvas_worker_provider_recovery_oracle import scalar
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import DATABASE, finish_worker, start_worker

CASE_LAYOUT = (
    ("renewal_lock_early_release", "request_plus_12"),
    ("renewal_lock_crosses_expiry", "original_expiry_plus_1"),
)
SCHEDULE = [0, 8, 16, 24, 34]
ENVIRONMENT = {
    "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
    "CANVAS_SYNC_WORKER_LEASE_SECONDS": "30",
    "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
    "LOG_LEVEL": "WARNING",
}
SOURCE_SHA256 = body.SOURCE_SHA256 | {
    "issuance.infrastructure.adapters.postgres_repository": "34ba42bd10227e0040c99378254c3652c388bab3131aadfdba2e0fe92cf89ccb",
    "issuance.application.canvas_sync_jobs": "e3cc45ef4b40cf9f80ad46699768e7d584bde53e75d29f36ab783780fa03e5f9",
}
SCENARIO = "canvas-worker-lease-expiry-scenarios.json"
require = body.require
late_window_end = body.late_window_end


def validate_case(name):
    require(
        type(name) is str and name in dict(CASE_LAYOUT), "Unknown lease-expiry case"
    )
    return {"name": name, "release_policy": dict(CASE_LAYOUT)[name]}


def validate_job(current, initial, *, locked):
    body.assert_same_generation(initial, initial, leased=True)
    require(initial["id"] == "worker-validation-job", "Wrong lease-expiry job owner")
    require(
        type(current) is dict and set(current) == body.JOB_FIELDS,
        "Invalid lease-expiry job shape",
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
        "Lease-expiry job generation changed",
    )
    if locked:
        require(current == initial, "Blocked original lease changed")
    else:
        require(
            current["status"] in {"leased", "succeeded", "retry", "dead_letter"},
            "Unexpected observed lease-expiry job status",
        )
        if current["status"] == "leased":
            require(
                current["lease_owner"] == initial["lease_owner"]
                and isinstance(current["lease_expires_at"], datetime)
                and current["lease_expires_at"].tzinfo is not None
                and current["lease_expires_at"] >= initial["lease_expires_at"],
                "Observed lease renewal owner or deadline changed unexpectedly",
            )
        else:
            require(
                current["lease_owner"] is None and current["lease_expires_at"] is None,
                "Observed terminal lease was not released",
            )
    return current["status"]


def assert_blocker(row, expected_blocker):
    keys = {"waiting_count", "matching_count", "worker_pid", "blocker_pid"}
    require(
        type(row) is dict
        and set(row) == keys
        and all(type(value) is int for value in row.values())
        and type(expected_blocker) is int
        and expected_blocker > 1
        and row["waiting_count"] == row["matching_count"] == 1
        and row["blocker_pid"] == expected_blocker
        and row["worker_pid"] > 1
        and row["worker_pid"] != expected_blocker,
        "Exact owned renewal blocker was not observed",
    )
    return row["worker_pid"]


def validate_clock(sample, initial=None):
    require(
        type(sample) is dict
        and set(sample) == {"database_now", "monotonic_before", "monotonic_after"},
        "Invalid lease-expiry clock sample shape",
    )
    now, before, after = (
        sample[key] for key in ("database_now", "monotonic_before", "monotonic_after")
    )
    require(
        isinstance(now, datetime)
        and now.tzinfo is not None
        and all(body.finite_number(value) for value in (before, after))
        and 0 <= after - before <= 0.5,
        "Lease-expiry clock observation exceeded its bound",
    )
    if initial is not None:
        validate_clock(initial)
        delta = (now - initial["database_now"]).total_seconds()
        require(
            before - initial["monotonic_after"] - 0.5
            <= delta
            <= after - initial["monotonic_before"] + 0.5,
            "Lease-expiry database and monotonic clocks disagree",
        )
    return sample


def assert_release_timing(case, received_at, before, after, original_expiry):
    require(case == validate_case(case["name"]), "Invalid lease-expiry release policy")
    validate_clock(before)
    validate_clock(after, before)
    require(
        body.finite_number(received_at)
        and isinstance(original_expiry, datetime)
        and original_expiry.tzinfo is not None
        and 0 <= after["monotonic_after"] - before["monotonic_before"] <= 0.5,
        "Lease-expiry lock release exceeded its bound",
    )
    if case["release_policy"] == "request_plus_12":
        require(
            received_at + 11.5
            <= before["monotonic_before"]
            <= after["monotonic_after"]
            <= received_at + 12.5
            and after["database_now"] < original_expiry,
            "Early lock release was outside the current-lease control window",
        )
    else:
        require(
            1
            <= (before["database_now"] - original_expiry).total_seconds()
            <= (after["database_now"] - original_expiry).total_seconds()
            <= 2,
            "Cross-expiry release was outside the original-expiry window",
        )
    return True


def read_clock(engine):
    before = time.monotonic()
    now = scalar(engine, "SELECT clock_timestamp()")
    return validate_clock(
        {
            "database_now": now,
            "monotonic_before": before,
            "monotonic_after": time.monotonic(),
        }
    )


def read_blocker(engine, blocker_pid):
    # Only fixed counts and owned backend identities cross this internal seam.
    # No query text, bind parameters, arbitrary backend rows or IDs are emitted.
    started = time.monotonic()
    with engine.connect() as connection:
        row = dict(
            connection.execute(
                text(
                    "SELECT count(*)::integer AS waiting_count, "
                    "count(*) FILTER (WHERE usename='oracle' AND state='active' "
                    "AND wait_event_type='Lock' AND query LIKE 'UPDATE issuance_service.canvas_evidence_sync_jobs SET%')::integer AS matching_count, "
                    "COALESCE(min(pid),0)::integer AS worker_pid, CAST(:blocker AS integer) AS blocker_pid "
                    "FROM pg_stat_activity WHERE datname=current_database() "
                    "AND :blocker=ANY(pg_blocking_pids(pid))"
                ),
                {"blocker": blocker_pid},
            )
            .mappings()
            .one()
        )
    require(
        0 <= time.monotonic() - started <= 0.5,
        "Lease-expiry blocker observation exceeded its bound",
    )
    return row


def assert_schedule(fixture, *, crosses_expiry):
    ledger = fixture.observations()
    require(
        len(ledger) == len(SCHEDULE)
        and fixture.schedule_completed.is_set()
        and fixture.handler_finished.is_set(),
        "Lease-expiry body schedule incomplete",
    )
    projected = []
    for index, (row, offset, chunk) in enumerate(
        zip(ledger, SCHEDULE, fixture.chunks, strict=True)
    ):
        require(
            set(row)
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
            "Unexpected lease-expiry body observation shape",
        )
        require(
            type(row["index"]) is int
            and row["index"] == index
            and all(
                body.finite_number(row[key])
                for key in (
                    "scheduled_offset_seconds",
                    "write_started_seconds",
                    "write_completed_seconds",
                )
            )
            and row["scheduled_offset_seconds"] == offset
            and offset
            <= row["write_started_seconds"]
            <= row["write_completed_seconds"]
            <= offset + 0.5
            and type(row["byte_count"]) is int
            and row["byte_count"] == len(chunk) > 0,
            "Lease-expiry body missed its declared flush schedule",
        )
        if row["outcome"] == "flushed":
            require(
                type(row["flushed_byte_count"]) is int
                and row["flushed_byte_count"] == len(chunk)
                and row["disconnect_category"] is None,
                "Invalid lease-expiry successful flush",
            )
        else:
            require(
                crosses_expiry
                and index == len(SCHEDULE) - 1
                and row["outcome"] == "peer_closed"
                and row["flushed_byte_count"] is None
                and row["disconnect_category"]
                in {"broken_pipe", "connection_reset", "tls_eof", "tls_closed"},
                "Unexpected lease-expiry body failure",
            )
        projected.append(
            {
                key: row[key]
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


def cleanup(blocker, child, fixture, engine):
    original = sys.exception()
    failed = False
    operations = []
    if blocker is not None:
        operations.extend((blocker.rollback, blocker.close))
    if fixture is not None:
        operations.extend((fixture.cancel_schedule.set, fixture.initial_ready.set))
    if child is not None:
        operations.append(lambda: finish_worker(child))
    if fixture is not None:
        operations.append(fixture.close)
    if engine is not None:
        operations.append(engine.dispose)
    for operation in operations:
        try:
            operation()
        except BaseException:
            failed = True
    if failed:
        if original is not None:
            original.add_note("Owned lease-expiry cleanup failed; all owners attempted")
        else:
            raise AssertionError(
                "Owned lease-expiry cleanup failed; all owners attempted"
            ) from None


def verify_inputs(contracts, matrix):
    scenario = json.loads((contracts / SCENARIO).read_text(encoding="utf-8"))
    require(
        scenario["schema"] == "marty.canvas-worker-lease-expiry-scenarios/v1"
        and scenario["source_sha256"] == SOURCE_SHA256
        and scenario["environment"] == ENVIRONMENT
        and scenario["schedule"] == SCHEDULE
        and all(body.finite_number(value) for value in scenario["schedule"])
        and scenario["cases"] == [validate_case(name) for name, _ in CASE_LAYOUT],
        "Lease-expiry scenario differs from its reviewed controls",
    )
    provenance = body.verify_sources(matrix, contracts)
    for name, expected in SOURCE_SHA256.items():
        spec = importlib.util.find_spec(name)
        require(
            spec is not None and spec.origin is not None,
            "Missing pinned lease-expiry source",
        )
        observed = hashlib.sha256(
            Path(spec.origin).read_text(encoding="utf-8").encode()
        ).hexdigest()
        require(observed == expected, "Pinned lease-expiry source differs")
    return provenance | {
        SCENARIO: body.capture_input_sha256(contracts / SCENARIO),
        Path(__file__).name: body.capture_input_sha256(Path(__file__)),
    }


def run(case_name):
    case = validate_case(case_name)
    crosses_expiry = case["release_policy"] == "original_expiry_plus_1"
    contracts = Path("/verification/contracts")
    matrix, _, spec, shared, response, request, job_id = body.load_case(
        contracts, "application_body_progress"
    )
    provenance = verify_inputs(contracts, matrix)
    fixture = BodyTimeoutHttpsFixture(
        request,
        response,
        chunk_offsets=SCHEDULE,
        late_disconnect_from_index=4 if crosses_expiry else None,
    )
    child = engine = blocker = None
    with ExitStack() as owner:
        try:
            fixture.__enter__()
            directory = owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-lease-expiry-output-")
            )
            stdout_writer, stdout = owned_log_streams(owner, directory)
            stderr_writer, stderr = owned_log_streams(owner, directory)
            engine = create_engine(
                DATABASE,
                hide_parameters=True,
                connect_args={"options": "-c statement_timeout=1000"},
                pool_size=4,
                max_overflow=0,
            )
            preserved = seed_worker_database(engine, fixture.origin, spec, shared)

            def observe():
                state, rows, ciphertext = snapshot(engine, spec, shared)
                require(
                    (rows, ciphertext) == preserved,
                    "Lease-expiry changed issued rows or ciphertext",
                )
                state["target"] = scalar(engine, matrix["target_sql"])
                body.assert_target_generation(state["target"])
                return state

            def effects():
                return scalar(engine, matrix["effect_rows_sql"])

            def operational():
                return scalar(engine, matrix["operational_rows_sql"])

            def guard():
                require(child.poll() is None, "Owned lease-expiry worker exited")
                fixture.assert_requests()

            child = start_worker(
                worker_case(fixture.origin, fixture.cert, ENVIRONMENT),
                "worker-rest",
                stdout=stdout_writer,
                stderr=stderr_writer,
            )
            body.wait_until(
                fixture.request_started.is_set,
                30,
                "Lease-expiry provider request missing",
                lambda: require(
                    child.poll() is None,
                    "Owned lease-expiry worker exited before request",
                ),
            )
            guard()
            before = observe()
            # Effects already visible at the held request form the locked-I/O
            # baseline; do not conflate earlier legitimate setup reads with
            # changes occurring while the provider response is incomplete.
            initial_effects = effects()
            initial = body.sample_job(lambda: body.read_job(engine, job_id))[0]
            validate_job(initial, initial, locked=True)
            clock_origin = read_clock(engine)
            require(
                0
                <= (
                    clock_origin["database_now"] - initial["started_at"]
                ).total_seconds()
                <= 2
                and initial["lease_expires_at"] > clock_origin["database_now"]
                and before["facts"] == []
                and before["heartbeat"]["metadata"]["phase"] == "processing",
                "Lease-expiry initial held generation or timing differs",
            )
            blocker = engine.connect()
            blocker.exec_driver_sql("SET LOCAL lock_timeout='1s'")
            blocker_pid = blocker.exec_driver_sql(
                "SELECT pg_backend_pid()"
            ).scalar_one()
            require(
                blocker.execute(
                    text(
                        "SELECT id FROM issuance_service.canvas_evidence_sync_jobs "
                        "WHERE id=:job_id AND organization_id='org-review' FOR UPDATE"
                    ),
                    {"job_id": job_id},
                ).scalar_one()
                == job_id,
                "Lease-expiry row lock selected wrong job",
            )
            require(
                not fixture.body_started.is_set(),
                "Lease-expiry body preceded locked snapshot",
            )
            fixture.initial_ready.set()
            body.wait_until(
                fixture.body_started.is_set, 2, "Lease-expiry body did not start", guard
            )
            require(
                0 <= fixture.body_started_at - fixture.received_at < 2,
                "Lease-expiry body setup missed request budget",
            )
            worker_pid = None
            while True:
                guard()
                sample = read_clock(engine)
                validate_clock(sample, clock_origin)
                current = body.sample_job(lambda: body.read_job(engine, job_id))[0]
                validate_job(current, initial, locked=True)
                blocked = read_blocker(engine, blocker_pid)
                if blocked["waiting_count"]:
                    observed_pid = assert_blocker(blocked, blocker_pid)
                    require(
                        worker_pid is None or worker_pid == observed_pid,
                        "Lease-expiry blocked worker identity changed",
                    )
                    worker_pid = observed_pid
                release_due = (
                    (
                        sample["database_now"] - initial["lease_expires_at"]
                    ).total_seconds()
                    >= 1
                    if crosses_expiry
                    else time.monotonic() >= fixture.received_at + 12
                )
                if release_due:
                    require(
                        worker_pid is not None, "Renewal never reached the owned lock"
                    )
                    require(
                        assert_blocker(blocked, blocker_pid) == worker_pid,
                        "Renewal left lock before release",
                    )
                    require(
                        len(fixture.observations()) >= 2
                        and not fixture.schedule_completed.is_set()
                        and not fixture.handler_finished.is_set()
                        and not fixture.chunk_events[-1].is_set(),
                        "Lease-expiry provider I/O was not pending at release",
                    )
                    require(
                        effects() == initial_effects,
                        "Incomplete lease-expiry response changed business effects",
                    )
                    release_state = observe()
                    locked_sample = body.sample_job(
                        lambda: body.read_job(engine, job_id)
                    )
                    validate_job(
                        locked_sample[0],
                        initial,
                        locked=True,
                    )
                    released_before = read_clock(engine)
                    validate_clock(released_before, clock_origin)
                    blocker.rollback()
                    released_after = read_clock(engine)
                    assert_release_timing(
                        case,
                        fixture.received_at,
                        released_before,
                        released_after,
                        initial["lease_expires_at"],
                    )
                    blocker.close()
                    blocker = None
                    break
                require(
                    sample["monotonic_after"] - fixture.received_at < 34,
                    "Lease-expiry lock release was not reached",
                )
                time.sleep(0.025)
            lease_advanced_after_release = False
            first_terminal = None
            # One common loop owns EVERY post-release narrow observation. An
            # immediately terminal first sample is bracketed by the last real
            # locked leased query, never by an invented post-release timestamp.
            last_leased = locked_sample[1]
            limit = fixture.body_started_at + 40
            while True:
                guard()
                job, query_start, query_end = body.sample_job(
                    lambda: body.read_job(engine, job_id)
                )
                status = validate_job(job, initial, locked=False)
                if status == "leased":
                    require(
                        first_terminal is None, "Lease-expiry terminal job reverted"
                    )
                    last_leased = query_start
                    if job["lease_expires_at"] > initial["lease_expires_at"]:
                        lease_advanced_after_release = True
                elif first_terminal is None:
                    first_terminal = (status, last_leased, query_end)
                else:
                    require(
                        status == first_terminal[0],
                        "Lease-expiry terminal status changed",
                    )
                state = observe()
                observed_at = time.monotonic()
                require(
                    query_end < limit and observed_at < limit,
                    "Lease-expiry worker exceeded bounded idle observation",
                )
                if state["jobs"][0]["status"] != status:
                    require(
                        status == "leased"
                        and state["jobs"][0]["status"]
                        in {"succeeded", "retry", "dead_letter"},
                        "Lease-expiry state changed outside a terminal observation race",
                    )
                    # Full snapshots are not atomic with the earlier narrow
                    # read. Freeze the first terminal only on the next narrow
                    # query, retaining the previous verified leased start.
                    continue
                if state["heartbeat"]["metadata"]["phase"] == "idle":
                    outcome, outcome_at = state, observed_at
                    break
                require(
                    time.monotonic() < limit,
                    "Lease-expiry worker did not reach bounded idle observation",
                )
                time.sleep(0.025)
            # Only the early-release control has a predeclared positive result.
            # Cross-expiry output remains the actual complete observation.
            outcome_rows = effects(), operational()
            if not crosses_expiry:
                require(
                    lease_advanced_after_release, "Early-release control never renewed"
                )
                body.assert_outcome(
                    outcome,
                    {
                        "target_type": "learner_application",
                        "expected_status": "succeeded",
                    },
                    initial_effects,
                    outcome_rows[0],
                )

            def stable():
                guard()
                require(
                    (effects(), operational()) == outcome_rows,
                    "Late lease-expiry response changed durable state",
                )

            body.wait_until(
                lambda: (
                    fixture.schedule_completed.is_set()
                    and fixture.handler_finished.is_set()
                ),
                max(0.01, fixture.body_started_at + 35 - time.monotonic()),
                "Lease-expiry final body attempt missing",
                stable,
            )
            chunks = assert_schedule(fixture, crosses_expiry=crosses_expiry)
            logs = observed_log_profile(stdout, stderr, spec["token"])
            late_end = late_window_end(
                fixture, outcome_at, {"target_type": "learner_application"}, body.TIMING
            )
            while time.monotonic() < late_end:
                stable()
                time.sleep(0.025)
            fixture.close()
            stable()
            require(
                assert_schedule(fixture, crosses_expiry=crosses_expiry) == chunks
                and observe() == outcome,
                "Joined lease-expiry handlers changed observation",
            )
            require(
                observed_log_profile(stdout, stderr, spec["token"]) == logs,
                "Lease-expiry pre-interrupt output changed",
            )
            exit_code, shutdown_logs = body.finish_and_verify_output(
                child, stdout, stderr, spec["token"]
            )
            child = None
            require(
                (effects(), operational()) == outcome_rows and observe() == outcome,
                "Interrupted lease-expiry worker changed durable state",
            )
            require(
                verify_inputs(contracts, matrix) == provenance,
                "Lease-expiry capture inputs changed during execution",
            )
            return {
                "schema": "marty.canvas-worker-lease-expiry-observation/v1",
                "case": case_name,
                "initial_held": before,
                "before_release": release_state,
                "outcome": outcome,
                "requests": fixture.requests,
                "chunks": chunks,
                "blocked_renewal_observed": True,
                "provider_body_pending_at_release": True,
                "original_lease_expired_at_release": crosses_expiry,
                "lock_release_within_declared_window": True,
                "lease_advanced_after_release": lease_advanced_after_release,
                "first_terminal_status": first_terminal[0]
                if first_terminal is not None
                else None,
                "first_terminal_observed_separately_from_idle": first_terminal
                is not None,
                "stable_after_final_attempt_join_and_interrupt": True,
                "exit_code_after_interrupt": exit_code,
                "logs_before_interrupt": logs,
                "logs_after_interrupt": shutdown_logs,
                "source_sha256": SOURCE_SHA256,
                "capture_source_sha256": provenance,
                "scope": "Published process with owned renewal row lock and actual incomplete HTTPS body; post-release outcome observed, not native parity",
            }
        finally:
            cleanup(blocker, child, fixture, engine)


if __name__ == "__main__":
    require(len(sys.argv) == 2, "Expected one exact lease-expiry case")
    print(json.dumps(run(sys.argv[1]), sort_keys=True))
