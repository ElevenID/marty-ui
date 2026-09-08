"""Native lease-expiry transport owner; no SQL or published-worker execution.

The outer Rust caller owns PostgreSQL, its contained child owns the worker and
row lock, and this parent owns autonomous HTTPS writes. Diagnostic mismatches
finish bounded observation/cleanup before failing; they are never parity passes.
"""

from contextlib import ExitStack
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from canvas_worker_body_timeout_https_fixture import BodyTimeoutHttpsFixture
from canvas_worker_output_capture import owned_log_streams
from canvas_worker_owned_process import OwnedProcess
import run_canvas_worker_body_timeout_oracle as body
import run_canvas_worker_lease_expiry_oracle as reference
from test_canvas_worker_body_timeout_https import close_fixture, owned_fixture
import test_canvas_worker_timeout_https as header

ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = tuple(name for name, _ in reference.CASE_LAYOUT)
CORPUS_SHA256 = "455494bc6be253a73747116734c418c9c13e41d13eac09a1c31f721e5d44499d"
SCHEMA = "marty.canvas-worker-lease-expiry-native-observation/v1"
STATUSES = frozenset(("leased", "succeeded", "retry", "dead_letter"))
FIELDS = frozenset(
    (
        "schema",
        "status",
        "lease_advanced_after_release",
        "original_lease_expired_at_release",
        "first_terminal_status",
        "release_start_seconds",
        "release_end_seconds",
    )
)
CASE_TIMEOUT_SECONDS = 100
require = header.require
wait_for = header.wait_for
assert_control = header.assert_control
write_marker = header.write_marker
DIAGNOSTIC_PREFIX = b"MARTY_EXPIRY_DIAG_V1:"
DIAGNOSTIC_CATEGORIES = frozenset(
    name.encode("ascii")
    for name in (
        "AwaitRequest",
        "VerifyInitial",
        "LockHeld",
        "ReleaseDue",
        "VerifyHeldState",
        "VerifyEffects",
        "SampleBeforeRollback",
        "Rollback",
        "SampleAfterRollback",
        "CheckReleaseBand",
        "ObserveOutcome",
        "PublishOutcome",
        "AwaitLateWindow",
        "VerifyJoinedState",
        "VerifyShutdown",
        "Complete",
        "FailureClockAgreement",
        "FailureClockOrder",
        "FailureRenewalBlocker",
        "FailureRenewalNotObserved",
        "FailureRenewalLeftLock",
        "FailureHeldState",
        "FailureLockedJob",
        "FailurePreReleaseJob",
        "FailureEffects",
        "FailureReleaseBracket",
        "FailureEarlyBand",
        "FailureExpiryBand",
        "FailureLeasedIdentity",
        "FailureJobGeneration",
        "FailureTerminalLease",
        "FailureJobQuery",
        "FailureShutdownWait",
        "FailureShutdownStatus",
        "FailurePostShutdownState",
        "FailureOutput",
        "FailureParity",
        "FailureUnknown",
    )
)
coordinator_diagnostics = partial(
    header.coordinator_diagnostics,
    prefix=DIAGNOSTIC_PREFIX,
    categories=DIAGNOSTIC_CATEGORIES,
    family="expiry",
)


def validate_outcome(value):
    require(
        type(value) is dict and set(value) == FIELDS,
        "Native expiry observation fields differ",
    )
    require(
        type(value["schema"]) is str and value["schema"] == SCHEMA,
        "Native expiry observation schema differs",
    )
    status, terminal = value["status"], value["first_terminal_status"]
    require(
        type(status) is str and status in STATUSES,
        "Native expiry observation status differs",
    )
    require(
        terminal is None
        or (type(terminal) is str and terminal in STATUSES - {"leased"}),
        "Native expiry terminal category differs",
    )
    require(
        (terminal is None) if status == "leased" else terminal == status,
        "Native expiry terminal observation is inconsistent",
    )
    require(
        all(
            type(value[key]) is bool
            for key in (
                "lease_advanced_after_release",
                "original_lease_expired_at_release",
            )
        ),
        "Native expiry observation flags differ",
    )
    lo, hi = value["release_start_seconds"], value["release_end_seconds"]
    require(
        all(body.finite_number(item) for item in (lo, hi)) and 0 <= lo <= hi <= 60,
        "Native expiry release interval differs",
    )
    return value


def load_outcome(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate native expiry observation field")
            result[key] = value
        return result

    try:
        require(
            path.is_file() and not path.is_symlink(),
            "Invalid native expiry observation file",
        )
        with path.open("rb") as stream:
            raw = stream.read(513)
        require(0 < len(raw) <= 512, "Native expiry observation exceeds byte bound")
        value = json.loads(raw, object_pairs_hook=pairs)
    except (OSError, UnicodeError, ValueError):
        raise AssertionError("Native expiry observation cannot be decoded") from None
    return validate_outcome(value)


def release_interval(value, before_marker, after_ack, received_at, observed_at):
    validate_outcome(value)
    require(
        all(
            body.finite_number(item)
            for item in (before_marker, after_ack, received_at, observed_at)
        )
        and received_at <= before_marker <= after_ack <= observed_at,
        "Native expiry request anchor differs",
    )
    lo = before_marker + value["release_start_seconds"]
    hi = after_ack + value["release_end_seconds"]
    require(
        received_at <= lo <= hi <= received_at + 65,
        "Native expiry release bracket exceeds its bound",
    )
    return lo, hi


def validate_release(value, case, before_marker, after_ack, fixture, observed_at):
    lo, hi = release_interval(
        value, before_marker, after_ack, fixture.received_at, observed_at
    )
    if case["name"] == CASE_NAMES[0]:
        require(
            fixture.received_at + 11.5 <= lo <= hi <= fixture.received_at + 12.5,
            "Native expiry early release misses actual request window",
        )
    require(
        value["original_lease_expired_at_release"] is (case["name"] == CASE_NAMES[1]),
        "Native expiry release proof differs from selected case",
    )
    return lo, hi


def matches_reference(value, observed):
    validate_outcome(value)
    return (
        value["status"] == observed["outcome"]["jobs"][0]["status"]
        and value["first_terminal_status"] == observed["first_terminal_status"]
        and value["lease_advanced_after_release"]
        == observed["lease_advanced_after_release"]
        and value["original_lease_expired_at_release"]
        == observed["original_lease_expired_at_release"]
    )


def load_inputs(root):
    contracts = root / "contracts"
    raw = (contracts / "canvas-worker-lease-expiry-oracle.json").read_bytes()
    require(
        hashlib.sha256(raw).hexdigest() == CORPUS_SHA256,
        "Native expiry raw reference hash differs",
    )
    reports = json.loads(raw)
    matrix = json.loads((contracts / reference.SCENARIO).read_text(encoding="utf-8"))
    require(
        matrix
        == {
            "schema": "marty.canvas-worker-lease-expiry-scenarios/v1",
            "source_sha256": reference.SOURCE_SHA256,
            "environment": reference.ENVIRONMENT,
            "schedule": reference.SCHEDULE,
            "cases": [reference.validate_case(name) for name in CASE_NAMES],
        }
        and all(body.finite_number(item) for item in matrix["schedule"]),
        "Native expiry scenario differs",
    )
    require(
        type(reports) is list and len(reports) == 2,
        "Native expiry requires both reports",
    )
    _, _, _, _, response, request, _ = body.load_case(
        contracts, "application_body_progress"
    )
    for name, report in zip(CASE_NAMES, reports, strict=True):
        observed = report["worker_lease_expiry"]
        require(
            report["status"] == "passed"
            and observed["case"] == name
            and observed["schema"] == "marty.canvas-worker-lease-expiry-observation/v1"
            and observed["source_sha256"] == reference.SOURCE_SHA256
            and observed["requests"] == [request],
            "Native expiry reference provenance differs",
        )
        require(
            len(observed["capture_source_sha256"]) == 18,
            "Native expiry reference input closure differs",
        )
        for filename, expected in observed["capture_source_sha256"].items():
            require(
                Path(filename).name == filename and filename.endswith((".py", ".json")),
                "Native expiry source filename differs",
            )
            path = (
                root
                / ("scripts" if filename.endswith(".py") else "contracts")
                / filename
            )
            require(
                body.capture_input_sha256(path) == expected,
                "Native expiry captured input hash differs",
            )
    return matrix, reports, response


def run_case(executable, case, observed, response):
    require(
        case == reference.validate_case(case["name"])
        and observed["case"] == case["name"],
        "Native expiry case differs",
    )
    stop_at = time.monotonic() + CASE_TIMEOUT_SECONDS

    def remaining(maximum):
        budget = stop_at - time.monotonic()
        require(budget > 0, "Native expiry case exceeded total bound")
        return min(budget, maximum)

    with ExitStack() as owner:
        root = Path(
            owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-native-expiry-")
            )
        )
        control = root / "native-control"
        control.mkdir()
        empty_ca = root / "empty-ca-directory"
        empty_ca.mkdir()
        stdout_writer, stdout = owned_log_streams(owner, root)
        stderr_writer, stderr = owned_log_streams(owner, root)
        fixture = owner.enter_context(
            owned_fixture(
                BodyTimeoutHttpsFixture(
                    observed["requests"][0],
                    response,
                    chunk_offsets=reference.SCHEDULE,
                    late_disconnect_from_index=4
                    if case["name"] == CASE_NAMES[1]
                    else None,
                )
            )
        )
        environment = dict(os.environ)
        environment.update(
            MARTY_CANVAS_WORKER_LEASE_EXPIRY_NATIVE_ORIGIN=fixture.origin,
            MARTY_CANVAS_WORKER_LEASE_EXPIRY_CASE=case["name"],
            MARTY_CANVAS_WORKER_LEASE_EXPIRY_CONTROL=str(control),
            SSL_CERT_FILE=str(fixture.cert),
            SSL_CERT_DIR=str(empty_ca),
        )
        child = OwnedProcess(
            [executable, "worker_lease_expiry_native_child", "--exact", "--nocapture"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_writer,
            stderr=stderr_writer,
        )
        known = set()
        phase = "request-received"
        outcome = None

        def guard():
            require(
                not fixture.failures and fixture.requests == observed["requests"],
                "Native expiry HTTPS transcript differs",
            )

        def receive(name, seconds, *, allow_exited=False):
            def ready():
                guard()
                return assert_control(control, known, name)

            wait_for(child, ready, remaining(seconds), name, allow_exited=allow_exited)
            known.add(name)

        try:

            def received():
                assert_control(control, known)
                require(not fixture.failures, "Native expiry HTTPS handler failed")
                return fixture.request_started.is_set()

            wait_for(child, received, remaining(30), phase)
            guard()
            require(
                not fixture.body_started.is_set(),
                "Native expiry body preceded held snapshot",
            )
            anchor_lower = time.monotonic()
            write_marker(control, known, phase)
            phase = "before-release-verified"
            receive(phase, 2)
            anchor_upper = time.monotonic()
            require(
                not fixture.body_started.is_set(),
                "Native expiry body preceded lock acknowledgement",
            )
            fixture.initial_ready.set()
            phase = "outcome-observed"
            receive(phase, 42)
            outcome_at = time.monotonic()
            outcome = load_outcome(control / phase)
            _, released_upper = validate_release(
                outcome, case, anchor_lower, anchor_upper, fixture, outcome_at
            )
            parity = matches_reference(outcome, observed)
            phase = "independent-final-attempt"

            def finished():
                assert_control(control, known)
                guard()
                return (
                    fixture.schedule_completed.is_set()
                    and fixture.handler_finished.is_set()
                )

            wait_for(child, finished, remaining(36), phase)
            require(
                0 <= fixture.body_started_at - fixture.received_at < 2,
                "Native expiry body setup missed request budget",
            )
            chunks = reference.assert_schedule(
                fixture, crosses_expiry=case["name"] == CASE_NAMES[1]
            )
            require(
                released_upper < body.flush_interval(fixture, 4)["write_started_at"]
                if chunks[-1]["outcome"] == "flushed"
                else released_upper
                < fixture.body_started_at
                + fixture.observations()[-1]["write_started_seconds"],
                "Native expiry lock release did not precede final body attempt",
            )
            parity = parity and chunks == observed["chunks"]
            late_end = body.late_window_end(
                fixture, outcome_at, {"target_type": "learner_application"}, body.TIMING
            )
            phase = "late-response-window"

            def late_complete():
                assert_control(control, known)
                guard()
                require(
                    reference.assert_schedule(
                        fixture, crosses_expiry=case["name"] == CASE_NAMES[1]
                    )
                    == chunks,
                    "Native expiry late chunk ledger changed",
                )
                return time.monotonic() >= late_end

            wait_for(child, late_complete, remaining(60), phase)
            write_marker(control, known, "late-window-complete")
            phase = "late-window-verified"
            receive(phase, 8)
            phase = "handler-join"
            close_fixture(fixture)
            guard()
            require(
                reference.assert_schedule(
                    fixture, crosses_expiry=case["name"] == CASE_NAMES[1]
                )
                == chunks,
                "Native expiry joined chunk ledger changed",
            )
            write_marker(control, known, "handlers-joined")
            phase = "child-done"
            receive(phase, 20, allow_exited=True)
            phase = "child-exit"
            child.wait(timeout=remaining(10))
            assert_control(control, known)
            guard()
            require(
                parity,
                "Native expiry observation differs from frozen published behavior",
            )
            require(
                child.returncode == 0,
                "Native expiry coordinator failed final verification",
            )
        except BaseException as failure:
            failure.add_note(f"Native expiry phase: {phase}")
            if outcome is not None:
                # This object has passed the closed enum/type validator; never
                # quote arbitrary native output or unknown payload fields.
                failure.add_note(
                    "Native expiry outcome: "
                    f"status={outcome['status']}; "
                    f"terminal={outcome['first_terminal_status']}; "
                    f"renewed={outcome['lease_advanced_after_release']}; "
                    f"original_expired={outcome['original_lease_expired_at_release']}"
                )
            raise
        finally:
            failure = sys.exception()
            try:
                child.cleanup(timeout=10)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                if failure is None:
                    raise AssertionError(
                        "Owned native expiry process cleanup failed"
                    ) from None
                failure.add_note("Owned native expiry process cleanup failed")
            if failure is not None:
                failure.add_note(coordinator_diagnostics(stderr))
                try:
                    failure.add_note(header.output_counts(stdout, stderr))
                except (OSError, ValueError):
                    failure.add_note("Owned native expiry output counts unavailable")
        guard()
    guard()
    print(f"Native worker lease expiry {case['name']} passed (1 actual HTTPS request)")


def run(executable, case_name):
    require(
        sys.platform == "linux", "Actual native expiry qualification requires Linux"
    )
    require(
        type(case_name) is str and case_name in CASE_NAMES, "Unknown native expiry case"
    )
    matrix, reports, response = load_inputs(ROOT)
    index = CASE_NAMES.index(case_name)
    run_case(
        executable,
        matrix["cases"][index],
        reports[index]["worker_lease_expiry"],
        response,
    )


if __name__ == "__main__":
    require(len(sys.argv) == 3, "Expected compiled executable and exact expiry case")
    run(sys.argv[1], sys.argv[2])
