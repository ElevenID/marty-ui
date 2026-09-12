"""Native BODY replay using frozen Python transport rules, not Python execution.

The surviving Rust caller owns the database; the contained Rust coordinator owns
the real native worker and durable/quiet-output verification. This process owns
HTTPS and its autonomous writes. Parent SIGKILL/outer death is outside containment.
Importing the reference's pure checks requires the existing CI SQLAlchemy deps;
neither its run() nor installed-Python verify_sources() executes here.
"""

from contextlib import ExitStack, contextmanager
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
import test_canvas_worker_timeout_https as header

ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = [case[0] for case in body.CASE_LAYOUT]
CORPUS_SHA256 = "e97d7fee361a11d4245876b725c8ac417045254d766693f772da53409c9b50eb"
CASE_TIMEOUT_SECONDS = 90
require = header.require
assert_control = header.assert_control
write_marker = header.write_marker
wait_for = header.wait_for
load_transition = header.load_transition


def validate_matrix(matrix, reports):
    try:
        require(
            matrix["schema"] == "marty.canvas-worker-body-timeout-scenarios/v1"
            and matrix["environment"] == body.ENVIRONMENT
            and matrix["timing"] == body.TIMING
            and matrix["schedules"] == body.SCHEDULES
            and all(body.finite_number(value) for value in matrix["timing"].values())
            and all(
                body.finite_number(value)
                for offsets in matrix["schedules"].values()
                for value in offsets
            ),
            "Native body input timing or schema differs",
        )
        require(
            [
                (
                    case["name"],
                    case["target_type"],
                    case["mode"],
                    case["expected_status"],
                )
                for case in matrix["cases"]
            ]
            == body.CASE_LAYOUT
            and all(
                set(case) == {"name", "target_type", "mode", "expected_status"}
                for case in matrix["cases"]
            ),
            "Native body matrix must retain six exact cases",
        )
        require(
            type(reports) is list and len(reports) == 6,
            "Native body reference requires six full reports",
        )
        require(
            [report["worker_body_timeout"]["case"] for report in reports] == CASE_NAMES,
            "Native body reference case order differs",
        )
        for case, report in zip(matrix["cases"], reports, strict=True):
            observed = report["worker_body_timeout"]
            require(
                report["status"] == "passed"
                and report["worker_sha256"]
                == body.SOURCE_SHA256["issuance.canvas_worker"]
                and observed["schema"]
                == "marty.canvas-worker-body-timeout-observation/v1"
                and observed["source_sha256"] == body.SOURCE_SHA256
                and observed["runtime_versions"] == body.RUNTIME_VERSIONS
                and observed["exit_code_after_interrupt"] == -2
                and observed["stable_after_final_attempt_handler_join_and_interrupt"]
                is True,
                "Native body reference provenance or lifecycle differs",
            )
            require(
                observed["outcome"]["jobs"][0]["status"] == case["expected_status"]
                and len(observed["requests"]) == 1
                and observed["requests"][0]["method"] == "GET"
                and observed["requests"][0]["path"]
                == matrix["request_paths"][case["target_type"]]
                and observed["requests"][0]["accept"] == "application/json",
                "Native body frozen outcome or request differs",
            )
            expected_timing = dict.fromkeys(
                (
                    "all_attempts_within_declared_schedule",
                    "first_terminal_interval_within_declared_window",
                    "idle_outcome_within_declared_window",
                    "initial_response_within_request_budget",
                    "late_window_completed",
                    "original_lease_current_through_join",
                ),
                True,
            ) | {"outcome_before_final_attempt": case["mode"] == "stall"}
            require(
                observed["timing"] == expected_timing
                and all(type(value) is bool for value in observed["timing"].values()),
                "Native body frozen timing differs",
            )
    except (KeyError, TypeError, IndexError, ValueError):
        raise AssertionError("Malformed native body reference inputs") from None


def load_inputs(root):
    raw = (root / "contracts/canvas-worker-body-timeout-oracle.json").read_bytes()
    require(
        len(raw) == 46_042 and hashlib.sha256(raw).hexdigest() == CORPUS_SHA256,
        "Native body frozen raw corpus differs",
    )
    reports = json.loads(raw)
    responses = {}
    matrix = None
    for name, report in zip(CASE_NAMES, reports, strict=True):
        matrix, _, _, _, response, request, _ = body.load_case(root / "contracts", name)
        require(
            report["worker_body_timeout"]["requests"] == [request],
            "Native body request differs from its seed owner",
        )
        responses[name] = response
    validate_matrix(matrix, reports)
    return matrix, reports, responses


def project_transition(transition, anchor_lower, anchor_upper, request_at, outcome_at):
    header.validate_transition(transition)
    require(
        all(
            body.finite_number(value)
            for value in (anchor_lower, anchor_upper, request_at, outcome_at)
        )
        and request_at <= anchor_lower <= anchor_upper <= outcome_at,
        "Native body monotonic anchor bracket differs",
    )
    lower = anchor_lower + transition["last_leased_start_seconds"]
    upper = anchor_upper + transition["first_terminal_end_seconds"]
    require(
        request_at <= lower <= upper <= request_at + CASE_TIMEOUT_SECONDS,
        "Native body transition exceeded its observation ceiling",
    )
    # A conservative upper bound may follow actual marker receipt; never clip
    # it to that receipt. Both the whole source window and scalar idle window
    # must pass independently below.
    return lower, upper


def assert_requests(fixture, reference):
    require(not fixture.failures, "Owned native body HTTPS handler failed")
    require(
        fixture.requests == reference["requests"],
        "Native body request transcript differs",
    )


def receive_marker(child, control, known, name, timeout, *, guard, allow_exited=False):
    require(name not in known, "Duplicate native body child marker")

    def ready():
        guard()
        return assert_control(control, known, name)

    wait_for(child, ready, timeout, name, allow_exited=allow_exited)
    known.add(name)


def close_fixture(fixture):
    original = sys.exception()
    try:
        fixture.close()
    except (OSError, RuntimeError, AssertionError):
        if original is not None:
            original.add_note("Owned native body HTTPS cleanup failed")
        else:
            raise AssertionError("Owned native body HTTPS cleanup failed") from None


@contextmanager
def owned_fixture(fixture):
    fixture.__enter__()
    try:
        yield fixture
    finally:
        close_fixture(fixture)


def run_case(executable, matrix, case, reference, response):
    require(
        case["name"] in CASE_NAMES and case["name"] == reference["case"],
        "Native body case differs",
    )
    stop_at = time.monotonic() + CASE_TIMEOUT_SECONDS

    def remaining(maximum):
        budget = stop_at - time.monotonic()
        require(budget > 0, "Native body case exceeded its total bound")
        return min(budget, maximum)

    timing = matrix["timing"]
    offsets = matrix["schedules"][case["mode"]]
    with ExitStack() as owner:
        root = Path(
            owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-native-body-")
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
                    reference["requests"][0],
                    response,
                    chunk_offsets=offsets,
                    late_disconnect_from_index=len(offsets) - 1
                    if case["mode"] == "stall"
                    else None,
                )
            )
        )
        environment = dict(os.environ)
        environment.update(
            MARTY_CANVAS_WORKER_BODY_TIMEOUT_NATIVE_ORIGIN=fixture.origin,
            MARTY_CANVAS_WORKER_BODY_TIMEOUT_CASE=case["name"],
            MARTY_CANVAS_WORKER_BODY_TIMEOUT_CONTROL=str(control),
            SSL_CERT_FILE=str(fixture.cert),
            SSL_CERT_DIR=str(empty_ca),
        )
        child = OwnedProcess(
            [executable, "worker_body_timeout_native_child", "--exact", "--nocapture"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_writer,
            stderr=stderr_writer,
        )
        known = set()
        phase = "request-received"

        def guard():
            assert_requests(fixture, reference)

        def wait_events(events, maximum, label):
            def ready():
                assert_control(control, known)
                guard()
                return all(event.is_set() for event in events)

            wait_for(child, ready, remaining(maximum), label)

        def receive(name, maximum, *, allow_exited=False):
            receive_marker(
                child,
                control,
                known,
                name,
                remaining(maximum),
                guard=guard,
                allow_exited=allow_exited,
            )

        try:

            def received():
                assert_control(control, known)
                require(not fixture.failures, "Owned native body HTTPS handler failed")
                return fixture.request_started.is_set()

            wait_for(child, received, remaining(30), phase)
            guard()
            require(
                not fixture.body_started.is_set(), "Body started before held snapshot"
            )
            anchor_lower = time.monotonic()
            write_marker(control, known, phase)
            phase = "before-release-verified"
            receive(phase, 2)
            anchor_upper = time.monotonic()
            require(
                not fixture.body_started.is_set(), "Body started before held snapshot"
            )
            fixture.initial_ready.set()
            phase = "outcome-observed"
            receive(phase, timing[f"{case['mode']}_outcome_max_seconds"] + 2)
            outcome_at = time.monotonic()
            lower, upper = project_transition(
                load_transition(control / phase),
                anchor_lower,
                anchor_upper,
                fixture.received_at,
                outcome_at,
            )
            progress_index = 1 if case["mode"] == "stall" else len(offsets) - 1
            flush = body.flush_interval(fixture, progress_index)
            body.assert_transition_timing(lower, upper, flush, case, timing)
            body.assert_outcome_timing(
                fixture.received_at,
                fixture.body_started_at,
                outcome_at,
                flush,
                case,
                timing,
            )
            phase = "independent-final-attempt"
            wait_events(
                (fixture.schedule_completed, fixture.handler_finished),
                offsets[-1] + 2,
                phase,
            )
            chunks = body.assert_schedule(fixture, case, timing)
            require(
                chunks == reference["chunks"],
                "Native body flush transcript differs from frozen reference",
            )
            final = fixture.observations()[-1]
            final_start = fixture.body_started_at + final["write_started_seconds"]
            final_end = fixture.body_started_at + final["write_completed_seconds"]
            require(
                upper < final_start and outcome_at < final_start
                if case["mode"] == "stall"
                else outcome_at >= final_end,
                "Native body outcome differs from independent final-write ordering",
            )
            late_end = body.late_window_end(fixture, outcome_at, case, timing)
            phase = "late-response-window"

            def late_complete():
                assert_control(control, known)
                guard()
                require(
                    body.assert_schedule(fixture, case, timing) == chunks,
                    "Native body late flush transcript changed",
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
                body.assert_schedule(fixture, case, timing) == chunks,
                "Native body joined flush transcript changed",
            )
            write_marker(control, known, "handlers-joined")
            phase = "child-done"
            receive(phase, 20, allow_exited=True)
            phase = "child-exit"
            child.wait(timeout=remaining(10))
            require(
                child.returncode == 0,
                "Native body coordinator failed after final verification",
            )
            assert_control(control, known)
            guard()
        except BaseException as failure:
            failure.add_note(f"Native body phase: {phase}")
            raise
        finally:
            # Containment applies even when the leader already exited. Killing
            # only a still-running coordinator can leave its worker orphaned.
            failure = sys.exception()
            try:
                child.cleanup(timeout=10)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                if failure is None:
                    raise AssertionError(
                        "Owned native body process cleanup failed"
                    ) from None
                failure.add_note("Owned native body process cleanup failed")
            if failure is not None:
                try:
                    note = header.output_counts(stdout, stderr)
                except (OSError, ValueError):
                    note = "Owned native body output counts unavailable"
                failure.add_note(note)
                failure.add_note(header.coordinator_diagnostics(stderr))
        guard()
    guard()
    print(f"Native worker body timeout {case['name']} passed (1 actual HTTPS request)")


def run(executable, case_name):
    require(sys.platform == "linux", "Actual native body qualification requires Linux")
    require(case_name in CASE_NAMES, "Unknown native body case")
    matrix, reports, responses = load_inputs(ROOT)
    index = CASE_NAMES.index(case_name)
    run_case(
        executable,
        matrix,
        matrix["cases"][index],
        reports[index]["worker_body_timeout"],
        responses[case_name],
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            "Expected the compiled published-schema executable and exact case"
        )
    run(sys.argv[1], sys.argv[2])
