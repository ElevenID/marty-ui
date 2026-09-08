"""Native worker delayed-header controls against the frozen published corpus.

The outer Rust caller owns each disposable database. The inner Rust coordinator
owns exact durable projections and worker interruption; this parent owns only
real HTTPS, independent release timing and ordered control markers. The shared
process owner contains coordinator failures, not SIGKILL of this parent/runner.
"""

from contextlib import ExitStack
from functools import partial
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from canvas_worker_output_capture import owned_log_streams
from canvas_worker_owned_process import OwnedProcess
from canvas_worker_timeout_https_fixture import TimeoutHttpsFixture
import canvas_worker_process_control as process_control


ROOT = Path(__file__).resolve().parents[1]
CASE_LAYOUT = [
    ("application_prompt", "learner_application", False, "succeeded"),
    ("application_delayed_headers", "learner_application", True, "retry"),
    ("roster_prompt", "background_roster", False, "succeeded"),
    ("roster_delayed_headers", "background_roster", True, "succeeded"),
]
CASE_NAMES = [case[0] for case in CASE_LAYOUT]
CASE_TIMEOUT_SECONDS = 90
POLL_SECONDS = 0.025
assert_control = partial(process_control.assert_control, family="timeout")
output_counts = partial(process_control.output_counts, family="timeout")
write_marker = partial(process_control.write_marker, family="timeout")


def require(condition, message):
    # Explicit static errors remain payload-free under pytest rewriting too.
    if not condition:
        raise AssertionError(message)


def validate_matrix(matrix, reference):
    require(
        matrix["schema"] == "marty.canvas-worker-timeout-scenarios/v1"
        and reference["schema"] == "marty.canvas-worker-timeout-oracle/v1",
        "Unexpected native timeout input schema",
    )
    require(
        [
            (
                case["name"],
                case["target_type"],
                case["delayed"],
                case["expected_status"],
            )
            for case in matrix["cases"]
        ]
        == CASE_LAYOUT
        and all(type(case["delayed"]) is bool for case in matrix["cases"]),
        "Timeout matrix must retain all four exact controls",
    )
    require(
        [item["case"] for item in reference["observations"]] == CASE_NAMES,
        "Timeout reference must retain all four ordered observations",
    )
    require(
        matrix["environment"]
        == {
            "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "120",
            "CANVAS_SYNC_WORKER_LEASE_SECONDS": "90",
            "CANVAS_SYNC_WORKER_POLL_SECONDS": "120",
            "LOG_LEVEL": "WARNING",
        },
        "Timeout isolation configuration differs",
    )
    require(
        matrix["timing"]
        == {
            "delay_seconds": 17,
            "release_min_seconds": 16.5,
            "release_max_seconds": 18,
            "prompt_max_seconds": 2,
            "outcome_max_seconds": 25,
            "application_timeout_min_seconds": 14.5,
            "application_timeout_max_seconds": 16.5,
            "observe_until_seconds": 22,
            "after_outcome_seconds": 2,
        },
        "Timeout timing contract differs",
    )
    require(
        set(matrix["request_paths"]) == {"learner_application", "background_roster"},
        "Timeout matrix must retain both provider paths",
    )
    for case, observed in zip(matrix["cases"], reference["observations"], strict=True):
        require(
            observed["schema"] == "marty.canvas-worker-timeout-observation/v1"
            and observed["exit_code_after_interrupt"] == -2
            and observed["stable_after_release_handler_join_and_interrupt"] is True,
            "Timeout reference lifecycle contract differs",
        )
        require(
            all(type(value) is bool for value in observed["timing"].values())
            and observed["timing"]
            == {
                "outcome_within_declared_source_window": True,
                "release_within_declared_band": True,
                "outcome_before_release": case["expected_status"] == "retry",
                "lease_current_while_response_held": True,
                "original_lease_current_after_outcome": True,
            },
            "Timeout frozen timing observations differ",
        )
        requests = observed["requests"]
        require(len(requests) == 1, "Timeout reference must retain exactly one request")
        request = requests[0]
        require(
            set(request) == {"method", "path", "authorization", "accept"}
            and request["method"] == "GET"
            and request["path"] == matrix["request_paths"][case["target_type"]]
            and request["accept"] == "application/json"
            and isinstance(request["authorization"], str)
            and request["authorization"].startswith("Bearer ")
            and request["authorization"] != "Bearer ",
            "Timeout frozen provider request differs",
        )


def load_inputs(root):
    def read(name):
        return json.loads((root / "contracts" / name).read_text(encoding="utf-8"))

    matrix = read("canvas-worker-timeout-scenarios.json")
    reference = read("canvas-worker-timeout-oracle.json")
    validate_matrix(matrix, reference)
    spec = read(matrix["reference_scenario"])
    matches = [stage for stage in spec["stages"] if stage["name"] == "initial_permit"]
    require(len(matches) == 1, "Timeout application response owner is ambiguous")
    require(matches[0]["status"] == 200, "Timeout application response is not positive")
    responses = {}
    for case, observation in zip(
        matrix["cases"], reference["observations"], strict=True
    ):
        expected = {
            "method": "GET",
            "path": matrix["request_paths"][case["target_type"]],
            "authorization": f"Bearer {spec['token']}",
            "accept": "application/json",
        }
        require(
            observation["requests"] == [expected],
            "Timeout frozen request differs from its seed owner",
        )
        responses[case["name"]] = (
            {"status": 200, "body": []}
            if case["target_type"] == "background_roster"
            else matches[0]
        )
    return matrix, reference, responses


def wait_for(child, predicate, timeout, phase, *, allow_exited=False):
    require(
        type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0,
        "Invalid native timeout wait budget",
    )
    stop_at = time.monotonic() + timeout
    while True:
        value = predicate()
        status = child.poll()
        require(
            status is None or (allow_exited and status == 0 and value),
            f"Native timeout child exited during {phase}",
        )
        require(time.monotonic() < stop_at, f"Native timeout wait expired: {phase}")
        if value:
            return value
        time.sleep(POLL_SECONDS)


def receive_marker(
    child, control, known, name, timeout, *, guard=None, allow_exited=False
):
    require(name not in known, "Duplicate native timeout child marker")

    def ready():
        if guard is not None:
            guard()
        return assert_control(control, known, name)

    wait_for(child, ready, timeout, name, allow_exited=allow_exited)
    known.add(name)


def assert_requests(fixture, reference):
    require(not fixture.failures, "Owned native timeout HTTPS handler failed")
    require(
        fixture.requests == reference["requests"],
        "Native timeout request transcript differs from the frozen reference",
    )


def assert_outcome_timing(received_at, outcome_at, case, timing):
    require(
        all(finite_number(value) for value in (received_at, outcome_at)),
        "Invalid native timeout response timing sample",
    )
    elapsed = outcome_at - received_at
    require(
        0 <= elapsed <= timing["outcome_max_seconds"],
        "Native timeout outcome exceeded its observation budget",
    )
    # Preserve the published observation-quality bound as well as proving the
    # durable transition separately. Slow delivery is inconclusive, not parity.
    if case["name"] == "application_delayed_headers":
        require(
            timing["application_timeout_min_seconds"]
            <= elapsed
            <= timing["application_timeout_max_seconds"],
            "Native application timeout differs from the frozen source window",
        )


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def validate_transition(transition):
    require(
        type(transition) is dict
        and set(transition)
        == {
            "schema",
            "last_leased_start_seconds",
            "first_terminal_end_seconds",
        }
        and transition["schema"] == "marty.canvas-worker-timeout-transition/v1",
        "Native timeout transition payload differs from its closed schema",
    )
    lower = transition["last_leased_start_seconds"]
    upper = transition["first_terminal_end_seconds"]
    require(
        finite_number(lower)
        and finite_number(upper)
        and 0 <= lower <= upper <= CASE_TIMEOUT_SECONDS,
        "Native timeout transition offsets are invalid",
    )
    return transition


def load_transition(path):
    def unique_object(pairs):
        values = {}
        for key, value in pairs:
            if key in values:
                raise ValueError("Duplicate transition key")
            values[key] = value
        return values

    try:
        with path.open("rb") as stream:
            payload = stream.read(513)
        require(len(payload) <= 512, "Native timeout transition payload is oversized")
        transition = json.loads(
            payload.decode("utf-8"), object_pairs_hook=unique_object
        )
    except (OSError, UnicodeError, ValueError):
        raise AssertionError(
            "Native timeout transition payload could not be read"
        ) from None
    return validate_transition(transition)


def assert_transition_timing(
    transition, anchor_lower, anchor_upper, request_at, case, timing
):
    validate_transition(transition)
    require(
        all(finite_number(value) for value in (anchor_lower, anchor_upper, request_at))
        and request_at <= anchor_lower <= anchor_upper,
        "Native timeout monotonic anchor bracket is invalid",
    )
    lower = anchor_lower + transition["last_leased_start_seconds"] - request_at
    upper = anchor_upper + transition["first_terminal_end_seconds"] - request_at
    require(
        0 <= lower <= upper <= timing["outcome_max_seconds"],
        "Native timeout transition interval exceeded its observation budget",
    )
    if case["name"] == "application_delayed_headers":
        require(
            timing["application_timeout_min_seconds"]
            <= lower
            <= upper
            <= timing["application_timeout_max_seconds"],
            "Native application transition interval differs from the source window",
        )
    return lower, upper


def assert_transition_before_release(elapsed_upper, received_at, released_at, case):
    require(
        all(
            finite_number(value) for value in (elapsed_upper, received_at, released_at)
        ),
        "Native timeout transition release sample is invalid",
    )
    if case["name"] == "application_delayed_headers":
        require(
            received_at + elapsed_upper < released_at,
            "Native application transition interval does not precede release",
        )


def assert_release_timing(fixture, case, timing):
    require(
        all(
            finite_number(value) for value in (fixture.received_at, fixture.released_at)
        ),
        "Invalid native timeout release timing sample",
    )
    elapsed = fixture.released_at - fixture.received_at
    require(
        timing["release_min_seconds"] <= elapsed <= timing["release_max_seconds"]
        if case["delayed"]
        else 0 <= elapsed < timing["prompt_max_seconds"],
        "Native timeout independent release missed its declared band",
    )


def assert_outcome_order(outcome_at, released_at, case):
    require(
        all(finite_number(value) for value in (outcome_at, released_at)),
        "Native timeout release was not observed",
    )
    require(
        (outcome_at < released_at) is (case["expected_status"] == "retry"),
        "Native timeout outcome occurred on the wrong side of release",
    )


def remaining(stop_at, maximum):
    budget = stop_at - time.monotonic()
    require(budget > 0, "Native timeout case exceeded its total fixture bound")
    return min(budget, maximum)


def run_case(executable, matrix, case, reference, response):
    require(
        case["name"] in CASE_NAMES and case["name"] == reference["case"],
        "Native timeout case differs",
    )
    stop_at = time.monotonic() + CASE_TIMEOUT_SECONDS
    timing = matrix["timing"]
    with ExitStack() as owner:
        owned_root = Path(
            owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-native-timeout-")
            )
        )
        control = owned_root / "native-control"
        control.mkdir()
        empty_ca = owned_root / "empty-ca-directory"
        empty_ca.mkdir()
        stdout_writer, stdout = owned_log_streams(owner, owned_root)
        stderr_writer, stderr = owned_log_streams(owner, owned_root)
        fixture = owner.enter_context(
            TimeoutHttpsFixture(
                reference["requests"][0],
                response,
                delay_seconds=timing["delay_seconds"] if case["delayed"] else 0,
            )
        )
        environment = dict(os.environ)
        environment.update(
            MARTY_CANVAS_WORKER_TIMEOUT_NATIVE_ORIGIN=fixture.origin,
            MARTY_CANVAS_WORKER_TIMEOUT_CASE=case["name"],
            MARTY_CANVAS_WORKER_TIMEOUT_CONTROL=str(control),
            SSL_CERT_FILE=str(fixture.cert),
            SSL_CERT_DIR=str(empty_ca),
        )
        child = OwnedProcess(
            [executable, "worker_timeout_native_child", "--exact", "--nocapture"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_writer,
            stderr=stderr_writer,
        )
        known = set()
        phase = "request-received"
        try:

            def received():
                assert_control(control, known)
                require(
                    not fixture.failures, "Owned native timeout HTTPS handler failed"
                )
                return fixture.request_started.is_set()

            wait_for(child, received, remaining(stop_at, 30), phase)
            assert_requests(fixture, reference)
            require(
                not fixture.release.is_set(),
                "Timeout response preceded the held snapshot",
            )
            # The child captures its Instant origin after seeing this marker,
            # before the initial leased query. The following acknowledgment
            # therefore brackets that origin without sharing clock epochs.
            anchor_lower = time.monotonic()
            write_marker(control, known, phase)
            phase = "before-release-verified"
            receive_marker(
                child,
                control,
                known,
                phase,
                remaining(stop_at, 2),
                guard=lambda: assert_requests(fixture, reference),
            )
            anchor_upper = time.monotonic()
            require(
                not fixture.release.is_set(),
                "Timeout response preceded the held snapshot",
            )
            # This event controls prompt cases only. Delayed release remains
            # solely the unchanged fixture controller's independent 17s timer.
            fixture.prompt_ready.set()
            phase = "outcome-observed"
            receive_marker(
                child,
                control,
                known,
                phase,
                remaining(stop_at, timing["outcome_max_seconds"]),
                guard=lambda: assert_requests(fixture, reference),
            )
            outcome_at = time.monotonic()
            assert_outcome_timing(fixture.received_at, outcome_at, case, timing)
            transition = load_transition(control / "outcome-observed")
            _, transition_upper = assert_transition_timing(
                transition,
                anchor_lower,
                anchor_upper,
                fixture.received_at,
                case,
                timing,
            )
            phase = "independent-release"

            def released():
                assert_control(control, known)
                assert_requests(fixture, reference)
                return fixture.release.is_set()

            wait_for(child, released, remaining(stop_at, 20), phase)
            assert_release_timing(fixture, case, timing)
            assert_outcome_order(outcome_at, fixture.released_at, case)
            assert_transition_before_release(
                transition_upper, fixture.received_at, fixture.released_at, case
            )
            late_end = max(
                fixture.received_at + timing["observe_until_seconds"],
                outcome_at + timing["after_outcome_seconds"],
            )
            phase = "late-response-window"

            def late_complete():
                assert_control(control, known)
                assert_requests(fixture, reference)
                return time.monotonic() >= late_end

            wait_for(child, late_complete, remaining(stop_at, 25), phase)
            write_marker(control, known, "late-window-complete")
            phase = "late-window-verified"
            receive_marker(
                child,
                control,
                known,
                phase,
                remaining(stop_at, 8),
                guard=lambda: assert_requests(fixture, reference),
            )
            phase = "handler-release"
            wait_for(
                child,
                lambda: fixture.response_unblocked.is_set(),
                remaining(stop_at, 2),
                phase,
            )
            phase = "handler-join"
            fixture.close()
            assert_requests(fixture, reference)
            write_marker(control, known, "handlers-joined")
            phase = "child-done"
            receive_marker(
                child,
                control,
                known,
                phase,
                remaining(stop_at, 20),
                guard=lambda: assert_requests(fixture, reference),
                allow_exited=True,
            )
            phase = "child-exit"
            child.wait(timeout=remaining(stop_at, 10))
            require(
                child.returncode == 0,
                "Native timeout child failed after final verification",
            )
            assert_control(control, known)
            assert_requests(fixture, reference)
        except BaseException as failure:
            failure.add_note(f"Native timeout phase: {phase}")
            raise
        finally:
            try:
                if child.poll() is None:
                    try:
                        child.wait(timeout=35)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
            finally:
                failure = sys.exception()
                try:
                    child.cleanup(timeout=10)
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    if failure is None:
                        raise
                    failure.add_note("Owned native timeout process cleanup failed")
                if failure is not None:
                    try:
                        note = output_counts(stdout, stderr)
                    except (OSError, ValueError):
                        note = "Owned native timeout child output counts unavailable"
                    failure.add_note(note)
        assert_requests(fixture, reference)
    assert_requests(fixture, reference)
    print(f"Native worker timeout {case['name']} passed (1 actual HTTPS request)")


def run(executable, case_name):
    require(
        sys.platform == "linux",
        "Actual POSIX timeout worker qualification requires Linux",
    )
    require(case_name in CASE_NAMES, "Unknown native timeout case")
    matrix, reference, responses = load_inputs(ROOT)
    for case, observed in zip(matrix["cases"], reference["observations"], strict=True):
        if case["name"] == case_name:
            run_case(executable, matrix, case, observed, responses[case_name])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            "Expected the compiled published-schema executable and exact case"
        )
    run(sys.argv[1], sys.argv[2])
