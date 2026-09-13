"""Supply real HTTPS deadline barriers to the actual native worker test child.

Rust owns the worker, database, lease/timing assertions and native log privacy.
This parent owns only synthetic responses and ordered test-control markers.
It never edits a running job, lease, clock or schedule, and never compares
native output to Python-only import warnings.

The outer Rust caller retains the disposable database across this per-case
driver. This driver contains coordinator failures and harness-controlled kills;
SIGKILL of this driver or its outer runner is not a qualified cleanup path.
"""

from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from canvas_worker_deadline_https_fixture import DeadlineHttpsFixture
from canvas_worker_output_capture import owned_log_streams
from canvas_worker_owned_process import OwnedProcess
from canvas_worker_process_control import assert_control, output_counts, write_marker


ROOT = Path(__file__).resolve().parents[1]
CASE_NAMES = ["early_release", "deadline_cancel"]
CASE_TIMEOUT_SECONDS = 120
POLL_SECONDS = 0.025


def validate_matrix(matrix, reference):
    assert matrix["schema"] == "marty.canvas-worker-deadline-scenarios/v1"
    assert reference["schema"] == "marty.canvas-worker-deadline-oracle/v1"
    assert matrix["cases"] == [
        {"name": "early_release", "status": "succeeded", "facts": 3},
        {"name": "deadline_cancel", "status": "retry", "facts": 2},
    ], "Deadline matrix must retain both exact controls"
    observations = reference["observations"]
    assert [item["case"] for item in observations] == CASE_NAMES, (
        "Deadline reference must retain both ordered observations"
    )
    assert matrix["environment"] == {
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS": "30",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS": "30",
        "CANVAS_SYNC_WORKER_POLL_SECONDS": "60",
        "LOG_LEVEL": "WARNING",
    }
    assert matrix["requirement_ids"] == ["assignment", "quiz", "module"]
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
    paths = matrix["request_paths"]
    assert len(paths) == len(set(paths)) == 3
    for observation in observations:
        assert observation["schema"] == "marty.canvas-worker-deadline-observation/v1"
        assert len(observation["completed_read_states"]) == 2
        assert observation["timing_bounds"] == matrix["timing_bounds"]
        requests = observation["requests"]
        assert len(requests) == 3
        assert [item["path"] for item in requests] == paths
        for request in requests:
            assert set(request) == {"method", "path", "authorization", "accept"}
            assert request["method"] == "GET"
            assert request["accept"] == "application/json"
            assert isinstance(request["authorization"], str)
            assert request["authorization"].startswith("Bearer ")
            assert request["authorization"] != "Bearer "


def load_inputs(root):
    def read(name):
        return json.loads((root / "contracts" / name).read_text(encoding="utf-8"))

    matrix = read("canvas-worker-deadline-scenarios.json")
    reference = read("canvas-worker-deadline-oracle.json")
    validate_matrix(matrix, reference)
    extension = read(matrix["reference_scenario"])
    spec = {**read(extension["extends"]), **extension}
    [stage] = [
        item for item in spec["stages"] if item["name"] == matrix["response_stage"]
    ]
    responses = {path: stage["responses"][path] for path in matrix["request_paths"]}
    assert all(response["status"] == 200 for response in responses.values())
    expected = [
        {
            "method": "GET",
            "path": path,
            "authorization": f"Bearer {spec['token']}",
            "accept": "application/json",
        }
        for path in matrix["request_paths"]
    ]
    assert all(
        observation["requests"] == expected for observation in reference["observations"]
    ), "Frozen deadline requests differ from their seed owner"
    return matrix, reference, responses


def wait_for(child, predicate, timeout, phase, *, allow_exited=False):
    assert math.isfinite(timeout) and timeout > 0, "Invalid deadline wait budget"
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        status = child.poll()
        assert status is None or (allow_exited and status == 0 and value), (
            f"Native deadline child exited during {phase} (status {status})"
        )
        # A predicate can itself block. A late-ready marker must not turn an
        # expired observation budget into a successful bounded wait.
        if time.monotonic() >= deadline:
            raise AssertionError(f"Native deadline wait expired: {phase}")
        if value:
            return value
        time.sleep(POLL_SECONDS)


def receive_marker(child, control, known, name, timeout, *, allow_exited=False):
    assert name not in known, "Duplicate deadline child marker"
    wait_for(
        child,
        lambda: assert_control(control, known, name),
        timeout,
        name,
        allow_exited=allow_exited,
    )
    known.add(name)


def assert_requests(fixture, reference, count=3):
    # Explicit errors also remain payload-free under pytest assertion rewriting.
    if fixture.failures:
        raise AssertionError("Owned native deadline HTTPS handler failed")
    if fixture.requests != reference["requests"][:count]:
        raise AssertionError(
            "Native deadline request transcript differs from the frozen reference"
        )


def remaining(deadline, maximum):
    budget = deadline - time.monotonic()
    assert budget > 0, "Native deadline case exceeded its total fixture bound"
    return min(maximum, budget)


def run_case(executable, matrix, case, reference, responses):
    assert case["name"] in CASE_NAMES and case["name"] == reference["case"]
    deadline = time.monotonic() + CASE_TIMEOUT_SECONDS
    # Control/output must survive HTTPS.close(), which joins request handlers
    # and removes its certificate directory BEFORE native worker interruption.
    with ExitStack() as owner:
        owned_root = Path(
            owner.enter_context(
                tempfile.TemporaryDirectory(prefix="canvas-native-deadline-")
            )
        )
        control = owned_root / "native-control"
        control.mkdir()
        empty_ca_directory = owned_root / "empty-ca-directory"
        empty_ca_directory.mkdir()
        stdout_writer, stdout = owned_log_streams(owner, owned_root)
        stderr_writer, stderr = owned_log_streams(owner, owned_root)
        fixture = owner.enter_context(
            DeadlineHttpsFixture(matrix["request_paths"], responses)
        )
        environment = dict(os.environ)
        environment.update(
            MARTY_CANVAS_WORKER_DEADLINE_NATIVE_ORIGIN=fixture.origin,
            MARTY_CANVAS_WORKER_DEADLINE_CASE=case["name"],
            MARTY_CANVAS_WORKER_DEADLINE_CONTROL=str(control),
            SSL_CERT_FILE=str(fixture.cert),
            SSL_CERT_DIR=str(empty_ca_directory),
        )
        child = OwnedProcess(
            [executable, "worker_deadline_native_child", "--exact", "--nocapture"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_writer,
            stderr=stderr_writer,
        )
        known = set()
        phase = "first-request"
        try:
            for index in range(3):
                phase = f"request-received-{index}"

                def request_received():
                    assert_control(control, known)
                    if fixture.failures:
                        raise AssertionError(
                            "Owned native deadline HTTPS handler failed"
                        )
                    return fixture.request_received[index].is_set()

                wait_for(
                    child,
                    request_received,
                    remaining(deadline, 20 if index == 0 else 8),
                    phase,
                )
                assert_requests(fixture, reference, index + 1)
                assert not any(
                    event.is_set() for event in fixture.response_release[index:]
                ), "A future deadline response was released prematurely"
                write_marker(control, known, phase)
                if index == 2:
                    break
                phase = f"renewal-observed-{index}"
                receive_marker(child, control, known, phase, remaining(deadline, 14))
                phase = f"release-delay-{index}"
                wait_for(
                    child,
                    lambda: (
                        time.monotonic() - fixture.received_at[index]
                        >= matrix["completed_response_delay_seconds"]
                    ),
                    remaining(deadline, 12),
                    phase,
                )
                assert_control(control, known)
                assert_requests(fixture, reference, index + 1)
                elapsed = time.monotonic() - fixture.received_at[index]
                assert (
                    matrix["completed_response_delay_seconds"]
                    <= elapsed
                    < matrix["completed_response_latest_seconds"]
                ), "Native deadline response missed its declared release band"
                fixture.response_release[index].set()

            phase = "committed-prefix"
            receive_marker(child, control, known, phase, remaining(deadline, 8))
            assert_requests(fixture, reference)
            assert not fixture.response_release[2].is_set()
            if case["name"] == "early_release":
                assert time.monotonic() - fixture.received_at[0] < 27, (
                    "Early deadline control missed its response budget"
                )
                fixture.response_release[2].set()
            phase = "outcome-observed"
            receive_marker(child, control, known, phase, remaining(deadline, 20))
            assert_requests(fixture, reference)
            if case["name"] == "deadline_cancel":
                assert not fixture.response_release[2].is_set()
                assert (
                    time.monotonic() - fixture.received_at[2]
                    < matrix["published_http_timeout_seconds"]
                ), "Deadline outcome did not precede the pending HTTP timeout"
                fixture.response_release[2].set()

            late_end = (
                fixture.received_at[2]
                + max(
                    matrix["published_http_timeout_seconds"],
                    matrix["native_http_timeout_seconds"],
                )
                + matrix["post_response_observation_margin_seconds"]
            )
            phase = "late-response-window"

            def late_window_complete():
                assert_control(control, known)
                assert_requests(fixture, reference)
                return time.monotonic() >= late_end

            wait_for(child, late_window_complete, remaining(deadline, 25), phase)
            write_marker(control, known, "late-window-complete")
            phase = "late-window-verified"
            receive_marker(child, control, known, phase, remaining(deadline, 8))
            assert all(event.is_set() for event in fixture.response_unblocked), (
                "A native deadline response handler is still blocked"
            )
            phase = "handler-join"
            fixture.close()
            assert_requests(fixture, reference)
            write_marker(control, known, "handlers-joined")
            phase = "child-done"
            receive_marker(
                child, control, known, phase, remaining(deadline, 20), allow_exited=True
            )
            phase = "child-exit"
            child.wait(timeout=remaining(deadline, 10))
            assert child.returncode == 0, (
                "Native deadline child failed after final verification"
            )
            assert_control(control, known)
            assert_requests(fixture, reference)
        except BaseException as error:
            # Static phase and sizes are sufficient to locate the failing owner;
            # never expose Rust assertion payloads or synthetic authentication.
            error.add_note(f"Native deadline phase: {phase}")
            raise
        finally:
            try:
                if child.poll() is None:
                    # Let the child's bounded waits unwind its owned worker/DB
                    # cleanup before a last-resort termination of the test child.
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
                    failure.add_note("Owned deadline process cleanup failed")
                if failure is not None:
                    try:
                        note = output_counts(stdout, stderr)
                    except (OSError, ValueError):
                        note = "Owned deadline child output counts unavailable"
                    failure.add_note(note)
        # Repeat after child exit; the fixture also checks failures during its
        # context-manager shutdown. No traffic may disappear from the ledger.
        assert_requests(fixture, reference)
    assert_requests(fixture, reference)
    print(f"Native worker deadline {case['name']} passed (3 actual HTTPS requests)")


def run(executable, case_name):
    assert sys.platform == "linux", "Actual POSIX worker interruption requires Linux"
    if case_name not in CASE_NAMES:
        raise AssertionError("Unknown native deadline case")
    matrix, reference, responses = load_inputs(ROOT)
    for case, observation in zip(
        matrix["cases"], reference["observations"], strict=True
    ):
        if case["name"] == case_name:
            run_case(executable, matrix, case, observation, responses)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(
            "Expected the compiled published-schema executable and exact case"
        )
    run(sys.argv[1], sys.argv[2])
