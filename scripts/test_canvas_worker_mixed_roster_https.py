"""Replay frozen mixed-roster transports around natural native worker cycles.

The Rust child owns the actual worker, isolated database and durable assertions.
This parent owns only synthetic provider responses and test-harness markers; it
never changes a worker clock, schedule, job, lease or candidate row. The signer
is a synthetic transport fixture, not remote-signing or crypto qualification.
"""

from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from canvas_worker_mixed_roster_https_fixture import MixedRosterHttpsFixture

TRANSPORT_FIELDS = (
    "requests",
    "token_scopes",
    "signer_requests",
    "signer_operations",
)
CASE_TIMEOUT_SECONDS = 660
STAGE_TIMEOUT_SECONDS = 120
OUTPUT_TAIL_BYTES = 4096


def validate_matrix(matrix, reference):
    assert matrix["schema"] == "marty.canvas-worker-mixed-roster-scenarios/v1"
    assert reference["schema"] == "marty.canvas-worker-mixed-roster-oracle/v1"
    cases = matrix["cases"]
    names = [case["name"] for case in cases]
    assert names, "Mixed-roster matrix must not be empty"
    assert len(names) == len(set(names)), "Duplicate mixed-roster cases"
    # The independently captured artifact contains one complete worker case.
    # Reject missing/extra cases instead of silently selecting one from either.
    assert set(names) == {reference["case"]}, "Mixed-roster case matrix differs"
    assert names == ["mixed_candidates_resume_wrap"], "Unexpected mixed-roster case"
    for case in cases:
        stages = [stage["name"] for stage in case["stages"]]
        assert stages, "Mixed-roster stage matrix must not be empty"
        assert len(stages) == len(set(stages)), "Duplicate mixed-roster stages"
        assert len(stages) == 7, "Mixed-roster replay requires all seven stages"
        assert stages == [item["name"] for item in reference["observations"]], (
            "Mixed-roster stage matrix differs"
        )
    for observation in reference["observations"]:
        for field in TRANSPORT_FIELDS:
            assert isinstance(observation[field], list), (
                "Mixed-roster transport reference must contain exact lists"
            )


def assert_transport(fixture, observation):
    assert not fixture.failures, "Mixed-roster synthetic transport contract failed"
    actual = {
        field: copy.deepcopy(getattr(fixture, field)) for field in TRANSPORT_FIELDS
    }
    for field in TRANSPORT_FIELDS:
        assert actual[field] == observation[field], (
            f"Mixed-roster {observation['name']} {field} differs from published reference "
            f"(observed {len(actual[field])}, expected {len(observation[field])} entries)"
        )
    return actual


def wait_marker(child, path, timeout):
    deadline = time.monotonic() + timeout
    while not path.is_file():
        assert child.poll() is None, f"Native child exited before {path.name}"
        assert time.monotonic() < deadline, f"Timed out waiting for {path.name}"
        time.sleep(0.01)


def diagnostic_tail(output):
    output.flush()
    size = output.seek(0, os.SEEK_END)
    output.seek(max(0, size - OUTPUT_TAIL_BYTES))
    tail = output.read(OUTPUT_TAIL_BYTES).decode("utf-8", errors="replace")
    prefix = "[earlier output omitted]\n" if size > OUTPUT_TAIL_BYTES else ""
    return prefix + tail


def remaining_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    assert remaining > 0, "Mixed-roster native replay exceeded its total bound"
    return min(maximum, remaining)


def run_case(executable, matrix, case, reference):
    assert case["name"] == reference["case"]
    observations = reference["observations"]
    assert [stage["name"] for stage in case["stages"]] == [
        observation["name"] for observation in observations
    ]
    assert observations, "Mixed-roster replay must execute at least one stage"
    snapshots = []
    deadline = time.monotonic() + CASE_TIMEOUT_SECONDS
    with MixedRosterHttpsFixture(matrix) as fixture, ExitStack() as output_owner:
        certificate_root = Path(fixture.certificates.name)
        empty_ca_directory = certificate_root / "empty-ca-directory"
        empty_ca_directory.mkdir()
        control = certificate_root / "native-control"
        control.mkdir()
        # A Rust assertion can exceed a pipe's capacity while this parent is
        # waiting for a marker. Owned files let the child finish panic cleanup
        # without an output drain; expose only bounded tails on failure.
        stdout_file, stderr_file = [
            output_owner.enter_context(tempfile.TemporaryFile(dir=certificate_root))
            for _ in range(2)
        ]
        environment = dict(os.environ)
        environment.update(
            MARTY_CANVAS_WORKER_MIXED_ROSTER_NATIVE_ORIGIN=fixture.origin,
            MARTY_CANVAS_WORKER_MIXED_ROSTER_SIGNER_ORIGIN=fixture.signer_origin,
            MARTY_CANVAS_WORKER_MIXED_ROSTER_CASE=case["name"],
            MARTY_CANVAS_WORKER_MIXED_ROSTER_CONTROL=str(control),
            SSL_CERT_FILE=str(fixture.cert),
            SSL_CERT_DIR=str(empty_ca_directory),
        )
        child = subprocess.Popen(
            [executable, "worker_mixed_roster_native_child", "--exact", "--nocapture"],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
        )
        failure = None
        try:
            for index, (stage, observation) in enumerate(
                zip(case["stages"], observations, strict=True)
            ):
                # A done marker means the durable assertions completed. Keep
                # that stage's ledger until just before the next ready marker,
                # catching requests arriving after its initial comparison.
                # Use the existing observer locks in a fixed order so a
                # concurrent request cannot be recorded between the final
                # comparison and set_stage clearing the prior ledger.
                with (
                    fixture.server.RequestHandlerClass.request_observation_lock,
                    fixture.signer_server.RequestHandlerClass.request_observation_lock,
                ):
                    if index:
                        assert_transport(fixture, observations[index - 1])
                    else:
                        assert not fixture.failures
                        assert all(
                            not getattr(fixture, field) for field in TRANSPORT_FIELDS
                        )
                    fixture.set_stage(stage)
                    (control / f"stage-ready-{index}").touch(exist_ok=False)
                wait_marker(
                    child,
                    control / f"stage-done-{index}",
                    remaining_timeout(deadline, STAGE_TIMEOUT_SECONDS),
                )
                snapshots.append(assert_transport(fixture, observation))
                # This acknowledgment follows BOTH durable and transport
                # comparisons. Rust performs only the specified idle restart,
                # after stage 1's ack and before consuming stage 2's ready.
                (control / f"stage-ack-{index}").touch(exist_ok=False)

            # Final done is emitted only after worker shutdown and post-exit
            # durable verification. Still retain its ledger through child exit
            # and joined handler shutdown: late extra traffic must fail too.
            child.communicate(timeout=remaining_timeout(deadline, 90))
            assert child.returncode == 0, (
                f"Native mixed-roster child failed with status {child.returncode}"
            )
            assert_transport(fixture, observations[-1])
        except BaseException as error:
            failure = error
            raise
        finally:
            try:
                if child.poll() is None:
                    # Let the child's bounded marker waits and owned-worker/DB
                    # cleanup finish before a last-resort kill of the test child.
                    try:
                        child.communicate(timeout=60)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate(timeout=10)
            finally:
                if failure is not None:
                    failure.add_note(
                        "Owned synthetic child stdout tail:\n"
                        + diagnostic_tail(stdout_file)
                        + "\nOwned synthetic child stderr tail:\n"
                        + diagnostic_tail(stderr_file)
                    )
    assert_transport(fixture, observations[-1])
    print(
        f"Native worker mixed-roster {case['name']} passed "
        f"({len(snapshots)} stages, "
        f"{sum(len(snapshot['requests']) for snapshot in snapshots)} actual HTTPS requests)"
    )
    return snapshots


def run(executable):
    assert sys.platform == "linux", "Actual POSIX worker restarts require Linux"
    root = Path(__file__).resolve().parents[1]
    matrix = json.loads(
        (root / "contracts/canvas-worker-mixed-roster-scenarios.json").read_text()
    )
    reference = json.loads(
        (root / "contracts/canvas-worker-mixed-roster-oracle.json").read_text()
    )
    validate_matrix(matrix, reference)
    for case in matrix["cases"]:
        run_case(executable, matrix, case, reference)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Expected the exact compiled published-schema executable")
    run(sys.argv[1])
