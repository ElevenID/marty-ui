"""Hold real HTTPS responses while the native child checks signal/state parity."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from canvas_worker_https_fixture import WorkerHttpsFixture


def wait_for(child, predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate():
        if child.poll() is not None:
            stdout, stderr = child.communicate(timeout=5)
            raise AssertionError(
                f"Native signal child exited before {description}: {stdout} {stderr}"
            )
        assert time.monotonic() < deadline, f"Timed out waiting for {description}"
        time.sleep(0.01)


def run(executable, scenario="signals"):
    assert sys.platform == "linux", "Actual POSIX worker signals require Linux"
    assert scenario in {"signals", "recovery"}
    root = Path(__file__).resolve().parents[1]
    spec = json.loads(
        (root / "contracts/canvas-worker-rest-scenarios.json").read_text()
    )
    reference = json.loads(
        (root / f"contracts/canvas-worker-provider-{scenario}-oracle.json").read_text()
    )
    cases = (
        ["SIGINT", "SIGTERM", "SIGKILL"]
        if scenario == "signals"
        else ["renewal", "recovery"]
    )
    assert set(reference) == set(cases)
    for signal_name in cases:
        with WorkerHttpsFixture() as https:
            https.stage = {**spec["stages"][0], "hold_response": True}
            certificate_root = Path(https.certificates.name)
            empty_ca_directory = certificate_root / "empty-ca-directory"
            empty_ca_directory.mkdir()
            control = certificate_root / "native-control"
            control.mkdir()
            environment = dict(os.environ)
            environment.update(
                MARTY_CANVAS_WORKER_SIGNAL_NATIVE_ORIGIN=https.origin,
                MARTY_CANVAS_WORKER_SIGNAL_NAME=signal_name,
                MARTY_CANVAS_WORKER_SIGNAL_CONTROL=str(control),
                SSL_CERT_FILE=str(https.cert),
                SSL_CERT_DIR=str(empty_ca_directory),
            )
            child = subprocess.Popen(
                [
                    executable,
                    f"worker_provider_{scenario}_native_child",
                    "--exact",
                    "--nocapture",
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                wait_for(child, https.received.is_set, "actual HTTPS request")
                # Synchronize the test harness only, never the worker or DB.
                (control / "request-received").touch(exist_ok=False)
                release_response = scenario == "recovery" or signal_name == "SIGTERM"
                if release_response:
                    wait_for(
                        child,
                        (control / "release-response").is_file,
                        "verified pending-I/O state",
                    )
                    https.release.set()
                if scenario == "recovery" and signal_name == "recovery":
                    wait_for(
                        child,
                        (control / "reclaimer-idle").is_file,
                        "recovery retry",
                        timeout=45,
                    )
                    assert len(https.requests) == 1, (
                        "Recovery bypassed retry eligibility"
                    )
                    (control / "reclaimer-observed").touch(exist_ok=False)
                stdout, stderr = child.communicate(timeout=90)
                assert child.returncode == 0, (
                    f"Native {signal_name} failed: {stdout} {stderr}"
                )
                assert https.release.is_set() == release_response
                assert https.requests == reference[signal_name]["requests"]
                print(
                    f"Native worker active-provider {signal_name} passed ({len(https.requests)} actual HTTPS requests)"
                )
            finally:
                # Release a fixture response even on failure, allowing native
                # bounded waits/RAII cleanup to finish before last-resort kill.
                https.release.set()
                if child.poll() is None:
                    try:
                        child.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.communicate(timeout=10)


if __name__ == "__main__":
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(
            "Expected the exact compiled published-schema executable [signals|recovery]"
        )
    run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "signals")
