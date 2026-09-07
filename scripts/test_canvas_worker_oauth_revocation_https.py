"""Owned real HTTPS responses for the actual native revocation worker."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from canvas_worker_https_fixture import WorkerHttpsFixture
from test_canvas_worker_provider_signals_https import wait_for
from test_canvas_worker_rest_https import assert_retry_timing


def run_fenced_child(command, environment, https):
    """Reuse the existing marker protocol; SQL and worker remain in the child."""
    control = Path(https.certificates.name) / "native-control"
    control.mkdir()
    environment["MARTY_CANVAS_WORKER_SIGNAL_CONTROL"] = str(control)
    child = subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for(child, https.received.is_set, "actual revocation DELETE")
        received_at = time.monotonic()
        (control / "request-received").touch(exist_ok=False)
        wait_for(
            child,
            (control / "release-response").is_file,
            "committed owner transfer",
            timeout=5,
        )
        assert time.monotonic() - received_at < 5, (
            "Owner transfer exceeded the pre-timeout budget"
        )
        https.release.set()
        stdout, stderr = child.communicate(timeout=90)
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    finally:
        https.release.set()
        if child.poll() is None:
            try:
                child.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=10)


def run(executable, kind="oauth-revocation"):
    assert kind in {
        "oauth-revocation",
        "oauth-revocation-fence",
        "oauth-revocation-patch",
        "oauth-revocation-retry-after",
        "oauth-revocation-backoff",
    }
    root = Path(__file__).resolve().parents[1]
    matrix = json.loads(
        (root / f"contracts/canvas-worker-{kind}-scenarios.json").read_text()
    )
    reference = json.loads(
        (root / f"contracts/canvas-worker-{kind}-oracle.json").read_text()
    )
    names = [case["name"] for case in matrix["cases"]]
    assert len(names) == len(set(names)) and set(names) == set(reference)
    failures = []
    for case in matrix["cases"]:
        with WorkerHttpsFixture() as https:
            https.stage = case
            empty_ca = Path(https.certificates.name) / "empty-ca"
            empty_ca.mkdir()
            environment = dict(os.environ)
            environment.update(
                MARTY_CANVAS_PUBLISHED_SCHEMA_TEST="1",
                MARTY_CANVAS_WORKER_REVOCATION_NATIVE_ORIGIN=https.origin,
                MARTY_CANVAS_WORKER_OAUTH_REVOCATION_CASE=case["name"],
                MARTY_CANVAS_WORKER_OAUTH_REVOCATION_KIND=kind,
                SSL_CERT_FILE=str(https.cert),
                SSL_CERT_DIR=str(empty_ca),
            )
            command = [
                executable,
                "worker_oauth_revocation_native_child",
                "--exact",
                "--nocapture",
            ]
            child = (
                run_fenced_child(command, environment, https)
                if kind == "oauth-revocation-fence"
                else subprocess.run(
                    command,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=240,
                )
            )
            if child.returncode != 0:
                failures.append(case["name"])
                print(
                    f"Native OAuth revocation {case['name']} failed ({len(https.requests)} HTTP requests observed)"
                )
                print(child.stdout, child.stderr)
                continue
            assert https.requests == reference[case["name"]]["requests"]
            if kind == "oauth-revocation-retry-after":
                assert_retry_timing(
                    child.stdout,
                    case,
                    https.retry_after_dates,
                    reference[case["name"]]["retry_timing"],
                )
            if case.get("hold_response"):
                assert https.received.is_set()
                assert https.release.is_set() == (kind == "oauth-revocation-fence")
            print(
                f"Native OAuth revocation {case['name']} PASS ({len(https.requests)} request)"
            )
    assert not failures, f"Native OAuth revocation failures: {failures}"


if __name__ == "__main__":
    assert len(sys.argv) in {2, 3}, (
        "Expected the compiled published-schema test executable [matrix]"
    )
    if sys.platform != "linux":
        raise SystemExit(
            "Native HTTPS process qualification requires Linux platform trust; no host trust-store changes are allowed"
        )
    run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "oauth-revocation")
