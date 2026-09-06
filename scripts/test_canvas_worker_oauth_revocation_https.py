"""Owned real HTTPS responses for the actual native revocation worker."""

import json
import os
from pathlib import Path
import subprocess
import sys

from canvas_worker_https_fixture import WorkerHttpsFixture


def run(executable):
    root = Path(__file__).resolve().parents[1]
    matrix = json.loads(
        (root / "contracts/canvas-worker-oauth-revocation-scenarios.json").read_text()
    )
    reference = json.loads(
        (root / "contracts/canvas-worker-oauth-revocation-oracle.json").read_text()
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
                SSL_CERT_FILE=str(https.cert),
                SSL_CERT_DIR=str(empty_ca),
            )
            child = subprocess.run(
                [
                    executable,
                    "worker_oauth_revocation_native_child",
                    "--exact",
                    "--nocapture",
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=240,
            )
            if child.returncode != 0:
                failures.append(case["name"])
                print(
                    f"Native OAuth revocation {case['name']} failed ({len(https.requests)} HTTP requests observed)"
                )
                print(child.stdout, child.stderr)
                continue
            assert https.requests == reference[case["name"]]["requests"]
            if case.get("hold_response"):
                assert https.received.is_set() and not https.release.is_set()
            print(
                f"Native OAuth revocation {case['name']} PASS ({len(https.requests)} request)"
            )
    assert not failures, f"Native OAuth revocation failures: {failures}"


if __name__ == "__main__":
    assert len(sys.argv) == 2, "Expected the compiled published-schema test executable"
    if sys.platform != "linux":
        raise SystemExit(
            "Native HTTPS process qualification requires Linux platform trust; no host trust-store changes are allowed"
        )
    run(sys.argv[1])
