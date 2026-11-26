"""Exercise the target-side observation harness with real oracle values."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from test_feature_regression_rust_probe import EXPECTED_OBSERVATIONS, EXPECTED_OPERATIONS


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / ".github/feature-regression/observation_harness.py"
REVISION = "7a636da20f86e519e37b1ab0f79ddec5dfe7e2c9"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def capture() -> dict[str, object]:
    observations = [
        {
            "id": f"{case_id}.{dimension}",
            "operation_id": EXPECTED_OPERATIONS[case_id],
            "case_id": case_id,
            "dimension": dimension,
            "value": value,
        }
        for (case_id, dimension), value in sorted(EXPECTED_OBSERVATIONS.items())
    ]
    subject = canonical({"schema": "elevenid.behavior-subject-output/v2", "observations": observations})
    return {
        "schema": "elevenid.behavior-subject-capture/v2",
        "receipt": {
            "runtime": "rust-cargo",
            "stderr_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
            "stdout_sha256": "sha256:" + hashlib.sha256(subject).hexdigest(),
        },
        "observations": observations,
    }


def run_harness(
    document: dict[str, object], command: str = "emit", *, optimized: bool = False
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable, *(["-O"] if optimized else []), str(HARNESS), command,
            "--repository", "ElevenID/marty-ui", "--revision", REVISION,
            "--phase", "before",
        ],
        input=canonical(document),
        capture_output=True,
        check=False,
    )


def test_harness_emits_exact_oracle_observations() -> None:
    result = run_harness(capture())
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    document = json.loads(result.stdout)
    assert document["schema"] == "elevenid.behavior-observations-runtime/v2"
    assert document["repository"] == "ElevenID/marty-ui"
    assert document["revision"] == REVISION
    assert len(document["observations"]) == len(EXPECTED_OBSERVATIONS)
    assert {item["producer_test"] for item in document["observations"]} == {
        f"test:ElevenID/marty-ui@{REVISION}:tests/test_feature_regression_rust_probe.py::assert_expected_probe_output"
    }


def test_harness_rejects_changed_public_value_even_with_updated_capture_digest() -> None:
    document = capture()
    document["observations"][0]["value"] = "unreviewed private value"
    subject = canonical({"schema": "elevenid.behavior-subject-output/v2", "observations": document["observations"]})
    document["receipt"]["stdout_sha256"] = "sha256:" + hashlib.sha256(subject).hexdigest()
    assert run_harness(document).returncode != 0


def test_harness_rejects_capture_digest_mismatch() -> None:
    document = capture()
    document["observations"][0]["value"] = "unreviewed private value"
    assert run_harness(document).returncode != 0


def test_harness_rejects_optimized_interpreter() -> None:
    document = capture()
    document["observations"][0]["value"] = "unreviewed private value"
    subject = canonical({"schema": "elevenid.behavior-subject-output/v2", "observations": document["observations"]})
    document["receipt"]["stdout_sha256"] = "sha256:" + hashlib.sha256(subject).hexdigest()
    result = run_harness(document, optimized=True)
    assert result.returncode != 0
    assert result.stdout == b""
