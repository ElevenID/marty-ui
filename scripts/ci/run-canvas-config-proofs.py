"""Run the image-free Canvas config proofs early, or verify their same-run proof.

Only a matching composition-test executable may authorize the later exact skips.
Local/standalone full runs without this evidence continue to execute all cases.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from canvas_worker_owned_process import OwnedProcess, OwnedProcessError

TARGET = "canvas_published_schema_contract"
PACKAGE = "#marty-canvas-acceptance@"
EVIDENCE = "canvas-config-proofs.json"
CASES = (
    (
        "rendered_base_process::renderer_bounds_proof_is_image_free",
        "RENDERED_BASE_RENDERER_LIMITS_COMPLETE_V1",
    ),
    (
        "rendered_base_process::rendered_base_renewal_config_crosses_encryption_and_private_address_policy",
        "RENDERED_BASE_RENEWAL_CONFIG_2X2_COMPLETE_V1",
    ),
    (
        "resolved_kubernetes_runtime::resolved_kubernetes_renewal_config_crosses_encryption_and_private_address_policy",
        "RESOLVED_KUBERNETES_RENEWAL_CONFIG_2X2_COMPLETE_V1",
    ),
)
IDENTITY = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_SHA")
PASSED = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored;")
OUTPUT_LIMIT = 2 * 1024 * 1024


def executable_from_artifacts(artifacts: Path) -> Path:
    with artifacts.open(encoding="utf-8") as source:
        matches = [
            row["executable"]
            for line in source
            if (row := json.loads(line)).get("reason") == "compiler-artifact"
            and PACKAGE in row.get("package_id", "")
            and row.get("target", {}).get("name") == TARGET
            and row.get("target", {}).get("kind") == ["test"]
            and row.get("profile", {}).get("test") is True
            and row.get("executable") is not None
        ]
    if len(matches) != 1:
        raise ValueError("Expected exactly one Canvas composition test executable")
    executable = Path(matches[0])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("Canvas composition test executable is absent")
    return executable


def expected(executable: Path) -> dict[str, object]:
    identity = {name: os.environ.get(name, "") for name in IDENTITY}
    tier = os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0")
    if not all(identity.values()) or tier not in ("0", "1"):
        raise ValueError("Canvas config proof requires complete run identity and tier")
    digest = hashlib.sha256()
    with executable.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "schema": 1,
        "composition_sha256": digest.hexdigest(),
        "run": identity,
        "qualification": tier,
        "cases": [name for name, _ in CASES],
    }


def evidence_path() -> Path:
    return Path(os.environ["RUNNER_TEMP"]) / EVIDENCE


def verify(executable: Path) -> bool:
    try:
        with evidence_path().open(encoding="ascii") as source:
            actual = json.load(source)
        if not isinstance(actual, dict) or type(actual.get("schema")) is not int:
            return False
        return actual == expected(executable)
    except (OSError, UnicodeError, ValueError, KeyError, json.JSONDecodeError):
        return False


def run_case(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Bound the whole Rust child and reap its owned renderer process group."""
    if sys.platform != "linux":
        raise ValueError("Early Canvas config proof requires Linux process containment")
    with tempfile.TemporaryFile() as output:
        child = OwnedProcess(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            status = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise ValueError("Canvas config proof child exceeded deadline") from error
        finally:
            child.cleanup(timeout=10)
        output.seek(0)
        result = output.read(OUTPUT_LIMIT + 1)
        if len(result) > OUTPUT_LIMIT:
            raise ValueError("Canvas config proof output exceeded limit")
        return subprocess.CompletedProcess(command, status, result.decode("utf-8"), "")


def run(executable: Path) -> None:
    proof = evidence_path()
    proof.unlink(missing_ok=True)  # A failed rerun must not reuse earlier evidence.
    identity = expected(executable)
    if os.environ.get("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST") != "1":
        raise ValueError("Canvas published-schema test opt-in is required")
    listed = run_case([str(executable), "--list"], 30)
    if listed.returncode:
        raise ValueError("Canvas config proof test discovery failed")
    listing = listed.stdout.splitlines()
    for name, marker in CASES:
        if listing.count(f"{name}: test") != 1:
            raise ValueError(f"Canvas config proof is not uniquely registered: {name}")
        result = run_case(
            [str(executable), name, "--exact", "--nocapture", "--test-threads=1"],
            600,
        )
        output = result.stdout + result.stderr
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (
            result.returncode
            or output.count(marker) != 1
            or len(PASSED.findall(output)) != 1
        ):
            raise ValueError(f"Canvas config proof did not pass exactly once: {name}")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="ascii", newline="\n", dir=proof.parent, delete=False
    ) as temporary:
        json.dump(identity, temporary, sort_keys=True)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, proof)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("run", "verify"):
        print(
            "Usage: run-canvas-config-proofs.py [run|verify] ARTIFACTS_OR_EXECUTABLE",
            file=sys.stderr,
        )
        return 2
    try:
        if sys.argv[1] == "run":
            run(executable_from_artifacts(Path(sys.argv[2])))
            return 0
        return 0 if verify(Path(sys.argv[2])) else 1
    except (OSError, UnicodeError, ValueError, OwnedProcessError) as error:
        print(f"Canvas config proof failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
