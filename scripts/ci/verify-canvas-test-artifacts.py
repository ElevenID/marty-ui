"""Fail early if the narrow Canvas compile omitted or substituted a required target."""

import json
import os
import sys
from pathlib import Path

TEST_TARGETS = (
    ("marty-canvas-worker-acceptance", "canvas_published_worker_contract", "test"),
    ("marty-canvas-acceptance", "canvas_published_schema_contract", "test"),
    ("marty-flow-acceptance", "flow_published_schema_contract", "test"),
    ("marty-selfhost-acceptance", "selfhost_public_image_contract", "test"),
    ("marty-issuance-service", "canvas_oauth_behavior", "test"),
    ("marty-issuance-service", "issuance-behavior", "test"),
    ("marty-issuance-service", "marty_issuance_service", "lib"),
)
BIN_TARGETS = (
    ("marty-issuance-service", "marty-issuance-service", "bin"),
    ("marty-issuance-service", "marty-canvas-sync-worker", "bin"),
    ("marty-gateway", "marty-gateway", "bin"),
    ("marty-flow", "marty-flow", "bin"),
)
WORKER_TEST_TARGETS = (TEST_TARGETS[0],)
WORKER_BIN_TARGETS = (BIN_TARGETS[1],)
FLOW_TEST_TARGETS = (TEST_TARGETS[2],)
FLOW_BIN_TARGETS = (BIN_TARGETS[0], BIN_TARGETS[3])


def verify(
    artifacts: Path,
    target_directory: Path,
    *,
    worker_only: bool = False,
    flow_only: bool = False,
) -> None:
    if worker_only and flow_only:
        raise ValueError("Artifact scope must have one owner")
    debug = target_directory.resolve() / "debug"
    records = [
        json.loads(line) for line in artifacts.read_text(encoding="utf-8").splitlines()
    ]
    if worker_only:
        required = (*WORKER_TEST_TARGETS, *WORKER_BIN_TARGETS)
    elif flow_only:
        required = (*FLOW_TEST_TARGETS, *FLOW_BIN_TARGETS)
    else:
        required = (*TEST_TARGETS, *BIN_TARGETS)
    for package, target, kind in required:
        matches = {
            (record["executable"], record["profile"].get("test"))
            for record in records
            if record.get("reason") == "compiler-artifact"
            and f"#{package}@" in record.get("package_id", "")
            and record.get("target", {}).get("name") == target
            and kind in record.get("target", {}).get("kind", ())
            and record.get("executable") is not None
            and record.get("profile", {}).get("test") is (kind != "bin")
        }
        if len(matches) != 1:
            raise ValueError(
                f"Expected exactly one {package}/{target} executable; found {len(matches)}"
            )
        executable, is_test = matches.pop()
        path = Path(executable).resolve()
        if kind == "bin":
            if is_test is not False or path != debug / target:
                raise ValueError(f"Expected a real, non-test {package}/{target} binary")
        elif is_test is not True or path.parent != debug / "deps":
            raise ValueError(f"Expected a test harness for {package}/{target}")
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError(f"Missing executable for {package}/{target}")


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4) or (
        len(sys.argv) == 4 and sys.argv[1] not in ("--worker-only", "--flow-only")
    ):
        raise SystemExit(
            "Usage: verify-canvas-test-artifacts.py "
            "[--worker-only|--flow-only] ARTIFACTS TARGET_DIRECTORY"
        )
    scoped = len(sys.argv) == 4
    offset = 1 + scoped
    verify(
        Path(sys.argv[offset]),
        Path(sys.argv[offset + 1]),
        worker_only=scoped and sys.argv[1] == "--worker-only",
        flow_only=scoped and sys.argv[1] == "--flow-only",
    )
