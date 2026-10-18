"""Fail early if the narrow Canvas compile omitted or substituted a required target."""

import json
import os
import subprocess
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
SELFHOST_TEST_TARGETS = (TEST_TARGETS[3],)
RENEWAL_UNIT_TEST_TARGETS = (TEST_TARGETS[6],)


def verify(
    artifacts: Path,
    target_directory: Path,
    *,
    worker_only: bool = False,
    flow_only: bool = False,
    selfhost_only: bool = False,
    renewal_unit_only: bool = False,
    check_worker_inventory: bool = False,
) -> None:
    if sum((worker_only, flow_only, selfhost_only, renewal_unit_only)) > 1:
        raise ValueError("Artifact scope must have one owner")
    debug = target_directory.resolve() / "debug"
    records = [
        json.loads(line) for line in artifacts.read_text(encoding="utf-8").splitlines()
    ]
    if worker_only:
        required = (*WORKER_TEST_TARGETS, *WORKER_BIN_TARGETS)
    elif flow_only:
        required = (*FLOW_TEST_TARGETS, *FLOW_BIN_TARGETS)
    elif selfhost_only:
        required = SELFHOST_TEST_TARGETS
    elif renewal_unit_only:
        required = RENEWAL_UNIT_TEST_TARGETS
    else:
        required = (*TEST_TARGETS, *BIN_TARGETS)
    worker_test_executable = None
    for package, target, kind in required:
        matches = [
            (record["executable"], record["profile"].get("test"))
            for record in records
            if record.get("reason") == "compiler-artifact"
            and f"#{package}@" in record.get("package_id", "")
            and record.get("target", {}).get("name") == target
            and kind in record.get("target", {}).get("kind", ())
            and record.get("executable") is not None
            and record.get("profile", {}).get("test") is (kind != "bin")
        ]
        if not renewal_unit_only:
            matches = list(set(matches))
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
        if (package, target, kind) == WORKER_TEST_TARGETS[0]:
            worker_test_executable = path
    if check_worker_inventory:
        if worker_test_executable is None:
            raise ValueError("Canvas worker inventory requires the compiled worker target")
        listed = subprocess.run(
            [str(worker_test_executable), "--list"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        subprocess.run(
            [sys.executable, str(Path(__file__).with_name("check_canvas_tier_obligations.py"))],
            input=listed,
            check=True,
            text=True,
        )


if __name__ == "__main__":
    args = sys.argv[1:]
    check_worker_inventory = "--check-worker-inventory" in args
    if check_worker_inventory:
        args.remove("--check-worker-inventory")
    if len(args) not in (2, 3) or (
        len(args) == 3
        and args[0]
        not in (
            "--worker-only",
            "--flow-only",
            "--selfhost-only",
            "--renewal-unit-only",
        )
    ):
        raise SystemExit(
            "Usage: verify-canvas-test-artifacts.py "
            "[--worker-only|--flow-only|--selfhost-only|--renewal-unit-only] "
            "[--check-worker-inventory] ARTIFACTS TARGET_DIRECTORY"
        )
    scoped = len(args) == 3
    offset = int(scoped)
    verify(
        Path(args[offset]),
        Path(args[offset + 1]),
        worker_only=scoped and args[0] == "--worker-only",
        flow_only=scoped and args[0] == "--flow-only",
        selfhost_only=scoped and args[0] == "--selfhost-only",
        renewal_unit_only=scoped and args[0] == "--renewal-unit-only",
        check_worker_inventory=check_worker_inventory,
    )
