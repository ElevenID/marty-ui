"""Fail early if the narrow Canvas compile omitted or substituted a required target."""

import json
import os
from pathlib import Path
import sys


TEST_TARGETS = (
    ("marty-canvas-acceptance", "canvas_published_worker_contract", "test"),
    ("marty-canvas-acceptance", "canvas_published_schema_contract", "test"),
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


def verify(artifacts: Path, target_directory: Path) -> None:
    debug = target_directory.resolve() / "debug"
    records = [
        json.loads(line) for line in artifacts.read_text(encoding="utf-8").splitlines()
    ]
    for package, target, kind in (*TEST_TARGETS, *BIN_TARGETS):
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
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: verify-canvas-test-artifacts.py ARTIFACTS TARGET_DIRECTORY"
        )
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
