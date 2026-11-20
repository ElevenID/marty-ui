"""Reject missing or substituted executables for platform acceptance scopes."""

import json
import os
import sys
from pathlib import Path

FLOW_TEST_TARGETS = (("marty-flow-acceptance", "flow_published_schema_contract", "test"),)
FLOW_BIN_TARGETS = (
    ("marty-issuance-service", "marty-issuance-service", "bin"),
    ("marty-flow", "marty-flow", "bin"),
)
SELFHOST_TEST_TARGETS = (("marty-selfhost-acceptance", "selfhost_public_image_contract", "test"),)
RENEWAL_UNIT_TEST_TARGETS = (("marty-issuance-service", "marty_issuance_service", "lib"),)


def verify(
    artifacts: Path,
    target_directory: Path,
    *,
    flow_only: bool = False,
    selfhost_only: bool = False,
    renewal_unit_only: bool = False,
) -> None:
    if sum((flow_only, selfhost_only, renewal_unit_only)) > 1:
        raise ValueError("Artifact scope must have one owner")
    debug = target_directory.resolve() / "debug"
    records = [
        json.loads(line) for line in artifacts.read_text(encoding="utf-8").splitlines()
    ]
    if flow_only:
        required = (*FLOW_TEST_TARGETS, *FLOW_BIN_TARGETS)
    elif selfhost_only:
        required = SELFHOST_TEST_TARGETS
    elif renewal_unit_only:
        required = RENEWAL_UNIT_TEST_TARGETS
    else:
        required = (*FLOW_TEST_TARGETS, *FLOW_BIN_TARGETS, *SELFHOST_TEST_TARGETS, *RENEWAL_UNIT_TEST_TARGETS)
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


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) not in (2, 3) or (
        len(args) == 3
        and args[0]
        not in (
            "--flow-only",
            "--selfhost-only",
            "--renewal-unit-only",
        )
    ):
        raise SystemExit(
            "Usage: verify-platform-test-artifacts.py "
            "[--flow-only|--selfhost-only|--renewal-unit-only] "
            "ARTIFACTS TARGET_DIRECTORY"
        )
    scoped = len(args) == 3
    offset = int(scoped)
    verify(
        Path(args[offset]),
        Path(args[offset + 1]),
        flow_only=scoped and args[0] == "--flow-only",
        selfhost_only=scoped and args[0] == "--selfhost-only",
        renewal_unit_only=scoped and args[0] == "--renewal-unit-only",
    )
