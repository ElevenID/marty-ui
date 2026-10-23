#!/usr/bin/env python3
"""Reject release claims whose official harness pin has not reached main."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = "ElevenID/marty-integration-tests"
WORKFLOW = f"{REPOSITORY}/.github/workflows/official-interoperability.yml"


def harness_pin(workflow: str) -> str:
    # Accept only the literal, immutable reusable-workflow job we actually call.
    jobs = re.findall(
        r"^  official-interoperability:\s*\n(.*?)(?=^  \S|\Z)",
        workflow, re.MULTILINE | re.DOTALL,
    )
    if len(jobs) != 1:
        raise ValueError("Expected exactly one official interoperability job")
    uses = re.findall(r"^    uses: (\S+)\s*$", jobs[0], re.MULTILINE)
    revisions = re.findall(r"^      harness_revision: (\S+)\s*$", jobs[0], re.MULTILINE)
    if len(uses) != 1 or len(revisions) != 1:
        raise ValueError("Expected one literal official harness pin and revision")
    revision = revisions[0]
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or uses[0] != f"{WORKFLOW}@{revision}":
        raise ValueError("Official harness must use the same full commit SHA in both bindings")
    return revision


def require_main_ancestor(pin: str, comparison: object) -> None:
    if not isinstance(comparison, dict):
        raise ValueError("Missing official harness main-ancestry evidence")
    base = comparison.get("base_commit")
    merge_base = comparison.get("merge_base_commit")
    if (
        comparison.get("status") not in ("identical", "ahead")
        or type(comparison.get("behind_by")) is not int
        or comparison["behind_by"] != 0
        or not isinstance(base, dict)
        or base.get("sha") != pin
        or not isinstance(merge_base, dict)
        or merge_base.get("sha") != pin
    ):
        raise ValueError("Official harness pin must be an accepted commit in integration main")


def validate(workflow: Path) -> str:
    pin = harness_pin(workflow.read_text(encoding="utf-8"))
    try:
        response = subprocess.run(
            ["gh", "api", "--hostname", "github.com",
             f"repos/{REPOSITORY}/compare/{pin}...main?per_page=1"],
            check=True, capture_output=True, encoding="utf-8", timeout=30,
        )
        comparison = json.loads(response.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ValueError("Unable to verify official harness main ancestry") from None
    require_main_ancestor(pin, comparison)
    return pin


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, default=Path(".github/workflows/cd.yml"))
    args = parser.parse_args()
    try:
        pin = validate(args.workflow)
    except (OSError, ValueError) as exc:
        print(f"Official harness source rejected: {exc}", file=sys.stderr)
        return 1
    print(f"Official harness pin is accepted in integration main: {pin}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
