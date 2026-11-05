"""Execute the actual child guard before any production web build or upload."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/production-web-release.yml"


@pytest.mark.parametrize("job_name", ["release", "compose"])
@pytest.mark.parametrize(("expected", "actual", "allowed"), [
    ("a" * 40, "a" * 40, True),
    ("", "a" * 40, True),  # Existing standalone dispatch remains supported.
    ("a" * 40, "b" * 40, False),  # Main advanced after the parent's read.
    ("main", "a" * 40, False),
    ("A" * 40, "a" * 40, False),
    ("a" * 40 + "\n", "a" * 40, False),
])
def test_child_refuses_foreign_expected_source_before_other_work(
    tmp_path: Path, job_name: str, expected: str, actual: str, allowed: bool,
) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text())
    steps = workflow["jobs"][job_name]["steps"]
    guard = steps[1]
    assert steps[0]["uses"].startswith("actions/checkout@")
    assert guard["name"].startswith("Require the exact protected-main")
    assert guard["env"]["EXPECTED_SOURCE_SHA"] == "${{ inputs.expected_source_sha }}"
    # A local inert git stub makes the full shell step executable without a
    # remote connection. Refusal must happen before even this read-only probe.
    executable = tmp_path / "git"
    probe = tmp_path / "git-calls"
    executable.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$PROBE_LOG"\n'
        'if [ "$1" = rev-parse ]; then printf "%s\\n" "$GITHUB_SHA"; fi\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
                       PROBE_LOG=str(probe), GITHUB_REF="refs/heads/main", GITHUB_SHA=actual,
                       EXPECTED_SOURCE_SHA=expected, MODE="website", BACKEND_TAG="")
    result = subprocess.run(["bash", "--noprofile", "--norc"], input=guard["run"],
                            env=environment, capture_output=True, text=True, check=False)
    assert (result.returncode == 0) is allowed, result.stderr
    assert probe.exists() is allowed
