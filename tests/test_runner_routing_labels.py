"""Exercise the shared one-job runner's purpose-label policy."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("pwsh") or shutil.which("powershell")


def run_policy(body: str) -> subprocess.CompletedProcess[str]:
    if SHELL is None:
        pytest.skip("PowerShell is unavailable on this test host")
    policy = str(ROOT / "scripts" / "runner-routing-label-policy.ps1").replace("'", "''")
    command = f"$ErrorActionPreference = 'Stop'; . '{policy}'; {body}"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [SHELL, "-NoProfile", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        check=False,
    )


def runner(name: str, *labels: str) -> dict:
    return {"name": name, "labels": [{"name": label} for label in labels]}


def ps_json(value: object) -> str:
    return json.dumps(value).replace("'", "''")


@pytest.mark.parametrize(
    ("existing", "expected_ok"),
    [
        ([], True),
        ([runner("other", "self-hosted", "linux", "x64", "passport-beta-wsl2")], True),
        ([runner("same", "self-hosted", "linux", "x64", "canvas-oss-wsl2")], False),
        ([runner("dual", "canvas-oss-wsl2", "passport-beta-wsl2")], False),
    ],
)
def test_existing_runner_routing(existing: list[dict], expected_ok: bool) -> None:
    payload = ps_json({"total_count": len(existing), "runners": existing})
    body = (f"$response = '{payload}' | ConvertFrom-Json; "
            "$runners = @(Assert-CompleteRunnerInventory $response); "
            "Assert-ExistingRunnerRouting $runners 'canvas-oss-wsl2'")
    result = run_policy(body)
    assert (result.returncode == 0) is expected_ok, result.stderr


def test_incomplete_runner_inventory_rejected() -> None:
    payload = ps_json({"total_count": 2, "runners": [runner("one", "self-hosted")]})
    result = run_policy(
        f"$response = '{payload}' | ConvertFrom-Json; "
        "Assert-CompleteRunnerInventory $response"
    )
    assert result.returncode != 0


@pytest.mark.parametrize(
    ("labels", "expected_ok"),
    [
        (("self-hosted", "linux", "x64", "passport-beta-wsl2"), True),
        (("self-hosted", "linux", "x64"), False),
        (("self-hosted", "linux", "x64", "passport-beta-wsl2", "canvas-oss-wsl2"), False),
    ],
)
def test_new_runner_routing(labels: tuple[str, ...], expected_ok: bool) -> None:
    payload = ps_json(runner("passport-beta-wsl2-test", *labels))
    result = run_policy(
        f"$registered = '{payload}' | ConvertFrom-Json; "
        "Assert-NewRunnerRouting $registered 'passport-beta-wsl2'"
    )
    assert (result.returncode == 0) is expected_ok, result.stderr
