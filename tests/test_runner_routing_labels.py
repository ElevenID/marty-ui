"""Exercise the shared one-job runner's purpose-label policy."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SHELL = shutil.which("pwsh") or shutil.which("powershell")


def run_policy(body: str, policy_name: str = "runner-routing-label-policy.ps1") -> subprocess.CompletedProcess[str]:
    if SHELL is None:
        if os.environ.get("CI") == "true":
            pytest.fail("PowerShell is required to validate runner routing in CI")
        pytest.skip("PowerShell is unavailable on this test host")
    policy = str(ROOT / "scripts" / policy_name).replace("'", "''")
    command = f"$ErrorActionPreference = 'Stop'; . '{policy}'; {body}"
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        [SHELL, "-NoProfile", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        check=False,
    )


def test_ci_cannot_skip_runner_routing_without_powershell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys.modules[__name__], "SHELL", None)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(pytest.fail.Exception, match="PowerShell is required"):
        run_policy("Assert-NewRunnerRouting")


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


@pytest.mark.parametrize("available,expected_ok", [(80 * 1024**3, True), (80 * 1024**3 - 1, False)])
def test_physical_capacity_boundary_uses_the_data_disk_volume(tmp_path: Path, available: int, expected_ok: bool) -> None:
    disk = tmp_path / "controlled-data.vhdx"
    disk.write_bytes(b"Controlled policy fixture, never a mounted virtual disk")
    literal = str(disk).replace("'", "''")
    body = (
        "$global:measured = ''; "
        "function Get-Volume { param([string]$FilePath) $global:measured=$FilePath; "
        f"[PSCustomObject]@{{SizeRemaining=[UInt64]{available}}} "
        "}; "
        f"$result = Get-CanvasDockerBackingCapacity -DataDiskPath '{literal}'; "
        "@{result=$result;measured=$global:measured} | ConvertTo-Json -Depth 4 -Compress"
    )
    result = run_policy(body, "runner-host-capacity-policy.ps1")
    assert (result.returncode == 0) is expected_ok, result.stderr
    if expected_ok:
        response = json.loads(result.stdout)
        assert Path(response["measured"]) == disk
        assert response["result"]["production_demo_ready"] is False
        assert response["result"]["physical_free_bytes"] == available
    else:
        assert "at least 80 GiB" in result.stderr


@pytest.mark.parametrize("volume_expression", ["@()", "@(@{SizeRemaining=100GB},@{SizeRemaining=100GB})",
                                                   "@{SizeRemaining=$null}", "@{SizeRemaining='100000000000'}",
                                                   "@{SizeRemaining=$true}"])
def test_unknown_or_ambiguous_physical_capacity_fails_closed(tmp_path: Path, volume_expression: str) -> None:
    disk = tmp_path / "controlled-data.vhdx"
    disk.write_bytes(b"Controlled policy fixture")
    body = (f"function Get-Volume {{ param([string]$FilePath) {volume_expression} }}; "
            f"Get-CanvasDockerBackingCapacity -DataDiskPath '{str(disk).replace(chr(39), chr(39)*2)}'")
    result = run_policy(body, "runner-host-capacity-policy.ps1")
    assert result.returncode != 0
    assert "Cannot establish physical free space" in result.stderr


def test_low_backing_capacity_prevents_wsl_and_github_registration(tmp_path: Path) -> None:
    disk = tmp_path / "controlled-data.vhdx"
    disk.write_bytes(b"Controlled policy fixture")
    wrapper = str(ROOT / "scripts/register-canvas-oss-runner.ps1").replace("'", "''")
    body = (
        f"$env:ProgramData='{str(tmp_path).replace(chr(39), chr(39)*2)}'; "
        "$global:calls=@(); "
        "function gh { if (($args -join ' ') -ne 'auth status') {throw 'UNEXPECTED_GITHUB_OPERATION'}; "
        "$global:calls+='auth-status'; $global:LASTEXITCODE=0 }; "
        "function wsl.exe {$global:calls+='wsl'; throw 'WSL_MUST_NOT_BE_REACHED'}; "
        "function Get-Volume { param([string]$FilePath) [PSCustomObject]@{SizeRemaining=1GB} }; "
        f"try {{ & '{wrapper}' -DockerDesktopDataDiskPath '{str(disk).replace(chr(39), chr(39)*2)}'; "
        "throw 'EXPECTED_CAPACITY_REJECTION' } catch { "
        "@{reason=$_.Exception.Message;calls=$global:calls} | ConvertTo-Json -Compress }"
    )
    result = run_policy(body)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "at least 80 GiB" in payload["reason"]
    assert payload["calls"] == ["auth-status"]
