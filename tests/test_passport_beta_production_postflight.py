"""Exercise the beta operator's production failure receipt without Docker."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts/run-passport-beta-aggregate-deploy.ps1"


@pytest.mark.parametrize(
    ("ready", "recovery_verified", "continuity_breached", "continuity_throws", "expected"),
    [
        (True, True, True, True, (False, True, True)),
        (True, False, False, False, (False, True, True)),
        (False, False, False, False, (True, True, False)),
    ],
)
def test_failed_cutover_production_postflight(
    tmp_path: Path,
    ready: bool,
    recovery_verified: bool,
    continuity_breached: bool,
    continuity_throws: bool,
    expected: tuple[bool, bool, bool],
) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    source = OPERATOR.read_text(encoding="utf-8")
    function = re.search(r"(?ms)^function Write-ProductionPostflight \{.*?^\}", source)
    assert function
    receipt = tmp_path / "postflight.json"
    harness = tmp_path / "postflight.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:productionRecoveryReady = ${str(ready).lower()}\n"
        f"$productionPostflightPath = '{receipt.as_posix()}'\n"
        "function Invoke-ProductionRecovery {\n"
        f"  return [pscustomobject]@{{ verified = ${str(recovery_verified).lower()}; "
        f"continuity_breached = ${str(continuity_breached).lower()}; "
        "schema = 'marty.passport-beta-production-recovery/v1' }\n"
        "}\n"
        "function Assert-ProductionContinuity { param([switch]$MaintenanceOnly)\n"
        + ("  throw 'production changed'\n" if continuity_throws else
           "  return [pscustomobject]@{ verified = $true }\n")
        + "}\n"
        "function Replace-DurableJson { param($Path, $Json) "
        "[IO.File]::WriteAllText($Path, $Json) }\n"
        + function.group() + "\n"
        "Write-ProductionPostflight 3>$null\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["schema"] == "marty.passport-beta-production-postflight/v1"
    assert (data["verified"], data["production_running"],
            data["recovery_attempted"]) == expected
    assert ("recovery" in data) is ready


def test_recovery_capture_is_armed_before_final_preflight() -> None:
    source = OPERATOR.read_text(encoding="utf-8")
    capture = source.index("$recoveryBaseline = Invoke-Plan")
    ready = source.index("$script:productionRecoveryReady = $true", capture)
    final_preflight = source.index("$null = Assert-ProductionContinuity", ready)
    beta_application = source.index("$applicationProof = Invoke-Plan", final_preflight)
    assert capture < ready < final_preflight < beta_application


def test_failed_recovery_command_keeps_its_structured_receipt(tmp_path: Path) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    source = OPERATOR.read_text(encoding="utf-8")
    function = re.search(r"(?ms)^function Invoke-ProductionRecovery \{.*?^\}", source)
    assert function
    harness = tmp_path / "recovery.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        "$script:productionRecoveryDigest = 'a' * 64\n"
        "$productionRecoveryPath = 'private-baseline.json'\n"
        "function python {\n"
        "  $global:LASTEXITCODE = 1\n"
        "  return '{\"schema\":\"marty.passport-beta-production-recovery/v1\","
        "\"verified\":false,\"continuity_breached\":false,"
        "\"status\":\"blocked\"}'\n"
        "}\n"
        + function.group() + "\n"
        "$value = Invoke-ProductionRecovery\n"
        "$value | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["status"] == "blocked"
