"""Exercise the actual PowerShell helper without Docker or real credentials."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/deploy-local-beta-release.ps1"
POWERSHELL = (
    os.environ.get("POWERSHELL_TEST_EXE")
    or shutil.which("pwsh")
    or shutil.which("powershell")
)
IMAGE_DIGEST = "a" * 64


def test_ci_requires_executable_powershell_contracts() -> None:
    assert not os.environ.get("CI") or POWERSHELL, (
        "CI must provide PowerShell; do not silently skip runner contracts"
    )


def test_both_modes_pin_the_actual_runtime_before_schema_rehearsal() -> None:
    script = RUNNER.read_text(encoding="utf-8")
    build = script.index('Write-Step "Build marker-bearing application images"')
    pin = script.index("$verificationMigrationImage = & docker image inspect")
    rehearsal = script.index(
        'Write-Step "Rehearse one-way migration on isolated beta copy"'
    )
    maintenance = script.index(
        'Write-Step "Enter maintenance window and apply live migration"'
    )
    assert build < pin < rehearsal < maintenance
    assert "$verificationMigrationImage = $env:MARTY_SERVICES_IMAGE" in script
    assert "--format '{{.Id}}'" in script
    assert "image: $verificationMigrationImage" in script
    assert "$script:ComposeFiles += $verificationImageOverride" in script
    assert script.count('Write-Step "Build marker-bearing application images"') == 1
    assert script.index("if ($PlanOnly)") < build


def test_rehearsal_repeat_and_live_migration_gate_application_startup() -> None:
    script = RUNNER.read_text(encoding="utf-8")
    rehearsal = script.index("foreach ($verificationPass in 1..2)")
    cleanup = script.index(
        "foreach ($expectedContainer in $rehearsalContainers)", rehearsal
    )
    maintenance = script.index(
        'Write-Step "Enter maintenance window and apply live migration"'
    )
    backup = script.index('-Phase "maintenance_quiesced"')
    live = script.index(
        '-LogPath (Join-Path $logsDir "verification-migration-live.log")'
    )
    cutover = script.index(
        'Write-Step "Recreate application containers from coordinated images"'
    )
    assert rehearsal < cleanup < maintenance < backup < live < cutover
    assert "-Image $verificationMigrationImage -DatabaseUrl $copyUrl" in script
    assert (
        '-DatabaseUrl "postgresql://marty:${martyDbPassword}@postgres:5432/marty"'
        in script
    )
    assert (
        script.count("Invoke-VerificationMigration -Image $verificationMigrationImage")
        == 2
    )


@pytest.mark.skipif(
    not POWERSHELL, reason="PowerShell is required for executable runner contracts"
)
@pytest.mark.parametrize("prior", [None, "preserved-parent-value"])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize(
    "image",
    [
        f"sha256:{IMAGE_DIGEST}",
        f"ghcr.io/elevenid/services@sha256:{IMAGE_DIGEST}",
        "services:mutable",
    ],
)
def test_actual_helper_command_failure_and_secret_environment_restoration(
    tmp_path: Path, prior: str | None, failure: bool, image: str
) -> None:
    harness = tmp_path / "exercise.ps1"
    harness.write_text(
        r"""
param([string]$Source, [string]$Image, [string]$Prior, [string]$Fail)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw "Runner has syntax errors" }
$definition = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-VerificationMigration'
}, $true)
if ($null -eq $definition) { throw "Migration helper missing" }
Invoke-Expression $definition.Extent.Text
$script:BetaNetwork = 'elevenid-beta-network'
$script:Calls = @()
function Invoke-DockerLogged {
    param([string[]]$Arguments, [string]$LogPath, [string]$FailureMessage)
    $script:Calls += @{
        arguments=$Arguments; log=$LogPath; failure_message=$FailureMessage
        database=[Environment]::GetEnvironmentVariable('DATABASE_URL','Process')
    }
    if ($Fail -eq 'yes') { throw "sentinel native failure" }
}
if ($Prior -eq '<absent>') {
    Remove-Item Env:\DATABASE_URL -ErrorAction SilentlyContinue
} else {
    [Environment]::SetEnvironmentVariable('DATABASE_URL',$Prior,'Process')
}
$caught = $false
$errorKind = $null
try {
    Invoke-VerificationMigration -Image $Image -DatabaseUrl 'postgresql://marty:fake@copy:5432/marty' -LogPath 'rehearsal.log'
} catch {
    $caught = $true
    $errorKind = if ($_.Exception.Message -eq 'sentinel native failure') { 'native' } else { 'validation' }
}
@{
    caught=$caught; error_kind=$errorKind; calls=@($script:Calls)
    restored=[Environment]::GetEnvironmentVariable('DATABASE_URL','Process')
} | ConvertTo-Json -Depth 10 -Compress
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-File",
            str(harness),
            "-Source",
            str(RUNNER),
            "-Image",
            image,
            "-Prior",
            prior or "<absent>",
            "-Fail",
            "yes" if failure else "no",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["restored"] == prior
    if image == "services:mutable":
        assert report["caught"] is True
        assert report["error_kind"] == "validation"
        assert report["calls"] == []
        return
    assert report["caught"] is failure
    assert report["error_kind"] == ("native" if failure else None)
    assert len(report["calls"]) == 1
    call = report["calls"][0]
    assert call["arguments"] == [
        "run",
        "--rm",
        "--network",
        "elevenid-beta-network",
        "--entrypoint",
        "/usr/local/bin/marty-verification-service",
        "--env",
        "DATABASE_URL",
        image,
        "migrate",
    ]
    assert call["database"] == "postgresql://marty:fake@copy:5432/marty"
    assert all("fake" not in argument for argument in call["arguments"])
    assert call["log"] == "rehearsal.log"
    assert call["failure_message"] == "Native verification migration failed"
