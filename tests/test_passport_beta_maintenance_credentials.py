"""Maintenance rejects absent launch credentials before stopping beta services."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "scripts/start-passport-beta-db-maintenance.ps1"


@pytest.mark.parametrize("include_token,accepted", [(True, True), (False, False)])
def test_maintenance_preflights_passport_credentials(
    tmp_path: Path, include_token: bool, accepted: bool,
) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    source = MAINTENANCE.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^function Assert-BetaPassportLaunchCredentials \{.*?^\}",
                      source)
    assert match
    assert source.index("Assert-BetaPassportLaunchCredentials\n") < source.index(
        "Write-DurableJson -Path $intentAbsolute")
    ceremony = tmp_path / "elevenid-beta-passport-ceremony"
    ceremony.mkdir()
    (ceremony / "dsc_issue_gateway_key").write_text("d" * 40, encoding="ascii")
    (ceremony / "csca_issue_gateway_key").write_text("c" * 40, encoding="ascii")
    generated = tmp_path / ".env.beta.generated.local"
    generated.write_text(
        f"PASSPORT_BETA_CEREMONY_SECRET_DIR={ceremony}\n"
        + ("PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN=" + "r" * 40 + "\n"
           if include_token else ""),
        encoding="utf-8",
    )
    root = str(tmp_path).replace("'", "''")
    harness = tmp_path / "credentials.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$repo = '{root}'\n"
        + match.group() + "\n"
        "try { Assert-BetaPassportLaunchCredentials } catch { "
        "[Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=8, check=False,
    )
    assert (result.returncode == 0) is accepted, result.stdout + result.stderr
    if not accepted:
        assert "setting is absent" in result.stderr
