"""Old beta deploy and restore must stop before flattening an installed fence."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/beta-passport-fence-legacy-boundary.ps1"


@pytest.mark.parametrize("schema_count,exit_code,marker_exists,allowed", [
    ("0", "0", False, True),
    ("1", "0", False, False),
    ("", "1", False, False),
    ("0", "0", True, False),
])
def test_legacy_beta_path_requires_proven_absence_of_fence(
    tmp_path: Path, schema_count: str, exit_code: str,
    marker_exists: bool, allowed: bool,
) -> None:
    marker = tmp_path / "passport-fence.pending"
    if marker_exists:
        marker.write_text("intent", encoding="utf-8")
    quoted = str(HELPER).replace("'", "''")
    script = f"""
        $ErrorActionPreference = 'Stop'
        . '{quoted}'
        function Get-BetaPassportFenceMarkerPath {{ return $env:FENCE_TEST_MARKER }}
        function docker {{
            $global:LASTEXITCODE = [int]$env:FENCE_TEST_EXIT
            if ($global:LASTEXITCODE -eq 0) {{ Write-Output $env:FENCE_TEST_RESULT }}
        }}
        try {{
            Assert-LegacyBetaDatabaseUnfenced -PostgresContainer ('a' * 64)
            'allowed'
        }} catch {{
            'blocked'
        }}
    """
    env = {**os.environ, "FENCE_TEST_MARKER": str(marker),
           "FENCE_TEST_RESULT": schema_count, "FENCE_TEST_EXIT": exit_code}
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=20, env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("allowed" if allowed else "blocked")
