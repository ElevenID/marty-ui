"""The forward beta operator checks ingress it preserves instead of recreating."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts/run-passport-beta-aggregate-deploy.ps1"


@pytest.mark.parametrize("upstream,accepted", [
    ("gateway:8000", True),
    ("prod-gateway:8000", False),
])
def test_preserved_ingress_origin_is_checked_before_login(
    tmp_path: Path, upstream: str, accepted: bool,
) -> None:
    powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    source = OPERATOR.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^function Assert-PreservedIngressOrigin \{.*?^\}", source)
    assert match
    assert source.index("Assert-PreservedIngressOrigin\n") < source.index(
        "$enablePath = Join-Path $root")
    keycloak_id = "1" * 64
    nginx_id = "2" * 64
    keycloak = json.dumps([
        "KC_HOSTNAME=https://beta.elevenidllc.com",
        "UI_BASE_URL=https://beta.elevenidllc.com",
        "PUBLIC_DOMAIN=beta.elevenidllc.com",
    ])
    nginx = json.dumps([
        "PUBLIC_DOMAIN=beta.elevenidllc.com", f"GATEWAY_UPSTREAM={upstream}",
    ])
    harness = tmp_path / "ingress.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:plan = [pscustomobject]@{{ old_container_ids_by_service = "
        f"[pscustomobject]@{{ keycloak = '{keycloak_id}'; "
        f"'nginx-proxy' = '{nginx_id}' }} }}\n"
        "function docker {\n"
        "  $global:LASTEXITCODE = 0\n"
        f"  if ($args[1] -eq '{keycloak_id}') {{ return '{keycloak}' }}\n"
        f"  if ($args[1] -eq '{nginx_id}') {{ return '{nginx}' }}\n"
        "  throw 'Unexpected container'\n"
        "}\n"
        + match.group() + "\n"
        "try { Assert-PreservedIngressOrigin } catch { "
        "[Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True, text=True, timeout=8, check=False,
    )
    assert (result.returncode == 0) is accepted, result.stdout + result.stderr
    if not accepted:
        assert "outside the beta gateway" in result.stderr
