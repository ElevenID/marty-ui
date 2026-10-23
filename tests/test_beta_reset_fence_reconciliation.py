"""Actual PowerShell boundary checks with controlled Docker observations."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mode', ['archive', 'active_fence', 'same_cluster', 'tampered_receipt', 'production'])
def test_replaced_cluster_is_required_and_archive_preserves_evidence(tmp_path, mode):
    shell = shutil.which('powershell') or shutil.which('pwsh')
    if not shell:
        pytest.skip('PowerShell is unavailable')
    current = 'a' * 64
    receipt = tmp_path / 'receipt.json'
    receipt.write_text(json.dumps({
        'schema': 'marty.passport-beta-fence-installation/v1',
        'postgres_container_id': 'b' * 64,
        'postgres_system_identifier': '101' if mode == 'same_cluster' else '202',
    }), encoding='utf8')
    marker = tmp_path / 'marker.pending'
    marker.write_text(json.dumps({
        'schema': 'marty.passport-beta-fence-host-record/v1',
        'receipt_path': str(receipt),
        'receipt_file_sha256': '0' * 64 if mode == 'tampered_receipt'
        else hashlib.sha256(receipt.read_bytes()).hexdigest(),
    }), encoding='utf8')
    original = marker.read_bytes()
    inspect = tmp_path / 'inspect.json'
    inspect.write_text(json.dumps([{'Id': current, 'State': {'Running': True}, 'Config': {'Labels': {
        'com.docker.compose.project': 'marty-selfhost-prod' if mode == 'production' else 'elevenid-beta',
        'com.docker.compose.service': 'postgres',
    }}}]), encoding='utf8')
    database = tmp_path / 'database.json'
    database.write_text(json.dumps({'database_oid': '123', 'system_identifier': '101',
                                   'passport_cutover_schema_count': 1 if mode == 'active_fence' else 0}),
                        encoding='utf8')
    output = tmp_path / 'reconciliation.json'
    source = ROOT / 'scripts/reconcile-reset-beta-passport-fence.ps1'

    def quote(path):
        return "'" + str(path).replace("'", "''") + "'"

    script = tmp_path / 'run.ps1'
    script.write_text(f"""$ErrorActionPreference = 'Stop'
. {quote(source)}
function Enter-BetaDeploymentLock {{ return $null }}
function Exit-BetaDeploymentLock {{ }}
function docker {{
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'inspect') {{ Get-Content -LiteralPath {quote(inspect)} -Raw }}
    else {{ Get-Content -LiteralPath {quote(database)} -Raw }}
}}
$container = '{current}'
$marker = {quote(marker)}
$output = {quote(output)}
try {{
    $probe = Invoke-BetaResetFenceReconciliation -Container $container -MarkerPath $marker -Output $output
    if (-not (Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath $output)) {{ throw 'Read-only probe mutated files' }}
    Invoke-BetaResetFenceReconciliation -Container $container -MarkerPath $marker -Output $output -Archive | ConvertTo-Json
}} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
""", encoding='utf8')
    result = subprocess.run([shell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(script)],
                            capture_output=True, text=True, timeout=20)
    if mode == 'archive':
        assert result.returncode == 0, result.stderr
        record = json.loads(output.read_text(encoding='utf8'))
        assert record['state'] == 'ARCHIVED_STALE_AFTER_RESET'
        assert not marker.exists()
        assert Path(record['archive_path']).read_bytes() == original
        assert record['database_changed'] is False
    else:
        assert result.returncode != 0, result.stdout
        assert marker.read_bytes() == original
        assert not output.exists()
