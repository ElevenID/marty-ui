"""Execute the shared volume boundary against controlled Docker observations."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mode', ['renamed', 'foreign_volume', 'shared_production', 'running_initializer', 'recreated'])
def test_actual_volume_identity_survives_reset_and_rejects_unsafe_targets(tmp_path, mode):
    shell = shutil.which('powershell') or shutil.which('pwsh')
    if not shell:
        pytest.skip('PowerShell is unavailable')
    responses = {}
    names = {}
    for number, (service, logical, target) in enumerate([
        ('postgres', 'postgres_data', '/var/lib/postgresql/data'),
        ('redis', 'redis_data', '/data'), ('applicant', 'applicant_data', '/app/data'),
        ('openbao', 'openbao_data', '/bao/data'),
    ], 1):
        cid = str(number) * 64
        name = 'elevenid-beta-fresh-control_' + logical
        names[logical] = name
        responses['service:' + service] = [cid]
        responses['inspect:' + cid] = json.dumps([{
            'Id': cid, 'Config': {'Labels': {'com.docker.compose.project': 'elevenid-beta',
                                            'com.docker.compose.service': service}},
            'Mounts': [{'Destination': target, 'Type': 'volume', 'Name': name, 'RW': True}],
        }])
        volume = {'Name': name, 'CreatedAt': '2026-10-18T19:22:09Z', 'Labels': {
            'com.docker.compose.project': 'marty-selfhost-prod' if mode == 'foreign_volume' and service == 'applicant' else 'elevenid-beta',
            'com.docker.compose.volume': logical,
        }}
        responses['volume:' + name] = json.dumps([volume])
        responses['attached:' + name] = [cid]
    extra = 'f' * 64
    if mode in ['shared_production', 'running_initializer']:
        responses['attached:' + names['openbao_data']].append(extra)
        responses['inspect:' + extra] = json.dumps([{
            'Config': {'Labels': {
                'com.docker.compose.project': 'marty-selfhost-prod' if mode == 'shared_production' else 'elevenid-beta',
                'com.docker.compose.service': 'openbao-init',
            }}, 'State': {'Status': 'running', 'ExitCode': 0},
        }])
    else:
        # An exited, successful beta initializer is a legitimate shared owner.
        responses['attached:' + names['openbao_data']].append(extra)
        responses['inspect:' + extra] = json.dumps([{
            'Config': {'Labels': {'com.docker.compose.project': 'elevenid-beta',
                                   'com.docker.compose.service': 'openbao-tls-init'}},
            'State': {'Status': 'exited', 'ExitCode': 0},
        }])
    fixture = tmp_path / 'docker.json'
    fixture.write_text(json.dumps(responses), encoding='utf8')
    changed = dict(responses)
    volume = json.loads(changed['volume:' + names['applicant_data']])
    volume[0]['CreatedAt'] = '2026-10-20T00:00:00Z'
    changed['volume:' + names['applicant_data']] = json.dumps(volume)
    changed_fixture = tmp_path / 'changed.json'
    changed_fixture.write_text(json.dumps(changed), encoding='utf8')

    def quote(path):
        return "'" + str(path).replace("'", "''") + "'"

    harness = tmp_path / 'run.ps1'
    harness.write_text(f"""$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. {quote(ROOT / 'scripts/beta-state-volume-plan.ps1')}
$fake = Get-Content -LiteralPath {quote(fixture)} -Raw | ConvertFrom-Json
function docker {{
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'inspect') {{ $key = 'inspect:' + $args[1] }}
    elseif ($args[0] -eq 'volume') {{ $key = 'volume:' + $args[2] }}
    else {{
        $filter = @($args | Where-Object {{ $_ -like 'label=com.docker.compose.service=*' }})
        if ($filter.Count) {{ $key = 'service:' + ($filter[0] -split '=')[-1] }}
        else {{ $filter = @($args | Where-Object {{ $_ -like 'volume=*' }}); $key = 'attached:' + ($filter[0] -split '=',2)[1] }}
    }}
    $response = $fake.PSObject.Properties[$key]
    if (-not $response) {{ throw ('Unexpected Docker observation: ' + $key) }}
    $response.Value
}}
try {{
    $plan = @(Get-BetaStateVolumePlan)
    if ('{mode}' -eq 'recreated') {{ $fake = Get-Content -LiteralPath {quote(changed_fixture)} -Raw | ConvertFrom-Json }}
    Assert-BetaStateVolumePlan -Expected $plan -SameContainers
    ConvertTo-BetaStateVolumeOverride -Plan $plan
}} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}
""", encoding='utf8')
    result = subprocess.run([shell, '-NoProfile', '-File', str(harness)],
                            capture_output=True, text=True, timeout=20)
    if mode == 'renamed':
        assert result.returncode == 0, result.stderr
        volumes = json.loads(result.stdout)['volumes']
        assert {name: item['name'] for name, item in volumes.items()} == names
        assert all(item['external'] is True for item in volumes.values())
    else:
        assert result.returncode != 0, result.stdout
