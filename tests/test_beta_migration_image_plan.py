"""Render native migration jobs through actual PowerShell and Compose."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_actual_rehearsal_job_receives_notification_trust_without_root_token(tmp_path):
    shell = shutil.which('powershell') or shutil.which('pwsh')
    if not shell:
        pytest.skip('PowerShell is required')
    source = str(ROOT / 'scripts/deploy-local-beta-release.ps1').replace("'", "''")
    script = tmp_path / 'rehearsal.ps1'
    script.write_text(f"""$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('{source}',[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'Runner parse failed' }}
$assignments=@($ast.FindAll({{param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
 $node.Left.VariablePath.UserPath -eq 'rehearsalArguments' -and [string]$node.Operator -eq 'Equals'
}},$true))
if ($assignments.Count -ne 1) {{ throw 'Rehearsal job is ambiguous' }}
$copyOpenBaoContainer='controlled-bao'; $copyCaMount='controlled-ca-mount'
$copyUrl='postgresql://controlled.invalid/demo'; $copyPassword='CONTROLLED_NOT_A_PASSWORD'
$migrationAdminEmail='operator@example.test'; $BetaOrigin='https://beta.elevenidllc.com'
$copyNotificationToken='CONTROLLED_NOT_A_TOKEN'; $encodedCopyRedisPassword='CONTROLLED'
$copyRedisContainer='controlled-redis'; $PilotOrganizationId='00000000-0000-0000-0000-000000000001'
Invoke-Expression $assignments[0].Extent.Text
$environment=@{{}}
for ($i=0; $i -lt $rehearsalArguments.Count-1; $i++) {{
 if ($rehearsalArguments[$i] -eq '--env') {{
  $pair=$rehearsalArguments[++$i] -split '=',2; $environment[$pair[0]]=$pair[1]
 }}
}}
$environment | ConvertTo-Json
""", encoding='utf8')
    result = subprocess.run([shell, '-NoProfile', '-File', str(script)],
                            capture_output=True, text=True, check=True, timeout=20)
    environment = json.loads(result.stdout)
    assert environment['NOTIFICATION_OPENBAO_CA_CERT_FILE'] == environment['BAO_CACERT'] == '/bao-public-ca/ca.crt'
    assert environment['MARTY_KMS_BOOTSTRAP_ENABLED'] == 'false'
    assert 'BAO_TOKEN' not in environment


def test_migration_jobs_use_frozen_artifacts_without_initialization_privilege(tmp_path):
    shell, docker = shutil.which('powershell') or shutil.which('pwsh'), shutil.which('docker')
    if not shell or not docker:
        pytest.skip('PowerShell and Docker Compose are required')
    base = {'services': {role: {'image': 'controlled-invalid:latest', 'build': {'context': '.'}}
                         for role in ['db-migrate', 'issuance-migrations', 'revocation-profile-migrate']},
            'volumes': {name: {} for name in ['bootstrap', 'openbao_public_ca', 'openbao_notification']}}
    base['services']['db-migrate'].update(
        environment={'BAO_TOKEN': 'CONTROLLED_NOT_A_REAL_TOKEN', 'BAO_TOKEN_FILE': '/bootstrap/token',
                     'OPENBAO_SERVICE_TOKEN': 'CONTROLLED_NOT_A_REAL_TOKEN',
                     'MARTY_KMS_BOOTSTRAP_ENABLED': 'true'},
        volumes=['bootstrap:/bao/bootstrap-token'])
    base_path = tmp_path / 'base.json'
    base_path.write_text(json.dumps(base), encoding='utf8')
    override = tmp_path / 'migration-images.yml'
    source = str(ROOT / 'scripts/beta-migration-image-plan.ps1').replace("'", "''")
    script = tmp_path / 'render.ps1'
    images = ['sha256:' + value * 64 for value in ['a', 'b', 'c']]
    script.write_text(f"""$ErrorActionPreference='Stop'
. '{source}'
$lines=@(ConvertTo-BetaMigrationImageLines -MigrationImage '{images[0]}' -IssuanceImage '{images[1]}' -RevocationImage '{images[2]}')
[IO.File]::WriteAllText('{str(override).replace("'", "''")}',($lines -join "`n"),[Text.UTF8Encoding]::new($false))
""", encoding='utf8')
    subprocess.run([shell, '-NoProfile', '-File', str(script)], check=True, capture_output=True, timeout=20)
    result = subprocess.run([docker, 'compose', '--project-name', 'controlled-migration-projection',
                             '-f', str(base_path), '-f', str(override), 'config', '--format', 'json'],
                            check=True, capture_output=True, timeout=20)
    services = json.loads(result.stdout)['services']
    for role, image in zip(['db-migrate', 'issuance-migrations', 'revocation-profile-migrate'], images):
        assert services[role]['image'] == image
        assert not services[role].get('build')
    environment = services['db-migrate']['environment']
    assert environment['MARTY_KMS_BOOTSTRAP_ENABLED'] == 'false'
    assert environment['BAO_CACERT'] == environment['NOTIFICATION_OPENBAO_CA_CERT_FILE'] == '/bao/public-ca/ca.crt'
    for name in ['BAO_TOKEN', 'BAO_TOKEN_FILE', 'OPENBAO_SERVICE_TOKEN', 'OPENBAO_SERVICE_TOKEN_FILE']:
        assert environment[name] == ''
    mounts = services['db-migrate']['volumes']
    assert {mount['target'] for mount in mounts} == {'/bao/public-ca', '/bao/notification'}
    assert all(mount['read_only'] is True for mount in mounts)
