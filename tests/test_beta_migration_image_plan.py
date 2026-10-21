"""Render native migration jobs through actual PowerShell and Compose."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


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
    for name in ['BAO_TOKEN', 'BAO_TOKEN_FILE', 'OPENBAO_SERVICE_TOKEN', 'OPENBAO_SERVICE_TOKEN_FILE']:
        assert environment[name] == ''
    mounts = services['db-migrate']['volumes']
    assert {mount['target'] for mount in mounts} == {'/bao/public-ca', '/bao/notification'}
    assert all(mount['read_only'] is True for mount in mounts)
