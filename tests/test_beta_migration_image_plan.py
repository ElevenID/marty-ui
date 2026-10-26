"""Render native migration jobs through actual PowerShell and Compose."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("path_mode", ["relative", "absolute", "missing", "relative-reused"])
def test_actual_rehearsal_context_binds_pinned_inputs_without_credentials(tmp_path, path_mode):
    shell = shutil.which('powershell') or shutil.which('pwsh')
    if not shell:
        pytest.skip('PowerShell is required')
    source = str(ROOT / 'scripts/deploy-local-beta-release.ps1').replace("'", "''")
    invocation = tmp_path / 'invocation'
    invocation.mkdir()
    env_paths = [invocation / 'first credential.env', invocation / 'second.env']
    for path in env_paths:
        path.write_text('CONTROLLED_NOT_A_CREDENTIAL=synthetic\n')
    dsc = 'controlled-dsc-operator-' + 'd' * 32
    csca = 'controlled-csca-operator-' + 'c' * 32
    env_paths[1].write_text(f'SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY={dsc}\nSIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY={csca}\n')
    if path_mode == 'relative-reused':
        env_paths[0].write_text(f'ANOTHER_BETA_SETTING={dsc}\n')
    repo = tmp_path / 'different-repo'
    repo.mkdir()
    # Decoys establish that relative parameters belong to the caller's CWD.
    for path in env_paths:
        (repo / path.name).write_text('CONTROLLED_DECOY=unused\n')
    supplied = [str(path) if path_mode == 'absolute' else path.name for path in env_paths]
    if path_mode == 'missing':
        env_paths[1].unlink()
    def literal(value):
        return "'" + str(value).replace("'", "''") + "'"
    runner_source = (ROOT / 'scripts/deploy-local-beta-release.ps1').read_text()
    guard_start = runner_source.index('$operatorGatewayKeys = @{}')
    guard_end = runner_source.index('\nforeach ($envFile in $script:EnvFiles) {', guard_start)
    credential_guard = runner_source[guard_start:guard_end]
    script = tmp_path / 'rehearsal.ps1'
    script.write_text(f'''$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('{source}',[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'Runner parse failed' }}
$assignments=@($ast.FindAll({{param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
 $node.Left.VariablePath.UserPath -eq 'rehearsalContext'
}},$true))
if ($assignments.Count -ne 1) {{ throw 'Rehearsal context is ambiguous' }}
$script:RepoRoot={literal(repo)}; $script:ArtifactDir='controlled-artifacts'
$envAssignments=@($ast.FindAll({{param($node)
 $node -is [Management.Automation.Language.AssignmentStatementAst] -and
 $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
 $node.Left.VariablePath.UserPath -eq 'script:EnvFiles'
}},$true))
if ($envAssignments.Count -ne 2) {{ throw 'Environment setup is ambiguous' }}
$TunnelEnvFile={literal(supplied[0])}; $GeneratedEnvFile={literal(supplied[1])}
$start=$envAssignments[0].Extent.StartOffset
$end=$envAssignments[-1].Extent.EndOffset
Invoke-Expression $ast.Extent.Text.Substring($start,$end-$start)
$definitions=@($ast.FindAll({{param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-DotEnvValue'
}},$true))
if ($definitions.Count -ne 1) {{ throw 'Environment reader is ambiguous' }}
Invoke-Expression $definitions[0].Extent.Text
$EnablePassportNative=$true; $EnablePassportPhysicalProvider=$true
Invoke-Expression {literal(credential_guard)}
$preflightBackupDir='controlled-backup'; $logsDir='controlled-logs'
$sourceId='a'*40; $migrationImage='sha256:'+('b'*64); $verificationMigrationImage='sha256:'+('c'*64)
$script:ComposeFiles=@('base.yml','frozen-images.yml')
$migrationAdminEmail='operator@example.invalid'; $BetaOrigin='https://beta.elevenidllc.com'
$PilotOrganizationId='00000000-0000-0000-0000-000000000001'
Invoke-Expression $assignments[0].Extent.Text
$rehearsalContext | ConvertTo-Json
''', encoding='utf8')
    result = subprocess.run([shell, '-NoProfile', '-File', str(script)],
                            capture_output=True, text=True, cwd=invocation, timeout=20)
    if path_mode == 'missing':
        assert result.returncode != 0
        assert 'Required beta environment file is missing' in result.stderr
        assert result.stdout.strip() == ''
        return
    if path_mode == 'relative-reused':
        assert result.returncode != 0
        assert 'operator credential is reused by another beta setting' in result.stderr
        assert result.stdout.strip() == ''
        assert dsc not in result.stderr
        return
    assert result.returncode == 0, result.stderr
    context = json.loads(result.stdout)
    assert [Path(path) for path in context['env_files']] == env_paths
    assert all(Path(path).is_absolute() for path in context['env_files'])
    context['env_files'] = [str(Path(path)) for path in context['env_files']]
    context['repo_root'] = str(Path(context['repo_root']))
    assert context == {
        'repo_root': str(repo), 'artifact_dir': 'controlled-artifacts',
        'backup_dir': 'controlled-backup', 'logs_dir': 'controlled-logs',
        'source_id': 'a'*40, 'migration_image': 'sha256:'+'b'*64,
        'verification_image': 'sha256:'+'c'*64,
        'env_files': [str(path) for path in env_paths], 'compose_files': ['base.yml', 'frozen-images.yml'],
        'migration_admin_email': 'operator@example.invalid', 'beta_origin': 'https://beta.elevenidllc.com',
        'pilot_organization_id': '00000000-0000-0000-0000-000000000001',
    }


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
