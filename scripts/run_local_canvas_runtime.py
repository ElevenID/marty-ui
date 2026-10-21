"""Run stock Canvas locally on the existing Windows Docker Desktop beta daemon.

Windows orchestrates only. Canvas, its state services and all contract browsers
remain Docker Compose services. No GitHub registration or second daemon is used.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

if __package__:
    from .canvas_beta_topology import inspect_beta_tunnel
    from .canvas_oss_beta_lifecycle import assert_beta, assert_canvas, assert_monitor
    from .canvas_prebuilt_runtime import inspect_prebuilt_image, physical_runtime_capacity
    from .check_canvas_oss_runner import check_passport_host_quarantine
else:
    from canvas_beta_topology import inspect_beta_tunnel
    from canvas_oss_beta_lifecycle import assert_beta, assert_canvas, assert_monitor
    from canvas_prebuilt_runtime import inspect_prebuilt_image, physical_runtime_capacity
    from check_canvas_oss_runner import check_passport_host_quarantine

ROOT = Path(__file__).resolve().parents[1]


def docker(*args):
    result = subprocess.run(['docker', '--context', 'desktop-linux', *args], capture_output=True, text=True,
                            encoding='utf8', timeout=60)
    if result.returncode:
        raise RuntimeError('Local Docker observation failed: ' + args[0])
    return result.stdout.strip()


def production_invariant():
    ids = docker('ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=marty-selfhost-prod').splitlines()
    rows = []
    for cid in ids:
        # Deliberately exclude environment, commands and mounts from artifacts.
        rows.append(json.loads(docker('inspect', cid, '--format',
            '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}}}')))
    return sorted(rows, key=lambda row: row['id'])


def preflight(deployment):
    if sys.platform != 'win32':
        raise RuntimeError('This local entrypoint requires Windows; WSL/GitHub admission remains separate')
    endpoint = json.loads(docker('context', 'inspect', 'desktop-linux'))[0]['Endpoints']['docker']['Host']
    if endpoint != 'npipe:////./pipe/dockerDesktopLinuxEngine':
        raise RuntimeError('The local runtime must use the existing Docker Desktop Linux engine')
    daemon = docker('info', '--format', '{{.ID}}')
    if docker('info', '--format', '{{.OSType}}') != 'linux' or int(docker('info', '--format', '{{.MemTotal}}')) < 12 * 1024**3:
        raise RuntimeError('The Linux daemon must expose at least12GiB')
    topology = inspect_beta_tunnel(docker)
    release = assert_beta()
    if release['source_id'] != deployment['marty_ui_sha'] or release['release_version'] != deployment['release_version']:
        raise RuntimeError('Actual beta differs from the supplied deployment manifest')
    image = inspect_prebuilt_image(ROOT, docker)
    capacity = physical_runtime_capacity(image, ROOT / 'scripts')
    check_passport_host_quarantine(runner=docker)
    return dict(scope='LOCAL_WINDOWS_PREBUILT_CANVAS_RUNTIME', daemon_id=daemon, topology=topology,
        observed_beta=release, image=image, backing_capacity=capacity, github_labels_verified=False,
        host_browser_processes=False, production_demo_qualified=False)


def protected_inputs(directory):
    directory.mkdir(parents=True, exist_ok=False)
    identity = os.environ['USERDOMAIN'] + '\\' + os.environ['USERNAME']
    subprocess.run(['icacls', str(directory), '/inheritance:r', '/grant:r',
                    identity + ':(OI)(CI)F', 'SYSTEM:(OI)(CI)F'], check=True, capture_output=True)
    secret_dir = directory / 'secrets'
    secret_dir.mkdir()
    for name in ['canvas-admin-password', 'canvas-postgres-password']:
        (secret_dir / name).write_text(secrets.token_urlsafe(32), encoding='ascii')
    (secret_dir / 'canvas-admin-email').write_text('canvas.admin@marty.demo', encoding='ascii')
    # Compose mounts these files for isolated contract unit tests. Empty inputs
    # cannot authorize a real full contract; bootstrap never consumes them.
    for name in ['canvas-learner-email', 'canvas-learner-password', 'canvas-marty-api-key']:
        (secret_dir / name).write_text('', encoding='ascii')
    config_dir = directory / 'config'
    subprocess.run(['node', str(ROOT / 'scripts/canvas-oss/generate-runtime-config.mjs'), str(config_dir)],
                   check=True, capture_output=True)
    return secret_dir, config_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--beta-deployment-manifest', type=Path, required=True)
    parser.add_argument('--bootstrap', action='store_true')
    args = parser.parse_args()
    os.environ['DOCKER_CONTEXT'] = 'desktop-linux'
    for name in ['DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']:
        os.environ.pop(name, None)
    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = artifact_dir / 'local-runtime.json'
    if receipt_path.exists():
        raise RuntimeError('Use a new artifact directory; retain prior attempt evidence')
    if subprocess.check_output(['git', '-C', str(ROOT), 'status', '--porcelain']).strip():
        raise RuntimeError('Local Canvas runtime requires a clean source worktree')
    revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip()
    deployment_bytes = args.beta_deployment_manifest.read_bytes()
    deployment = json.loads(deployment_bytes.decode('utf-8-sig'))
    production = production_invariant()
    receipt = preflight(deployment)
    receipt.update(source_revision=revision, deployment_manifest_sha256=hashlib.sha256(deployment_bytes).hexdigest(),
        started_at=datetime.now(timezone.utc).isoformat(), bootstrap_requested=args.bootstrap,
        full_contract_credentials_configured=False,
        bootstrap_completed=False, production_invariant_sha256=hashlib.sha256(json.dumps(production, sort_keys=True).encode()).hexdigest())
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf8')
    if not args.bootstrap:
        print(json.dumps(receipt))
        return
    if docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=canvas-oss-portability'):
        raise RuntimeError('An existing Canvas attempt requires inspection; do not overwrite its state')
    private = Path.home() / '.codex/private' / ('canvas-stock-local-' + uuid.uuid4().hex)
    secret_dir, config_dir = protected_inputs(private)
    lock = json.loads((ROOT / 'deploy-config/catalog/canvas-oss.lock.json').read_text(encoding='utf8'))
    env = os.environ.copy()
    settings = dict(CANVAS_OSS_IMAGE=receipt['image']['image_reference'],
        CANVAS_OSS_ADMIN_EMAIL='canvas.admin@marty.demo', CANVAS_OSS_SECRET_DIR=str(secret_dir),
        CANVAS_OSS_CONFIG_DIR=str(config_dir), CANVAS_OSS_ARTIFACT_DIR=str(artifact_dir),
        CANVAS_OSS_DRIVER_SOURCE_SHA=revision, CANVAS_OSS_PLAYWRIGHT_IMAGE=lock['contract_driver']['base_image'],
        CANVAS_OSS_CONTRACT_IMAGE='elevenid-local/canvas-contract:' + revision[:12])
    env.update(settings)
    for variable, role in [('POSTGRES', 'postgres'), ('REDIS', 'redis'), ('MAILPIT', 'mailpit'), ('EDGE', 'edge')]:
        env['CANVAS_OSS_' + variable + '_IMAGE'] = lock['runtime_dependencies'][role]
        settings['CANVAS_OSS_' + variable + '_IMAGE'] = lock['runtime_dependencies'][role]
    # Only file locations and non-secret runtime settings are retained here.
    (private / 'runtime-environment.json').write_text(json.dumps(settings, indent=2) + '\n', encoding='utf8')
    receipt['private_runtime_inputs'] = str(private)
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf8')
    if inspect_beta_tunnel(docker) != receipt['topology'] or docker('info', '--format', '{{.ID}}') != receipt['daemon_id']:
        raise RuntimeError('Beta daemon/topology changed before Canvas bootstrap')
    for role in ['postgres', 'redis', 'mailpit', 'edge']:
        with (private / (role + '-pull.log')).open('wb') as log:
            subprocess.run(['docker', '--context', 'desktop-linux', 'pull', lock['runtime_dependencies'][role]],
                           check=True, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
    compose = ['docker', '--context', 'desktop-linux', 'compose', '--project-name', 'canvas-oss-portability',
               '--file', str(ROOT / 'docker-compose.canvas-oss-acceptance.yml')]
    with (private / 'contract-build.log').open('wb') as log:
        subprocess.run(compose + ['--profile', 'contract', 'build', '--pull', 'canvas-contract'],
                       cwd=ROOT, env=env, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=1200)
    contract_image = json.loads(docker('image', 'inspect', settings['CANVAS_OSS_CONTRACT_IMAGE']))[0]
    labels = contract_image['Config']['Labels']
    required_labels = {'org.opencontainers.image.source': 'https://github.com/ElevenID/marty-ui',
                       'org.opencontainers.image.revision': revision,
                       'io.elevenid.canvas-oss.execution-boundary': 'docker-compose-one-shot'}
    if any(labels.get(name) != value for name, value in required_labels.items()):
        raise RuntimeError('Contract image source/boundary labels differ')
    env['CANVAS_OSS_CONTRACT_IMAGE_ID'] = contract_image['Id']
    settings['CANVAS_OSS_CONTRACT_IMAGE_ID'] = contract_image['Id']
    (private / 'runtime-environment.json').write_text(json.dumps(settings, indent=2) + '\n', encoding='utf8')
    with (private / 'contract-unit.log').open('wb') as log:
        subprocess.run(compose + ['--profile', 'contract', 'run', '--rm', '--no-deps', 'canvas-contract',
            'node', '--test', 'scripts/run-canvas-oss-standard-contract.test.js'],
            cwd=ROOT, env=env, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    manifest = dict(schema_version=1, execution_boundary='docker_compose_one_shot',
        compose_project='canvas-oss-portability', compose_service='canvas-contract',
        image_reference=settings['CANVAS_OSS_CONTRACT_IMAGE'], image_id=contract_image['Id'],
        source_sha=revision, source_repository='https://github.com/ElevenID/marty-ui',
        dockerfile='tests/Dockerfile.canvas-oss-contract', package_manifest='tests/canvas-oss-contract/package.json',
        package_lock='tests/canvas-oss-contract/package-lock.json', audit_level='high',
        base_image=settings['CANVAS_OSS_PLAYWRIGHT_IMAGE'], secret_transport='compose_secret_files',
        host_browser_processes=False, unit_test_exit_code=0, contract_exit_code=None, labels=required_labels)
    (artifact_dir / 'contract-driver-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    with (private / 'monitor-start.log').open('wb') as log:
        subprocess.run(compose + ['--profile', 'monitor', 'up', '--detach', '--no-deps', 'canvas-continuity-monitor'],
                       cwd=ROOT, env=env, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    try:
        with (private / 'bootstrap.log').open('wb') as log:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/run_canvas_oss_lifecycle.py'),
                '--compose', str(ROOT / 'docker-compose.canvas-oss-acceptance.yml'), '--project', 'canvas-oss-portability',
                '--audit', str(artifact_dir / 'bootstrap-audit.json')], cwd=ROOT, env=env,
                stdout=log, stderr=subprocess.STDOUT, timeout=1800)
        receipt['bootstrap_exit_code'] = result.returncode
        if result.returncode:
            raise RuntimeError('Stock Canvas bootstrap failed; inspect the private log and retained state')
        assert_canvas()
        if assert_beta() != receipt['observed_beta']:
            raise RuntimeError('Beta release changed during Canvas bootstrap')
        receipt['bootstrap_completed'] = True
    finally:
        (artifact_dir / 'stop-beta-monitor').write_text('stop\n', encoding='ascii')
        monitor = docker('ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=canvas-oss-portability',
                         '--filter', 'label=com.docker.compose.service=canvas-continuity-monitor').splitlines()
        if len(monitor) != 1:
            raise RuntimeError('Canvas continuity monitor identity is ambiguous')
        docker('wait', monitor[0])
        assert_monitor(artifact_dir / 'beta-continuity.json')
        receipt['beta_continuity_verified'] = True
        receipt['production_invariant_preserved'] = production_invariant() == production
        receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf8')
        if not receipt['production_invariant_preserved']:
            raise RuntimeError('Self-host production changed during the local Canvas operation')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
