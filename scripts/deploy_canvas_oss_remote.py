#!/usr/bin/env python3
"""Bootstrap a new dedicated remote stock Canvas host; no AWS API or image build.

Default is a file-only plan. Execution requires a reviewed host engine identity,
an empty owned state directory, installed Docker Compose/Node/Python, and TLS.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timezone

GIB = 1024**3
ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / 'docker-compose.canvas-oss-remote.yml'
ORIGIN = 'https://canvas-test.elevenidllc.com'
FREE_RAM = 6 * GIB  # max simultaneous real cgroup caps + 1 GiB host + 256 MiB cushion


def require(value, code):
    if not value:
        raise RuntimeError(code)


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, timeout=kwargs.pop('timeout', 120), **kwargs)


def physical_memory():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        values[key] = int(value.split()[0]) * 1024
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--engine-id')
    parser.add_argument('--admin-email')
    parser.add_argument('--state-directory', type=Path, default=Path('/srv/canvas-oss-remote'))
    parser.add_argument('--tls-directory', type=Path)
    parser.add_argument('--acme-directory', type=Path)
    args = parser.parse_args()
    plan = {'scope': 'NEW_DEDICATED_REMOTE_STOCK_CANVAS_BOOTSTRAP', 'origin': ORIGIN,
            'compose': str(COMPOSE), 'publishedStockImageOnly': True, 'canvasSourceChanges': False,
            'imageBuilds': False, 'awsApiCalls': False, 'hostRamRecommendationBytes': 8 * GIB,
            'requiredAvailablePhysicalBytes': FREE_RAM, 'requiredHostSwapBytes': 2 * GIB,
            'requiredFreeDiskAfterPullBytes': 20 * GIB, 'resourceProfileQualified': False,
            'localCanvasChanges': False, 'existingUxHostUseAuthorized': False,
            'postBootstrapSetup': 'Existing stock REST/OAuth/LTI synthetic fixture owners only'}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_AMD64_HOST_REQUIRED')
    require(os.geteuid() == 0, 'ROOT_DEPLOYMENT_OPERATOR_REQUIRED')
    require(args.engine_id and args.admin_email and re.fullmatch(r'[^\s=@]+@[^\s=@]+', args.admin_email), 'REVIEWED_ENGINE_AND_ADMIN_EMAIL_REQUIRED')
    require(args.tls_directory and args.acme_directory, 'REVIEWED_TLS_AND_ACME_DIRECTORIES_REQUIRED')
    require(args.state_directory.is_absolute() and not args.state_directory.exists(), 'NEW_OWNED_STATE_DIRECTORY_REQUIRED')
    for directory in [args.state_directory, args.tls_directory, args.acme_directory]:
        require(directory.is_absolute() and not any(char in str(directory) for char in '\r\n:=,$'), 'SIMPLE_ABSOLUTE_DEPLOYMENT_PATH_REQUIRED')
    require(not args.tls_directory.is_symlink() and not args.acme_directory.is_symlink(), 'REGULAR_DEPLOYMENT_DIRECTORIES_REQUIRED')
    for name in ['fullchain.pem', 'privkey.pem']:
        file = args.tls_directory / name
        require(file.is_file() and not file.is_symlink(), 'REGULAR_DEPLOYMENT_TLS_FILE_REQUIRED')
    require(args.acme_directory.is_dir() and not args.acme_directory.is_symlink(), 'ACME_WEBROOT_REQUIRED')
    memory = physical_memory()
    require(memory['MemTotal'] >= 8 * GIB * .95 and memory['MemAvailable'] >= FREE_RAM, 'DEDICATED_HOST_PHYSICAL_HEADROOM_REQUIRED')
    require(memory['SwapTotal'] >= 2 * GIB, 'BOUNDED_TRIAL_HOST_SWAP_REQUIRED')
    require(shutil.disk_usage(args.state_directory.parent).free >= 20 * GIB, 'HOST_DISK_HEADROOM_REQUIRED')
    engine = run(['docker', 'info', '--format', '{{.ID}}'], capture_output=True, text=True).stdout.strip()
    require(engine == args.engine_id, 'REMOTE_ENGINE_CHANGED')
    require(not run(['docker', 'ps', '-aq'], capture_output=True, text=True).stdout.strip(), 'DEDICATED_UNUSED_DOCKER_ENGINE_REQUIRED')
    lock = json.loads((ROOT / 'deploy-config/catalog/canvas-oss.lock.json').read_text())
    from canvas_prebuilt_runtime import inspect_prebuilt_image
    from check_canvas_oss_portability import validate_lock
    validate_lock(lock)
    images = [lock['image']['repository'] + '@' + lock['image']['digest'], *lock['runtime_dependencies'].values()]
    for image in images:
        run(['docker', 'pull', '--platform', 'linux/amd64', image], timeout=900)
    def docker(*arguments):
        return run(['docker', *arguments], capture_output=True, text=True).stdout
    image_proof = inspect_prebuilt_image(ROOT, docker)
    require(docker('info', '--format', '{{.ID}}').strip() == args.engine_id, 'POST_PULL_REMOTE_ENGINE_CHANGED')
    require(not docker('ps', '-aq').strip(), 'POST_PULL_DEDICATED_ENGINE_CHANGED')
    require(shutil.disk_usage(args.state_directory.parent).free >= image_proof['required_free_bytes'], 'POST_PULL_DISK_HEADROOM_REQUIRED')
    require(physical_memory()['MemAvailable'] >= FREE_RAM, 'POST_PULL_PHYSICAL_HEADROOM_REQUIRED')
    args.state_directory.mkdir(mode=0o700)
    state = args.state_directory.resolve()
    for name in ['config', 'secrets', 'audit']:
        (state / name).mkdir(mode=0o700)
    audit = dict(plan, state='BOOTSTRAP_STARTED', engineId=engine, image=image_proof,
                 startedAt=datetime.now(timezone.utc).isoformat(), automaticRetry=False)
    def save():
        (state / 'audit/bootstrap.json').write_text(json.dumps(audit, indent=2) + '\n')
    save()
    try:
        for name in ['canvas-admin-password', 'canvas-postgres-password']:
            with (state / 'secrets' / name).open('x') as stream:
                # Parent directories are0700. Local Compose secrets are bind
                # mounts: Canvas's nonroot user must be able to read its file.
                os.chmod(stream.name, 0o644)
                stream.write(secrets.token_urlsafe(48) + '\n')
        run(['node', str(ROOT / 'scripts/canvas-oss/generate-runtime-config.mjs'), str(state / 'config')])
        settings = dict(CANVAS_OSS_IMAGE=images[0], CANVAS_OSS_ADMIN_EMAIL=args.admin_email,
                   CANVAS_OSS_CONFIG_DIR=str(state / 'config'), CANVAS_OSS_SECRET_DIR=str(state / 'secrets'),
                   CANVAS_OSS_TLS_DIR=str(args.tls_directory.resolve()), CANVAS_OSS_ACME_DIR=str(args.acme_directory.resolve()),
                   **{'CANVAS_OSS_' + key.upper() + '_IMAGE': value for key, value in lock['runtime_dependencies'].items()})
        env = dict(os.environ, **settings)
        # Keep a resumable, secret-scalar-free Compose environment, inside owned mode0700 state.
        (state / 'runtime.env').write_text(''.join(key + '=' + value + '\n' for key, value in sorted(settings.items())))
        run([sys.executable, '-B', str(ROOT / 'scripts/run_canvas_oss_lifecycle.py'),
             '--compose', str(COMPOSE), '--project', 'canvas-oss-remote',
             '--audit', str(state / 'audit/lifecycle.json'), '--health-timeout', '900'], env=env, timeout=2700)
        audit['state'] = 'STOCK_CANVAS_BOOTSTRAPPED_NOT_WORKLOAD_QUALIFIED'
        audit['resourceProfileQualified'] = False
        audit['nextAction'] = 'Root reviews health/TLS/limits/owned identities then existing stock REST/OAuth/LTI fixtures and full worker workload'
    except Exception as error:
        audit.update(state='FAILED_OR_OUTCOME_UNKNOWN_PRESERVE_OWNED_STATE', errorClass=type(error).__name__)
        raise
    finally:
        audit['finishedAt'] = datetime.now(timezone.utc).isoformat()
        save()
    print(json.dumps({'state': audit['state'], 'audit': str(state / 'audit/bootstrap.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
