#!/usr/bin/env python3
"""Prepare only GitHub's disposable hosted VM, never a local/beta runner."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

GIB = 1024**3
# These preinstalled SDKs are unrelated to the pristine Docker source build.
# No Docker data, arbitrary caller paths, user homes, or mounted volumes qualify.
HOSTED_SDKS = (
    Path('/usr/local/lib/android'), Path('/usr/share/dotnet'),
    Path('/opt/ghc'), Path('/usr/local/.ghcup'),
    Path('/opt/hostedtoolcache'), Path('/usr/local/share/powershell'),
)


def require_hosted_vm(environment: dict[str, str], platform: str, os_release: str) -> None:
    if (platform != 'linux' or environment.get('GITHUB_ACTIONS') != 'true'
            or environment.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or environment.get('ImageOS') != 'ubuntu24'
            or environment.get('GITHUB_REPOSITORY') != 'ElevenID/marty-ui'
            or environment.get('GITHUB_REF') != 'refs/heads/main'
            or environment.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'):
        raise RuntimeError('Source SDK reclamation requires the reviewed disposable GitHub hosted VM')
    if 'ID=ubuntu\n' not in os_release or 'VERSION_ID="24.04"' not in os_release:
        raise RuntimeError('Source builder requires Ubuntu 24.04')


def require_capacity(free_bytes: int, docker_memory: int) -> None:
    if docker_memory < 12 * GIB:
        raise RuntimeError('Source builder Docker requires at least 12 GiB RAM')
    if free_bytes < 80 * GIB:
        raise RuntimeError('Source builder still requires at least 80 GiB free on the Docker backing filesystem')


def docker(*args: str) -> str:
    return subprocess.check_output(['docker', '--host', 'unix:///var/run/docker.sock', *args],
                                   text=True, timeout=30).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reclaim-hosted-sdks', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = {'scope': 'HOSTED_SOURCE_BUILD_PREREQUISITES_ONLY', 'productionDemoReady': False,
               'state': 'FAILED', 'reclaimed_sdk_paths': []}
    try:
        require_hosted_vm(dict(os.environ), sys.platform,
                          Path('/etc/os-release').read_text(encoding='utf-8'))
        for tool in ('docker', 'jq', 'git', 'gh', 'python3', 'sudo'):
            if shutil.which(tool) is None:
                raise RuntimeError(f'Source builder requires {tool}')
        if docker('ps', '-aq'):
            raise RuntimeError('Disposable source builder already has containers')
        info = json.loads(docker('info', '--format', '{{json .}}'))
        if info['OSType'] != 'linux':
            raise RuntimeError('Source builder requires Linux Docker')
        root = Path(info['DockerRootDir']).resolve(strict=True)
        if root != Path('/var/lib/docker') or root.stat().st_dev != Path.cwd().stat().st_dev:
            raise RuntimeError('Source builder Docker and checkout must use the hosted root backing filesystem')
        receipt['free_disk_gib_before'] = round(shutil.disk_usage(root).free / GIB, 2)
        if args.reclaim_hosted_sdks:
            # Validate the complete fixed inventory before making any change.
            existing = [path for path in HOSTED_SDKS if path.exists() or path.is_symlink()]
            for path in existing:
                if path.resolve(strict=True) != path or not path.is_dir():
                    raise RuntimeError('Hosted SDK inventory includes an unexpected symlink or non-directory')
            for path in existing:
                subprocess.run(['sudo', '-n', 'rm', '-rf', '--', str(path)], check=True, timeout=300)
                receipt['reclaimed_sdk_paths'].append(str(path))
        free = shutil.disk_usage(root).free
        receipt.update(free_disk_gib=round(free / GIB, 2), docker_memory_gib=round(info['MemTotal'] / GIB, 2))
        require_capacity(free, info['MemTotal'])
        receipt['state'] = 'HOSTED_SOURCE_BUILDER_READY'
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
