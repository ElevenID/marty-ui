"""Admit runtime-only work from the exact already-pulled reviewed Canvas image."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

if __package__:
    from .check_canvas_oss_portability import validate_lock
else:
    from check_canvas_oss_portability import validate_lock

GIB = 1024**3


def inspect_prebuilt_image(root: Path, docker) -> dict:
    lock = json.loads((root / 'deploy-config/catalog/canvas-oss.lock.json').read_text(encoding='utf8'))
    validate_lock(lock)
    image = lock['image']
    if image['digest_state'] != 'published' or not re.fullmatch('sha256:[0-9a-f]{64}', image['digest']):
        raise RuntimeError('Runtime-only admission requires a published immutable Canvas image')
    reference = image['repository'] + '@' + image['digest']
    actual = json.loads(docker('image', 'inspect', reference, '--format', '{{json .}}'))
    if (actual.get('Os') != 'linux' or actual.get('Architecture') != 'amd64'
            or reference not in actual.get('RepoDigests', [])
            or not re.fullmatch('sha256:[0-9a-f]{64}', actual.get('Id', ''))):
        raise RuntimeError('Reviewed Linux/amd64 Canvas image is not present by exact digest')
    labels = actual.get('Config', {}).get('Labels', {})
    if any(labels.get(name) != value for name, value in image['required_oci_labels'].items()):
        raise RuntimeError('Present Canvas image differs from its reviewed source/base labels')
    size = actual.get('Size')
    if type(size) is not int or size <= 0:
        raise RuntimeError('Cannot establish present Canvas image size')
    return dict(image_reference=reference, image_id=actual['Id'], image_size_bytes=size,
                required_free_bytes=max(20 * GIB, 2 * size), canvas_source_build_allowed=False)


def physical_runtime_capacity(image: dict, scripts: Path) -> dict:
    powershell = shutil.which('powershell.exe')
    if not powershell:
        raise RuntimeError('Runtime-only admission requires Windows backing-volume observation')
    wrapper = str(scripts / 'check-canvas-prebuilt-backing-capacity.ps1')
    if os.name != 'nt':
        wrapper = subprocess.check_output(['wslpath', '-w', wrapper], text=True).strip()
    result = subprocess.run([powershell, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', wrapper,
                             '-PrebuiltImageSizeBytes', str(image['image_size_bytes'])],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Windows Docker backing volume does not satisfy prebuilt runtime capacity')
    capacity = json.loads(result.stdout)
    if (capacity.get('capacity_mode') != 'PrebuiltRuntime'
            or capacity.get('required_free_bytes') != image['required_free_bytes']
            or type(capacity.get('physical_free_bytes')) not in (int, float)
            or capacity['physical_free_bytes'] < image['required_free_bytes']):
        raise RuntimeError('Invalid prebuilt runtime backing-volume observation')
    return capacity
