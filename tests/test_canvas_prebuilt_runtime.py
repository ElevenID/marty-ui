"""A lower runtime reserve must never admit an absent or substituted image."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from scripts.canvas_prebuilt_runtime import GIB, inspect_prebuilt_image, physical_runtime_capacity

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mutation', ['none', 'large_image', 'pending', 'wrong_digest', 'wrong_source', 'wrong_platform', 'unknown_size'])
def test_prebuilt_admission_binds_published_digest_source_platform_and_measured_size(tmp_path, mutation):
    lock = json.loads((ROOT / 'deploy-config/catalog/canvas-oss.lock.json').read_text())
    original = deepcopy(lock)
    reference = lock['image']['repository'] + '@' + lock['image']['digest']
    image = dict(Id='sha256:' + '1' * 64, Os='linux', Architecture='amd64', RepoDigests=[reference],
                 Size=3 * GIB, Config=dict(Labels=deepcopy(lock['image']['required_oci_labels'])))
    if mutation == 'large_image':
        image['Size'] = 15 * GIB
    elif mutation == 'pending':
        lock['image']['digest_state'] = 'pending_source_build'
    elif mutation == 'wrong_digest':
        image['RepoDigests'] = ['other@sha256:' + '2' * 64]
    elif mutation == 'wrong_source':
        image['Config']['Labels']['org.opencontainers.image.revision'] = '2' * 40
    elif mutation == 'wrong_platform':
        image['Architecture'] = 'arm64'
    elif mutation == 'unknown_size':
        image['Size'] = True
    target = tmp_path / 'deploy-config/catalog/canvas-oss.lock.json'
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(lock))

    def docker(*args):
        assert args == ('image', 'inspect', reference, '--format', '{{json .}}')
        return json.dumps(image)

    if mutation in ['none', 'large_image']:
        proof = inspect_prebuilt_image(tmp_path, docker)
        assert proof['required_free_bytes'] == (30 if mutation == 'large_image' else 20) * GIB
        assert proof['canvas_source_build_allowed'] is False
        assert proof['image_reference'] == reference
    else:
        with pytest.raises(RuntimeError):
            inspect_prebuilt_image(tmp_path, docker)
    assert original['image']['required_oci_labels']['org.opencontainers.image.revision'] != '2' * 40


def test_relocated_backing_disk_is_forwarded_to_physical_observer(monkeypatch):
    from types import SimpleNamespace
    from scripts import canvas_prebuilt_runtime as runtime
    monkeypatch.setattr(runtime.shutil, 'which', lambda _: 'powershell.exe')
    calls = []
    disk = 'E:\\Docker Data\\docker_data.vhdx'
    def run(arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=json.dumps(dict(capacity_mode='PrebuiltRuntime',
            required_free_bytes=20 * GIB, physical_free_bytes=25 * GIB)))
    conversions = []
    def convert(arguments, **kwargs):
        assert arguments[:2] == ['wslpath', '-w']
        conversions.append(arguments)
        return r'C:\operator\check-canvas-prebuilt-backing-capacity.ps1'
    monkeypatch.setattr(runtime.subprocess, 'check_output', convert)
    monkeypatch.setattr(runtime.subprocess, 'run', run)
    physical_runtime_capacity(dict(image_size_bytes=3 * GIB, required_free_bytes=20 * GIB), ROOT / 'scripts', disk)
    assert len(calls) == 1
    assert calls[0][-2:] == ['-DockerDesktopDataDiskPath', disk]
    assert len(conversions) == (0 if runtime.os.name == 'nt' else 1)
    if conversions:
        assert r'C:\operator\check-canvas-prebuilt-backing-capacity.ps1' in calls[0]
