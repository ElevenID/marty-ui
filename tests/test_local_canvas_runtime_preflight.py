"""Local admission cannot substitute a different daemon or deployed beta."""
import json

import pytest

from scripts import run_local_canvas_runtime as runtime


@pytest.mark.parametrize('mutation', ['none', 'wrong_daemon', 'wrong_beta'])
def test_local_preflight_refuses_substituted_engine_or_beta_before_capacity_admission(monkeypatch, mutation):
    monkeypatch.setattr(runtime.sys, 'platform', 'win32')
    deployment = {'marty_ui_sha': 'a' * 40, 'release_version': 'dev-reviewed-source'}
    admitted = []

    def docker(*args):
        assert args[0] in ['context', 'info'], 'Admission must not start or mutate services'
        if args[0] == 'context':
            return json.dumps([{'Endpoints': {'docker': {'Host': 'tcp://other:2375' if mutation == 'wrong_daemon'
                                                          else 'npipe:////./pipe/dockerDesktopLinuxEngine'}}}])
        return {'{{.ID}}': 'actual-desktop', '{{.OSType}}': 'linux', '{{.MemTotal}}': str(16 * 1024**3)}[args[-1]]

    monkeypatch.setattr(runtime, 'docker', docker)
    monkeypatch.setattr(runtime, 'inspect_beta_tunnel', lambda _: {'beta_network': 'elevenid-beta-network'})
    monkeypatch.setattr(runtime, 'assert_beta', lambda: {
        'source_id': 'b' * 40 if mutation == 'wrong_beta' else deployment['marty_ui_sha'],
        'release_version': deployment['release_version']})
    monkeypatch.setattr(runtime, 'inspect_prebuilt_image', lambda *_: {'canvas_source_build_allowed': False})
    monkeypatch.setattr(runtime, 'physical_runtime_capacity', lambda *_: admitted.append(True) or {'verified': True})
    monkeypatch.setattr(runtime, 'check_passport_host_quarantine', lambda **_: None)
    if mutation == 'none':
        result = runtime.preflight(deployment)
        assert result['production_demo_qualified'] is False
        assert result['github_labels_verified'] is False
        assert result['host_browser_processes'] is False
        assert result['image']['canvas_source_build_allowed'] is False
        assert admitted == [True]
    else:
        with pytest.raises(RuntimeError, match='Docker Desktop|Actual beta'):
            runtime.preflight(deployment)
        assert admitted == []
