"""Concrete interruption boundaries; no beta state is touched by these controls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('forward_simulator', ROOT / 'scripts/complete_beta_passport_simulator.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize('encoding', ['utf-8-sig', 'utf-16'])
def test_retained_powershell_log_decoding_preserves_original_bytes(tmp_path, encoding):
    path = tmp_path / 'retained.log'
    original = 'Success! Uploaded policy: passport-callback-hmac-service\n'.encode(encoding)
    path.write_bytes(original)
    assert 'Success! Uploaded policy: passport-callback-hmac-service' in MODULE.retained_log(path)
    assert path.read_bytes() == original


def test_overlay_is_exact_single_environment_change():
    before = {'services': {'passport-callback-signer': {'image': 'immutable', 'environment': {'BAO_TOKEN_FILE': '/scoped'}}}}
    after = copy.deepcopy(before)
    after['services']['passport-callback-signer']['environment']['PRESERVE_BAO_TOKEN_FILE'] = '1'
    MODULE.validate_overlay(before, after)
    after['services']['passport-callback-signer']['image'] = 'other'
    with pytest.raises(RuntimeError, match='more than'):
        MODULE.validate_overlay(before, after)


def test_callback_network_rejects_foreign_authority_and_missing_members():
    network = dict(Name=MODULE.NETWORK, Internal=True, Labels={
        'com.docker.compose.project': 'elevenid-beta',
        'com.docker.compose.network': 'passport-callback-signing'}, Containers={'signer': {}, 'bureau': {}})
    MODULE.validate_network(network, {'signer', 'bureau', 'bao'})
    with pytest.raises(RuntimeError, match='Incomplete'):
        MODULE.validate_network(network, {'signer', 'bureau', 'bao'}, complete=True)
    network['Containers']['foreign'] = {}
    with pytest.raises(RuntimeError, match='Unexpected callback network authority'):
        MODULE.validate_network(network, {'signer', 'bureau', 'bao'})


def phase():
    roles = {f'app-{i}' for i in range(19)}
    images = {role: 'candidate' for role in roles | MODULE.CALLBACK | {'ui-prod'}}
    prior = [dict(service=role, container_id=role + '-old', image_id='old') for role in roles | {'ui-prod', 'keycloak'}]
    current = {row['service']: dict(Id=row['container_id'], Image='old', State={'Running': False, 'Status': 'exited'}) for row in prior}
    current.update({role: dict(Id=role + '-new', Image='candidate', State={'Status': 'created'}) for role in MODULE.CALLBACK})
    current['keycloak'] = dict(Id='kc-new', State={'Health': {'Status': 'healthy'}})
    return current, prior, images


def test_simulator_phase_requires_exact_stopped_prior_id_and_image():
    current, prior, images = phase()
    MODULE.validate_phase(current, prior, images)
    current['app-0']['Id'] = 'unrelated'
    with pytest.raises(RuntimeError, match='exactly stopped'):
        MODULE.validate_phase(current, prior, images)


def test_simulator_phase_rejects_old_writer_running_or_missing_role():
    current, prior, images = phase()
    current['app-0']['State']['Running'] = True
    with pytest.raises(RuntimeError, match='exactly stopped'):
        MODULE.validate_phase(current, prior, images)
    del images['app-1']
    with pytest.raises(RuntimeError, match='role selection'):
        MODULE.validate_phase(current, prior, images)


@pytest.mark.parametrize('preserve,forbidden,healthy', [
    ('1', None, True), (None, None, False),
    ('1', 'BAO_TOKEN', False), ('1', 'OPENBAO_SERVICE_TOKEN', False),
    ('1', 'OPENBAO_SERVICE_TOKEN_FILE', False),
])
def test_actual_production_entrypoint_scoped_file_contract(tmp_path, preserve, forbidden, healthy):
    image = os.environ.get('MARTY_TEST_CALLBACK_IMAGE')
    if not image:
        pytest.skip('Explicit immutable locally built image required; no image pull')
    subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, check=True)
    token = tmp_path / 'scoped-token'
    token.write_text('synthetic-scoped-callback-token\n')
    name = 'marty-callback-entrypoint-test-' + uuid.uuid4().hex
    command = ['docker', 'run', '--detach', '--name', name, '--network', 'none', '--memory', '256m', '--cpus', '1',
               '--label', 'elevenid.audit.owner=callback-entrypoint-focused',
               '--mount', f'type=bind,source={token.resolve()},target=/test/scoped-token,readonly']
    env = {'SERVICE_NAME': 'passport_callback_signer', 'ENVIRONMENT': 'beta',
           'PASSPORT_CALLBACK_SIGNER_ENABLED': 'true', 'SIGNING_KEYS_SERVICE_PORT': '8018',
           'SIGNING_KEYS_INTERNAL_API_KEY': 'synthetic-isolated-internal-key',
           'BAO_ADDR': 'https://unreachable.invalid:8200', 'BAO_TOKEN_FILE': '/test/scoped-token'}
    if preserve:
        env['PRESERVE_BAO_TOKEN_FILE'] = preserve
    if forbidden:
        env[forbidden] = '/test/scoped-token' if forbidden.endswith('_FILE') else 'synthetic-forbidden-token'
    for key, value in env.items():
        command += ['--env', key + '=' + value]
    try:
        result = subprocess.run(command + [image], capture_output=True)
        assert result.returncode == 0, 'Disposable production image failed to create'
        for _ in range(40):
            state = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]['State']
            if healthy:
                probe = subprocess.run(['docker', 'exec', name, 'curl', '--fail', '--silent',
                                        'http://127.0.0.1:8018/health'], capture_output=True)
                if probe.returncode == 0:
                    break
            elif not state['Running']:
                break
            time.sleep(0.2)
        if healthy:
            assert probe.returncode == 0, 'File-only signer did not reach real HTTP health'
        else:
            assert not state['Running'] and state['ExitCode'] != 0
            logs = subprocess.check_output(['docker', 'logs', name], stderr=subprocess.STDOUT)
            assert b'inline or shared OpenBao credentials are forbidden' in logs
    finally:
        subprocess.run(['docker', 'rm', '--force', name], capture_output=True, check=True)
