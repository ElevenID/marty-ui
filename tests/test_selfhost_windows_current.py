"""Current custody proof stays separate from changing-generation admission."""
import base64
import hashlib
import io
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import selfhost_windows_renewal as renewal
import selfhost_windows_renewal_native as native

PROJECT = 'marty-production-synthetic'


def config():
    return {'binary': 'PUBLIC_BINARY', 'binary_sha256': hashlib.sha256(b'PUBLIC_BINARY').hexdigest(),
            'source_sha': '1'*40, 'release_tag': 'v1.2.3', 'helper_image': 'python@sha256:'+'2'*64,
            'control_volume': PROJECT+'-renewal-control', 'network': PROJECT+'_default',
            'bao_addr': 'https://openbao:8200', 'ca_file': 'PUBLIC_CA', 'minimum_ttl': 3600,
            'current': '/control/current', 'renewed': '/control/new', 'token_file': '/control/session/token'}


@pytest.mark.parametrize('current_only', [False, True])
def test_native_transport_binds_mode_and_sends_held_bytes_only_on_pipe(monkeypatch, current_only):
    cfg = config();calls = []
    @contextmanager
    def held(*_a, **_k):yield b'PUBLIC_BINARY'
    def run(args, *, stdin_bytes, timeout):
        request = json.loads(stdin_bytes);calls.append(request)
        assert 'PUBLIC_OLD' not in ' '.join(args) and 'PUBLIC_NEW' not in ' '.join(args)
        assert timeout == 240 and request['transition'] is not current_only
        assert request['bytes']['old']['leaf'] == base64.b64encode(b'PUBLIC_OLD').decode()
        if current_only:
            assert request['current'] == request['renewed'] == '/control/current'
            assert request['changed'] == 0 and request['bytes']['new'] == request['bytes']['old']
        else:
            assert request['changed'] == 1 and request['current'] != request['renewed']
        return subprocess.CompletedProcess(args, 0, json.dumps({'authority': True,
            'generation': not current_only, 'tokens': True, 'certificates': True}).encode(), b'')
    monkeypatch.setattr(native, 'hold_private_input', held)
    monkeypatch.setattr(renewal, 'run_owned_mutation', run)
    if current_only:native.preflight_current(cfg, PROJECT, {'leaf': b'PUBLIC_OLD'}, ['SYNTHETIC_DOCKER'])
    else:native.preflight(cfg, PROJECT, {'leaf': b'PUBLIC_OLD'}, {'leaf': b'PUBLIC_NEW'}, ['SYNTHETIC_DOCKER'])
    assert len(calls) == 1
    assert cfg['renewed'] == '/control/new'  # Current proof never rewrites caller configuration.


def test_transition_still_refuses_unchanged_generation_and_current_requires_hour(monkeypatch):
    monkeypatch.setattr(renewal, 'run_owned_mutation', lambda *_a, **_k: pytest.fail('Refusal happened after transport'))
    cfg = config()
    with pytest.raises(ValueError):native.preflight(cfg, PROJECT, {'leaf': b'X'}, {'leaf': b'X'}, [])
    cfg['minimum_ttl'] = 60
    with pytest.raises(ValueError):native.preflight_current(cfg, PROJECT, {'leaf': b'X'}, [])


@pytest.mark.parametrize('current_only', [False, True])
@pytest.mark.skipif(os.name != 'posix', reason='Fixed worker executes only in the Linux helper')
def test_worker_current_or_transition_checks_use_frozen_snapshot_after_mirror_mutation(tmp_path, monkeypatch, capsys, current_only):
    old = tmp_path/'old';new = old if current_only else tmp_path/'new';proof = tmp_path/'proof'
    old.mkdir();proof.mkdir()
    if new != old:new.mkdir()
    (old/'leaf').write_bytes(b'PUBLIC_OLD')
    if new != old:(new/'leaf').write_bytes(b'PUBLIC_NEW')
    token = tmp_path/'token';token.write_text('PUBLIC_SYNTHETIC_TOKEN')
    binary = tmp_path/'binary';binary.write_bytes(b'PUBLIC_BINARY')
    data = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'source_sha': '1'*40,
            'release_tag': 'v1.2.3', 'current': str(old), 'renewed': str(new), 'token_file': str(token),
            'bao_addr': 'https://openbao:8200', 'minimum_ttl': 3600, 'count': 1,
            'changed': 0 if current_only else 1, 'transition': not current_only,
            'bytes': {'old': {'leaf': base64.b64encode(b'PUBLIC_OLD').decode()},
                      'new': {'leaf': base64.b64encode(b'PUBLIC_OLD' if current_only else b'PUBLIC_NEW').decode()}}}
    operations = []
    def native_call(args, **kwargs):
        if args[-1] == '--build-identity':
            return subprocess.CompletedProcess(args, 0, ('1'*40+':v1.2.3\n').encode(), b'')
        operation = args[2];operations.append(operation);body = json.loads(kwargs['input'])
        if operation == 'authority-check':
            (old/'leaf').write_bytes(b'PUBLIC_TAMPER_AFTER_COMPARISON')
            if new != old:(new/'leaf').write_bytes(b'PUBLIC_TAMPER_AFTER_COMPARISON')
            value = None
        else:
            old_path = body.get('current', body.get('old'));new_path = body.get('candidate', body.get('new'))
            assert Path(old_path, 'leaf').read_bytes() == b'PUBLIC_OLD'
            assert Path(new_path, 'leaf').read_bytes() == (b'PUBLIC_OLD' if current_only else b'PUBLIC_NEW')
            assert Path(old_path).parent == proof and Path(new_path).parent == proof
            value = [1, 1] if operation == 'generation' else None
        return subprocess.CompletedProcess(args, 0, json.dumps({'value': value}).encode(), b'')
    monkeypatch.setattr(subprocess, 'run', native_call)
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(data)))
    code = native.WORKER.replace("'/operator/tool'", repr(str(binary))).replace("'/proof'", repr(str(proof)))
    previous = os.umask(0o077)
    try:exec(compile(code, '<fixed native snapshot worker>', 'exec'), {})
    finally:os.umask(previous)
    assert operations == ['authority-check', *([] if current_only else ['generation']), 'activation-tokens', 'activation-certificates']
    assert json.loads(capsys.readouterr().out)['generation'] is not current_only
