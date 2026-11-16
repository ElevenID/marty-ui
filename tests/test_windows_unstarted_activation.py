"""Pre-command reconciliation with actual private NTFS records and fake Docker."""
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_selfhost_windows_selection import fixture, selection
from test_selfhost_windows_renewal import context_container, model


def unstarted(monkeypatch, cfg):
    renewal = selection.renewal
    current_model = model(Path(cfg['current_secrets']))
    services = set(current_model['services']) - renewal.INITIALIZERS
    rows = [context_container(f'{number:064x}', service=role)
            for number, role in enumerate(sorted(services), 1)]
    changing = renewal.owned_roles(current_model, services)
    intent = {k: cfg[k] for k in ['current_env', 'renewed_env', 'current_secrets',
        'renewed_secrets', 'compose_sha256', 'project', 'step_receipts']}
    intent.update(schema=renewal.SCHEMA, candidate_only=True, changing=sorted(changing),
        layers=renewal.dependency_layers(current_model, services, changing),
        owned_before={renewal._service(x): x['Id'] for x in rows},
        data_mounts_before=renewal.data_mounts(rows))
    Path(cfg['intent']).write_text(json.dumps(intent))
    Path(cfg['new_log']).write_bytes(renewal.bounded_diagnostic(b'').encode())
    reads = []
    class Docker:
        prefix = ['docker']
        def __init__(self, host, engine):
            assert (host, engine) == (cfg['docker_host'], cfg['engine_id'])
        def compose(self, project, env, source):
            assert (project, str(env), str(source)) == (cfg['project'], cfg['current_env'], cfg['compose_file'])
            return ['docker', 'compose']
        def json(self, args):
            assert args == ['compose', '--profile', '*', 'config', '--format', 'json']
            return deepcopy(current_model)
        def containers(self):
            reads.append(True)
            return deepcopy(rows)
    monkeypatch.setattr(renewal, 'Docker', Docker)
    return rows, intent, current_model, reads


def test_empty_first_boundary_selects_original_without_replaying_or_rewriting(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        _rows, _intent, _model, reads = unstarted(monkeypatch, cfg)
        originals = {k: Path(cfg[k]).read_bytes() for k in ['intent', 'result', 'new_log', 'rollback_log']}
        record = selection.complete(next_path, reconcile=True)
        assert record['decision'] == 'reconciled-old' and record['choice'] == 'old'
        assert len(reads) == 2  # Same original IDs/data before AND after native proof.
        assert originals == {k: Path(cfg[k]).read_bytes() for k in originals}
        assert selection.status(path)['state'] == 'selected'


@pytest.mark.parametrize('bad', ['id', 'image', 'mount', 'missing-role', 'duplicate-role',
    'intent-extra', 'intent-role', 'intent-data', 'wrong-layers', 'new-tail', 'empty-log',
    'rollback-log', 'new-started', 'new-completed', 'rollback-started', 'model-role'])
def test_unknown_or_started_attempt_keeps_pending_selection(monkeypatch, bad):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        rows, intent, current_model, _reads = unstarted(monkeypatch, cfg)
        if bad == 'id':rows[0]['Id'] = 'f'*64
        elif bad == 'image':rows[0]['Image'] = 'CHANGED'
        elif bad == 'mount':rows[0]['Mounts'] = []
        elif bad == 'missing-role':rows.pop()
        elif bad == 'duplicate-role':rows.append(deepcopy(rows[0]))
        elif bad == 'intent-extra':intent['unknown'] = True
        elif bad == 'intent-role':intent['owned_before']['extra'] = 'f'*64
        elif bad == 'intent-data':intent['data_mounts_before'] = {}
        elif bad == 'wrong-layers':intent.update(layers=[['postgres']], changing=['postgres'])
        elif bad == 'new-tail':Path(cfg['new_log']).write_text(selection.renewal.bounded_diagnostic(b'PUBLIC_OUTPUT'))
        elif bad == 'empty-log':Path(cfg['new_log']).write_bytes(b'')
        elif bad == 'rollback-log':Path(cfg['rollback_log']).write_bytes(b'PUBLIC_OUTPUT')
        elif bad == 'model-role':current_model['services']['gateway']['secrets'] = []
        else:
            phase, event = bad.split('-')
            Path(cfg['step_receipts'][0][phase+'_'+event]).write_text(json.dumps(
                {'roles': ['gateway'], 'event': event, 'time': 1.0}))
        Path(cfg['intent']).write_text(json.dumps(intent))
        with pytest.raises(ValueError):selection.complete(next_path, reconcile=True)
        assert selection.status(path)['state'] == 'pending-reconciliation'
        assert not Path(cfg['result']).read_bytes()


@pytest.mark.parametrize('change', ['id', 'image', 'mount', 'native-refusal'])
def test_old_proof_must_pass_and_preserve_original_identity_until_selection(monkeypatch, change):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        rows, _intent, _model, _reads = unstarted(monkeypatch, cfg)
        actual = selection._prove
        def proof(*args, **kwargs):
            result = actual(*args, **kwargs)
            if change == 'native-refusal':raise ValueError('PUBLIC_NATIVE_REFUSAL')
            if change == 'id':rows[0]['Id'] = 'f'*64
            elif change == 'image':rows[0]['Image'] = 'CHANGED'
            else:rows[0]['Mounts'] = []
            return result
        monkeypatch.setattr(selection, '_prove', proof)
        with pytest.raises(ValueError):selection.complete(next_path, reconcile=True)
        assert selection.status(path)['state'] == 'pending-reconciliation'


def test_unstarted_receipts_stay_held_through_current_native_proof(monkeypatch):
    with fixture(monkeypatch) as (_root, _phase, tx, _outcome, path, _cfg):
        selection.adopt(path);next_path, cfg = tx(2);selection.prepare(next_path)
        unstarted(monkeypatch, cfg)
        actual = selection._prove
        denied = []
        def proof(*args, **kwargs):
            with pytest.raises(OSError):Path(cfg['step_receipts'][0]['new_started']).write_bytes(b'PUBLIC_TAMPER')
            denied.append(True)
            return actual(*args, **kwargs)
        monkeypatch.setattr(selection, '_prove', proof)
        assert selection.complete(next_path, reconcile=True)['choice'] == 'old'
        assert denied == [True]
