"""Producer/receipt ordering and failure boundaries, using real context shapes.

The engine transport and private writer are replaced; no SQL or Docker mutation
is performed. Full schema admission and writer quiescence remain separate.
"""
from copy import deepcopy
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_product_helper_context import CID, CYCLE, fixture, helper
import selfhost_windows_product_deploy as deploy


def scenario(tmp_path, monkeypatch, *, fault=None):
    context, docker, original = fixture(tmp_path)
    events = []
    receipts = {}

    def write(name, body):
        events.append(name)
        if fault == name:
            raise OSError('private receipt unavailable')
        assert name not in receipts
        receipts[name] = json.loads(body)

    def mutate(command, **kwargs):
        assert 0 < kwargs['timeout'] <= 240
        if 'run' in command:
            events.append('create')
            assert 'issuance-migration.started.json' in receipts
            docker.items.append(helper(context, original))
            if fault == 'create-timeout':
                raise deploy.renewal.UncertainComposeMutation('unknown creation')
            output = b'not-a-full-id\n' if fault == 'create-id' else (CID+'\n').encode()
        elif command[-2:] == ['wait', CID]:
            events.append('wait')
            assert 'issuance-migration.acknowledged.json' in receipts
            if fault == 'wait-timeout':
                raise deploy.renewal.UncertainComposeMutation('unknown wait')
            row = next(item for item in docker.items if item['Id'] == CID)
            row['State'].update(Status='exited', Running=False, Pid=0,
                                FinishedAt='2026-11-12T00:00:02Z', ExitCode=1 if fault == 'exit' else 0)
            output = b'1\n' if fault == 'exit' else b'0\n'
        else:
            assert command == [*docker.prefix, 'rm', CID]
            events.append('rm')
            assert 'issuance-migration.cleanup.started.json' in receipts
            assert 'issuance-migration.completed.json' in receipts
            assert receipts['issuance-migration.completed.json']['witness']['observation_sha256'] == deploy.product.digest(
                receipts['issuance-migration.observation.json'])
            docker.items[:] = [item for item in docker.items if item['Id'] != CID]
            if fault == 'rm-timeout':
                raise deploy.renewal.UncertainComposeMutation('unknown removal')
            output = b'' if fault == 'rm-id' else (CID+'\n').encode()
        return CompletedProcess(command, 1 if fault == 'cli-code' else 0, output, b'never expose stderr')

    monkeypatch.setattr(deploy.renewal, 'run_owned_mutation', mutate)
    return context, docker, events, receipts, write


def run(context, tmp_path, write):
    return deploy._run_issuance_migration(context, tmp_path/'selected.env',
                                          tmp_path/'new.compose.json', CYCLE, write=write)


def test_success_retains_same_observation_and_never_replays(tmp_path, monkeypatch):
    context, docker, events, receipts, write = scenario(tmp_path, monkeypatch)
    result = run(context, tmp_path, write)
    assert result['exit_code'] == 0
    assert not any(item['Id'] == CID for item in docker.items)
    assert events == ['issuance-migration.started.json', 'create', 'issuance-migration.create-returned.json',
                      'issuance-migration.acknowledged.json',
                      'wait', 'issuance-migration.observation.json', 'issuance-migration.completed.json',
                      'issuance-migration.cleanup.started.json', 'rm', 'issuance-migration.cleanup.completed.json']
    before = deepcopy(events)
    with pytest.raises(ValueError):
        run(context, tmp_path, write)
    assert events == before
    assert receipts['issuance-migration.observation.json']['Id'] == CID


@pytest.mark.parametrize('fault', ['create-timeout', 'create-id', 'cli-code', 'wait-timeout', 'exit',
    'issuance-migration.create-returned.json', 'issuance-migration.acknowledged.json', 'issuance-migration.observation.json',
    'issuance-migration.completed.json', 'issuance-migration.cleanup.started.json'])
def test_failure_preserves_helper_without_cleanup_or_replay(tmp_path, monkeypatch, fault):
    context, docker, events, receipts, write = scenario(tmp_path, monkeypatch, fault=fault)
    with pytest.raises((ValueError, OSError, deploy.renewal.UncertainComposeMutation)):
        run(context, tmp_path, write)
    assert any(item['Id'] == CID for item in docker.items)
    assert 'rm' not in events and 'issuance-migration.cleanup.completed.json' not in receipts
    before = deepcopy(events)
    with pytest.raises(ValueError):
        run(context, tmp_path, write)
    assert events == before


def test_failed_intent_does_not_send_create(tmp_path, monkeypatch):
    context, docker, events, _, write = scenario(tmp_path, monkeypatch, fault='issuance-migration.started.json')
    with pytest.raises(OSError):
        run(context, tmp_path, write)
    assert events == ['issuance-migration.started.json']
    assert not any(item['Id'] == CID for item in docker.items)


def test_failed_admission_retains_definite_producer_id(tmp_path, monkeypatch):
    context, docker, events, receipts, write = scenario(tmp_path, monkeypatch)

    def refuse_admission(cid):
        assert cid == CID
        raise ValueError('context changed after creation')

    monkeypatch.setattr(context, 'acknowledge_issuance_helper', refuse_admission)
    with pytest.raises(ValueError):
        run(context, tmp_path, write)
    assert receipts['issuance-migration.create-returned.json']['id'] == CID
    assert receipts['issuance-migration.create-returned.json']['admitted'] is False
    assert 'issuance-migration.acknowledged.json' not in receipts and 'rm' not in events
    assert any(item['Id'] == CID for item in docker.items)


@pytest.mark.parametrize('fault', ['rm-timeout', 'rm-id', 'issuance-migration.cleanup.completed.json'])
def test_missing_cleanup_ack_stays_incomplete_without_retry(tmp_path, monkeypatch, fault):
    context, _, events, receipts, write = scenario(tmp_path, monkeypatch, fault=fault)
    with pytest.raises((OSError, deploy.renewal.UncertainComposeMutation)):
        run(context, tmp_path, write)
    assert events.count('create') == events.count('rm') == 1
    assert 'issuance-migration.cleanup.completed.json' not in receipts
    before = deepcopy(events)
    with pytest.raises(ValueError):
        run(context, tmp_path, write)
    assert events == before
