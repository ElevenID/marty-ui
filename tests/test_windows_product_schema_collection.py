"""Read-only collector orchestration; synthetic witnesses grant no admission."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'scripts'), str(Path(__file__).resolve().parent)]
import selfhost_windows_product_deploy as deploy
import selfhost_windows_product_schema as membership
import selfhost_windows_product_startup as startup
import selfhost_windows_product_ledger as ledger
import selfhost_windows_product_catalog as catalog
from test_windows_product_schema_evidence import pair


@pytest.fixture
def collection(monkeypatch):
    before, after = pair()
    case = SimpleNamespace(before=before, after=after, side='before', calls=[], files={}, fault=None)
    rows = [{'Id': 'a'*64, 'Config': {'Env': ['PRIVATE_TEST_SENTINEL=not-public']}}]
    stopped = {'schema': 'synthetic-stopped-witness', 'writers': {'gateway': {'id': 'b'*64}}}
    context = SimpleNamespace(_issuance_helper=None, project='synthetic-project', docker=object())
    def observe():
        case.calls.append('stopped-open')
        return deepcopy(stopped), deepcopy(rows)
    def close():
        case.calls.append('stopped-close')
        return {} if case.fault == 'stopped-drift' else deepcopy(stopped)
    context.schema_stopped_observation = observe
    context.schema_stopped_witness = close
    case.context = context
    counts = {}
    def capture(name):
        def read(docker, owned, project, *args, **kwargs):
            assert docker is context.docker and owned == rows and project == context.project
            assert kwargs['profile'] == deploy.probe.LedgerProfile()
            counts[name] = counts.get(name, 0) + 1
            case.calls.append(name)
            if case.fault == 'quiet-open' and name == 'quiet': raise ValueError('not quiet')
            if case.fault == 'quiet-close' and name == 'quiet' and counts[name] == 2: raise ValueError('not quiet')
            if case.fault == 'capture' and name == 'catalog': raise ValueError('read failed')
            prior = case.before['parts']
            if name in {'membership', 'startup', 'ledger', 'catalog'}:
                assert kwargs['before'] == (None if case.side == 'before' else prior[name])
                if name == 'startup':
                    assert kwargs['organization_id'] == 'org' and kwargs['issuer_did'] == 'did:example:issuer'
            if name == 'mutable_rows':
                scope = prior if case.side == 'after' else case.before['parts']
                assert args == (scope['membership'], scope['startup'])
            if name == 'quiet': return {'synthetic_read_only_quiet': True}
            result = deepcopy(getattr(case, case.side)['parts'][name])
            if case.fault == name+'-drift' and counts[name] == 2: result['unexpected'] = True
            return result
        return read
    for name, attr in [('quiet','quiescence_snapshot'),('schema','detailed_schema_snapshot'),
                       ('rows','retained_rows_snapshot'),('mutable_rows','retained_mutable_rows_snapshot')]:
        monkeypatch.setattr(deploy.probe, attr, capture(name))
    for name, module in [('membership',membership),('startup',startup),('ledger',ledger),('catalog',catalog)]:
        monkeypatch.setattr(module, 'capture', capture(name))
    def write(name, body):
        assert name not in case.files
        if case.fault == 'write' and name.endswith('.json') and not name.endswith(('.started.json','.runtime.json')):
            raise OSError('durable evidence write failed')
        case.files[name] = json.loads(body)
    case.write = write
    case.run = lambda: deploy._capture_application_schema_evidence(context, 'org', 'did:example:issuer',
        write=case.write, before=None if case.side == 'before' else case.before)
    return case


@pytest.mark.parametrize('side', ['before','after'])
def test_complete_cohort_retains_private_runtime_and_binds_all_parts(collection, side):
    case = collection; case.side = side
    result = case.run()
    assert result == getattr(case, side)
    prefix = 'schema-evidence.'+side
    assert set(case.files) == {prefix+suffix for suffix in ('.started.json','.runtime.json','.json','.completed.json')}
    receipt = case.files[prefix+'.completed.json']
    assert receipt['evidence_sha256'] == deploy.selection.digest(deploy.selection.packed(result))
    assert receipt['runtime_sha256'] == deploy.selection.digest(deploy.selection.packed(case.files[prefix+'.runtime.json']))
    assert case.calls == ['stopped-open','quiet','schema','rows','membership','startup','ledger','catalog',
                          'mutable_rows','schema','rows','quiet','stopped-close']
    assert 'PRIVATE_TEST_SENTINEL' not in json.dumps(result)
    assert 'PRIVATE_TEST_SENTINEL' not in json.dumps(receipt)
    assert 'PRIVATE_TEST_SENTINEL' in json.dumps(case.files[prefix+'.runtime.json'])


@pytest.mark.parametrize('fault', ['quiet-open','quiet-close','capture','schema-drift','rows-drift','stopped-drift','write'])
def test_collection_failure_retains_intent_without_success_or_replay(collection, fault):
    case = collection; case.fault = fault
    with pytest.raises((ValueError,OSError)): case.run()
    assert 'schema-evidence.before.started.json' in case.files
    assert 'schema-evidence.before.completed.json' not in case.files
    assert 'schema-evidence.before.json' not in case.files
    assert case.calls.count('stopped-open') == 1


def test_after_proof_must_preserve_unscoped_application_rows(collection):
    case = collection;case.side = 'after'
    case.after['parts']['rows']['tables']['customer_schema.accounts']['sha256'] = 'f'*64
    with pytest.raises(ValueError):case.run()
    assert 'schema-evidence.after.completed.json' not in case.files
    assert 'schema-evidence.after.json' not in case.files


@pytest.mark.parametrize('fault',['busy-helper','wrong-profile'])
def test_invalid_collection_phase_refused_before_any_read_or_receipt(collection, fault):
    case = collection
    if fault == 'busy-helper':case.context._issuance_helper = {'stage':'running'}
    else:
        case.side = 'after'
        case.before['parts']['schema']['database_roles']['application'] = 'different'
    with pytest.raises(ValueError):case.run()
    assert not case.calls and not case.files


def test_elapsed_collection_budget_refuses_success_before_any_receipt(collection, monkeypatch):
    ticks = iter([0,500,1000])
    monkeypatch.setattr(deploy.time,'monotonic',lambda:next(ticks))
    with pytest.raises(ValueError):collection.run()
    assert not collection.files


@pytest.mark.parametrize('suffix', ['.started.json','.runtime.json','.json','.completed.json'])
def test_slow_durable_writer_never_returns_success_after_budget(collection, monkeypatch, suffix):
    case = collection
    clock = [0]
    monkeypatch.setattr(deploy.time, 'monotonic', lambda:clock[0])
    original = case.write
    target = 'schema-evidence.before'+suffix
    def slow_write(name, body):
        original(name, body)
        if name == target:clock[0] = 901
    case.write = slow_write
    with pytest.raises(ValueError):case.run()
    assert target in case.files
    if suffix != '.completed.json':
        assert 'schema-evidence.before.completed.json' not in case.files
    # A late completed-file write is retained as uncertain evidence. The
    # collector raises, so its caller cannot adopt it as a successful phase.
