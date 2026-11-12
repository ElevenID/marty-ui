"""Exact writer stopping shapes and producer failures; no runtime mutation."""
from copy import deepcopy
import json
from pathlib import Path
from subprocess import CompletedProcess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_windows_product_helper_context import CYCLE, PROJECT, fixture
import selfhost_windows_product as product
import selfhost_windows_product_deploy as deploy


def context_fixture(tmp_path):
    previous, docker, _ = fixture(tmp_path)
    for row in docker.items:
        row['Created'] = '2026-11-12T00:00:00Z'
        row['RestartCount'] = 0
        row['State'].update(Status='running', Running=True, Pid=123,
            StartedAt='2026-11-12T00:00:01Z', ExitCode=0, Paused=False, Dead=False,
            OOMKilled=False, Restarting=False, Error='')
        row['NetworkSettings'] = {'Networks': {'synthetic': {'NetworkID': '9'*64}}}
        if product.renewal._service(row) in product.MIGRATION_ROLES | product.CONFIGURATION_ROLES:
            row['State'].update(Status='exited', Running=False, Pid=0, ExitCode=0)
    context = product.ProductContext(docker, PROJECT, deepcopy(docker.items), {}, 'synthetic',
        old_model=previous.old_model, new_model=previous.new_model, admitted=previous.admitted,
        image_ids=previous.image_ids, configuration_hashes=previous.configuration_hashes)
    def check(**kwargs):
        context._candidate(docker.items, before_intent=kwargs.get('before_intent', False))
        return deepcopy(docker.items)
    context.check = check
    return context, docker


def stopped(row):
    row['State'].update(Status='exited', Running=False, Pid=0, ExitCode=143,
                        FinishedAt='2026-11-12T00:00:02Z')


def test_every_writer_stopped_and_same_observation_retained(tmp_path):
    context, docker = context_fixture(tmp_path)
    roles = context.prepare_schema_stops(CYCLE)
    assert set(roles) == {'gateway', 'issuance-native', 'keycloak', 'signing-keys'}
    for role, cid in roles.items():
        context.begin_schema_stop(role)
        row = next(row for row in docker.items if row['Id'] == cid)
        stopped(row)
        witness = context.acknowledge_schema_stop(role, cid)
        assert witness['observation_sha256'] == product.digest(row)
    witness = context.schema_stopped_witness()
    assert witness['product_transition_admission'] is False
    assert set(witness['writers']) == set(roles)
    with pytest.raises(ValueError):context.prepare_schema_stops(CYCLE)
    with pytest.raises(ValueError):context._candidate(docker.items, before_intent=True)


@pytest.mark.parametrize('fault', ['restart', 'resume', 'cid', 'image', 'config', 'mount', 'network',
                                  'host', 'oom', 'kill', 'terminal-edit', 'naive-finish', 'early-finish'])
def test_stopped_writer_cannot_hide_replacement_restart_or_unsafe_stop(tmp_path, fault):
    context, docker = context_fixture(tmp_path)
    roles = context.prepare_schema_stops(CYCLE)
    role = next(iter(roles));cid = roles[role]
    context.begin_schema_stop(role)
    row = next(row for row in docker.items if row['Id'] == cid)
    stopped(row)
    context.acknowledge_schema_stop(role, cid)
    if fault == 'restart':row['State']['StartedAt'] = '2026-11-12T00:00:03Z'
    elif fault == 'resume':row['State'].update(Status='running', Running=True, Pid=124)
    elif fault == 'cid':row['Id'] = 'f'*64
    elif fault == 'image':row['Image'] = 'sha256:'+'f'*64
    elif fault == 'config':row['Config']['Env'] = ['INJECTED=value']
    elif fault == 'mount':row['Mounts'].append({'Type':'bind','Source':'C:/unknown','Destination':'/unknown','RW':True})
    elif fault == 'network':row['NetworkSettings']['Networks']['synthetic']['NetworkID'] = 'e'*64
    elif fault == 'host':row.setdefault('HostConfig', {})['Privileged'] = True
    elif fault == 'oom':row['State']['OOMKilled'] = True
    elif fault == 'kill':row['State']['ExitCode'] = 137
    elif fault == 'terminal-edit':row['State']['FinishedAt'] = '2026-11-12T00:00:04Z'
    elif fault == 'naive-finish':row['State']['FinishedAt'] = '2026-11-12T00:00:02'
    elif fault == 'early-finish':row['State']['FinishedAt'] = '2026-11-11T00:00:00Z'
    with pytest.raises(ValueError):context.check()


def test_unarmed_stop_or_partial_cohort_is_not_quiescence(tmp_path):
    context, docker = context_fixture(tmp_path)
    roles = context.prepare_schema_stops(CYCLE)
    with pytest.raises(ValueError):context.schema_stopped_witness()
    row = next(row for row in docker.items if row['Id'] == roles['gateway'])
    stopped(row)
    with pytest.raises(ValueError):context.check()


@pytest.mark.parametrize('role', ['db-migrate', 'openbao', 'gateway'])
def test_candidate_activation_is_not_allowed_in_schema_stop_phase(tmp_path, role):
    context, docker = context_fixture(tmp_path)
    roles = context.prepare_schema_stops(CYCLE)
    if role != 'gateway':
        for writer, cid in roles.items():
            context.begin_schema_stop(writer)
            stopped(next(row for row in docker.items if row['Id'] == cid))
            context.acknowledge_schema_stop(writer, cid)
        context.schema_stopped_witness()
    row = next(row for row in docker.items if product.renewal._service(row) == role)
    row.update(Id='f'+row['Id'][1:], Image=context.image_ids[role])
    row['Config']['Image'] = context.new_model['services'][role]['image']
    row['Config']['Labels']['com.docker.compose.config-hash'] = context.configuration_hashes['new'][role]
    row['State'].update(Status='running', Running=True, Pid=456, StartedAt='2026-11-12T00:00:03Z')
    with pytest.raises(ValueError):context.check()


@pytest.mark.parametrize('fault', [None, 'unknown-ack', 'timeout', 'returned-write', 'context-proof'])
def test_stop_producer_order_and_no_replay_or_restart(tmp_path, monkeypatch, fault):
    context, docker = context_fixture(tmp_path)
    events = [];receipts = {}
    def write(name, body):
        events.append(name)
        if fault == 'returned-write' and name.endswith('.returned.json'):raise OSError('receipt failed')
        receipts[name] = json.loads(body)
    def mutate(command, **kwargs):
        assert command[-4:-1] == ['stop', '--time', '30'] and 0 < kwargs['timeout'] <= 60
        cid = command[-1]
        events.append('stop:'+cid)
        assert any(name.endswith('.started.json') and body.get('id') == cid for name,body in receipts.items())
        row = next(row for row in docker.items if row['Id'] == cid);stopped(row)
        if fault == 'timeout':raise deploy.renewal.UncertainComposeMutation('unknown')
        if fault == 'context-proof':row['Config']['Env'] = ['UNKNOWN=value']
        return CompletedProcess(command, 0, b'' if fault == 'unknown-ack' else (cid+'\n').encode(), b'')
    monkeypatch.setattr(deploy.renewal, 'run_owned_mutation', mutate)
    if fault:
        with pytest.raises((ValueError, OSError, deploy.renewal.UncertainComposeMutation)):
            deploy._stop_schema_writers(context, CYCLE, write=write)
        assert 'schema-stop.completed.json' not in receipts
        assert len([event for event in events if event.startswith('stop:')]) == 1
        if fault == 'context-proof':assert any(name.endswith('.returned.json') for name in receipts)
    else:
        witness = deploy._stop_schema_writers(context, CYCLE, write=write)
        assert set(witness['writers']) == {'gateway', 'issuance-native', 'keycloak', 'signing-keys'}
        assert events[-1] == 'schema-stop.completed.json'
    before = deepcopy(events)
    with pytest.raises(ValueError):deploy._stop_schema_writers(context, CYCLE, write=write)
    assert events == before
