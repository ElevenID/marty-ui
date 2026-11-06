"""Closed command-boundary recovery controls; only disposable synthetic files."""
import hashlib
import json
import os
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_renewal as renewal
from activate_selfhost_renewed_secrets import RENEWED_TOKEN_FILES, checked_secret_mounts
from test_selfhost_windows_inputs import private_fixture
from test_selfhost_windows_renewal import PROJECT, model, states


@contextmanager
def prefix_fixture():
    if os.name != 'nt':
        pytest.skip('Real private NTFS prefix receipts')
    with private_fixture() as (root, _):
        output = root / 'activation';output.mkdir()
        cfg = {'schema': renewal.SCHEMA, 'project': PROJECT, 'candidate_only': True,
               'compose_sha256': '1' * 64, 'step_receipts': []}
        for key in ('current_env', 'renewed_env', 'current_secrets', 'renewed_secrets'):
            cfg[key] = str(root / key)
        for key in ('intent', 'result', 'new_log', 'rollback_log'):
            path = output / key;path.write_bytes(b'');cfg[key] = str(path)
        layers = [['postgres'], ['keycloak'], ['gateway']]
        for index, layer in enumerate(layers):
            step = {}
            for phase in ('new', 'rollback'):
                for event in ('started', 'completed'):
                    path = output / f'{index}-{phase}_{event}'
                    raw = json.dumps({'roles': layer, 'event': event, 'time': 1000.0 + index}).encode()
                    path.write_bytes(raw if phase == 'new' and index < 2 else b'')
                    step[phase+'_'+event] = str(path)
            cfg['step_receipts'].append(step)
        intent = {key: cfg[key] for key in ('schema', 'project', 'compose_sha256', 'current_env',
                                           'renewed_env', 'current_secrets', 'renewed_secrets', 'candidate_only')}
        intent.update(layers=layers, step_receipts=cfg['step_receipts'], changing=['gateway', 'keycloak', 'postgres'],
                      data_mounts_before={}, owned_before={role: hashlib.sha256(role.encode()).hexdigest()
                                                          for layer in layers for role in layer})
        Path(cfg['intent']).write_text(json.dumps(intent), encoding='utf-8')
        yield cfg, layers, intent


def test_prefix_receipts_and_original_intent_remain_held_until_owner_exit():
    with prefix_fixture() as (cfg, layers, intent), ExitStack() as stack:
        prefix, original, digest = renewal.closed_activation_prefix(cfg, layers, stack)
        assert prefix == 2 and original == intent
        assert digest == hashlib.sha256(Path(cfg['intent']).read_bytes()).hexdigest()
        for path in [cfg['intent'], cfg['step_receipts'][0]['new_completed'], cfg['step_receipts'][1]['new_started']]:
            with pytest.raises(OSError):
                Path(path).write_bytes(b'CONCURRENT_REPLACEMENT')


@pytest.mark.parametrize('bad', ['unknown-intent-field', 'project', 'schema', 'candidate', 'compose', 'env',
                               'layers', 'changing', 'ids', 'result', 'unfinished', 'orphan-completed',
                               'gap', 'rollback-started', 'rollback-completed', 'roles', 'event',
                               'nan', 'infinite', 'negative', 'boolean-time', 'empty', 'fully-complete'])
def test_unknown_or_unfinished_history_never_qualifies_as_closed_prefix(bad):
    with prefix_fixture() as (cfg, layers, intent), ExitStack() as stack:
        first, second, last = cfg['step_receipts']
        if bad == 'unknown-intent-field':intent['unbound'] = True
        elif bad == 'project':intent['project'] = 'marty-production-other'
        elif bad == 'schema':intent['schema'] = 'unknown'
        elif bad == 'candidate':intent['candidate_only'] = False
        elif bad == 'compose':intent['compose_sha256'] = '2' * 64
        elif bad == 'env':intent['current_env'] = str(Path(cfg['current_env']).with_name('other.env'))
        elif bad == 'layers':intent['layers'] = list(reversed(layers))
        elif bad == 'changing':intent['changing'] = ['gateway']
        elif bad == 'ids':intent['owned_before']['gateway'] = intent['owned_before']['postgres']
        elif bad == 'result':Path(cfg['result']).write_bytes(b'ALREADY_TERMINAL')
        elif bad == 'unfinished':Path(second['new_completed']).write_bytes(b'')
        elif bad == 'orphan-completed':Path(first['new_started']).write_bytes(b'')
        elif bad == 'gap':
            Path(first['new_started']).write_bytes(b'');Path(first['new_completed']).write_bytes(b'')
        elif bad.startswith('rollback-'):
            Path(first[bad.replace('-', '_')]).write_bytes(b'ROLLBACK_BOUNDARY')
        elif bad in ('roles', 'event', 'nan', 'infinite', 'negative', 'boolean-time'):
            path = Path(first['new_completed']);record = json.loads(path.read_bytes())
            if bad == 'roles':record['roles'] = ['gateway']
            elif bad == 'event':record['event'] = 'started'
            else:record['time'] = {'nan': float('nan'), 'infinite': float('inf'), 'negative': -1, 'boolean-time': True}[bad]
            path.write_text(json.dumps(record), encoding='utf-8')
        elif bad == 'empty':
            for step in cfg['step_receipts']:
                Path(step['new_started']).write_bytes(b'');Path(step['new_completed']).write_bytes(b'')
        elif bad == 'fully-complete':
            for event in ('started', 'completed'):
                Path(last['new_'+event]).write_text(json.dumps({'roles': layers[-1], 'event': event, 'time': 2000.0}), encoding='utf-8')
        Path(cfg['intent']).write_text(json.dumps(intent), encoding='utf-8')
        with pytest.raises((ValueError, json.JSONDecodeError)):
            renewal.closed_activation_prefix(cfg, layers, stack)


def mixed_mount_fixture(tmp_path):
    old, new = tmp_path / 'old', tmp_path / 'new'
    old_m, new_m = model(old), model(new)
    shared = sorted(RENEWED_TOKEN_FILES)[0]
    for m in (old_m, new_m):
        m['services']['postgres']['secrets'] = [{'source': shared, 'target': '/run/secrets/'+shared}]
    services = {row['Service'] for row in states(old_m)}
    bindings = {role: (new, new_m) if role == 'postgres' else (old, old_m) for role in services}
    items = []
    for role in services:
        root, m = bindings[role]
        items.append({'Config': {'Labels': {'com.docker.compose.project': PROJECT, 'com.docker.compose.service': role}},
                      'Mounts': [{'Source': str(root / ref['source']), 'Destination': ref['target'], 'Type': 'bind', 'RW': False}
                                 for ref in m['services'][role].get('secrets', [])]})
    return old, new, old_m, new_m, services, bindings, items


def test_mixed_prefix_checks_real_bindings_without_dropping_global_token_closure(tmp_path):
    old, _new, old_m, _new_m, services, bindings, items = mixed_mount_fixture(tmp_path)
    assert checked_secret_mounts(items, PROJECT, old, services, old_m, generation_bindings=bindings) == len(RENEWED_TOKEN_FILES)+2


@pytest.mark.parametrize('bad', ['wrong-root', 'wrong-model', 'missing-role', 'extra-role', 'outside-parent',
                               'list-binding', 'writable', 'extra-secret', 'missing-secret', 'missing-global-token'])
def test_mixed_prefix_never_weakens_actual_mount_or_token_scope(tmp_path, bad):
    old, new, old_m, new_m, services, bindings, items = mixed_mount_fixture(tmp_path)
    pg = next(item for item in items if item['Config']['Labels']['com.docker.compose.service'] == 'postgres')
    gateway = next(item for item in items if item['Config']['Labels']['com.docker.compose.service'] == 'gateway')
    if bad == 'wrong-root':pg['Mounts'][0]['Source'] = str(old / Path(pg['Mounts'][0]['Source']).name)
    elif bad == 'wrong-model':bindings['postgres'] = (new, old_m)
    elif bad == 'missing-role':bindings.pop('postgres')
    elif bad == 'extra-role':bindings['unknown'] = (old, old_m)
    elif bad == 'outside-parent':bindings['postgres'] = (tmp_path / 'elsewhere' / 'new', new_m)
    elif bad == 'list-binding':bindings['postgres'] = [new, new_m]
    elif bad == 'writable':pg['Mounts'][0]['RW'] = True
    elif bad == 'extra-secret':
        pg['Mounts'].append({'Source': str(new / 'unknown'), 'Destination': '/run/secrets/unknown', 'Type': 'bind', 'RW': False})
    elif bad == 'missing-secret':pg['Mounts'] = []
    elif bad == 'missing-global-token':
        missing = sorted(RENEWED_TOKEN_FILES)[-1]
        for m in (old_m, new_m):
            m['services']['gateway']['secrets'] = [ref for ref in m['services']['gateway']['secrets'] if ref['source'] != missing]
        gateway['Mounts'] = [mount for mount in gateway['Mounts'] if mount['Destination'] != '/run/secrets/'+missing]
    with pytest.raises(RuntimeError):
        checked_secret_mounts(items, PROJECT, old, services, old_m, generation_bindings=bindings)


@pytest.mark.skipif(os.name != 'nt', reason='Real NTFS output and actual remaining-layer dispatcher')
def test_recreation_resumes_only_remaining_layers_with_original_indices(monkeypatch):
    import subprocess
    with private_fixture() as (root, log):
        log.write_bytes(b'')
        m = model(root);services = {row['Service'] for row in states(m)}
        m['services']['db-migrate']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
        m['services']['gateway']['depends_on'] = {'db-migrate': {'condition': 'service_completed_successfully'}}
        calls, events = [], []
        def run(args, **_):
            calls.append(args[args.index('--force-recreate')+1:])
            return subprocess.CompletedProcess(args, 0, b'PUBLIC_REMAINING_LAYER', b'')
        monkeypatch.setattr(renewal, 'run_owned_mutation', run)
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: states(m))
        renewal.recreate(None, ['SYNTHETIC_COMPOSE'], {'postgres', 'db-migrate', 'gateway'}, services, m, log,
                         progress=lambda event, index, layer: events.append((event, index, layer)), start_at=2)
        assert calls == [['gateway']]
        assert events == [('started', 2, ['gateway']), ('completed', 2, ['gateway'])]


@pytest.mark.skipif(os.name != 'nt', reason='Real private NTFS output')
@pytest.mark.parametrize('start,record', [(-1, True), (3, True), (True, True), (1, False)])
def test_invalid_skip_or_missing_boundary_recorder_never_invokes_compose(monkeypatch, start, record):
    with private_fixture() as (root, log):
        log.write_bytes(b'');m = model(root);services = {row['Service'] for row in states(m)}
        m['services']['db-migrate']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
        m['services']['gateway']['depends_on'] = {'db-migrate': {'condition': 'service_completed_successfully'}}
        monkeypatch.setattr(renewal, 'run_owned_mutation', lambda *_a, **_k: pytest.fail('Invalid prefix invoked Compose'))
        with pytest.raises(ValueError):
            renewal.recreate(None, ['SYNTHETIC_COMPOSE'], {'postgres', 'db-migrate', 'gateway'}, services, m, log,
                             progress=(lambda *_: None) if record else None, start_at=start)
        assert log.read_bytes() == b''


@contextmanager
def partial_transaction(monkeypatch):
    import subprocess
    import selfhost_windows_selection as selection
    if os.name != 'nt':pytest.skip('Actual NTFS activation, immutable inputs and resume evidence')
    with private_fixture() as (root, _):
        old, new = root/'old', root/'new';old.mkdir();new.mkdir()
        old_m, new_m = model(old), model(new)
        shared = sorted(RENEWED_TOKEN_FILES)[0]
        data = root/'database-data';data.mkdir()
        for m in (old_m, new_m):
            for role in ('postgres', 'keycloak'):
                m['services'][role]['secrets'] = [{'source': shared, 'target': '/run/secrets/'+shared}]
            m['services']['postgres']['volumes'] = [{'type': 'bind', 'source': str(data), 'target': '/var/lib/postgresql/data'}]
            m['services']['keycloak']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
            m['services']['gateway']['depends_on'] = {'keycloak': {'condition': 'service_healthy'}}
        for name in old_m['secrets']:
            (old/name).write_bytes(b'PUBLIC_OLD')
            (new/name).write_bytes(b'PUBLIC_NEW' if name in RENEWED_TOKEN_FILES else b'PUBLIC_OLD')
        source = root/'compose.json';source.write_text(json.dumps(old_m), encoding='utf-8')
        old_env, new_env = root/'old.env', root/'new.env'
        old_env.write_text('SELFHOST_SECRET_DIR='+str(old)+'\nFIXED=public\n', encoding='utf-8')
        new_env.write_text('SELFHOST_SECRET_DIR='+str(new)+'\nFIXED=public\n', encoding='utf-8')
        output = root/'activation';output.mkdir()
        changed = {'postgres', 'keycloak', 'gateway'}
        cfg = {'schema': renewal.SCHEMA, 'candidate_only': True, 'project': PROJECT,
               'current_secrets': str(old), 'renewed_secrets': str(new),
               'compose_file': str(source), 'compose_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
               'current_env': str(old_env), 'renewed_env': str(new_env),
               'docker_host': 'npipe:////./pipe/dockerDesktopLinuxEngine', 'engine_id': 'PUBLIC_SYNTHETIC_ENGINE',
               'native': {'helper_image': 'synthetic@sha256:'+'1'*64}, 'step_receipts': []}
        identity = lambda role, generation: hashlib.sha256((role+str(generation)).encode()).hexdigest()
        cfg['tls_init_receipt'] = {'id': identity('openbao-tls-init', 'fixed'), 'image': 'SYNTHETIC_IMAGE', 'config_hash': '1'*64}
        for name in ('intent', 'result', 'new_log', 'rollback_log'):
            path = output/name;path.write_bytes(b'');cfg[name] = str(path)
        for index in range(3):
            step = {}
            for name in ('new_started', 'new_completed', 'rollback_started', 'rollback_completed'):
                path = output/f'{index}-{name}';path.write_bytes(b'');step[name] = str(path)
            cfg['step_receipts'].append(step)
        (root/f'.{PROJECT}.renewal.lock').write_bytes(b'')
        active = {row['Service']: old for row in states(old_m)}
        calls, admissions = [], []
        flags = {'interrupt': True, 'fault': None}
        def current_states():
            rows = states(old_m)
            if flags['fault'] == 'tail-failure' and active['gateway'] == new:
                next(row for row in rows if row['Service'] == 'gateway').update(State='exited', ExitCode=1)
            return rows
        class Docker:
            prefix = ['docker', '--host', 'PUBLIC_PIPE']
            def __init__(self, *_):pass
            compose = renewal.Docker.compose
            def json(self, args):return new_m if str(new_env) in args else old_m
            def volumes(self):return {}
            def native_witnesses(self, *_):return {}
            def hashes(self, command):
                return {role: ('2' if str(new_env) in command and role in changed else '1')*64 for role in old_m['services']}
            def containers(self):
                items = []
                for state in current_states():
                    role = state['Service'];generation = active[role]
                    m = new_m if generation == new else old_m
                    mounts = [{'Type': 'bind', 'Source': str(generation/ref['source']), 'Destination': ref['target'], 'RW': False}
                              for ref in m['services'][role].get('secrets', [])]
                    if role == 'postgres':
                        mounts.append({'Type': 'bind', 'Source': str(data/'different') if flags['fault'] == 'data' else str(data),
                                       'Destination': '/var/lib/postgresql/data', 'RW': True})
                    item = {'Id': identity(role, generation if role in changed else 'fixed'), 'Image': 'SYNTHETIC_IMAGE',
                            'State': {'Status': state['State'], 'StartedAt': 'FIXED', 'ExitCode': state['ExitCode']},
                            'RestartCount': 0, 'Mounts': mounts,
                            'Config': {'Labels': {'com.docker.compose.project': PROJECT, 'com.docker.compose.service': role,
                                                 'com.docker.compose.config-hash': ('2' if role in changed and generation == new else '1')*64}}}
                    if flags['fault'] == 'unstarted-id' and role == 'gateway':item['Id'] = 'e'*64
                    if flags['fault'] == 'completed-id' and role == 'postgres':item['Id'] = identity(role, old)
                    if flags['fault'] == 'protected-image' and role == 'openbao':item['Image'] = 'CHANGED_IMAGE'
                    if flags['fault'] == 'binding' and role == 'postgres':item['Mounts'][0]['Source'] = str(old/shared)
                    if flags['fault'] == 'config-hash' and role == 'postgres':item['Config']['Labels']['com.docker.compose.config-hash'] = '9'*64
                    items.append(item)
                return items
        def native(_cfg, project, old_bytes, new_bytes, _prefix):
            assert project == PROJECT and set(old_bytes) == set(new_bytes)
            admissions.append('native')
            if len(calls) == 2:
                for path in [cfg['intent'], cfg['new_log'], cfg['step_receipts'][0]['new_completed']]:
                    with pytest.raises(OSError):Path(path).write_bytes(b'REPLACE_HISTORY')
            if flags['fault'] == 'native':raise ValueError('PUBLIC_NATIVE_REFUSAL')
        @contextmanager
        def admission(config, old_bytes, new_bytes, before, after):
            assert config == cfg and set(old_bytes) == set(new_bytes) and before != after
            admissions.append('journal');yield
        def run(args, **_):
            layer = args[args.index('--force-recreate')+1:]
            generation = new if str(new_env) in args else old
            calls.append(('new' if generation == new else 'old', layer))
            if flags['fault'] == 'uncertain':raise renewal.UncertainComposeMutation('PUBLIC_UNKNOWN_DAEMON_OUTCOME')
            for role in layer:active[role] = generation
            return subprocess.CompletedProcess(args, 0, b'PUBLIC_COMPOSE_LAYER', b'')
        original_check = renewal.ForeignContext.check
        def context_check(self, **kwargs):
            if flags['interrupt'] and len(calls) == 2:
                flags['interrupt'] = False
                raise renewal.UnsafeRenewalContext('PUBLIC_CONTEXT_PAUSE')
            return original_check(self, **kwargs)
        monkeypatch.setattr(renewal, 'Docker', Docker)
        monkeypatch.setattr(renewal, 'native_preflight', native)
        monkeypatch.setattr(selection, 'activation_admission', admission)
        monkeypatch.setattr(renewal, 'run_owned_mutation', run)
        monkeypatch.setattr(renewal.ForeignContext, 'check', context_check)
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: current_states())
        with pytest.raises(RuntimeError, match='requires operator recovery'):
            renewal.activate(cfg)
        assert calls == [('new', ['postgres']), ('new', ['keycloak'])]
        journal = selection.directory(cfg);journal.mkdir()
        yield cfg, calls, flags, journal, admissions


def test_actual_activation_resumption_preserves_evidence_and_never_replays_prefix(monkeypatch):
    with partial_transaction(monkeypatch) as (cfg, calls, _flags, _journal, admissions):
        immutable = {path: Path(path).read_bytes() for path in [cfg['intent'], cfg['new_log'],
                      *[step['new_'+event] for step in cfg['step_receipts'][:2] for event in ('started', 'completed')]]}
        result = renewal.activate(cfg, resume=True)
        assert result['result'] == 'activated' and result['resumed_completed_layers'] == 2
        assert calls == [('new', ['postgres']), ('new', ['keycloak']), ('new', ['gateway'])]
        assert admissions == ['journal', 'native', 'journal', 'native']
        assert all(Path(path).read_bytes() == raw for path, raw in immutable.items())
        assert all(Path(step['new_completed']).read_bytes() for step in cfg['step_receipts'])
        assert all(not Path(step['rollback_started']).read_bytes() for step in cfg['step_receipts'])
        assert len(list(Path(cfg['intent']).parent.glob('resume-*.intent.json'))) == 1
        assert json.loads(Path(cfg['result']).read_bytes())['result'] == 'activated'


@pytest.mark.parametrize('fault', ['unstarted-id', 'completed-id', 'protected-image', 'data', 'binding',
                                 'config-hash', 'native', 'unregistered', 'rollback', 'inflight'])
def test_partial_activation_drift_refuses_before_any_remaining_command(monkeypatch, fault):
    with partial_transaction(monkeypatch) as (cfg, calls, flags, journal, _admissions):
        flags['fault'] = fault
        if fault == 'unregistered':journal.rmdir()
        if fault == 'rollback':Path(cfg['step_receipts'][0]['rollback_started']).write_bytes(b'ROLLBACK')
        if fault == 'inflight':Path(cfg['step_receipts'][2]['new_started']).write_bytes(b'UNKNOWN_COMMAND')
        before = list(calls)
        with pytest.raises((ValueError, RuntimeError)):
            renewal.activate(cfg, resume=True)
        assert calls == before and Path(cfg['result']).read_bytes() == b''


def test_uncertain_tail_preserves_boundary_and_refuses_another_resumption(monkeypatch):
    with partial_transaction(monkeypatch) as (cfg, calls, flags, _journal, _admissions):
        flags['fault'] = 'uncertain'
        with pytest.raises(RuntimeError, match='requires operator recovery'):
            renewal.activate(cfg, resume=True)
        assert calls[-1] == ('new', ['gateway']) and len(calls) == 3
        last = cfg['step_receipts'][2]
        assert Path(last['new_started']).read_bytes() and not Path(last['new_completed']).read_bytes()
        assert not any(phase == 'old' for phase, _layer in calls)
        with pytest.raises((ValueError, RuntimeError)):
            renewal.activate(cfg, resume=True)
        assert len(calls) == 3 and not Path(cfg['result']).read_bytes()


def test_proven_tail_failure_uses_complete_recorded_rollback_without_replaying_new_prefix(monkeypatch):
    with partial_transaction(monkeypatch) as (cfg, calls, flags, _journal, _admissions):
        flags['fault'] = 'tail-failure'
        with pytest.raises(RuntimeError, match='prior generation restored'):
            renewal.activate(cfg, resume=True)
        assert calls == [('new', ['postgres']), ('new', ['keycloak']), ('new', ['gateway']),
                         ('old', ['postgres']), ('old', ['keycloak']), ('old', ['gateway'])]
        assert all(Path(step['rollback_started']).read_bytes() and Path(step['rollback_completed']).read_bytes()
                   for step in cfg['step_receipts'])
        result = json.loads(Path(cfg['result']).read_bytes())
        assert result['result'] == 'rolled_back' and result['resumed_completed_layers'] == 2


@pytest.mark.parametrize('outcome_name', ['activated', 'rolled_back', 'unknown'])
@pytest.mark.parametrize('wait', [False, True])
def test_registered_owner_resolves_only_pending_activation_without_holding_project_lock(monkeypatch, outcome_name, wait):
    import selfhost_windows_selection as selection
    import selfhost_windows_recovery as recovery
    from test_selfhost_windows_selection import fixture
    with fixture(monkeypatch) as (root, phase, transaction, outcome, anchor, _cfg):
        selection.adopt(anchor)
        path, cfg = transaction(2);selection.prepare(path)
        calls = []
        def wait_for_engine(host, engine):
            assert host == cfg['docker_host'] and engine == cfg['engine_id']
            with renewal.hold_private_input(root/f'.{PROJECT}.renewal.lock', exclusive=True):pass
            calls.append('wait')
        def activate(bound, *, resume):
            assert bound == cfg and resume is True
            with renewal.hold_private_input(root/f'.{PROJECT}.renewal.lock', exclusive=True):pass
            with pytest.raises(OSError):path.write_bytes(b'CHANGED_CONFIG')
            calls.append('activate')
            if outcome_name == 'unknown':raise renewal.UncertainComposeMutation('PUBLIC_UNKNOWN')
            phase['active'] = Path(cfg['renewed_secrets' if outcome_name == 'activated' else 'current_secrets'])
            outcome(cfg, outcome_name)
            if outcome_name == 'rolled_back':raise RuntimeError('PUBLIC_CLOSED_ROLLBACK')
            return {'result': 'activated'}
        monkeypatch.setattr(renewal, 'activate', activate)
        monkeypatch.setattr(recovery, 'wait_for_engine', wait_for_engine)
        if outcome_name == 'activated':
            result = selection.resume_activation(anchor, wait_for_engine=wait)
            assert result['result'] == 'resumed-and-selected' and result['sequence'] == 2
            assert selection.status(anchor)['selected']['secrets_dir'] == cfg['renewed_secrets']
        else:
            with pytest.raises(RuntimeError):selection.resume_activation(anchor, wait_for_engine=wait)
            status = selection.status(anchor)
            if outcome_name == 'unknown':assert status['state'] == 'pending-reconciliation'
            else:assert status['state'] == 'selected' and status['selected']['secrets_dir'] == cfg['current_secrets']
        assert calls == (['wait', 'activate'] if wait else ['activate'])


@pytest.mark.parametrize('bad', ['settled', 'config-replaced', 'wrong-operation'])
def test_registered_resumption_refuses_changed_or_inapplicable_pending_records(monkeypatch, bad):
    import selfhost_windows_selection as selection
    from test_selfhost_windows_selection import fixture
    with fixture(monkeypatch) as (_root, _phase, transaction, _outcome, anchor, cfg):
        selection.adopt(anchor)
        if bad != 'settled':
            path, pending = transaction(2);selection.prepare(path)
            if bad == 'config-replaced':path.write_bytes(b'REPLACED_CONFIG')
            else:
                entry = selection.directory(cfg)/'000002.intent.json'
                record = json.loads(entry.read_bytes());record['operation'] = 'adopt'
                entry.write_text(json.dumps(record), encoding='utf-8')
        monkeypatch.setattr(renewal, 'activate', lambda *_a, **_k: pytest.fail('Refused journal invoked activation'))
        with pytest.raises((ValueError, json.JSONDecodeError)):
            selection.resume_activation(anchor)


def test_managed_resume_dispatch_is_explicit_and_never_enters_renewal_or_selected_recovery(monkeypatch, capsys):
    import selfhost_windows_recovery as recovery
    import selfhost_windows_selection as selection
    if os.name != 'nt':pytest.skip('Actual private NTFS managed dispatch')
    with private_fixture() as (root, managed):
        anchor = root/'selector.json';anchor.write_bytes(b'')
        managed.write_text(json.dumps({'schema': 'marty.windows-managed-recovery/v1', 'selection_file': str(anchor)}), encoding='utf-8')
        calls = []
        def resume(path, *, wait_for_engine):
            calls.append((path, wait_for_engine));return {'result': 'resumed-and-selected', 'production_admission': False}
        monkeypatch.setattr(selection, 'resume_activation', resume)
        monkeypatch.setattr(selection, 'renew_once', lambda *_a, **_k: pytest.fail('Resume minted a generation'))
        monkeypatch.setattr(selection, 'selected_inputs', lambda *_a, **_k: pytest.fail('Resume bypassed pending journal'))
        assert recovery.main(['--configuration', str(managed), '--resume-activation', '--wait-for-engine']) == 0
        assert calls == [(anchor, True)]
        assert json.loads(capsys.readouterr().out)['result'] == 'resumed-and-selected'


@pytest.mark.parametrize('extra', [['--check-only'], ['--renew-once', '--logical-project', 'marty-selfhost-synthetic'],
                                 ['--logical-project', 'marty-selfhost-synthetic']])
def test_managed_resume_rejects_mixed_modes_before_any_owner_call(monkeypatch, tmp_path, extra):
    import selfhost_windows_recovery as recovery
    import selfhost_windows_selection as selection
    monkeypatch.setattr(selection, 'resume_activation', lambda *_a, **_k: pytest.fail('Mixed modes reached owner'))
    assert recovery.main(['--configuration', str(tmp_path/'not-read.json'), '--resume-activation', *extra]) == 1
