"""Model refusal cases and real NTFS transaction/rollback boundaries."""
from copy import deepcopy
import json
import os
from pathlib import Path, PureWindowsPath
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import selfhost_windows_renewal as renewal
from activate_selfhost_renewed_secrets import RENEWED_TOKEN_FILES


PROJECT = 'marty-production-synthetic'


def model(root):
    names = sorted(RENEWED_TOKEN_FILES | {'smtp_password'})
    services = {name: {'healthcheck': {'test': ['CMD', 'true']}}
                for name in ['keycloak', 'gateway', 'signing-keys', 'postgres', 'openbao']}
    services['gateway']['secrets'] = [{'source': name, 'target': '/run/secrets/' + name} for name in names]
    services.update({'openbao-unseal': {}, 'openbao-tls-init': {},
                     'db-migrate': {'environment': {'MARTY_KMS_BOOTSTRAP_ENABLED': 'false'}},
                     'kms-initialize': {'profiles': ['kms-init']},
                     'openbao-bootstrap': {'profiles': ['kms-init']}})
    for spec in services.values():
        spec['image'] = 'example.invalid/synthetic@sha256:' + '1' * 64
    return {'services': services, 'secrets': {name: {'file': str(root / name)} for name in names}}


def states(m):
    rows = []
    for name, spec in m['services'].items():
        if name in renewal.INITIALIZERS:
            continue
        completed = name in {'openbao-tls-init', 'db-migrate'}
        rows.append({'Service': name, 'State': 'exited' if completed else 'running',
                     'ExitCode': 0, 'Health': 'healthy' if spec.get('healthcheck') else ''})
    return rows


def test_managed_bao_closure_keeps_initializers_absent_and_recreates_only_secret_roles(tmp_path):
    m = model(tmp_path);rows = states(m);roles = {x['Service'] for x in rows}
    assert renewal.owned_roles(m, roles) == {'gateway'}
    assert renewal.windows_healthy(rows, roles, m)
    for role in renewal.INITIALIZERS:
        with pytest.raises(ValueError):
            renewal.owned_roles(m, roles | {role})
    for role in renewal.BAO_ROLES:
        with pytest.raises(ValueError):
            renewal.owned_roles(m, roles - {role})
    m['services']['openbao']['secrets'] = ['smtp_password']
    with pytest.raises(ValueError):
        renewal.owned_roles(m, roles)


@pytest.mark.parametrize('mutation', ['bootstrap-profile', 'bootstrap-db', 'missing-service', 'tls-running', 'tls-failed'])
def test_model_and_health_refuse_unsafe_or_incomplete_closure(tmp_path, mutation):
    m = model(tmp_path);rows = states(m);roles = {x['Service'] for x in rows}
    if mutation == 'bootstrap-profile':
        m['services']['openbao-bootstrap']['profiles'] = []
    elif mutation == 'bootstrap-db':
        m['services']['db-migrate']['environment']['MARTY_KMS_BOOTSTRAP_ENABLED'] = 'true'
    elif mutation == 'missing-service':
        m['services']['required-role'] = {}
    else:
        row = next(x for x in rows if x['Service'] == 'openbao-tls-init')
        row.update(State='running' if mutation == 'tls-running' else 'exited', ExitCode=1)
        assert not renewal.windows_healthy(rows, roles, m)
        return
    with pytest.raises(ValueError):
        renewal.owned_roles(m, roles)


def test_models_change_only_complete_generation_bindings(tmp_path):
    old_root, new_root = tmp_path / 'old', tmp_path / 'new'
    old, new = model(old_root), model(new_root);names = list(old['secrets'])
    renewal.checked_models(old, new, old_root, new_root, names)
    for mutate in [lambda m: m['secrets'].pop(names[0]),
                   lambda m: m['secrets'][names[0]].update(file=str(tmp_path / 'wrong')),
                   lambda m: m['services']['gateway'].update(image='different')]:
        broken = deepcopy(new);mutate(broken)
        with pytest.raises(ValueError):
            renewal.checked_models(old, broken, old_root, new_root, names)


@pytest.mark.parametrize('change', ['ingress', 'public-port', 'host-network', 'mutable-image', 'build'])
def test_candidate_boundary_refuses_ingress_public_ports_and_mutable_images(tmp_path, change):
    m = model(tmp_path);roles = {x['Service'] for x in states(m)}
    if change == 'ingress':
        m['services']['cloudflared'] = deepcopy(m['services']['keycloak']);roles.add('cloudflared')
    elif change == 'public-port': m['services']['gateway']['ports'] = [{'published': '8080', 'target': 8080}]
    elif change == 'host-network': m['services']['gateway']['network_mode'] = 'host'
    elif change == 'mutable-image': m['services']['gateway']['image'] = 'example.invalid/synthetic:latest'
    else: m['services']['gateway']['build'] = '.'
    with pytest.raises(ValueError): renewal.owned_roles(m, roles)


def test_candidate_storage_cannot_overlap_foreign_consumers_or_aliases(monkeypatch):
    def identity(path):
        p = PureWindowsPath(str(path))
        ancestors = {str(PureWindowsPath(*p.parts[:i])).lower() for i in range(1, len(p.parts) + 1)}
        return p, str(p).lower(), ancestors
    monkeypatch.setattr(renewal, 'windows_identity', identity)
    def item(project, source, rw=True):
        return {'Config': {'Labels': {'com.docker.compose.project': project}},
                'Mounts': [{'Type': 'bind', 'Source': source, 'RW': rw}]}
    selected = item(PROJECT, 'C:/Marty/fresh/database')
    renewal.disjoint_storage([selected, item('foreign', 'C:/Other/data')], PROJECT, {})
    for path in ['c:/marty/fresh/database', 'C:/Marty/fresh', 'C:/Marty/fresh/database/child',
                 '/run/desktop/mnt/host/c/Marty/fresh/database', '/host_mnt/c/Marty/fresh',
                 '/mnt/c/Marty/fresh/database/child']:
        with pytest.raises(ValueError, match='overlaps'):
            renewal.disjoint_storage([selected, item('foreign', path, False)], PROJECT, {})


def test_bind_and_named_volume_root_share_identity_and_unknown_subpaths_refuse():
    root = '/var/lib/docker/volumes/synthetic/_data'
    volumes = {'synthetic': {'Name': 'synthetic', 'Driver': 'local', 'Options': None, 'Mountpoint': root}}
    def item(project, mount):
        return {'Config': {'Labels': {'com.docker.compose.project': project}}, 'Mounts': [mount]}
    owned = item(PROJECT, {'Type': 'volume', 'Name': 'synthetic', 'Source': root, 'RW': True})
    for source in [root, root + '/opaque-subpath', '/unknown/native/path']:
        foreign = item('foreign', {'Type': 'bind', 'Source': source, 'RW': False})
        with pytest.raises(ValueError): renewal.disjoint_storage([owned, foreign], PROJECT, volumes)
    volumes['synthetic']['Options'] = {'type': 'none', 'device': 'C:/alias', 'o': 'bind'}
    with pytest.raises(ValueError): renewal.disjoint_storage([owned], PROJECT, volumes)


def test_legacy_volume_name_source_uses_inspected_local_identity():
    name = 'synthetic';root = '/var/lib/docker/volumes/synthetic/_data'
    volumes = {name: {'Name': name, 'Driver': 'local', 'Options': None, 'Mountpoint': root}}
    assert renewal.storage_identity({'Type': 'volume', 'Source': name}, volumes) == ('volume', name)


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows path flavor')
def test_secret_mount_comparison_accepts_only_exact_windows_path_spellings():
    from test_selfhost_windows_inputs import private_fixture
    with private_fixture() as (_, path):
        expected = str(path);suffix = path.as_posix()[3:]
        for actual in [path.as_posix(), path.as_posix().replace('C:', 'c:'),
                       '/run/desktop/mnt/host/c/'+suffix, '/host_mnt/c/'+suffix]:
            assert renewal.windows_mount_path_equal(actual, expected)
        for actual in [str(path.with_name('other')), 'C:/Marty/private/generation/../other/token',
                       '/var/lib/docker/volumes/opaque/_data/token', 'relative/token', None]:
            assert not renewal.windows_mount_path_equal(actual, expected)


def kernel_fixture():
    volumes = {name: {'Name': name, 'Driver': 'local', 'Options': None,
                      'Mountpoint': '/var/lib/docker/volumes/'+name+'/_data'} for name in ['native', 'anchor']}
    source = volumes['native']['Mountpoint'] + '/sub'
    item = {'Mounts': [{'Type': 'bind', 'Source': source, 'Destination': '/state'},
                       {'Type': 'volume', 'Name': 'anchor', 'Source': 'anchor', 'Destination': '/anchor'}]}
    rows = [{'id': '2', 'parent': '1', 'target': '/state', 'root': '/data/docker/volumes/native/_data/sub', 'device': '8:48', 'fstype': 'ext4'},
            {'id': '3', 'parent': '1', 'target': '/anchor', 'root': '/data/docker/volumes/anchor/_data', 'device': '8:48', 'fstype': 'ext4'},
            {'id': '1', 'parent': '0', 'target': '/', 'root': '/', 'device': '0:1', 'fstype': 'overlay'}]
    return volumes, source, item, rows


def test_native_bind_kernel_witness_requires_ordinary_volume_device_anchor():
    volumes, source, item, rows = kernel_fixture()
    assert renewal.volume_witnesses(item, rows, volumes)[source]['volume'] == 'native'
    for change in ['device', 'filesystem', 'root', 'prefix', 'duplicate', 'missing-anchor']:
        bad = deepcopy(rows)
        if change == 'device': bad[0]['device'] = '8:49'
        elif change == 'filesystem': bad[0]['fstype'] = '9p'
        elif change == 'root': bad[0]['root'] = '/data/docker/volumes/other/_data/sub'
        elif change == 'prefix': bad[0]['root'] = '/untrusted/volumes/native/_data/sub'
        elif change == 'duplicate': bad.append(deepcopy(bad[0]))
        else: bad.pop(1)
        with pytest.raises(ValueError): renewal.volume_witnesses(item, bad, volumes)
    assert renewal.mount_path('/data/with\\040space') == '/data/with space'
    for path in ['/data/../alias', '/data/./alias', '/data\\057alias']:
        with pytest.raises(ValueError): renewal.mount_path(path)


def test_hidden_ancestor_overmount_and_missing_or_cyclic_parents_refuse():
    volumes, _, item, rows = kernel_fixture()
    item['Mounts'][0]['Destination'] = '/parent/state';rows[0]['target'] = '/parent/state'
    over = {'id': '4', 'parent': '1', 'target': '/parent', 'root': '/', 'device': '0:2', 'fstype': 'tmpfs'}
    with pytest.raises(ValueError, match='hidden'):
        renewal.volume_witnesses(item, rows + [over], volumes)
    rows[0]['parent'] = '4'
    assert renewal.volume_witnesses(item, rows + [over], volumes)
    rows[0]['parent'] = '999'
    with pytest.raises(ValueError): renewal.volume_witnesses(item, rows + [over], volumes)
    rows[0]['parent'] = '2'
    with pytest.raises(ValueError): renewal.volume_witnesses(item, rows + [over], volumes)


@pytest.mark.parametrize('mode,pid', [('host', 123), ('container:other', 123), ('', 0)])
def test_shared_or_missing_pid_witness_refuses_before_helper_execution(monkeypatch, mode, pid):
    volumes, _, item, _ = kernel_fixture()
    item.update(Id='1'*64, Config={'Labels': {'com.docker.compose.project': 'foreign'}},
                HostConfig={'PidMode': mode}, State={'Status': 'running', 'Pid': pid})
    docker = object.__new__(renewal.Docker);docker.prefix = ['SYNTHETIC_DOCKER']
    def forbidden(*_a, **_k): raise AssertionError('helper launched before PID namespace refusal')
    monkeypatch.setattr(renewal.subprocess, 'run', forbidden)
    with pytest.raises(ValueError, match='private PID namespace'):
        docker.native_witnesses([item], PROJECT, volumes, 'synthetic@sha256:'+'1'*64)


def test_historical_native_bind_inference_requires_exact_project_source_and_zero_exit():
    volumes, source, item, rows = kernel_fixture()
    evidence = renewal.volume_witnesses(item, rows, volumes)[source]
    evidence['live_ids'] = {'live'}
    witnesses = {('foreign', source): evidence}
    foreign = {'Id': 'historical', 'Config': {'Labels': {'com.docker.compose.project': 'foreign'}},
               'State': {'Status': 'exited', 'ExitCode': 0}, 'Mounts': [item['Mounts'][0]]}
    renewal.disjoint_storage([foreign], PROJECT, volumes, witnesses)
    for change in ['project', 'source', 'failed', 'no-live']:
        bad = deepcopy(foreign);proofs = deepcopy(witnesses)
        if change == 'project': bad['Config']['Labels']['com.docker.compose.project'] = 'unrelated'
        elif change == 'source': bad['Mounts'][0]['Source'] += '/other'
        elif change == 'failed': bad['State']['ExitCode'] = 1
        else: proofs[('foreign', source)]['live_ids'] = set()
        with pytest.raises(ValueError): renewal.disjoint_storage([bad], PROJECT, volumes, proofs)


def test_large_docker_inventories_are_batched_below_windows_command_limit(monkeypatch):
    import subprocess
    names = [f'{i:064x}' for i in range(1200)]
    docker = object.__new__(renewal.Docker);docker.prefix = ['SYNTHETIC_DOCKER']
    monkeypatch.setattr(renewal.subprocess, 'run', lambda *_a, **_k:
                        subprocess.CompletedProcess([], 0, ('\n'.join(names)+'\n').encode(), b''))
    batches = []
    def inspect(args):
        values = args[2:] if args[:2] == ['volume', 'inspect'] else args[1:]
        assert 0 < len(values) <= 64
        batches.append(values)
        return [{'Name': name, 'Id': name} for name in values]
    monkeypatch.setattr(docker, 'json', inspect)
    assert len(docker.volumes()) == 1200
    assert len(docker.containers()) == 1200
    assert len(batches) == 38


@pytest.mark.parametrize('raw', [b'\xff' * 60000, b'\0' * 60000, ('\u03bb' * 60000).encode()],
                         ids=['invalid-utf8', 'nul-bytes', 'multibyte-utf8'])
def test_diagnostics_remain_valid_bounded_utf8_after_replacement(raw):
    value = renewal.bounded_diagnostic(raw)
    assert len(value.encode('utf-8')) <= 65536 and '\0' not in value


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows metadata aliases')
def test_junction_alias_to_candidate_storage_refuses_even_for_read_only_consumer():
    from test_selfhost_windows_inputs import private_fixture, powershell
    with private_fixture() as (root, _):
        data = root / 'data';data.mkdir();alias = root / 'alias'
        powershell("New-Item -ItemType Junction -Path '"+str(alias).replace("'", "''")+
                   "' -Target '"+str(data).replace("'", "''")+"' | Out-Null")
        def item(project, source, rw):
            return {'Config': {'Labels': {'com.docker.compose.project': project}},
                    'Mounts': [{'Type': 'bind', 'Source': str(source), 'RW': rw}]}
        try:
            with pytest.raises(ValueError, match='overlaps'):
                renewal.disjoint_storage([item(PROJECT, data, True), item('foreign', alias, False)], PROJECT, {})
        finally:
            alias.rmdir()


@pytest.mark.skipif(os.name != 'nt', reason='Actual bounded Windows log writer')
def test_real_recreate_writes_bounded_malformed_diagnostics(monkeypatch):
    from test_selfhost_windows_inputs import private_fixture
    import subprocess
    with private_fixture() as (root, path):
        path.write_bytes(b'');m = model(root);rows = states(m);services = {x['Service'] for x in rows}
        monkeypatch.setattr(renewal.subprocess, 'run', lambda *_a, **_k:
                            subprocess.CompletedProcess([], 0, b'\xff' * 60000, b''))
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: rows)
        renewal.recreate(None, ['OWNED_SYNTHETIC_COMPOSE'], {'gateway'}, services, m, path)
        assert 0 < len(path.read_bytes()) <= 65536


@pytest.mark.skipif(os.name != 'nt', reason='Real NTFS Compose log boundary')
def test_recreate_polls_starting_roles_without_rerunning_completed_jobs(monkeypatch):
    from test_selfhost_windows_inputs import private_fixture
    import subprocess
    with private_fixture() as (root, path):
        path.write_bytes(b'');m = model(root);ready = states(m);services = {x['Service'] for x in ready}
        starting = deepcopy(ready);next(x for x in starting if x['Service'] == 'gateway')['Health'] = 'starting'
        sequence = iter([starting, starting, ready]);calls = []
        def up(args, **_):
            calls.append(args);return subprocess.CompletedProcess(args, 0, b'PUBLIC_SYNTHETIC_LOG', b'')
        monkeypatch.setattr(renewal.subprocess, 'run', up)
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: next(sequence))
        monkeypatch.setattr(renewal.time, 'sleep', lambda _: None)
        renewal.recreate(None, ['SYNTHETIC_COMPOSE'], {'gateway'}, services, m, path)
        assert len(calls) == 1 and '--no-deps' in calls[0] and '--pull' in calls[0]


@pytest.mark.skipif(os.name != 'nt', reason='Real NTFS Compose log boundary')
def test_partial_creation_does_not_restart_a_successful_completed_job(monkeypatch):
    from test_selfhost_windows_inputs import private_fixture
    import subprocess
    with private_fixture() as (root, path):
        path.write_bytes(b'');m = model(root);ready = states(m);services = {x['Service'] for x in ready}
        partial = [x for x in ready if x['Service'] != 'gateway'];calls = []
        assert next(x for x in partial if x['Service'] == 'db-migrate')['ExitCode'] == 0
        def up(args, **_):
            calls.append(args);return subprocess.CompletedProcess(args, 1, b'PARTIAL_CREATION', b'')
        monkeypatch.setattr(renewal.subprocess, 'run', up)
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: partial)
        with pytest.raises(ValueError, match='incomplete'):
            renewal.recreate(None, ['SYNTHETIC_COMPOSE'], {'gateway', 'db-migrate'}, services, m, path)
        assert len(calls) == 1


@pytest.mark.skipif(os.name != 'nt', reason='Actual held NTFS transaction')
@pytest.mark.parametrize('fail_new', [False, True, 'rollback', 'unselected'])
def test_real_ntfs_transaction_uses_same_held_inputs_and_restores_failed_recreation(monkeypatch, fail_new):
    from test_selfhost_windows_inputs import private_fixture
    import hashlib
    with private_fixture() as (root, _):
        old_root, new_root = root / 'old', root / 'new';old_root.mkdir();new_root.mkdir()
        old_m, new_m = model(old_root), model(new_root)
        for name in old_m['secrets']:
            (old_root / name).write_bytes(b'SYNTHETIC_OLD\r\n')
            (new_root / name).write_bytes(b'SYNTHETIC_NEW\n' if name in RENEWED_TOKEN_FILES else b'SYNTHETIC_OLD\r\n')
        source = root / 'compose.json';source.write_text(json.dumps(old_m), encoding='utf-8')
        old_env, new_env = root / 'old.env', root / 'new.env'
        old_env.write_text(f'SELFHOST_SECRET_DIR={old_root}\nSETTING=fixed\n', encoding='utf-8')
        new_env.write_text(f'SELFHOST_SECRET_DIR={new_root}\nSETTING=fixed\n', encoding='utf-8')
        output = root / 'output';output.mkdir()
        cfg = {'schema': renewal.SCHEMA, 'candidate_only': True, 'project': PROJECT,
               'current_secrets': str(old_root), 'renewed_secrets': str(new_root),
               'compose_file': str(source), 'compose_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
               'current_env': str(old_env), 'renewed_env': str(new_env),
               'docker_host': 'npipe:////./pipe/dockerDesktopLinuxEngine', 'engine_id': 'SYNTHETIC_ENGINE',
               'native': {'helper_image': 'synthetic@sha256:'+'1'*64}, 'tls_init_receipt': {'id': 'openbao-tls-init', 'image': 'SYNTHETIC_IMAGE',
                                                'config_hash': '1' * 64}}
        for name in ['intent', 'result', 'new_log', 'rollback_log']:
            p = output / name;p.write_bytes(b'');cfg[name] = str(p)
        (root / f'.{PROJECT}.renewal.lock').write_bytes(b'')
        phase = {'root': old_root};calls = []
        class FakeDocker:
            prefix = ['docker', '--host', 'SYNTHETIC_PIPE']
            def __init__(self, *_): pass
            compose = renewal.Docker.compose
            def json(self, args):
                return new_m if str(new_env) in args else old_m
            def volumes(self): return {}
            def native_witnesses(self, *_): return {}
            def hashes(self, command):
                return {name: ('2' if str(new_env) in command and spec.get('secrets') else '1') * 64
                        for name, spec in old_m['services'].items()}
            def containers(self):
                rows = []
                for state in states(old_m):
                    name = state['Service'];spec = old_m['services'][name]
                    mounts = [{'Type': 'bind', 'Source': str(phase['root'] / s['source']),
                               'Destination': s['target'], 'RW': False} for s in spec.get('secrets', [])]
                    rows.append({'Id': name + (str(phase['root']) if name == 'gateway' else ''),
                                 'Image': 'SYNTHETIC_IMAGE', 'State': {'Status': state['State'], 'StartedAt':
                                     'EXTERNALLY_CHANGED' if phase.get('unselected_changed') and name == 'openbao' else 'FIXED',
                                     'ExitCode': state['ExitCode']},
                                 'RestartCount': 0, 'Mounts': mounts,
                                 'Config': {'Labels': {'com.docker.compose.project': PROJECT,
                                                       'com.docker.compose.service': name,
                                                       'com.docker.compose.config-hash':
                                                           ('2' if phase['root'] == new_root and name == 'gateway' else '1') * 64}}})
                return rows
        def native(_, project, old_bytes, new_bytes, prefix):
            assert project == PROJECT and old_bytes.keys() == new_bytes.keys()
            for path in [source, old_env, new_env, old_root / 'smtp_password', new_root / 'smtp_password']:
                with pytest.raises(OSError): path.write_bytes(b'CONCURRENT_REPLACEMENT')
            calls.append('native')
        def recreate(_, command, changing, services, m, log):
            assert changing == {'gateway'} and not changing & renewal.BAO_ROLES
            phase['root'] = new_root if str(new_env) in command else old_root
            calls.append('new' if phase['root'] == new_root else 'old')
            renewal.write_empty_private_file(log, 'SYNTHETIC_COMPOSE_LOG\n')
            if fail_new == 'unselected': phase['unselected_changed'] = True
            elif fail_new and (phase['root'] == new_root or fail_new == 'rollback'):
                raise RuntimeError('SYNTHETIC_PARTIAL_FAILURE')
        monkeypatch.setattr(renewal, 'Docker', FakeDocker)
        monkeypatch.setattr(renewal, 'native_preflight', native)
        monkeypatch.setattr(renewal, 'recreate', recreate)
        monkeypatch.setattr(renewal, 'statuses', lambda *_a, **_k: states(old_m))
        if fail_new in {'rollback', 'unselected'}:
            with pytest.raises(RuntimeError, match='requires operator recovery'):
                renewal.activate(cfg)
            assert calls == ['native', 'new', 'old']
            assert Path(cfg['result']).read_bytes() == b''
            assert Path(cfg['intent']).read_bytes()
            (old_root / 'smtp_password').write_bytes(b'AFTER_RECOVERY_REFUSAL')
            return
        if fail_new:
            with pytest.raises(RuntimeError, match='prior generation restored'):
                renewal.activate(cfg)
            assert calls == ['native', 'new', 'old'] and phase['root'] == old_root
        else:
            assert renewal.activate(cfg)['result'] == 'activated'
            assert calls == ['native', 'new'] and phase['root'] == new_root
        result = json.loads(Path(cfg['result']).read_text())
        assert result['result'] == ('rolled_back' if fail_new else 'activated')
        assert result['production_admission'] is False
        assert (output / 'intent').read_bytes()
        # Locks are released but durable one-shot intent prevents a blind retry.
        with pytest.raises(ValueError): renewal.activate(cfg)
        (old_root / 'smtp_password').write_bytes(b'AFTER_RELEASE')
