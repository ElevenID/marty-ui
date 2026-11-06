"""Actual private NTFS ownership with synthetic signed inputs/fake Docker.

No release authenticity or real runtime operation is claimed by this fixture.
The real verifier call and owned-mutation transport are tested separately.
"""
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path[:0] = [str(Path(__file__).resolve().parents[1]/'scripts'), str(Path(__file__).resolve().parent)]
import selfhost_windows_product_deploy as deploy
import selfhost_windows_product_journal as journal
import selfhost_windows_product as product
import selfhost_windows_product_probe as probe
import selfhost_windows_selection as selection
import selfhost_windows_renewal_native as native
from test_windows_product_journal import installed


@contextmanager
def runtime(monkeypatch, fault=None, *, extended=False):
    with installed(monkeypatch) as data:
        current = selection.decode((data['attempt']/'after.json').read_bytes())
        old = selection.decode(Path(data['new_config']['compose_file']).read_bytes())
        admitted = selection.decode((data['attempt']/'inputs/web-composition.json').read_bytes())
        mutable = {'gateway', 'ui'} | ({'db-migrate', 'keycloak', 'openbao', 'openbao-unseal'} if extended else set())
        for role in mutable-product.PROVIDER_ROLES:
            admitted['images'][role] = admitted['images'][role].split('@')[0]+'@sha256:'+'5'*64
        if extended:admitted['openbao_didcomm_image'] = admitted['openbao_didcomm_image'].split('@')[0]+'@sha256:'+'5'*64
        admitted['application']['image']['digest'] = 'sha256:'+'5'*64
        admitted.pop('composition_id')
        admitted['composition_id'] = product.composition.ui.digest(product.composition.ui.canonical(admitted))
        product.composition.validate_record(admitted)
        new = product.product_model(old, admitted)
        foreign = deepcopy(current[0])
        foreign['Id'] = 'b'*64
        foreign['Config']['Labels']['com.docker.compose.project'] = 'marty-production-foreign'
        foreign['Mounts'][0].update(Name='foreign-data', Source='/foreign-data')
        roles = {product.renewal._service(item) for item in current}
        events = [];mutation_layers = []
        schema = selection.decode((data['attempt']/'schema-before.json').read_bytes())
        provider = selection.decode((data['attempt']/'provider-before.json').read_bytes())
        assets = data['root']/'incoming';assets.mkdir()
        for name in journal.ARTIFACTS:
            (assets/name).write_bytes(selection.packed(admitted) if name == 'web-composition.json' else b'PUBLIC_SYNTHETIC_SUBJECT')
        class Docker:
            prefix = ['docker']
            def compose(self, project, env, source):
                assert project == data['config']['project']
                return ['docker', 'compose', '--file', str(source)]
            def containers(self):return deepcopy([*current, foreign])
            def volumes(self):return {}
            def hashes(self, command):
                model = selection.decode(Path(command[-1]).read_bytes())
                return {role: ('6'*64 if model == new and role in mutable else '4'*64) for role in roles}
            def json(self, args):
                if args[:2] == ['image', 'inspect']:
                    events.append('image-inspect')
                    if fault == 'missing-image':raise ValueError('PUBLIC_NO_CACHED_IMAGE')
                    reference = args[-1]
                    return [{'Id': 'sha256:'+('5'*64 if reference.endswith('5'*64) else '2'*64),
                        'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [reference], 'Config': {'Volumes': {}}}]
                assert args[0:2] == ['compose', '--file'] and args[-3:] == ['config', '--format', 'json']
                return selection.decode(Path(args[2]).read_bytes())
        docker = Docker()
        class Context:
            def check(self, **_kwargs):return docker.containers()
        def inspect(cfg, _choice, _values, _stack, *, expected_data):
            selection.require(expected_data == selection.digest(selection.packed(product.renewal.data_mounts(current))))
            model = selection.decode(Path(cfg['compose_file']).read_bytes())
            return {'docker': docker, 'owned': deepcopy(current), 'baseline': docker.containers(),
                'services': roles, 'model': model, 'command': docker.compose(cfg['project'], '', cfg['compose_file']),
                'context': Context()}
        monkeypatch.setattr(selection, '_inspect', inspect)
        @contextmanager
        def verified(path, **kwargs):
            assert path == assets and set(kwargs) == {'gh', 'cosign', 'registry_config'}
            events.append('verified-package')
            if fault == 'signature':raise ValueError('PUBLIC_INVALID_SIGNATURE')
            yield admitted, assets
        monkeypatch.setattr(product.composition, 'verified_package', verified)
        def foreign_check(self, *, before_intent):
            assert self.foreign and foreign['Id'] in self.foreign
            rows = docker.containers();self._candidate(rows, before_intent=before_intent)
            return rows
        monkeypatch.setattr(product.renewal.ForeignContext, '_check', foreign_check)
        def witness(category):
            def snapshot(*_args, **_kwargs):
                assert _args[1] and all(product.renewal._project(item) == data['config']['project'] for item in _args[1])
                events.append(category)
                if mutation_layers and fault == category+'-drift':return {'drift': True}
                return schema if category == 'schema' else provider
            return snapshot
        monkeypatch.setattr(probe, 'schema_snapshot', witness('schema'))
        monkeypatch.setattr(probe, 'provider_snapshot', witness('provider'))
        def reauthenticate(_native, project, prefix, session_dir):
            assert project == data['config']['project'] and prefix == ['docker']
            guard = product.renewal.product_transition_guard(data['config'])
            marker = selection.decode(guard.read_bytes())
            attempt = Path(marker['attempt_dir'])
            assert (attempt/'native-before.started.json').read_bytes()
            assert (attempt/'intent.json').read_bytes() == guard.read_bytes()
            events.append('reauthenticate')
            if fault == 'native':raise ValueError('PUBLIC_NATIVE_REFUSAL')
            return session_dir+'/token'
        monkeypatch.setattr(native, 'reauthenticate', reauthenticate)
        def current_native(_cfg, _choice, _values, _docker, authority):
            assert authority.startswith('/control/recovery-session-') and authority.endswith('/token')
            events.append('native-current')
            if fault == 'native-after' and mutation_layers:raise ValueError('PUBLIC_POST_NATIVE_REFUSAL')
        monkeypatch.setattr(selection, '_native_current', current_native)
        def recreate(_docker, command, changing, services, model, log, progress):
            assert _docker is docker and changing == mutable and services == roles and model == new
            assert all(role not in changing for role in product.renewal.INITIALIZERS | product.HISTORICAL_ROLES)
            events.append('compose')
            layers = product.renewal.dependency_layers(model, services, changing)
            for index, layer in enumerate(layers):
                progress('started', index, layer)
                mutation_layers.append(list(layer))
                if fault == 'uncertain':raise product.renewal.UncertainComposeMutation('PUBLIC_UNKNOWN_OUTCOME')
                for item in current:
                    role = product.renewal._service(item)
                    if role not in layer:continue
                    item['Id'] = 'e'+item['Id'][1:]
                    item['Image'] = 'sha256:'+'5'*64
                    item['Config']['Image'] = new['services'][role]['image']
                    item['Config']['Labels']['com.docker.compose.config-hash'] = '6'*64
                if fault == 'context-drift':current[0]['Mounts'][0]['Source'] = '/unqualified-data'
                data['phase']['data'] = selection.digest(selection.packed(product.renewal.data_mounts(current)))
                progress('completed', index, layer)
            product.renewal.write_empty_private_file(log, 'PUBLIC_SYNTHETIC_LOG')
        monkeypatch.setattr(product.renewal, 'recreate', recreate)
        monkeypatch.setattr(product.renewal, 'statuses', lambda *_args, **_kwargs: [])
        monkeypatch.setattr(product.renewal, 'windows_healthy', lambda *_args, **_kwargs: fault != 'unhealthy')
        data.update(assets=assets, events=events, mutation_layers=mutation_layers, docker=docker, mutable=mutable)
        yield data


def transition(lease, data):
    return lease.transition_product(data['assets'], gh=Path('synthetic-gh'), cosign=Path('synthetic-cosign'),
                                    registry_config=Path('synthetic-registry'))


@pytest.mark.parametrize('extended', [False, True])
def test_forward_executor_uses_verifier_and_fresh_authority_before_one_owned_transition(monkeypatch, extended):
    with runtime(monkeypatch, extended=extended) as data:
        before = selection.status(data['path'])
        with selection.selected_inputs(data['path']) as lease:
            result = transition(lease, data)
            assert result['credential_rotation'] is False
            assert product.renewal.product_transition_guard(data['config']).exists()
            for callback in (lease.check_current, lease.check_configuration, lease.continue_journal):
                with pytest.raises(ValueError):callback()
            with pytest.raises(ValueError):lease.recover_existing(data['root']/'forbidden')
            with pytest.raises(ValueError):lease.stage_renewal(data['root']/'forbidden', 'marty-production-forbidden')
            with pytest.raises(ValueError):lease.repair_model(data['root']/'forbidden', data['root']/'forbidden')
            with pytest.raises(ValueError):transition(lease, data)
        after = selection.status(data['path'])
        assert after['generation_sequence'] == before['generation_sequence'] == 1
        assert after['selected'] == before['selected']
        assert not product.renewal.product_transition_guard(data['config']).exists()
        events = data['events']
        assert events.index('verified-package') < events.index('reauthenticate') < events.index('compose')
        assert events.count('compose') == 1 and events.count('native-current') == 2
        assert {role for layer in data['mutation_layers'] for role in layer} == data['mutable']


@pytest.mark.parametrize('fault', ['signature', 'missing-image', 'native', 'native-after', 'uncertain', 'context-drift', 'schema-drift', 'provider-drift', 'unhealthy'])
def test_refused_or_uncertain_forward_execution_never_rolls_back_or_replays(monkeypatch, fault):
    with runtime(monkeypatch, fault) as data:
        before = selection.status(data['path'])
        with pytest.raises((ValueError, product.renewal.UncertainComposeMutation)):
            with selection.selected_inputs(data['path']) as lease:transition(lease, data)
        assert data['events'].count('compose') <= 1
        guard = product.renewal.product_transition_guard(data['config'])
        if fault in {'signature', 'missing-image'}:
            assert not guard.exists() and 'reauthenticate' not in data['events']
            assert selection.status(data['path']) == before
        else:
            assert guard.exists()
            with pytest.raises(ValueError):selection.status(data['path'])
            marker = selection.decode(guard.read_bytes())
            assert not (Path(marker['source_dir'])/journal.DECISION).exists()
            assert not (Path(marker['attempt_dir'])/'result.json').read_bytes()


@pytest.mark.parametrize('fault', [None, 'docker-hub-alias', 'platform', 'reference', 'new-volume', 'database-format'])
def test_cached_metadata_cannot_admit_unqualified_platform_storage_or_database_format(tmp_path, fault):
    from test_windows_product_transition import runtime_candidate
    owned, _after, old, new, _admitted, _ids = runtime_candidate(tmp_path)
    new['services']['postgres']['image'] = old['services']['postgres']['image']
    if fault == 'docker-hub-alias':
        old['services']['postgres']['image'] = new['services']['postgres']['image'] = 'docker.io/library/postgres@sha256:'+'1'*64
    if fault == 'database-format':new['services']['postgres']['image'] = 'example.invalid/pg@sha256:'+'5'*64
    class Docker:
        def json(self, args):
            assert args[:2] == ['image', 'inspect']
            reference = args[-1]
            return [{'Id': 'sha256:'+'1'*64, 'Os': 'linux',
                'Architecture': 'arm64' if fault == 'platform' else 'amd64',
                'RepoDigests': [] if fault == 'reference' else [reference.removeprefix('docker.io/library/')],
                'Config': {'Volumes': {'/unexpected': {}} if fault == 'new-volume' else {}}}]
    if fault in {None, 'docker-hub-alias'}:
        ids = deploy.qualified_images(Docker(), old, new, owned)
        assert set(ids) == {product.renewal._service(item) for item in owned}-product.HISTORICAL_ROLES
    else:
        with pytest.raises(ValueError):deploy.qualified_images(Docker(), old, new, owned)


def test_caller_failure_keeps_guard_then_explicit_reconciliation_never_replays(monkeypatch):
    with runtime(monkeypatch) as data:
        with pytest.raises(RuntimeError, match='PUBLIC_CALLER_FAILURE'):
            with selection.selected_inputs(data['path']) as lease:
                transition(lease, data)
                raise RuntimeError('PUBLIC_CALLER_FAILURE')
        guard = product.renewal.product_transition_guard(data['config'])
        assert guard.exists()
        counts = {name: data['events'].count(name) for name in ('verified-package', 'compose', 'reauthenticate')}
        result = deploy.reconcile_once(data['path'], authority_file='/control/recovery-session-'+'1'*32+'/token')
        assert result['result'] == 'product-selected' and result['credential_rotation'] is False
        assert not guard.exists()
        assert counts == {name: data['events'].count(name) for name in counts}


def test_incomplete_execution_reconciliation_does_not_call_native_or_compose_again(monkeypatch):
    with runtime(monkeypatch, 'uncertain') as data:
        with pytest.raises(product.renewal.UncertainComposeMutation):
            with selection.selected_inputs(data['path']) as lease:transition(lease, data)
        events = list(data['events'])
        with pytest.raises(ValueError):
            deploy.reconcile_once(data['path'], authority_file='/control/recovery-session-'+'1'*32+'/token')
        assert data['events'] == events
        assert product.renewal.product_transition_guard(data['config']).exists()


@pytest.mark.parametrize('arguments', [[], ['--config', 'PRIVATE_SENTINEL', '--unknown=PRIVATE_SENTINEL'],
                                    ['--config', 'PRIVATE_SENTINEL', '--reconcile']])
def test_cli_refusal_never_echoes_private_argument_values(arguments, capsys):
    with pytest.raises(SystemExit) as refused:deploy.main(arguments)
    captured = capsys.readouterr()
    assert 'PRIVATE_SENTINEL' not in str(refused.value)+captured.out+captured.err
    assert not captured.out and not captured.err
