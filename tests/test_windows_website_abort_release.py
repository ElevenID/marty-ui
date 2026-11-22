"""Terminal website abort release under real private NTFS selection coordination."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_selfhost_windows_selection import fixture
from tests.test_windows_website_plan import planned, rehash
import selfhost_windows_website_abort_release as release


selection = release.selection
renewal = selection.renewal
store = release.store
stage = release.stage
contract = release.contract


@contextmanager
def closed_abort(monkeypatch, planned, *, compensated=False, backout=False, prepared_routes=False):
    with fixture(monkeypatch) as (root, phase, _tx, _outcome, path, config):
        config['tls_init_receipt'] = {'id': '1'*64, 'image': 'sha256:'+'2'*64, 'config_hash': '3'*64}
        path.write_bytes(selection.packed(config))
        project = config['project']
        attempt = root / ('windows-website-' + 'a'*32)
        model = selection.decode(Path(config['compose_file']).read_bytes())
        host, port = 'www.example.test', '29382'
        model['services']['edge'] = {'environment': {'PUBLIC_DOMAIN': host},
            'ports': [{'host_ip': '127.0.0.1', 'target': 80, 'published': port}]}
        engine = object()
        owned = [{'Id': 'e'*64, 'Image': 'sha256:'+'d'*64,
                  'Config': {'Env': ['PUBLIC_DOMAIN='+host], 'Labels': {'com.docker.compose.project': project,
                      'com.docker.compose.service': 'edge'}}, 'Created': 'fixture', 'RestartCount': 0, 'Mounts': [],
                  'State': {'Status': 'running', 'StartedAt': 'fixture', 'ExitCode': 0, 'Pid': 100},
                  'NetworkSettings': {'Ports': {'80/tcp': [{'HostIp':'127.0.0.1', 'HostPort': port}]}}, 'HostConfig': {}}]
        runtime = renewal.context_snapshot(owned)
        data = renewal.data_mounts(owned)
        phase['data'] = contract.digest(data)
        selection.adopt(path)
        plans = []
        calls = []
        behavior = SimpleNamespace(fault=None)
        edge_configuration = {'container_id': owned[0]['Id'], 'routes_sha256': selection.digest(b'')}
        route_body = b'# Qualified inactive fixture route\n'

        def preflight(config, _choice, _values, _record, _assets, *, plan_owner,
                      plan_attempt_directory, guarded_attempt=False, **kwargs):
            if guarded_attempt:
                calls.append('signed-composition')
                assert kwargs['retained_edge_inputs'] == (engine, model, data) and kwargs['include_http']
                return plans[-1], {'http': {'signed': True}, 'routes': {'split': route_body}}
            plan = contract.plan(**planned)
            body = Path(config['compose_file']).read_bytes()
            model_hash = contract.digest(selection.decode(body))
            plan['owner'] = {**plan_owner, 'model_sha256': model_hash}
            plan['states']['combined']['model_sha256'] = model_hash
            plan['states']['combined']['data_sha256'] = phase['data']
            plan['backout']['preserved_selected_sha256'] = plan_owner['selected_sha256']
            plan['attempt_directory'] = str(plan_attempt_directory)
            plan['route_directory'] = str(plan_attempt_directory / 'routes')
            rehash(plan)
            plans.append(plan)
            return plan if kwargs.get('held_plan_only') else {'plan_sha256': plan['plan_sha256']}

        monkeypatch.setattr(release.website, 'inspect_composition', preflight)
        with selection.selected_inputs(path) as lease:
            original_generation = lease.generation_sequence
            initial_plan = lease.check_website_composition(root, plan_attempt_directory=attempt,
                                                          gh=None, cosign=None, registry_config=None)
            initial = lease.begin_website_transition(root, expected_plan_sha256=initial_plan['plan_sha256'],
                plan_attempt_directory=attempt, gh=None, cosign=None, registry_config=None)
        plan = plans[-1]
        _attempt, active, archive = release._paths(config, plan, 'backout' if backout else 'abort')
        original_bytes = active.read_bytes()
        original_identity = release._path_identities(active)
        owner = plan['owner']
        owner_lease = {'guard_sha256': initial['guard_sha256'], 'owner': owner}
        with ExitStack() as held:
            hashes = stage._evidence(attempt / 'stage-before.json', {
                'owner_lease': {**owner_lease, 'dispatch_schema': stage.DISPATCH_SCHEMA},
                'native_custody': {}, 'foreign_storage': {}, 'runtime_before': runtime}, held)
            started = store.append(plan, expected_anchor_sha256=initial['anchor_sha256'], phase=stage.PHASE,
                                   event='started', evidence_sha256=hashes)
            status = started
            evidence = {'owner_lease': owner_lease,
                'native_custody': {'selected_sha256': owner['selected_sha256'], 'native_sha256': owner['native_sha256']},
                'foreign_storage': {}, 'runtime_after': runtime, 'normalized_model': {'sha256': contract.digest(model)},
                'retained_product': {'composition_id': plan['composition_id'], 'data_sha256': phase['data']},
                'mounted_template': plan['edge_template'], 'edge_configuration': edge_configuration, 'public_routes': {},
                'application_handoffs': {}, 'candidate_absence': {'slot': contract.SLOT, 'engine': owner['engine_id'], 'absent': True},
                'selected_credentials': {'selected_sha256': owner['selected_sha256']}}
            if compensated:
                candidate_id = 'a'*64
                intent = {'candidate_id': candidate_id, 'remove_command': ['container','rm',candidate_id]}
                result = {'candidate_id': candidate_id, 'candidate_absent': True, 'completed_cli_job': True, 'remove_returncode': 0}
                for action, value in zip(release.journal.STAGE_ACTION_ORDER, ({}, {}, intent, result), strict=True):
                    status = release.reconcile._record_action(plan, status, action, value, attempt, held)
                evidence['candidate_compensation'] = {'intent': intent, 'result': result}
            if backout:
                import selfhost_windows_website_backout as retirement

                def publish(phase, event, name, value):
                    nonlocal status
                    status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase, event=event,
                        evidence_sha256=stage._evidence(attempt / name, value, held))

                stage_id = 'a'*64
                stage_row = {'project': project, 'service': contract.SLOT, 'image': 'sha256:'+'a'*64,
                             'mounts': [], 'status': 'running'}
                staged = {**runtime, stage_id: stage_row}
                publish('stage-candidate', 'completed', 'stage-after.json', {'runtime_after': staged,
                    'image_metadata': {}, 'candidate_health': {'container_id': stage_id}})
                for phase_name, fields in (('restore-combined', {'mounted_template': plan['edge_template'],
                                                            'edge_configuration': edge_configuration}),
                                      ('verify-combined', {'public_routes': {}, 'application_handoffs': {}})):
                    publish(phase_name, 'started', phase_name+'-before.json', {key: {} for key in release.journal.START_EVIDENCE})
                    publish(phase_name, 'completed', phase_name+'-after.json', {'runtime_after': staged, **fields})
                result = {'candidate_id': stage_id, 'stop_completed': True, 'remove_returncode': 0,
                          'completed_cli_job': True, 'candidate_absent': True}
                qualifications = {'runtime_sha256': contract.digest(runtime), 'edge_sha256': contract.digest(edge_configuration),
                    'public_routes_sha256': '3'*64, 'application_handoffs_sha256': '4'*64,
                    'native_sha256': owner['native_sha256'], 'foreign_storage_sha256': None, 'foreign_storage_changes': 0}
                route_state = 'materialized' if prepared_routes else 'absent'
                if prepared_routes:
                    release.edge._held_routes(Path(plan['route_directory']), route_body, held, create=True)
                retained = {'runtime_after': runtime, 'normalized_model': evidence['normalized_model'],
                            'edge_configuration': edge_configuration, 'retained_route_directory': route_state}
                publish(retirement.PHASE, 'started', retirement.BEFORE, {
                    'owner_lease': owner_lease, 'native_custody': {}, 'foreign_storage': {},
                    'runtime_before': {'containers': staged, 'edge_configuration': edge_configuration,
                        'retained_route_directory': route_state, 'normalized_model': evidence['normalized_model'], 'candidate_retirement': {
                            'candidate_id': stage_id, 'observed_candidate': stage_row, 'remove_command': ['container','rm',stage_id]}}})
                publish(retirement.PHASE, release.journal.RETIRE_RETURNED, retirement.RETURNED, {'candidate_retirement': result})
                publish(retirement.PHASE, 'completed', retirement.AFTER,
                        retirement._completion(plan, retained, result, qualifications))
                terminal, evidence_path = status, attempt / retirement.AFTER
            else:
                observations = {name: contract.digest(value) for name, value in evidence.items()}
                evidence_path = store.abort_observations_path(attempt, observations)
                stage._evidence(evidence_path, evidence, held)
                receipt = {'schema': release.journal.ABORT_SCHEMA, 'plan_sha256': plan['plan_sha256'],
                           'started_record_sha256': started['tail_sha256'], 'owner_binding_sha256': owner['binding_sha256'],
                           'selected_sha256': owner['selected_sha256'], 'state': plan['states']['combined'],
                           'candidate_outcome': 'created-then-compensated' if compensated else 'never-created',
                           'observations_sha256': observations}
                terminal = store.reconciled_abort(plan, expected_anchor_sha256=status['anchor_sha256'], receipt=receipt)

        def inspect(_config, _choice, _values, _held, *, expected_data):
            assert expected_data == phase['data'] and active.exists()
            calls.append('inspect-combined')
            rows = deepcopy(owned)
            if behavior.fault == 'runtime':
                rows[0]['RestartCount'] = 1
            roles = {'edge', contract.SLOT} if behavior.fault == 'candidate' else {'edge'}
            context = SimpleNamespace(proof_sha256=None, proof_count=0, check=lambda **_: rows)
            return {'docker': engine, 'model': model, 'context': context, 'services': roles, 'owned': rows}

        def native(*_):
            calls.append('native')
            if behavior.fault == 'native':
                raise ValueError('synthetic native refusal')

        def ingress(_row, observed_model, http, state):
            calls.append('public')
            assert observed_model == model and http == {'signed': True} and state == 'combined'
            if behavior.fault == 'public':
                raise ValueError('synthetic public refusal')
            if behavior.fault == 'competing':
                renewal.model_repair_guard(config).write_bytes(b'competing synthetic owner')
            return {'fresh': True}, {'application': 'combined'}

        monkeypatch.setattr(selection, '_inspect', inspect)
        monkeypatch.setattr(selection, '_native_current', native)
        monkeypatch.setattr(release.edge, '_probe', lambda *_: {} if behavior.fault == 'edge' else edge_configuration)
        monkeypatch.setattr(release.verify, '_observe', ingress)
        kwargs = {'guard_sha256': initial['guard_sha256'], 'expected_anchor_sha256': terminal['anchor_sha256'],
                  'assets':root, 'gh':None, 'cosign':None, 'registry_config':None}
        yield SimpleNamespace(root=root, path=path, config=config, attempt=attempt, active=active, archive=archive,
            original_bytes=original_bytes, original_identity=original_identity, evidence=evidence_path, plan=plan,
            kwargs=kwargs, calls=calls, behavior=behavior, generation=original_generation)


@pytest.mark.parametrize('compensated',[False, True])
def test_archives_terminal_guard_and_restores_same_owner(monkeypatch, planned, compensated):
    with closed_abort(monkeypatch, planned, compensated=compensated) as run:
        selected_root = selection.directory(run.config)
        before = {path.name: path.read_bytes() for path in selected_root.iterdir()}
        with pytest.raises(ValueError):
            with selection.selected_inputs(run.path):
                pytest.fail('ordinary owner entered before archive')
        original = release._held_private_input

        @contextmanager
        def locked(path, **kwargs):
            if kwargs.get('_rename_to') is not None:
                assert path == run.active and kwargs['_rename_to'] == run.archive
                assert (run.attempt / release.RELEASE).is_file()
                lock = run.root / ('.'+run.config['project']+'.renewal.lock')
                with pytest.raises(ValueError):
                    with renewal.hold_private_input(lock, exclusive=True):
                        pytest.fail('exclusive coordination released before the archive')
            with original(path, **kwargs) as data:
                yield data

        monkeypatch.setattr(release, '_held_private_input', locked)
        result = selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert result['guard_archived'] and result['result'] == 'website-abort-guard-archived'
        assert result['candidate_outcome'] == ('created-then-compensated' if compensated else 'never-created')
        assert not run.active.exists() and run.archive.read_bytes() == run.original_bytes
        assert release._path_identities(run.archive) == run.original_identity
        assert {path.name: path.read_bytes() for path in selected_root.iterdir()} == before
        with selection.selected_inputs(run.path) as lease:
            assert lease.generation_sequence == run.generation and lease.selected_sha256 == run.plan['owner']['selected_sha256']
        assert selection.release_website_abort(run.path, run.plan, **run.kwargs) == result
        assert run.calls == ['inspect-combined', 'signed-composition', 'native', 'public']


@pytest.mark.parametrize('fault',['anchor','guard','evidence','archive','runtime','candidate','native','public','edge','competing'])
def test_rejects_unqualified_release_and_preserves_active_guard(monkeypatch, planned, fault):
    with closed_abort(monkeypatch, planned) as run:
        if fault == 'anchor':
            run.kwargs['expected_anchor_sha256'] = 'b'*64
        if fault == 'guard':
            run.kwargs['guard_sha256'] = 'b'*64
        if fault == 'evidence':
            run.evidence.write_bytes(b'{}')
        if fault == 'archive':
            run.archive.write_bytes(b'foreign archive')
        run.behavior.fault = fault
        with pytest.raises(ValueError):
            selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert run.active.read_bytes() == run.original_bytes
        assert run.archive.exists() == (fault == 'archive')
        if run.archive.exists():
            assert run.archive.read_bytes() == b'foreign archive'


def test_owner_close_failure_leaves_guard_and_retry_requalifies(monkeypatch, planned):
    with closed_abort(monkeypatch, planned) as run:
        saved = renewal.hold_private_input

        @contextmanager
        def close_failure(path, **options):
            with saved(path, **options) as raw:
                yield raw
                if run.behavior.fault and path == Path(run.config['compose_file']):
                    raise ValueError('synthetic closing input refusal')

        monkeypatch.setattr(renewal, 'hold_private_input', close_failure)
        run.behavior.fault = 'closing-check'
        with pytest.raises(ValueError):
            selection.release_website_abort(run.path, run.plan, **run.kwargs)
        receipt = run.attempt / release.RELEASE
        assert receipt.exists() and run.active.exists() and not run.archive.exists()
        retained = receipt.read_bytes()
        run.behavior.fault = None
        result = selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert result['guard_archived'] and receipt.read_bytes() == retained
        assert run.calls.count('public') == 2


def test_readback_after_interruption_following_the_archive(monkeypatch, planned):
    with closed_abort(monkeypatch, planned) as run:
        identities = release._path_identities

        def interrupt(path):
            if path == run.archive and run.behavior.fault:
                raise RuntimeError('synthetic interruption after archive')
            return identities(path)

        monkeypatch.setattr(release, '_path_identities', interrupt)
        run.behavior.fault = 'after-archive'
        with pytest.raises(RuntimeError):
            selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert run.archive.read_bytes() == run.original_bytes and not run.active.exists()
        run.behavior.fault = None
        assert selection.release_website_abort(run.path, run.plan, **run.kwargs)['guard_archived']
        assert run.calls.count('public') == 1
        proof, = run.attempt.glob('abort-release-proof-*.json')
        proof.write_bytes(b'{}')
        with pytest.raises(ValueError):
            selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert run.archive.read_bytes() == run.original_bytes and not run.active.exists()


def test_abort_release_cli_outputs_result_after_private_handles_close(monkeypatch, planned, capsys):
    with closed_abort(monkeypatch, planned) as run:
        plan_file = store.namespace_paths(run.plan)[0] / store.PLAN
        args = ['--release-abort','--selection-file',str(run.path),'--plan-file',str(plan_file),
                '--composition-dir',str(run.root),'--gh',str(run.root/'gh'),'--cosign',str(run.root/'cosign'),
                '--guard-sha256',run.kwargs['guard_sha256'],'--expected-anchor-sha256',run.kwargs['expected_anchor_sha256']]
        run.behavior.fault = 'native'
        assert release.website.main(args) == 2
        captured = capsys.readouterr()
        assert not captured.out and captured.err == release.website.RELEASE_ERROR + '\n'
        run.behavior.fault = None
        assert release.website.main(args) == 0
        captured = capsys.readouterr()
        assert not captured.err and selection.decode(captured.out.encode())['guard_archived']


@pytest.mark.parametrize('drift,prepared_routes', [(False, False), (False, True), (True, False)])
def test_backout_release_reopens_original_generation_with_exact_terminal_records(monkeypatch, planned, drift, prepared_routes):
    with closed_abort(monkeypatch, planned, backout=True, prepared_routes=prepared_routes) as run:
        # An abort release cannot substitute for a completed backout.
        with pytest.raises(ValueError):
            selection.release_website_abort(run.path, run.plan, **run.kwargs)
        assert run.active.exists() and not run.archive.exists()
        if drift:
            run.evidence.write_bytes(b'{}')
            with pytest.raises(ValueError):
                selection.release_website_backout(run.path, run.plan, **run.kwargs)
            assert run.active.read_bytes() == run.original_bytes and not run.archive.exists()
            return
        plan_file = store.namespace_paths(run.plan)[0] / store.PLAN
        result = selection.release_website_backout(run.path, run.plan, **run.kwargs)
        assert result['guard_archived'] and result['result'] == 'website-backout-guard-archived'
        assert result['candidate_outcome'] == 'removed-after-combined-rollback' and contract.sha(result['retirement_sha256'])
        assert not run.active.exists() and run.archive.read_bytes() == run.original_bytes
        assert release._path_identities(run.archive) == run.original_identity
        assert selection.release_website_backout(run.path, run.plan, **run.kwargs) == result
        assert (run.attempt / release.BACKOUT_RELEASE).is_file() and plan_file.is_file()
        assert (Path(run.plan['route_directory']) / 'active.conf').is_file() is prepared_routes
        with selection.selected_inputs(run.path) as lease:
            assert lease.generation_sequence == run.generation
