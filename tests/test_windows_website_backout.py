"""Restore-combined verification through exact candidate retirement on private NTFS."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned, propose
from tests.test_windows_website_store import paths
import selfhost_windows_website_backout as backout


store, stage, contract, renewal, selection = backout.store, backout.stage, backout.contract, backout.renewal, backout.selection


@pytest.fixture
def rollback(paths, planned, monkeypatch):
    plan, records, anchors = paths
    project, attempt = plan['owner']['project'], records.parent
    proposal = propose(planned)
    combined, staged = (proposal['models'][name] for name in ('combined', 'staged'))
    command = ['docker','compose','-f',str(attempt/'source.json'),'-f',str(attempt/'stage.compose.json')]
    hashes = {role: f'{index+1:064x}' for index, role in enumerate(staged['services'])}

    def row(role, data, index):
        state = {'StartedAt': 'fixture', 'ExitCode': 0, 'Status': 'running'}
        if role == 'openbao-tls-init' or role in renewal.COMPLETED_SERVICES:
            state['Status'] = 'exited'
        elif staged['services'][role].get('healthcheck'):
            state['Health'] = {'Status': 'healthy'}
        return {'Id': f'{index+1:064x}', 'Image': data['image'], 'Mounts': deepcopy(data['mounts']),
                'Config': {'Image': staged['services'][role]['image'], 'Labels': {'com.docker.compose.project': project,
                    'com.docker.compose.service': role, 'com.docker.compose.config-hash': hashes[role]}},
                'Name': f'/{project}-{role}-1', 'State': state, 'HostConfig': {}, 'RestartCount': 0,
                'NetworkSettings': {'Networks': {project+'_default': {}}}}

    original = [row(role, data, index) for index, (role, data) in enumerate(proposal['data']['combined'].items())]
    candidate = row(contract.SLOT, proposal['data']['staged'][contract.SLOT], len(original))
    candidate['Config']['Labels'].update({'com.docker.compose.container-number': '1',
        'com.docker.compose.oneoff': 'False', 'com.docker.compose.project.config_files': ','.join((command[3], command[5]))})
    original_candidate = deepcopy(candidate)
    candidate_id = candidate['Id']
    tls = next(item for item in original if renewal._service(item) == 'openbao-tls-init')
    config = {'project': project, 'native': {'helper_image': 'pinned'}, 'tls_init_receipt': {
        'id': tls['Id'], 'image': tls['Image'], 'config_hash': hashes['openbao-tls-init']}}
    record = {'selected': {'secrets_dir': plan['owner']['root']}, 'data_sha256': plan['owner']['data_sha256']}
    control = SimpleNamespace(fault=None, candidate=candidate, calls=[], plan=plan, attempt=attempt, records=records,
                              anchors=anchors, source=combined)
    edge_config = {'container_id': 'fixture-edge', 'routes_sha256': selection.digest(b'')}

    class Engine:
        prefix = ['docker']

        def containers(self):
            rows = original + ([control.candidate] if control.candidate is not None else [])
            return deepcopy(rows)

        def volumes(self):
            return {}

        def native_witnesses(self, *_):
            return {}

    engine = Engine()
    monkeypatch.setattr(renewal, 'disjoint_storage', lambda *_: {})
    monkeypatch.setattr(renewal, 'checked_secret_mounts', lambda *_, **_kw: 1)
    live_context = SimpleNamespace(project=project, docker=engine, layouts={'staged': (command, staged, hashes)},
                               volumes={}, proof_sha256=None, proof_count=0, check=lambda **_: engine.containers())

    def prepare(*_, **options):
        assert options['prior_phase']=='verify-combined' and options['current']==options['target']=='staged'
        assert options['include_http'] and not options['candidate_ready']
        control.calls.append('staged-proof')
        return live_context, proposal, {}, None

    def refresh(_config, _choice, _values, _record, input_plan, retained, _attempt, **options):
        assert input_plan == plan and retained['runtime_after'] == renewal.context_snapshot(original)
        assert retained['normalized_model'] == {'sha256': contract.digest(combined)} and control.candidate is None
        assert options['proposal'] in (None, proposal)
        control.calls.append('combined-proof')
        if control.fault == 'public':
            raise ValueError('synthetic public probe refusal after removal')
        return {'runtime_sha256': contract.digest(retained['runtime_after']), 'edge_sha256': contract.digest(edge_config),
            'public_routes_sha256': 'e'*64, 'application_handoffs_sha256': 'f'*64,
            'native_sha256': plan['owner']['native_sha256'], 'foreign_storage_sha256': None, 'foreign_storage_changes': 0}

    monkeypatch.setattr(backout.edge, '_prepare', prepare)
    monkeypatch.setattr(backout.edge, '_probe', lambda *_: edge_config)
    monkeypatch.setattr(backout.owner_release, '_refresh', refresh)

    def mutate(arguments, *, timeout):
        assert max(records.glob('*.retire-candidate.started.json')).exists()
        assert not list(records.glob('*.retire-candidate.retirement-returned.json'))
        assert timeout == 30 and arguments[-1] == candidate_id
        control.calls.append(arguments[2])
        if control.fault == 'uncertain':
            raise renewal.UncertainComposeMutation('synthetic unknown stop result')
        if arguments[2] == 'stop':
            assert arguments == ['docker','container','stop','--time','10',candidate_id]
            control.candidate['State']['Status'] = 'exited'
        else:
            assert arguments == ['docker','container','rm',candidate_id]
            assert control.candidate['State']['Status'] == 'exited'
            control.candidate = None
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(renewal, 'run_owned_mutation', mutate)
    pin = 'd'*64

    def prepare_history(*, routed=False, prepared_routes='absent'):
        status = store.initialize(plan)
        with ExitStack() as held:
            snapshot = renewal.context_snapshot(original + [original_candidate])
            phases = [('stage-candidate', 'stage-after.json', {'runtime_after': snapshot,
                       'candidate_health': {'container_id': candidate_id}, 'image_metadata': {}})]
            if routed:
                phases.append(('route-website','route-website-after.json', {'runtime_after': snapshot,
                               'mounted_template': plan['edge_template'], 'edge_configuration': edge_config}))
            phases.extend([('restore-combined','restore-combined-after.json', {'runtime_after': snapshot,
                           'mounted_template': plan['edge_template'], 'edge_configuration': edge_config}),
                           ('verify-combined','verify-combined-after.json', {'runtime_after': snapshot,
                            'public_routes': {}, 'application_handoffs': {}})])
            for name, path, fields in phases:
                status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=name,
                    event='started', evidence_sha256={key: 'a'*64 for key in backout.journal.START_EVIDENCE})
                status = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=name,
                    event='completed', evidence_sha256=stage._evidence(attempt/path, fields, held))
            directory = Path(plan['route_directory'])
            if routed or prepared_routes == 'materialized':
                backout.edge._held_routes(directory, proposal['routes']['split'], held, create=True)
            if prepared_routes == 'empty':
                directory.mkdir()
        return status

    def execute(status):
        with ExitStack() as held:
            return backout.run(config, 'new', {}, record, plan, {**status, 'guard_sha256': pin}, backout.PHASE,
                               assets=attempt, gh=None, cosign=None, registry_config=None, authority_file=None, held=held)

    def latest():
        tail = max(anchors.iterdir())
        return {**store.inspect(plan, expected_anchor_sha256=selection.digest(tail.read_bytes())), 'guard_sha256': pin}

    control.prepare, control.execute, control.latest = prepare_history, execute, latest
    return control


@pytest.mark.parametrize('routed,prepared_routes',[(False,'absent'),(False,'empty'),(False,'materialized'),(True,'materialized')])
def test_only_exact_candidate_removed_and_historical_route_file_retained(rollback, routed, prepared_routes):
    result = rollback.execute(rollback.prepare(routed=routed, prepared_routes=prepared_routes))
    assert rollback.calls == ['staged-proof','stop','rm','combined-proof']
    assert result['classification'] == backout.CLASSIFICATION and result['retirement_returned']
    with ExitStack() as held:
        retained, receipt = backout.hold_retirement(rollback.plan, result, held)
    assert retained['retained_route_directory'] == prepared_routes
    assert receipt['candidate_outcome'] == 'removed-after-combined-rollback'
    directory = Path(rollback.plan['route_directory'])
    assert directory.exists() == (prepared_routes != 'absent')
    assert (directory/'active.conf').is_file() == (prepared_routes == 'materialized')


@pytest.mark.parametrize('fault',['drift','uncertain','public'])
def test_no_replay_and_no_terminal_claim_until_combined_proof(rollback, fault):
    initial = rollback.prepare()
    rollback.fault = fault
    if fault == 'drift':
        rollback.candidate['RestartCount'] = 1
    with pytest.raises((ValueError, RuntimeError)):
        rollback.execute(initial)
    after_failure = rollback.latest()
    assert after_failure['classification'] != backout.CLASSIFICATION
    rollback.fault = None
    if fault == 'drift':
        assert rollback.calls == ['staged-proof'] and after_failure['permitted_record_phases'] == [backout.PHASE]
    elif fault == 'uncertain':
        assert not after_failure['retirement_returned']
        with pytest.raises(renewal.UncertainComposeMutation):
            rollback.execute(after_failure)
        assert rollback.calls == ['staged-proof','stop']
    else:
        assert after_failure['retirement_returned'] and rollback.candidate is None
        assert rollback.execute(after_failure)['classification'] == backout.CLASSIFICATION
        assert rollback.calls == ['staged-proof','stop','rm','combined-proof','combined-proof']


def test_retry_after_unpublished_completion_keeps_first_evidence_and_does_not_remove_again(rollback, monkeypatch):
    status = rollback.prepare()
    append = selection._append
    interrupts = []

    def interrupt(root, raw, name, value, held):
        if name.endswith('.retire-candidate.completed.json') and not interrupts:
            interrupts.append(name)
            raise RuntimeError('synthetic interruption before completion record')
        return append(root, raw, name, value, held)

    monkeypatch.setattr(selection, '_append', interrupt)
    with pytest.raises(RuntimeError):
        rollback.execute(status)
    path = rollback.attempt / backout.AFTER
    retained = path.read_bytes()
    assert rollback.execute(rollback.latest())['classification'] == backout.CLASSIFICATION
    assert path.read_bytes() == retained
    assert rollback.calls == ['staged-proof','stop','rm','combined-proof','combined-proof']
