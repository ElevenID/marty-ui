"""Durable initial-stage aborts with NTFS evidence and controlled engine calls."""
from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows private stage recovery evidence')

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned, propose
from tests.test_windows_website_store import paths
import selfhost_windows_website_reconcile as reconcile


stage = reconcile.stage
store = reconcile.store
renewal = reconcile.renewal
selection = reconcile.selection
contract = reconcile.contract
journal = reconcile.journal


@pytest.fixture
def room(paths, planned, monkeypatch):
    plan, records, anchors = paths
    attempt = records.parent
    proposal = propose(planned)
    model = proposal['models']['combined']
    staged = proposal['models']['staged']
    project = plan['owner']['project']
    hashes = {role: f'{index+1:064x}' for index, role in enumerate(staged['services'])}
    command = ['docker', 'compose', '-f', str(attempt / 'combined.json')]
    overlay = [*command, '-f', str(attempt / 'stage.compose.json')]

    def item(role, data, index):
        configured = staged['services'][role]
        state = {'StartedAt': 'synthetic', 'ExitCode': 0, 'Status': 'running'}
        if role == 'openbao-tls-init' or role in renewal.COMPLETED_SERVICES:
            state['Status'] = 'exited'
        elif configured.get('healthcheck'):
            state['Health'] = {'Status': 'healthy'}
        return {'Id': f'{index+1:064x}', 'Image': data['image'], 'Mounts': deepcopy(data['mounts']),
                'Config': {'Image': configured['image'], 'Labels': {'com.docker.compose.project': project,
                    'com.docker.compose.service': role, 'com.docker.compose.config-hash': hashes[role]}},
                'Name': f'/{project}-{role}-1', 'State': state, 'HostConfig': {}, 'RestartCount': 0,
                'NetworkSettings': {'Networks': {project+'_default': {}}}}

    original = [item(role, data, index) for index, (role, data) in enumerate(proposal['data']['combined'].items())]
    slot = contract.SLOT
    website = item(slot, proposal['data']['staged'][slot], len(original))
    website['Config']['Labels'].update({'com.docker.compose.container-number': '1',
        'com.docker.compose.oneoff': 'False', 'com.docker.compose.project.config_files': ','.join(overlay[3::2])})
    # The argument prefix is docker compose -f input -f overlay.
    assert website['Config']['Labels']['com.docker.compose.project.config_files'] == ','.join((overlay[3], overlay[5]))
    tls = next(row for row in original if renewal._service(row) == 'openbao-tls-init')
    config = {'project': project, 'native': {'helper_image': 'test-witness'}, 'tls_init_receipt': {
        'id': tls['Id'], 'image': tls['Image'], 'config_hash': hashes['openbao-tls-init']}}
    record = {'selected': {'secrets_dir': plan['owner']['root']}, 'data_sha256': plan['owner']['data_sha256']}
    fixture = SimpleNamespace(plan=plan, records=records, anchors=anchors, attempt=attempt, project=project,
        website=website, calls=[], ingress=0, started=None, live_candidate=None, fault=None, probe_failed=False)

    class Engine:
        prefix = ['docker']

        def containers(self):
            return deepcopy(original + ([fixture.live_candidate] if fixture.live_candidate is not None else []))

        def json(self, args):
            assert args[-5:] == ['--profile', '*', 'config', '--format', 'json']
            return deepcopy(staged)

        def hashes(self, _command):
            return hashes

        def volumes(self):
            return {}

        def native_witnesses(self, _rows, observed, _volumes, _helper):
            assert observed == project
            return {}

    engine = Engine()
    monkeypatch.setattr(selection, '_compose_models', lambda *_: (engine, {'new': command}, {'new': model}))
    monkeypatch.setattr(selection, '_native_current', lambda *_: fixture.calls.append('native'))
    monkeypatch.setattr(renewal, 'checked_secret_mounts', lambda *_, **_kw: 1)
    monkeypatch.setattr(renewal, 'owned_roles', lambda _model, roles: roles)
    monkeypatch.setattr(renewal, 'dependency_layers', lambda *_: [])

    def storage(*_):
        if fixture.fault == 'foreign':
            raise ValueError('synthetic foreign overlap')
        return {}

    monkeypatch.setattr(renewal, 'disjoint_storage', storage)

    def authenticate(*_, **options):
        assert options['retained_edge_inputs'] == (engine, model, proposal['data']['combined']) and options['include_http']
        return plan, {**proposal, 'http': {'signed': True}}

    monkeypatch.setattr(reconcile.website, 'inspect_composition', authenticate)
    monkeypatch.setattr(reconcile.edge, '_probe', lambda *_: {'container_id': 'edge', 'combined_only': True})

    def ingress(_edge, layout, proof, state):
        assert layout == model and proof == {'signed': True} and state == 'combined'
        fixture.ingress += 1
        if fixture.probe_failed:
            raise ValueError('synthetic public gateway refusal')
        return {'public_sample': fixture.ingress}, {'application': 'retained'}

    monkeypatch.setattr(reconcile.verify, '_observe', ingress)

    def mutate(arguments, *, timeout):
        assert (records / '000005.stage-candidate.compensation-authorized.json').exists()
        assert (anchors / '000005.tail.json').exists()
        assert arguments[-1] == website['Id'] and timeout == 30
        fixture.calls.append(arguments[2])
        if fixture.fault == 'uncertain-stop':
            raise renewal.UncertainComposeMutation('synthetic missing daemon result')
        if arguments[2] == 'stop':
            assert arguments == ['docker', 'container', 'stop', '--time', '10', website['Id']]
            fixture.live_candidate['State']['Status'] = 'exited'
        else:
            assert arguments == ['docker', 'container', 'rm', website['Id']]
            assert fixture.live_candidate['State']['Status'] in reconcile.STOPPED
            fixture.live_candidate = None
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(renewal, 'run_owned_mutation', mutate)
    pin = 'e'*64

    def prepare(actions, *, candidate_state='running', legacy=False):
        fixture.started = store.initialize(plan)
        with ExitStack() as held:
            before = {'owner_lease': {'guard_sha256': pin, 'owner': plan['owner']}, 'native_custody': {},
                      'foreign_storage': {}, 'runtime_before': renewal.context_snapshot(original)}
            if not legacy:
                before['owner_lease']['dispatch_schema'] = stage.DISPATCH_SCHEMA
            fixture.started = store.append(plan, expected_anchor_sha256=fixture.started['anchor_sha256'], phase=stage.PHASE,
                event='started', evidence_sha256=stage._evidence(attempt / 'stage-before.json', before, held))
            status = fixture.started
            if actions:
                status = reconcile._record_action(plan, status, 'dispatch-authorized', {
                    'arguments_sha256': contract.digest(stage._command(overlay)), 'timeout_seconds': 120}, attempt, held)
            if actions == 2:
                status = reconcile._record_action(plan, status, 'dispatch-returned', {
                    'returncode': 1, 'completed_cli_job': True}, attempt, held)
                if candidate_state is not None:
                    fixture.live_candidate = deepcopy(website)
                    fixture.live_candidate['State']['Status'] = candidate_state
        return status

    def run(status):
        with ExitStack() as held:
            return reconcile.run(config, 'new', {}, record, plan, {**status, 'guard_sha256': pin}, 'reconcile-stage',
                                 assets=attempt, gh=None, cosign=None, registry_config=None, authority_file=None, held=held)

    def latest():
        last = max(anchors.iterdir())
        return store.inspect(plan, expected_anchor_sha256=selection.digest(last.read_bytes()))

    fixture.prepare, fixture.run, fixture.latest = prepare, run, latest
    return fixture


def check_receipt(room, outcome, count):
    receipt = selection.decode((room.records / store.ABORT).read_bytes())
    assert receipt['candidate_outcome'] == outcome and receipt['started_record_sha256'] == room.started['tail_sha256']
    assert set(receipt['observations_sha256']) == journal.ABORT_OBSERVATIONS | (
        {'candidate_compensation'} if outcome == 'created-then-compensated' else set())
    assert room.latest()['record_count'] == count and room.latest()['classification'] == 'abort-evidence-complete'
    assert room.latest()['completed_phases'] == []


def test_never_dispatched_candidate_closes_as_aborted_without_actuating_engine(room):
    result = room.run(room.prepare(0))
    check_receipt(room, 'never-created', 3)
    assert room.calls == ['native'] and result['receipt_contents_verified']


@pytest.mark.parametrize('candidate_state,commands', [('running', ['stop', 'rm']), ('created', ['rm'])])
def test_only_exact_compose_candidate_is_compensated(room, candidate_state, commands):
    result = room.run(room.prepare(2, candidate_state=candidate_state))
    check_receipt(room, 'created-then-compensated', 7)
    assert room.calls == ['native', *commands] and result['stage_actions'] == list(journal.STAGE_ACTIONS)
    evidence = selection.decode((room.attempt / 'stage-compensation-result.json').read_bytes())
    assert evidence['compensation_result']['candidate_id'] == room.website['Id']


@pytest.mark.parametrize('fault', ['authorized-only', 'dispatched-absent', 'candidate-spoofed', 'foreign', 'legacy', 'paused'])
def test_uncertain_or_unqualified_stage_is_preserved(room, fault):
    status = room.prepare(1 if fault == 'authorized-only' else 0 if fault == 'legacy' else 2,
        candidate_state=None if fault == 'dispatched-absent' else 'paused' if fault == 'paused' else 'running',
        legacy=fault == 'legacy')
    room.fault = fault
    if fault == 'candidate-spoofed':
        room.live_candidate['Config']['Labels']['com.docker.compose.oneoff'] = 'True'
    with pytest.raises((ValueError, RuntimeError)):
        room.run(status)
    assert not (room.records / store.ABORT).exists() and not any(call in {'stop', 'rm'} for call in room.calls)
    assert room.latest()['pending_phase'] == stage.PHASE
    assert 'compensation-authorized' not in room.latest()['stage_actions']


def test_uncertain_stop_does_not_replay_compensation(room):
    room.fault = 'uncertain-stop'
    with pytest.raises(renewal.UncertainComposeMutation):
        room.run(room.prepare(2))
    status = room.latest()
    assert status['stage_actions'][-1] == 'compensation-authorized'
    room.fault = None
    with pytest.raises(renewal.UncertainComposeMutation):
        room.run(status)
    assert room.calls == ['native', 'stop']


def test_public_verification_retries_after_compensation_with_no_second_mutation(room):
    room.probe_failed = True
    with pytest.raises(ValueError):
        room.run(room.prepare(2))
    status = room.latest()
    assert status['stage_actions'][-1] == 'compensation-returned' and room.live_candidate is None
    room.probe_failed = False
    room.run(status)
    check_receipt(room, 'created-then-compensated', 7)
    assert room.calls == ['native', 'stop', 'rm', 'native']


def test_prepared_receipt_survives_interrupted_record_write_and_fresh_http_probe(room, monkeypatch):
    status = room.prepare(0)
    original_append = selection._append
    attempted = []

    def interrupt(root, raw, name, value, held):
        if name.endswith('.reconciled-abort.json') and not attempted:
            attempted.append(name)
            raise RuntimeError('synthetic interruption after separate receipt')
        return original_append(root, raw, name, value, held)

    monkeypatch.setattr(selection, '_append', interrupt)
    with pytest.raises(RuntimeError):
        room.run(status)
    prepared = room.latest()
    assert prepared['prepared_abort_sha256'] == selection.digest((room.records / store.ABORT).read_bytes())
    assert prepared['classification'] == 'reconciliation-required'
    with pytest.raises(ValueError):
        store.append(room.plan, expected_anchor_sha256=prepared['anchor_sha256'], phase=stage.PHASE,
                     event='dispatch-authorized', evidence_sha256={'stage_command': 'a'*64})
    retained = (room.records / store.ABORT).read_bytes()
    room.run(prepared)
    assert (room.records / store.ABORT).read_bytes() == retained and room.ingress == 2
    check_receipt(room, 'never-created', 3)
