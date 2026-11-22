"""Windows edge-only Compose qualification, with independently anchored evidence."""
from contextlib import ExitStack
from copy import deepcopy
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned, propose
from tests.test_windows_website_store import paths
import selfhost_windows_selection as selection
import selfhost_windows_website_edge as edge
import selfhost_windows_website_plan as contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows private edge route evidence')


def with_path(proposal, plan):
    for mount in proposal['models']['split']['services']['edge']['volumes']:
        if mount['target'] == contract.ROUTE_TARGET:
            mount['source'] = plan['route_directory']
    return proposal


def test_real_compose_edge_overlay_changes_only_route_bind(paths, planned):
    plan, records, _anchors = paths
    proposal = with_path(propose(planned), plan)
    attempt = records.parent
    base = attempt / 'synthetic-combined.json'
    base.write_bytes(selection.packed(proposal['models']['combined']))

    class Docker:
        prefix = ['docker']

        def json(self, args):
            return json.loads(subprocess.check_output([*self.prefix, *args], timeout=30))

        def hashes(self, command):
            output = subprocess.check_output([*command, '--profile', '*', 'config', '--hash', '*'], timeout=30)
            return dict(line.split() for line in output.decode().splitlines())

    docker = Docker()
    command = [*docker.prefix, 'compose', '--project-name', plan['owner']['project'], '--env-file', os.devnull, '-f', str(base)]
    original = docker.json(command[1:] + ['--profile', '*', 'config', '--format', 'json'])
    with ExitStack() as held:
        staged = stage._stage_model(docker, command, original, proposal, attempt, held)
        edge._held_routes(attempt / 'routes', proposal['routes']['split'], held, create=True)
        invoked, split, hashes = edge._split_model(docker, *staged, proposal, attempt, held)
    assert invoked == staged[0] + ['-f', str(attempt / 'route.compose.json')]
    assert hashes['edge'] != staged[2]['edge']
    assert split['services']['edge']['volumes'][-1]['target'] == contract.ROUTE_TARGET


@pytest.mark.parametrize('fault', [None, 'backout-before-routing', 'changed-evidence', 'failed-compose',
    'changed-application', 'unexpected-bind', 'nginx-rejected', 'foreign-storage-changed', 'unready-site', 'changed-default-before-backout', 'sealed-backout'])
def test_edge_phase_reuses_owner_preserves_application_and_qualifies_reverse(paths, planned, monkeypatch, fault):
    plan, records, anchors = paths
    proposal = with_path(propose(planned), plan)
    attempt = records.parent
    project = plan['owner']['project']
    state = 'staged'
    calls = []
    site_unhealthy = fault == 'unready-site'
    changed_default = False
    hashes = {role: f'{index+1:064x}' for index, role in enumerate(proposal['models']['staged']['services'])}
    routed_hashes = {**hashes, 'edge': 'f'*64}
    combined = proposal['models']['combined']
    layouts = {'staged': ('stage.compose.json', proposal['models']['staged'], hashes),
               'split': ('route.compose.json', proposal['models']['split'], routed_hashes)}

    def items(state, edge_id):
        rows = []
        for index, (role, data) in enumerate(proposal['data'][state].items()):
            model = proposal['models'][state]['services'][role]
            exited = role == 'openbao-tls-init' or role in edge.renewal.COMPLETED_SERVICES
            health = {'Health': {'Status': 'unhealthy' if role == contract.SLOT and site_unhealthy else 'healthy'}}
            status = {'StartedAt': 'synthetic', 'Status': 'exited' if exited else 'running', 'ExitCode': 0}
            if model.get('healthcheck'):
                status.update(health)
            rows.append({'Id': f'{edge_id if role == "edge" else index+1:064x}', 'Image': data['image'],
                         'Mounts': deepcopy(data['mounts']), 'Config': {'Image': model['image'], 'Labels': {
                             'com.docker.compose.project': project, 'com.docker.compose.service': role,
                             'com.docker.compose.config-hash': (routed_hashes if state == 'split' else hashes)[role]}},
                         'State': status, 'HostConfig': {}, 'RestartCount': 0,
                         'NetworkSettings': {'Networks': {project+'_default': {}}}})
        return rows

    edge_id = 999
    before = items('combined', edge_id)
    staged_rows = items('staged', edge_id)
    assert len(staged_rows) == len(before)+1
    tls = next(row for row in before if edge.renewal._service(row) == 'openbao-tls-init')
    config = {'project': project, 'compose_file': str(attempt / 'combined.json'), 'native': {'helper_image': 'pinned'},
              'tls_init_receipt': {'id': tls['Id'], 'image': tls['Image'], 'config_hash': hashes['openbao-tls-init']}}
    record = {'selected': {'secrets_dir': plan['owner']['root']}, 'data_sha256': plan['owner']['data_sha256']}

    class Docker:
        prefix = ['docker']

        def json(self, command):
            active = 'split' if any(str(arg).endswith('route.compose.json') for arg in command) else 'staged'
            return deepcopy(layouts[active][1])

        def hashes(self, command):
            active = 'split' if any(str(arg).endswith('route.compose.json') for arg in command) else 'staged'
            return layouts[active][2]

        def containers(self):
            rows = items(state, edge_id)
            if state == 'split' and fault == 'changed-application':
                ui = next(row for row in rows if edge.renewal._service(row) == 'ui')
                ui['RestartCount'] = 1
            if state == 'split' and fault == 'unexpected-bind':
                edge._edge(rows)['Mounts'][-1]['RW'] = True
            return rows

        def volumes(self):
            return {}

        def native_witnesses(self, _items, name, _volumes, _helper):
            assert name == project
            return {}

    docker = Docker()
    base_command = ['docker', 'compose', '-f', config['compose_file']]
    monkeypatch.setattr(selection, '_compose_models', lambda *_: (docker, {'new': base_command}, {'new': combined}))
    monkeypatch.setattr(selection, '_native_current', lambda *_: calls.append('native'))

    def authenticate(*_args, retained_edge_inputs, **_kwargs):
        assert retained_edge_inputs == (docker, combined, proposal['data']['combined'])
        calls.append('authenticate')
        return plan, proposal

    monkeypatch.setattr(edge.website, 'inspect_composition', authenticate)
    monkeypatch.setattr(edge.renewal, 'owned_roles', lambda _model, roles: roles)
    monkeypatch.setattr(edge.renewal, 'dependency_layers', lambda *_: [])
    monkeypatch.setattr(edge.renewal, 'checked_secret_mounts', lambda *_, **_kw: 1)

    def prove_storage(*_ignored):
        if state == 'split' and fault == 'foreign-storage-changed':
            raise ValueError('injected foreign storage alias')
        return {}

    monkeypatch.setattr(edge.renewal, 'disjoint_storage', prove_storage)

    def probe(command, *, capture_output, timeout):
        assert command[1:3] == ['exec', edge._edge(docker.containers())['Id']]
        args = command[3:]
        assert capture_output and timeout == 30
        if args == ['cat', contract.TEMPLATE_TARGET]:
            return SimpleNamespace(returncode=0, stdout=planned['edge_template'])
        assert args == ['nginx', '-T']
        details = b'# configuration file ' + edge.DEFAULT_CONFIG + b':\n' + edge.website.composition.EDGE_INCLUDE.encode() + b'\n\n'
        if changed_default:
            details += b'# configuration changed after routing\n'
        if state == 'split':
            details += b'# configuration file ' + edge.ACTIVE_ROUTE.encode() + b':\n' + proposal['routes']['split'] + b'\n'
            if fault == 'nginx-rejected':
                details += b'wrong include\n'
        return SimpleNamespace(returncode=0, stdout=details)

    # Keep this substitution local to the routing probe, outside the Windows handle checks.
    monkeypatch.setattr(edge, 'subprocess', SimpleNamespace(run=probe, SubprocessError=subprocess.SubprocessError))

    def mutate(command, *, timeout):
        nonlocal state, edge_id
        phase = edge.FORWARD if state == 'staged' else edge.BACKOUT
        sequence = '000004' if phase == edge.FORWARD else ('000010' if fault == 'sealed-backout' else '000006')
        assert (records / f'{sequence}.{phase}.started.json').is_file()
        assert (anchors / f'{sequence}.tail.json').is_file()
        assert command[-10:] == ['up', '--no-deps', '--no-build', '--pull', 'never',
                                 '--force-recreate', '--wait', '--wait-timeout', '90', 'edge']
        state = 'split' if phase == edge.FORWARD else 'staged'
        assert command[-11].endswith(layouts[state][0]) and timeout == 120
        calls.append(phase)
        edge_id += 1
        return SimpleNamespace(returncode=int(fault == 'failed-compose'))

    monkeypatch.setattr(edge.renewal, 'run_owned_mutation', mutate)
    pin = 'e'*64
    initial = store.initialize(plan)
    with ExitStack() as held:
        started_evidence = stage._evidence(attempt / 'stage-before.json', {'owner_lease': {}, 'native_custody': {},
            'foreign_storage': {}, 'runtime_before': edge.renewal.context_snapshot(before)}, held)
        completed_evidence = stage._evidence(attempt / 'stage-after.json', {'image_metadata': {}, 'candidate_health': {},
            'runtime_after': edge.renewal.context_snapshot(staged_rows)}, held)
        started = store.append(plan, expected_anchor_sha256=initial['anchor_sha256'], phase='stage-candidate',
                               event='started', evidence_sha256=started_evidence)
        staged = store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase='stage-candidate',
                              event='completed', evidence_sha256=completed_evidence)

    def advance(status, phase):
        with ExitStack() as held:
            return edge.run(config, 'new', {}, record, plan, {**status, 'guard_sha256': pin}, phase,
                            assets=attempt, gh=None, cosign=None, registry_config=None, authority_file=None, held=held)

    if fault == 'changed-evidence':
        (attempt / 'stage-after.json').write_bytes(selection.packed({}))
        with pytest.raises(ValueError):
            advance(staged, edge.FORWARD)
        assert calls == [] and not (records / '000004.route-website.started.json').exists()
    elif fault == 'unready-site':
        with pytest.raises(edge.renewal.UnsafeRenewalContext):
            advance(staged, edge.FORWARD)
        assert calls == ['authenticate', 'native'] and not (records / '000004.route-website.started.json').exists()
    elif fault == 'backout-before-routing':
        result = advance(staged, edge.BACKOUT)
        assert calls == ['authenticate', 'native']
        assert result['model_state'] == 'staged' and result['permitted_record_phases'] == ['verify-combined']
    elif fault in {'failed-compose', 'changed-application', 'unexpected-bind', 'nginx-rejected',
                   'foreign-storage-changed'}:
        with pytest.raises((ValueError, RuntimeError)):
            advance(staged, edge.FORWARD)
        assert calls == ['authenticate', 'native', edge.FORWARD]
        assert not (records / '000005.route-website.completed.json').exists()
        with pytest.raises(ValueError):
            advance(staged, edge.FORWARD)
        assert calls.count(edge.FORWARD) == 1
    else:
        routed = advance(staged, edge.FORWARD)
        assert state == 'split' and routed['model_state'] == 'split'
        assert routed['permitted_record_phases'] == ['verify-website', 'restore-combined']
        if fault == 'sealed-backout':
            for phase in ('verify-website', 'seal-forward'):
                for event in ('started', 'completed'):
                    keys = (store.journal.START_EVIDENCE if event == 'started'
                            else store.journal.COMPLETION_EVIDENCE[phase])
                    routed = store.append(plan, expected_anchor_sha256=routed['anchor_sha256'], phase=phase, event=event,
                                          evidence_sha256={key: 'a'*64 for key in keys})
            assert routed['classification'] == 'forward-evidence-complete'
        site_unhealthy = True
        if fault == 'changed-default-before-backout':
            changed_default = True
            with pytest.raises(ValueError):
                advance(routed, edge.BACKOUT)
            assert calls == ['authenticate', 'native', edge.FORWARD, 'authenticate', 'native']
            assert not (records / '000006.restore-combined.started.json').exists()
            return
        restored = advance(routed, edge.BACKOUT)
        assert state == 'staged' and restored['model_state'] == 'staged'
        assert restored['permitted_record_phases'] == ['verify-combined']
        assert calls == ['authenticate', 'native', edge.FORWARD, 'authenticate', 'native', edge.BACKOUT]
        assert (attempt / 'routes/active.conf').read_bytes() == proposal['routes']['split']
