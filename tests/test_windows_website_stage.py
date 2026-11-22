"""First website stage with real NTFS receipts and a controlled Docker transport."""
from contextlib import ExitStack
from copy import deepcopy
import os
import json
import subprocess
from types import SimpleNamespace

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned
from tests.test_windows_website_store import paths
import selfhost_windows_website_plan as plan_contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import selfhost_windows_selection as selection


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows private stage evidence')


def test_real_compose_normalizes_staged_overlay_without_product_changes(paths, planned):
    plan, records, _anchors = paths
    expected = plan_contract.proposal(**{key: value for key, value in planned.items() if key != 'proof_sha256'})
    attempt = records.parent
    source = attempt / 'synthetic-combined.json'
    source.write_bytes(selection.packed(expected['models']['combined']))
    project = plan['owner']['project']

    class Docker:
        prefix = ['docker']

        def json(self, arguments):
            return json.loads(subprocess.check_output([*self.prefix, *arguments], timeout=30))

        def hashes(self, _command):
            return {plan_contract.SLOT: 'c'*64}

    docker = Docker()
    command = [*docker.prefix, 'compose', '--project-name', project, '--env-file', os.devnull, '-f', str(source)]
    combined = docker.json(command[1:] + ['--profile', '*', 'config', '--format', 'json'])
    with ExitStack() as held:
        stage_command, normalized, _hashes = stage._stage_model(docker, command, combined, expected, attempt, held)
    assert stage_command == command + ['-f', str(attempt / 'stage.compose.json')]
    assert normalized['services'][plan_contract.SLOT]['image'] == expected['models']['staged']['services'][plan_contract.SLOT]['image']
    assert set(normalized['services']) - set(combined['services']) == {plan_contract.SLOT}


@pytest.mark.parametrize('fault', [None, 'changed-model', 'nonzero', 'uncertain-dispatch', 'unhealthy', 'protected-restart', 'unexpected-port'])
def test_stage_records_boundaries_and_changes_only_website(paths, planned, monkeypatch, fault):
    plan, records, anchors = paths
    expected = plan_contract.proposal(**{key: value for key, value in planned.items() if key != 'proof_sha256'})
    model = expected['models']['combined']
    project = plan['owner']['project']
    statuses = {'moved': False}
    calls = []
    hashes = {role: f'{index+1:064x}' for index, role in enumerate(expected['models']['staged']['services'])}

    def item(role, data, number):
        reference = expected['models']['staged']['services'][role]['image']
        return {'Id': f'{number:064x}', 'Image': data['image'], 'Mounts': deepcopy(data['mounts']),
            'Config': {'Image': reference, 'Labels': {'com.docker.compose.project': project,
                'com.docker.compose.service': role, 'com.docker.compose.config-hash': hashes[role]}},
            'State': {'Status': 'exited' if role == 'openbao-tls-init' else 'running',
                      'ExitCode': 0, 'Health': {'Status': 'healthy'}, 'StartedAt': 'synthetic'},
            'HostConfig': {}, 'RestartCount': 0, 'NetworkSettings': {'Networks': {project+'_default': {}}}}

    baseline = [item(role, data, index+1) for index, (role, data) in enumerate(expected['data']['combined'].items())]
    tls = next(row for row in baseline if stage.renewal._service(row) == 'openbao-tls-init')
    website = item(plan_contract.SLOT, expected['data']['staged'][plan_contract.SLOT], len(baseline)+1)

    class Docker:
        prefix = ['docker', '--host', '|synthetic|']

        def json(self, arguments):
            assert arguments[-5:] == ['--profile', '*', 'config', '--format', 'json']
            value = deepcopy(expected['models']['staged'])
            if fault == 'changed-model':
                value['services']['ui']['image'] = 'other-image'
            return value

        def hashes(self, _command):
            return hashes

        def containers(self):
            rows = deepcopy(baseline)
            if statuses['moved']:
                site = deepcopy(website)
                if fault == 'unhealthy':
                    site['State']['Health']['Status'] = 'unhealthy'
                if fault == 'protected-restart':
                    rows[0]['RestartCount'] = 1
                if fault == 'unexpected-port':
                    site['HostConfig']['PortBindings'] = {'80/tcp': [{'HostPort': '80'}]}
                rows.append(site)
            return rows

        def volumes(self):
            return {}

        def native_witnesses(self, _items, name, _volumes, _helper):
            assert name == project
            return {}

    docker = Docker()
    config = {'project': project, 'native': {'helper_image': 'pinned-image'},
              'tls_init_receipt': {'id': tls['Id'], 'image': tls['Image'], 'config_hash': hashes['openbao-tls-init']}}
    record = {'selected': {'secrets_dir': plan['owner']['root']}, 'data_sha256': plan['owner']['data_sha256']}
    inspected = {'docker': docker, 'baseline': baseline, 'owned': baseline, 'model': model,
                 'command': docker.prefix + ['compose', '-f', 'original.json'], 'context': SimpleNamespace(volumes={})}
    monkeypatch.setattr(selection, '_inspect', lambda *_args, **_kwargs: inspected)
    monkeypatch.setattr(selection, '_native_current', lambda *_args: calls.append('native'))
    monkeypatch.setattr(stage.renewal, 'disjoint_storage', lambda *_args, **_kwargs: {})
    monkeypatch.setattr(stage.renewal, 'checked_secret_mounts', lambda *_args, **_kwargs: 1)

    def execute(arguments, *, timeout):
        assert (records / '000002.stage-candidate.started.json').is_file()
        assert (anchors / '000002.tail.json').is_file()
        assert (records / '000003.stage-candidate.dispatch-authorized.json').is_file()
        assert (anchors / '000003.tail.json').is_file()
        assert not (records / '000004.stage-candidate.dispatch-returned.json').exists()
        assert arguments[-10:] == ['up', '--no-deps', '--no-build', '--pull', 'never',
                                  '--no-recreate', '--wait', '--wait-timeout', '90', plan_contract.SLOT]
        assert timeout == 120
        calls.append('mutate')
        if fault == 'uncertain-dispatch':
            raise stage.renewal.UncertainComposeMutation('synthetic lost daemon outcome')
        statuses['moved'] = True
        return SimpleNamespace(returncode=int(fault == 'nonzero'))

    monkeypatch.setattr(stage.renewal, 'run_owned_mutation', execute)
    initial = {**store.initialize(plan), 'guard_sha256': 'e'*64}
    with ExitStack() as held:
        if fault:
            with pytest.raises((ValueError, RuntimeError)):
                stage.run(config, 'new', {}, record, plan, expected, initial, authority_file=None, held=held)
        else:
            result = stage.run(config, 'new', {}, record, plan, expected, initial, authority_file=None, held=held)
    if fault == 'changed-model':
        assert calls == [] and not (records / '000002.stage-candidate.started.json').exists()
    else:
        assert calls == ['native', 'mutate']
        assert (records / '000004.stage-candidate.dispatch-returned.json').is_file() == (fault != 'uncertain-dispatch')
        assert (records / '000005.stage-candidate.completed.json').is_file() == (fault is None)
    if fault is None:
        assert result['model_state'] == 'staged' and result['permitted_record_phases'] == ['route-website', 'restore-combined']
        assert not result['activation_supported']
