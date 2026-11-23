"""First managed website cutover is a bound declaration, not runtime admission."""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import os
import subprocess

import pytest

from tests.test_package_web_composition import candidate
from tests.test_full_standalone_website_release import full_candidate
import package_web_composition as composition
import selfhost_windows_website_plan as plan
import selfhost_windows_selection as selection
import ui_release as ui


@pytest.fixture
def planned(candidate):
    kwargs, _calls, _lock, _application, release = full_candidate(candidate)
    manifest = composition.package(**kwargs)
    for name in plan.product_journal.ARTIFACTS:
        path = kwargs['output'] / name
        if not path.exists():
            path.write_bytes(b'Synthetic proof bytes; not authenticated runtime evidence')
    proofs = {name: selection.digest((kwargs['output']/name).read_bytes()) for name in plan.product_journal.ARTIFACTS}
    root = r'C:\Marty\production'
    attempt = root + '\\windows-website-' + 'a'*32
    before = {'name': 'marty-production-synthetic', 'services': {
        role: {'image': image} for role, image in manifest['images'].items()},
        'volumes': {'application': {'name': 'marty-production-synthetic_application'}},
        'networks': {'default': {'name': 'marty-production-synthetic_default'}},
        'secrets': {'google_site_verification': {'file': root+r'\secrets\google_site_verification'},
                    'application_password': {'file': root+r'\secrets\application_password'}}}
    for role in plan.product.PROVIDER_ROLES:
        before['services'][role] = {'image': manifest['openbao_didcomm_image']}
    before['services']['edge'].update(
        healthcheck={'test': ['CMD', 'wget', 'http://127.0.0.1/edge-healthz']},
        networks={'default': None}, ports=[{'host_ip': '127.0.0.1', 'target': 80, 'published': '29382'}],
        volumes=[{'type': 'bind', 'source': root+r'\config\edge.template',
                  'target': plan.TEMPLATE_TARGET, 'read_only': True}])
    before['services']['ui'].update(environment={'APPLICATION_SECRET': 'PRIVATE_SENTINEL',
        'GOOGLE_SITE_VERIFICATION': 'public-verification', 'ORGANIZATION_CREATION_ENABLED': 'false'},
        secrets=[{'source': 'google_site_verification', 'target': '/run/secrets/google_site_verification'},
                 {'source': 'application_password', 'target': '/run/secrets/application_password'}])
    data = {role: {'image': 'sha256:'+hashlib.sha256(role.encode()).hexdigest(), 'mounts': []}
            for role in sorted(set(before['services'])-plan.product.renewal.INITIALIZERS)}
    data['edge']['mounts'] = [{'Type': 'bind', 'Source': '/run/desktop/mnt/host/c/Marty/production/config/edge.template',
        'Destination': plan.TEMPLATE_TARGET, 'Mode': 'ro', 'RW': False, 'Propagation': 'rprivate'}]
    data['gateway']['mounts'] = [{'Type': 'volume', 'Name': 'application', 'Source': '/var/lib/docker/volumes/application/_data',
                                  'Destination': '/app/data', 'Driver': 'local', 'Mode': '', 'RW': True}]
    anchor = {name: 'b'*64 for name in plan.ANCHOR_FIELDS if name.endswith('_sha256')}
    anchor.update(project='marty-production-synthetic', engine_id='SYNTHETIC_ENGINE_1234',
        docker_host='npipe:////./pipe/dockerDesktopLinuxEngine', root=root, selection_sequence=9,
        generation_sequence=33, model_sha256=plan.digest(before), data_sha256=plan.digest(data))
    inputs = {'before': before, 'manifest': manifest, 'website_release': release,
        'routes': plan.web.read(kwargs['website_assets']/'web-surface-routes.json'), 'anchor': anchor,
        'proof_sha256': proofs, 'attempt_directory': attempt,
        'edge_template': (Path(__file__).resolve().parents[1]/'docker/nginx-selfhost.prod.conf.template').read_bytes(),
        'data_before': data, 'website_image_id': 'sha256:'+'c'*64,
        'route_runtime_mount': {'Type': 'bind', 'Source': attempt+r'\routes', 'Destination': plan.ROUTE_TARGET,
                                'Mode': 'ro', 'RW': False, 'Propagation': 'rprivate'}}
    return inputs


def propose(inputs):
    return plan.proposal(**{key: value for key, value in inputs.items() if key != 'proof_sha256'})


def rehash(value):
    value['plan_sha256'] = plan.digest({key: item for key, item in value.items() if key != 'plan_sha256'})


def test_retained_resources_redirect_is_bound_to_exact_template(planned, monkeypatch):
    ordinary = propose(planned)['routes']
    assert b'location = /resources {' in ordinary['split']
    include = plan.composition.EDGE_INCLUDE.encode()
    planned['edge_template'] = planned['edge_template'].replace(include, include +
        b'\n    location = /resources { absolute_redirect off; return 308 /resources/; }')
    with pytest.raises(ValueError, match='transition plan refused'):
        propose(planned)
    monkeypatch.setattr(plan, 'RETAINED_RESOURCES_TEMPLATE_SHA256', selection.digest(planned['edge_template']))
    retained = propose(planned)['routes']
    assert retained['combined'] == retained['staged'] == b''
    assert b'location = /resources {' not in retained['split']
    assert b'rewrite ^/resources$ /_website/.managed-resources last;' in retained['split']
    assert b'location = /_website/.managed-resources {\n    internal;' in retained['split']
    assert b'proxy_pass http://$website_upstream/resources$is_args$args;' in retained['split']
    assert plan.plan(**planned)['states']['split']['routes_sha256'] == selection.digest(retained['split'])
    planned['edge_template'] += b'\n# changed after qualification\n'
    with pytest.raises(ValueError, match='transition plan refused'):
        propose(planned)


def test_first_cutover_preserves_combined_product_and_changes_only_declared_model_and_data(planned):
    original = deepcopy(planned)
    result = plan.plan(**planned);proposed = propose(planned)
    assert planned == original
    assert result['owner']['generation_sequence'] == 33 and result['owner']['selection_sequence'] == 9
    assert result['declared_roles'] == ['website-a'] and result['mutable_existing_roles'] == ['edge']
    assert result['backout']['preserved_selected_sha256'] == planned['anchor']['selected_sha256']
    assert result['application'] == planned['manifest']['application']
    assert result['backend'] == planned['manifest']['backend']
    assert result['website']['producer'] == planned['website_release']['producer']
    assert all(value is False for value in result['qualification'].values())
    assert 'PRIVATE_SENTINEL' not in selection.packed(result).decode()
    staged, split = proposed['models']['staged'], proposed['models']['split']
    assert {role: spec for role, spec in staged['services'].items() if role != plan.SLOT} == planned['before']['services']
    assert staged['services'][plan.SLOT]['environment'] == {'GOOGLE_SITE_VERIFICATION': 'public-verification',
                                                           'ORGANIZATION_CREATION_ENABLED': 'false'}
    assert staged['services'][plan.SLOT]['secrets'] == planned['before']['services']['ui']['secrets'][:1]
    recovered = deepcopy(split)
    recovered['services'].pop(plan.SLOT)
    recovered['services']['edge']['volumes'].pop()
    assert recovered == planned['before']
    for state in ('staged', 'split'):
        remaining = deepcopy(proposed['data'][state]);remaining.pop(plan.SLOT)
        if state == 'split':
            remaining['edge']['mounts'] = [row for row in remaining['edge']['mounts'] if row['Destination'] != plan.ROUTE_TARGET]
        assert remaining == planned['data_before']
    assert len({state['data_sha256'] for state in result['states'].values()}) == 3
    assert result['states']['combined']['routes_sha256'] == selection.digest(b'')
    assert b'location = /login' not in proposed['routes']['split']
    assert planned['website_release']['revision'].encode() in proposed['routes']['split']
    assert plan.validate_plan(result, **planned) == result
    plan.check_models(result, **dict(zip(('before', 'staged', 'split'),
                                        (planned['before'], staged, split))))


@pytest.mark.parametrize('fault', [None, 'missing-digest', 'other-platform', 'anonymous-volume', 'wrong-route-label'])
def test_owner_observation_uses_exact_signed_cache_and_engine_route_path(planned, monkeypatch, fault):
    release = planned['website_release']
    metadata = release['image_metadata']
    image = release['image']['uri'] + '@' + release['image']['digest']
    commerce = metadata['commerce_extension']['source_sha']
    row = {'Os': 'linux', 'Architecture': 'amd64', 'Id': planned['website_image_id'], 'RepoDigests': [image],
           'Config': {'ExposedPorts': {'80/tcp': {}}, 'Labels': {
               'org.opencontainers.image.source': 'https://github.com/' + plan.ui.COMMERCE_REPOSITORY,
               'org.opencontainers.image.revision': commerce,
               'org.opencontainers.image.version': metadata['revision'],
               'com.elevenid.website.repository': metadata['repository'],
               'com.elevenid.website.source-sha': metadata['source_sha'],
               'com.elevenid.website.commerce-source-sha': commerce,
               'com.elevenid.website.audience': 'production',
               'com.elevenid.website.pages': 'full',
               'com.elevenid.website.route-contract-sha256': metadata['route_contract']['sha256'],
           }}}
    if fault == 'missing-digest': row['RepoDigests'] = []
    elif fault == 'other-platform': row['Architecture'] = 'arm64'
    elif fault == 'anonymous-volume': row['Config']['Volumes'] = {'/html': {}}
    elif fault == 'wrong-route-label': row['Config']['Labels']['com.elevenid.website.route-contract-sha256'] = 'different'

    class Docker:
        def json(self, args):
            assert args == ['image', 'inspect', image]
            return [row]

    monkeypatch.setattr(plan.product.renewal, 'namespace_entry_exists', lambda _path: False)
    inputs = {key: value for key, value in planned.items() if key not in {'website_image_id', 'route_runtime_mount'}}
    if fault:
        with pytest.raises(ValueError):
            plan.from_observation(**inputs, docker=Docker())
        return
    result = plan.from_observation(**inputs, docker=Docker())
    assert result['route_runtime_mount']['Source'] == (
        '/run/desktop/mnt/host/c/Marty/production/windows-website-' + 'a'*32 + '/routes')
    assert result['states']['combined']['data_sha256'] == planned['anchor']['data_sha256']
    assert result['states']['combined']['model_sha256'] == planned['anchor']['model_sha256']
    assert not any(result['qualification'].values())


def test_real_compose_normalization_preserves_the_declared_first_cutover_delta(planned, tmp_path):
    """Source proposal hashes do not stand in for normalized Compose identities."""
    proposed = propose(planned)
    executable = os.environ.get('MARTY_INSTALLER_COMPOSE_EXECUTABLE') or os.environ.get('MARTY_COMPOSE_RENDERER')
    command = [executable] if executable else ['docker', 'compose']
    normalized = {}
    for name, model in proposed['models'].items():
        path = tmp_path / (name + '.json')
        path.write_bytes(selection.packed(model))
        rendered = subprocess.run([*command, '--project-name', planned['anchor']['project'],
            '--env-file', os.devnull, '-f', str(path), '--profile', '*', 'config',
            '--no-interpolate', '--no-env-resolution', '--no-path-resolution', '--format', 'json'],
            check=True, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        normalized[name] = json.loads(rendered.stdout)
    for name in ('staged', 'split'):
        recovered = deepcopy(normalized[name])
        candidate = recovered['services'].pop(plan.SLOT)
        assert set(candidate['networks']) == set(normalized['combined']['services']['edge']['networks'])
        assert candidate['environment'] == {'GOOGLE_SITE_VERIFICATION': 'public-verification',
                                            'ORGANIZATION_CREATION_ENABLED': 'false'}
        assert [secret['source'] for secret in candidate['secrets']] == ['google_site_verification']
        assert not candidate.get('ports') and not candidate.get('volumes') and not candidate.get('depends_on')
        if name == 'split':
            mounts = recovered['services']['edge']['volumes']
            added = [mount for mount in mounts if mount['target'] == plan.ROUTE_TARGET]
            assert len(added) == 1 and added[0]['read_only'] is True
            mounts.remove(added[0])
        assert recovered == normalized['combined']
    assert normalized['staged']['services'][plan.SLOT] == normalized['split']['services'][plan.SLOT]


@pytest.mark.parametrize('fault', ['product-image', 'provider-image', 'application-audience', 'extra-role',
    'slot-existing', 'owner-model', 'owner-data', 'owner-boolean-sequence', 'owner-native', 'proof-inventory',
    'proof-manifest', 'release-source', 'route-contract', 'network-alias', 'network-mode-host',
    'network-mode-container', 'network-missing', 'empty-build', 'route-mount-existing',
    'route-mount-shadowed', 'route-mount-writable', 'route-mount-other-source', 'attempt-escape',
    'template-comment-only', 'template-duplicate-include', 'template-writable', 'template-outside-owner',
    'template-runtime-missing', 'template-runtime-writable', 'template-runtime-other-source'])
def test_plan_refuses_unbound_or_expanded_inputs(planned, fault):
    inputs = deepcopy(planned)
    before, anchor = inputs['before'], inputs['anchor']
    if fault == 'product-image':before['services']['gateway']['image'] = 'example.invalid/gateway@sha256:'+'f'*64
    elif fault == 'provider-image':before['services']['openbao']['image'] = 'example.invalid/bao@sha256:'+'f'*64
    elif fault == 'application-audience':before['services']['ui']['image'] = ui.PUBLIC_IMAGE+'@sha256:'+'f'*64
    elif fault == 'extra-role':before['services']['extra'] = deepcopy(before['services']['gateway'])
    elif fault == 'slot-existing':before['services']['website-b'] = deepcopy(before['services']['gateway'])
    elif fault == 'owner-model':anchor['model_sha256'] = 'f'*64
    elif fault == 'owner-data':anchor['data_sha256'] = 'f'*64
    elif fault == 'owner-boolean-sequence':anchor['selection_sequence'] = True
    elif fault == 'owner-native':anchor['native_sha256'] = 'mutable-source'
    elif fault == 'proof-inventory':inputs['proof_sha256']['unknown.json'] = 'f'*64
    elif fault == 'proof-manifest':inputs['proof_sha256']['web-composition.json'] = 'f'*64
    elif fault == 'release-source':inputs['website_release']['source_sha'] = 'f'*40
    elif fault == 'route-contract':inputs['routes']['website']['exact_paths'].append('/auth')
    elif fault == 'network-alias':before['services']['edge']['networks']['default'] = {'aliases': ['gateway']}
    elif fault == 'network-mode-host':before['services']['edge']['network_mode'] = 'host'
    elif fault == 'network-mode-container':before['services']['edge']['network_mode'] = 'container:other'
    elif fault == 'network-missing':before['services']['edge'].pop('networks')
    elif fault == 'empty-build':before['services']['edge']['build'] = {}
    elif fault in {'route-mount-existing', 'route-mount-shadowed'}:
        before['services']['edge']['volumes'].append({'type': 'bind', 'source': anchor['root']+r'\other',
            'target': plan.ROUTE_TARGET if fault == 'route-mount-existing' else '/etc/nginx', 'read_only': True})
    elif fault == 'route-mount-writable':inputs['route_runtime_mount']['RW'] = True
    elif fault == 'route-mount-other-source':inputs['route_runtime_mount']['Source'] = anchor['root']+r'\other'
    elif fault == 'attempt-escape':inputs['attempt_directory'] = r'C:\elsewhere\windows-website-'+'a'*32
    elif fault == 'template-comment-only':inputs['edge_template'] = b'# '+composition.EDGE_INCLUDE.encode()+b'\nlocation = /edge-healthz {\n'
    elif fault == 'template-duplicate-include':inputs['edge_template'] += composition.EDGE_INCLUDE.encode()+b'\n'
    elif fault == 'template-writable':before['services']['edge']['volumes'][0]['read_only'] = False
    elif fault == 'template-outside-owner':before['services']['edge']['volumes'][0]['source'] = r'C:\elsewhere\edge.template'
    elif fault == 'template-runtime-missing':inputs['data_before']['edge']['mounts'] = []
    elif fault == 'template-runtime-writable':inputs['data_before']['edge']['mounts'][0]['RW'] = True
    elif fault == 'template-runtime-other-source':
        inputs['data_before']['edge']['mounts'][0]['Source'] = r'C:\Marty\production\config\other.template'
    if fault != 'owner-model':anchor['model_sha256'] = plan.digest(before)
    if fault != 'owner-data':anchor['data_sha256'] = plan.digest(inputs['data_before'])
    with pytest.raises(ValueError):plan.plan(**inputs)


@pytest.mark.parametrize('role,field,value', [('ui', 'image', 'example.invalid/changed@sha256:'+'f'*64),
    ('gateway', 'environment', {'PASSWORD': 'changed'}), ('openbao', 'volumes', []),
    ('openbao-tls-init', 'entrypoint', ['reinitialize']), ('edge', 'ports', ['80:80']),
    ('website-a', 'privileged', True), ('website-a', 'ports', ['99:80']),
    ('website-a', 'environment', {'APPLICATION_SECRET': 'PRIVATE_SENTINEL'})])
def test_qualified_hashes_do_not_permit_product_credential_or_website_privilege_mutation(planned, role, field, value):
    result = plan.plan(**planned);proposed = propose(planned)
    proposed['models']['split']['services'][role][field] = value
    with pytest.raises(ValueError):
        plan.check_models(result, planned['before'], proposed['models']['staged'], proposed['models']['split'])


@pytest.mark.parametrize('fault', ['extra-field', 'admission', 'numeric-false', 'route-digest',
                                  'protected-role', 'backout-selected', 'template-digest'])
def test_rehashed_plan_cannot_change_contract_or_claim_runtime_admission(planned, fault):
    value = plan.plan(**planned)
    if fault == 'extra-field':value['execute'] = True
    elif fault == 'admission':value['qualification']['production_admission'] = True
    elif fault == 'numeric-false':value['qualification']['production_admission'] = 0
    elif fault == 'route-digest':value['states']['split']['routes_sha256'] = 'f'*64
    elif fault == 'protected-role':value['protected_roles'].remove('ui')
    elif fault == 'backout-selected':value['backout']['preserved_selected_sha256'] = 'f'*64
    elif fault == 'template-digest':value['edge_template']['sha256'] = 'f'*64
    rehash(value)
    with pytest.raises(ValueError):plan.validate_plan(value, **planned)
