"""Inert first-cutover plan for the existing managed Windows generation owner.

This describes one website slot and one edge route mount. It never authenticates
an input, inspects Windows/Docker, writes a journal or grants runtime admission.
The future owner must derive every input while holding its existing lease and
must separately qualify mounted bytes, native custody, storage and live traffic.
"""
from copy import deepcopy
from pathlib import Path, PurePosixPath, PureWindowsPath
import re

import website_deployment_model as routing
import package_web_composition as composition
import selfhost_windows_product as product
import selfhost_windows_product_journal as product_journal
import selfhost_windows_selection as selection
from selfhost_windows_website import (
    ROUTE_TARGET, TEMPLATE_TARGET, combined_edge_binding, edge_template_identity,
    path_under_owner, runtime_bind_source, windows_path,
)
import ui_release as ui
import website_release as web


SCHEMA = 'marty.windows-website-transition-plan/v1'
SLOT = routing.SLOTS[0]
# The retained combined template owns an exact /resources -> /resources/ redirect.
# Its apex redirect precedes the website include. Only this qualified ordering
# admits a server rewrite before the legacy location is selected.
RETAINED_RESOURCES_TEMPLATE_SHA256 = 'f4461462daf66d8860244be6a97939c75c70de6f43142885ee632df7ba635fbe'
ANCHOR_FIELDS = {'project', 'engine_id', 'docker_host', 'root', 'selection_sequence',
    'generation_sequence', 'binding_sha256', 'journal_sha256', 'configuration_sha256', 'model_sha256',
    'selection_sha256', 'selected_sha256', 'native_sha256', 'historical_tls_sha256', 'data_sha256'}
UNQUALIFIED = {'composition_authenticated': False, 'owner_lease_held': False,
    'native_custody_checked': False, 'foreign_storage_custody_checked': False,
    'installed_image_bytes_checked': False, 'mounted_edge_template_checked': False,
    'runtime_readiness_checked': False, 'public_ingress_checked': False,
    'activation_supported': False, 'production_admission': False}
PLAN_FIELDS = {'schema', 'operation', 'owner', 'composition_id', 'proof_sha256', 'website',
    'application', 'backend', 'route_contract', 'attempt_directory', 'route_directory',
    'edge_template', 'route_runtime_mount', 'declared_roles', 'mutable_existing_roles',
    'protected_roles', 'states', 'backout', 'qualification', 'plan_sha256'}


def require(value):
    if not value:
        raise ValueError('Managed website transition plan refused')


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def digest(value):
    return selection.digest(selection.packed(value))


def cached_website_image(docker, release):
    """Resolve the original signed OCI coordinate to a local image configuration."""
    image = release['image']
    reference = image['uri'] + '@' + image['digest']
    rows = docker.json(['image', 'inspect', reference])
    require(type(rows) is list and len(rows) == 1)
    row = rows[0]
    require(row['Os'] == 'linux' and row['Architecture'] == 'amd64'
            and isinstance(row['Id'], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', row['Id'])
            and type(row['RepoDigests']) is list and reference in row['RepoDigests'])
    config = row['Config']
    require(isinstance(config, dict) and config.get('Volumes') in (None, {})
            and set(config.get('ExposedPorts') or {}) == {'80/tcp'})
    metadata = release['image_metadata']
    commerce = metadata['commerce_extension']['source_sha']
    expected = {
        'org.opencontainers.image.source': 'https://github.com/' + release['producer']['repository'],
        'org.opencontainers.image.revision': commerce,
        'org.opencontainers.image.version': metadata['revision'],
        'com.elevenid.website.repository': metadata['repository'],
        'com.elevenid.website.source-sha': metadata['source_sha'],
        'com.elevenid.website.commerce-source-sha': commerce,
        'com.elevenid.website.audience': metadata['audience'],
        'com.elevenid.website.pages': metadata['production_pages'],
        'com.elevenid.website.route-contract-sha256': metadata['route_contract']['sha256'],
    }
    labels = config.get('Labels')
    require(isinstance(labels, dict) and all(labels.get(name) == value for name, value in expected.items()))
    return row['Id']


def route_mount_proposal(template_mount, route_directory):
    """Use the installed engine's drive spelling for the proposed route bind."""
    source = template_mount['Source']
    template = runtime_bind_source(source)
    require(template.drive == route_directory.drive
            and template_mount['Mode'] == 'ro' and template_mount['Propagation'] == 'rprivate')
    if source.startswith('/'):
        suffix = template.as_posix()[3:]
        require(source.endswith('/' + suffix))
        route_source = source[:-len(suffix)] + route_directory.as_posix()[3:]
    else:
        route_source = route_directory.as_posix() if '/' in source else str(route_directory)
    return {'Type': 'bind', 'Source': route_source, 'Destination': ROUTE_TARGET,
            'Mode': 'ro', 'RW': False, 'Propagation': 'rprivate'}


def from_observation(before, manifest, website_release, routes, anchor, *, docker,
                     proof_sha256, attempt_directory, edge_template, data_before):
    """Derive application-preserving declarations from inputs held by the owner."""
    root = windows_path(anchor['root'])
    attempt = path_under_owner(root, str(attempt_directory))
    require(attempt.parent == root and re.fullmatch(r'windows-website-[0-9a-f]{32}', attempt.name))
    require(not product.renewal.namespace_entry_exists(Path(attempt)))
    template = next(mount for mount in data_before['edge']['mounts'] if mount['Destination'] == TEMPLATE_TARGET)
    return plan(before, manifest, website_release, routes, {**anchor, 'model_sha256': digest(before)},
        proof_sha256=proof_sha256, attempt_directory=str(attempt), edge_template=edge_template,
        data_before=data_before, website_image_id=cached_website_image(docker, website_release),
        route_runtime_mount=route_mount_proposal(template, attempt / 'routes'))


def validate_anchor(value):
    require(type(value) is dict and set(value) == ANCHOR_FIELDS)
    require(isinstance(value['project'], str) and re.fullmatch(
        r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', value['project']))
    require(isinstance(value['engine_id'], str) and 10 <= len(value['engine_id']) <= 128
            and not re.search(r'[\x00-\x20\x7f]', value['engine_id']))
    require(value['docker_host'] in {'npipe:////./pipe/dockerDesktopLinuxEngine', 'npipe:////./pipe/docker_engine'})
    windows_path(value['root'])
    require(type(value['selection_sequence']) is int and 1 <= value['selection_sequence'] <= selection.MAX_SELECTIONS
            and type(value['generation_sequence']) is int
            and value['selection_sequence'] <= value['generation_sequence'] <= 2**63-1)
    require(all(sha(value[name]) for name in ANCHOR_FIELDS if name.endswith('_sha256')))
    return value


def _data(value, roles):
    require(type(value) is dict and set(value) == roles)
    for row in value.values():
        require(type(row) is dict and set(row) == {'image', 'mounts'}
                and isinstance(row['image'], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', row['image'])
                and type(row['mounts']) is list)
        targets = []
        for mount in row['mounts']:
            require(type(mount) is dict and mount.get('Type') in {'bind', 'volume', 'tmpfs'})
            target = mount.get('Destination')
            require(isinstance(target, str) and target.startswith('/')
                    and '..' not in PurePosixPath(target).parts and not target.startswith('/run/secrets/'))
            targets.append(target)
        require(len(targets) == len(set(targets)) and targets == sorted(targets))


def managed_routes(state, edge_template):
    """Select the website include for the original bound edge template."""
    retained_redirect = selection.digest(edge_template) == RETAINED_RESOURCES_TEMPLATE_SHA256
    if '/resources' in state['routes']['website']['exact_paths'] and not retained_redirect:
        directives = b'\n'.join(line.split(b'#', 1)[0] for line in edge_template.splitlines())
        require(not re.search(rb'''\blocation\s+=\s+["']?/resources["']?\s*\{''', directives))
    return routing.render_routes(state, retained_resources_redirect=retained_redirect)


def proposal(before, manifest, website_release, routes, anchor, *, attempt_directory,
             edge_template, data_before, website_image_id, route_runtime_mount):
    """Return exact model/route/data proposals, without creating or qualifying them.

    `before` is the owner's retained all-profile Compose model. Additions use the
    ordinary renderer's Compose source form: the proposed model hashes identify
    those exact source objects, not fresh `compose config` output. A future owner
    must additionally bind the normalized models before any runtime operation.
    `data_before` has the existing renewal.data_mounts shape, including image config
    IDs and read-only mounts. The full data hash changes when adding the slot and
    route mount; all original rows/mounts survive those declared additions exactly.
    """
    validate_anchor(anchor)
    composition.validate_record(manifest)
    web.validate_release(website_release)
    require(website_release['schema'] == web.STANDALONE_FULL_RELEASE_SCHEMA
            and manifest['production_pages'] == 'full'
            and manifest['producer']['repository'] == ui.COMMERCE_REPOSITORY
            and manifest['application']['image']['uri'] == ui.COMMERCE_IMAGE
            and manifest['application']['producer']['repository'] == ui.COMMERCE_REPOSITORY)
    selected = manifest['website']
    require(selected == {**{name: website_release[name] for name in ('source_sha', 'revision', 'image', 'producer')},
                         'release_sha256': ui.digest(ui.canonical(website_release))})
    require(web.route_identity(routes) == manifest['route_contract']
            == website_release['image_metadata']['route_contract'])
    require(type(before) is dict and type(before.get('services')) is dict
            and len(selection.packed(before)) <= 2*1024*1024
            and anchor['model_sha256'] == digest(before))
    services = before['services']
    require(not set(routing.SLOTS).intersection(services)
            and set(services) == set(manifest['images']) | product.PROVIDER_ROLES)
    require({'ui', 'edge', 'gateway'} <= services.keys())
    for role, service in services.items():
        require(type(service) is dict and 'build' not in service)
        expected = manifest['openbao_didcomm_image'] if role in product.PROVIDER_ROLES else manifest['images'][role]
        require(product.image_identity(service['image']) == product.image_identity(expected))
    require(services['ui']['image'] == manifest['application']['image']['uri'] + '@' + manifest['application']['image']['digest'])
    root = windows_path(anchor['root'])
    attempt = path_under_owner(root, attempt_directory)
    require(attempt.parent == root and re.fullmatch(r'windows-website-[0-9a-f]{32}', attempt.name))
    route_directory = str(attempt / 'routes')
    require(type(route_runtime_mount) is dict and set(route_runtime_mount) == {
        'Type', 'Source', 'Destination', 'Mode', 'RW', 'Propagation'}
        and route_runtime_mount['Type'] == 'bind' and route_runtime_mount['Destination'] == ROUTE_TARGET
        and route_runtime_mount['Mode'] == 'ro' and route_runtime_mount['RW'] is False
        and route_runtime_mount['Propagation'] == 'rprivate'
        and str(runtime_bind_source(route_runtime_mount['Source'])) == route_directory)
    require(isinstance(website_image_id, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', website_image_id))
    _data(data_before, set(services) - product.renewal.INITIALIZERS)
    require(digest(data_before) == anchor['data_sha256'])
    binding = combined_edge_binding(before, data_before['edge']['mounts'], anchor['root'])
    template = edge_template_identity(binding, edge_template)

    # Reuse only the ordinary deployer's pure service/route definitions. This
    # intermediate rendering object is never persisted as an independent owner.
    render = routing.next_state(None, manifest, routes, {'project': anchor['project']}, {
        'images': manifest['images'], 'openbao_didcomm_image': manifest['openbao_didcomm_image'],
        'configuration_sha256': 'sha256:' + digest(before)})
    overlay = routing.compose_overlay(render, before, PureWindowsPath(route_directory))
    # Reusing a fixed address or alias from edge would give the new service a
    # competing network identity. The initial contract accepts ordinary networks.
    networks = services['edge'].get('networks', {})
    require('network_mode' not in services['edge'] and type(networks) is dict and bool(networks)
        and type(before.get('networks')) is dict and set(networks) <= set(before['networks'])
        and all(value is None or type(value) is dict and
        set(value) <= {'priority', 'gw_priority'} and all(type(item) is int and item >= 0 for item in value.values())
        for value in networks.values()))
    staged = deepcopy(before)
    staged['services'][SLOT] = deepcopy(overlay['services'][SLOT])
    split = deepcopy(staged)
    split['services']['edge'].setdefault('volumes', []).extend(deepcopy(overlay['services']['edge']['volumes']))
    staged_data = deepcopy(data_before)
    staged_data[SLOT] = {'image': website_image_id, 'mounts': []}
    split_data = deepcopy(staged_data)
    split_data['edge']['mounts'].append(deepcopy(route_runtime_mount))
    split_data['edge']['mounts'].sort(key=lambda mount: mount['Destination'])
    return {'models': {'combined': deepcopy(before), 'staged': staged, 'split': split},
            'data': {'combined': deepcopy(data_before), 'staged': staged_data, 'split': split_data},
            'routes': {'combined': b'', 'staged': b'',
                       'split': managed_routes(render, edge_template)},
            'edge_template': template, 'route_directory': route_directory,
            'route_runtime_mount': deepcopy(route_runtime_mount)}


def plan(before, manifest, website_release, routes, anchor, *, proof_sha256, **kwargs):
    """Build a closed first-cutover declaration, never a runtime authorization."""
    proposed = proposal(before, manifest, website_release, routes, anchor, **kwargs)
    require(type(proof_sha256) is dict and set(proof_sha256) == product_journal.ARTIFACTS
            and all(sha(value) for value in proof_sha256.values())
            and proof_sha256['web-composition.json'] == selection.digest(ui.canonical(manifest)))
    value = {'schema': SCHEMA, 'operation': 'first-cutover', 'owner': deepcopy(anchor),
        'composition_id': manifest['composition_id'], 'proof_sha256': deepcopy(proof_sha256),
        'website': deepcopy(manifest['website']), 'application': deepcopy(manifest['application']),
        'backend': deepcopy(manifest['backend']), 'route_contract': deepcopy(manifest['route_contract']),
        'attempt_directory': kwargs['attempt_directory'], 'route_directory': proposed['route_directory'],
        'edge_template': proposed['edge_template'], 'route_runtime_mount': proposed['route_runtime_mount'],
        'declared_roles': [SLOT], 'mutable_existing_roles': ['edge'],
        'protected_roles': sorted(set(before['services']) - {'edge'}),
        'states': {name: {'model_sha256': digest(proposed['models'][name]),
                         'data_sha256': digest(proposed['data'][name]),
                         'routes_sha256': selection.digest(proposed['routes'][name])}
                   for name in ('combined', 'staged', 'split')},
        'backout': {'restore_state': 'staged', 'verify_state': 'staged', 'retire_candidate_state': 'combined',
                    'application_role': 'ui', 'preserved_selected_sha256': anchor['selected_sha256']},
        'qualification': deepcopy(UNQUALIFIED)}
    value['plan_sha256'] = digest(value)
    return value


def validate_envelope(value):
    """Closed record integrity, still requiring held-input validate_plan later."""
    require(type(value) is dict and set(value) == PLAN_FIELDS and value['schema'] == SCHEMA
            and value['operation'] == 'first-cutover')
    validate_anchor(value['owner'])
    require(type(value['qualification']) is dict and set(value['qualification']) == set(UNQUALIFIED)
            and all(flag is False for flag in value['qualification'].values()))
    require(value['declared_roles'] == [SLOT] and value['mutable_existing_roles'] == ['edge'])
    require(type(value['protected_roles']) is list and all(isinstance(role, str) for role in value['protected_roles'])
            and value['protected_roles'] == sorted(set(value['protected_roles']))
            and {'ui', 'gateway', *product.PROVIDER_ROLES} <= set(value['protected_roles'])
            and not {'edge', *routing.SLOTS}.intersection(value['protected_roles']))
    require(type(value['states']) is dict and set(value['states']) == {'combined', 'staged', 'split'})
    for state in value['states'].values():
        require(type(state) is dict and set(state) == {'model_sha256', 'data_sha256', 'routes_sha256'}
                and all(sha(item) for item in state.values()))
    require(value['states']['combined']['data_sha256'] == value['owner']['data_sha256']
            and value['states']['combined']['model_sha256'] == value['owner']['model_sha256']
            and value['states']['combined']['routes_sha256'] == value['states']['staged']['routes_sha256']
                == selection.digest(b''))
    require(value['backout'] == {'restore_state': 'staged', 'verify_state': 'staged',
        'retire_candidate_state': 'combined', 'application_role': 'ui',
        'preserved_selected_sha256': value['owner']['selected_sha256']})
    require(value['plan_sha256'] == digest({key: item for key, item in value.items() if key != 'plan_sha256'}))
    return value


def validate_plan(value, before, manifest, website_release, routes, anchor, *, proof_sha256, **kwargs):
    """Rebuild from original held inputs, rejecting extra fields and every drift."""
    validate_envelope(value)
    require(value == plan(before, manifest, website_release, routes, anchor, proof_sha256=proof_sha256, **kwargs))
    return value


def check_models(value, before, staged, split):
    """Check supplied source proposals against a previously reconstructed plan.

    A caller must first use validate_plan with the original held inputs. These
    digests do not authenticate a plan or qualify actual container identities.
    """
    validate_envelope(value)
    require(all(digest(model) == value['states'][name]['model_sha256']
                for name, model in (('combined', before), ('staged', staged), ('split', split))))
