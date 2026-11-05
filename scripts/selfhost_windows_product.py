"""Typed Windows product transition contracts for the existing generation owner.

Planning is inert. A plan never authenticates a composition or authorizes runtime
writes: the transition owner must consume the existing verified-package context,
retain its inputs, prove native custody and commit real transition evidence.
Ordinary credential continuation and Applicant repair remain distinct operations.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess

import package_web_composition as composition
import selfhost_windows_renewal as renewal

SCHEMA = 'marty.windows-product-transition/v1'
PROVIDER_ROLES = renewal.BAO_ROLES | {'openbao-bootstrap'}
HISTORICAL_ROLES = frozenset({'openbao-tls-init'})
MIGRATION_ROLES = frozenset({'db-migrate'})
UI_FIXTURE_TARGETS = frozenset({'/opt/marty-ui-static', '/etc/nginx/conf.d/default.conf',
                              '/scripts/load-secrets-env.sh', '/docker-entrypoint.d/40-ui-selfhost.sh'})
UI_SHORT_FIXTURES = {'/etc/nginx/conf.d/default.conf': './ui/nginx.spa.conf',
                     '/scripts/load-secrets-env.sh': './scripts/load-secrets-env.sh',
                     '/docker-entrypoint.d/40-ui-selfhost.sh': './scripts/ui-selfhost-start.sh'}
IMAGE = re.compile(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z')
MIGRATION_INPUTS = frozenset({'services/Dockerfile.migrations', 'services/Dockerfile.migrations.dockerignore',
                             'scripts/load-secrets-env.sh', 'scripts/run-migrations-with-secrets.sh',
                             'docker/init-databases.sh'})


def require(value, message='Admitted product transition refused'):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fixture_target(mount):
    """Recognize only the exact read-only local UI code mounts being replaced."""
    if isinstance(mount, dict):
        target = mount.get('target')
        if target not in UI_FIXTURE_TARGETS:
            return None
        require(mount.get('type') == 'bind' and mount.get('read_only') is True
                and isinstance(mount.get('source'), str) and mount['source'],
                'UI fixture replacement cannot remove writable storage')
        return target
    require(isinstance(mount, str), 'Invalid UI mount')
    for target in UI_FIXTURE_TARGETS:
        if mount.endswith(':'+target+':ro'):
            require(target in UI_SHORT_FIXTURES and mount == UI_SHORT_FIXTURES[target]+':'+target+':ro',
                    'Short UI fixture source is not the retained code bind')
            return target
        require(not mount.endswith(':'+target) and not mount.endswith(':'+target+':rw'),
                'UI fixture replacement cannot remove writable storage')
    return None


def product_model(before, admitted):
    """Exact image replacement and the one supported local-to-packaged UI shape.

    `admitted` must come from verified_package at the runtime boundary. These
    structural checks are additional constraints, never signature verification.
    No ports, network, writable storage, credential or environment change is
    inferred from a new image or from an artifact-supplied executable.
    """
    require(admitted.get('schema') == composition.SCHEMA and admitted.get('platform') == 'linux/amd64'
            and admitted.get('kms_provider') == 'openbao' and admitted.get('production_pages') == 'full')
    services = before.get('services');images = admitted.get('images')
    require(isinstance(services, dict) and isinstance(images, dict)
            and PROVIDER_ROLES <= services.keys() and set(images) == set(services)-PROVIDER_ROLES,
            'Signed product role closure differs')
    references = [*images.values(), admitted.get('openbao_didcomm_image')]
    require(all(isinstance(ref, str) and IMAGE.fullmatch(ref) for ref in references),
            'Product images must be exact digest references')
    require('ui' in images and admitted.get('application', {}).get('image') == {
        'uri': images['ui'].split('@', 1)[0], 'digest': images['ui'].split('@', 1)[1], 'platform': 'linux/amd64'},
        'Application image differs from signed composition')
    after = deepcopy(before)
    for role, service in after['services'].items():
        require(isinstance(service, dict) and not service.get('build'))
        service['image'] = admitted['openbao_didcomm_image'] if role in PROVIDER_ROLES else images[role]
    ui = after['services']['ui']
    require(ui.get('entrypoint') is None and ui.get('command') is None,
            'Packaged UI requires its authenticated image startup configuration')
    mounts = ui.get('volumes', [])
    found = [fixture_target(mount) for mount in mounts]
    targets = [target for target in found if target is not None]
    require(not targets or len(targets) == len(set(targets)) and set(targets) == UI_FIXTURE_TARGETS,
            'Partial or duplicate local UI fixture mounts')
    if targets:
        retained = [mount for mount, target in zip(mounts, found) if target is None]
        if retained:ui['volumes'] = retained
        else:ui.pop('volumes', None)
    return after


def checked_model_change(before, after, admitted):
    require(product_model(before, admitted) == after, 'Model changed beyond admitted product contract')
    declared = {role for role in before['services'] if before['services'][role] != after['services'][role]}
    mutable = declared - renewal.INITIALIZERS - HISTORICAL_ROLES
    return {'declared_roles': sorted(declared), 'mutable_roles': sorted(mutable),
            'provider_roles': sorted(mutable & PROVIDER_ROLES),
            'migration_roles': sorted(mutable & MIGRATION_ROLES),
            'application_roles': sorted(mutable-PROVIDER_ROLES-MIGRATION_ROLES),
            'historical_roles': sorted(declared & HISTORICAL_ROLES),
            'initializers_never_run': sorted(renewal.INITIALIZERS)}


def checked_runtime_change(before, after, old_model, new_model, admitted, image_ids):
    """Prove the narrow runtime data edge, without granting journal authority.

    The caller must separately authenticate/pin image metadata, hold model and
    credential inputs, prove custody/readiness and retain real execution receipts.
    Here every mount (including credentials) must survive byte-for-byte except
    the four exact read-only UI fixtures. Initializer identities cannot change.
    An image config ID is not a registry signature or a reversible schema proof.
    """
    change = checked_model_change(old_model, new_model, admitted)
    require(isinstance(before, list) and isinstance(after, list))
    def indexed(items):
        result = {}
        for item in items:
            require(isinstance(item, dict) and renewal._project(item) is not None)
            role = renewal._service(item)
            require(role in old_model['services'] and role not in result)
            require(isinstance(item.get('Id'), str) and re.fullmatch(r'[0-9a-f]{64}', item['Id']))
            require(isinstance(item.get('Image'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', item['Image']))
            require(isinstance(item.get('Mounts'), list))
            require(all(isinstance(mount, dict) for mount in item['Mounts']))
            destinations = [mount.get('Destination') for mount in item['Mounts']]
            require(all(isinstance(target, str) and target.startswith('/') for target in destinations)
                    and len(destinations) == len(set(destinations)), 'Ambiguous runtime mounts')
            result[role] = item
        require(len({item['Id'] for item in result.values()}) == len(result), 'Duplicate runtime container identity')
        return result
    old = indexed(before);new = indexed(after)
    roles = set(old_model['services'])-renewal.INITIALIZERS
    require(set(old) == set(new) == roles, 'Runtime product role closure differs')
    projects = {renewal._project(item) for item in [*before, *after]}
    require(len(projects) == 1 and all(isinstance(name, str) and
            re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', name) for name in projects),
            'Runtime product project differs')
    require(isinstance(image_ids, dict) and set(image_ids) == roles-HISTORICAL_ROLES
            and all(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)
                    for value in image_ids.values()), 'Qualified image ID closure differs')
    fixture_removed = bool(old_model['services']['ui'].get('volumes')) and (
        old_model['services']['ui'].get('volumes') != new_model['services']['ui'].get('volumes'))
    for role in sorted(roles):
        prior = old[role];current = new[role]
        if role in HISTORICAL_ROLES:
            require(current == prior, 'Historical initializer changed')
            continue
        require(current['Image'] == image_ids[role], 'Runtime image differs from qualified image')
        mounts = deepcopy(prior['Mounts'])
        if role == 'ui' and fixture_removed:
            fixtures = [mount for mount in mounts if mount['Destination'] in UI_FIXTURE_TARGETS]
            require({mount['Destination'] for mount in fixtures} == UI_FIXTURE_TARGETS
                    and all(mount.get('Type') == 'bind' and mount.get('RW') is False for mount in fixtures),
                    'Runtime UI fixture mounts differ')
            mounts = [mount for mount in mounts if mount['Destination'] not in UI_FIXTURE_TARGETS]
        require(sorted(mounts, key=lambda mount: mount['Destination']) ==
                sorted(current['Mounts'], key=lambda mount: mount['Destination']),
                'Product transition changed retained storage or credentials')
        if role not in change['mutable_roles']:
            require(current == prior, 'Unchanged runtime role changed')
    # Match the existing generation owner's newline-terminated data fingerprint.
    return {'before_sha256': hashlib.sha256(canonical(renewal.data_mounts(before))+b'\n').hexdigest(),
            'after_sha256': hashlib.sha256(canonical(renewal.data_mounts(after))+b'\n').hexdigest(),
            'roles': sorted(roles), 'ui_fixture_mounts_removed': fixture_removed}


def migration_sources(checkout, source_sha):
    """Fingerprint migration source inputs, not a claim of reversible DB writes.

    This is a diagnostic filename inventory, not the executable build closure:
    compiler dependencies and ordinary startup source can also change database
    behavior. Equality never authorizes migration execution or image rollback.
    Separate qualified schema/custody and migration evidence remain required.
    """
    require(isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{40}', source_sha))
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(Path(checkout)),
                             'ls-tree', '-rz', '--full-tree', source_sha],
                            capture_output=True, check=True, timeout=30)
    require(len(result.stdout) <= 16*1024*1024, 'Migration source inventory is too large')
    rows = {}
    for line in result.stdout.decode('utf-8').split('\0'):
        if not line:continue
        metadata, name = line.split('\t', 1)
        runtime = name.startswith(('rust/', 'services/', 'docker/', 'openbao/', 'keycloak/'))
        selected = name in MIGRATION_INPUTS or runtime and (
            name.endswith('.sql') or '/migrations/' in name or 'migration' in Path(name).name)
        if selected:
            mode, kind, object_sha = metadata.split()
            require(kind == 'blob' and mode in {'100644', '100755'}, 'Migration input is not a regular source blob')
            rows[name] = {'mode': mode, 'blob': object_sha}
    require(rows and MIGRATION_INPUTS <= rows.keys(), 'Migration source closure is incomplete')
    return {'source_sha': source_sha, 'files': rows, 'sha256': digest(rows)}
