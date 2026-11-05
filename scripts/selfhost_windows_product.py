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
UI_FIXTURE_TARGETS = frozenset({'/opt/marty-ui-static', '/etc/nginx/conf.d/default.conf',
                              '/scripts/load-secrets-env.sh', '/docker-entrypoint.d/40-ui-selfhost.sh'})
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
        require(mount.get('type') == 'bind' and mount.get('read_only') is True,
                'UI fixture replacement cannot remove writable storage')
        return target
    require(isinstance(mount, str), 'Invalid UI mount')
    for target in UI_FIXTURE_TARGETS:
        if mount.endswith(':'+target+':ro'):
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
            'historical_roles': sorted(declared & HISTORICAL_ROLES),
            'initializers_never_run': sorted(renewal.INITIALIZERS)}


def migration_sources(checkout, source_sha):
    """Fingerprint migration source inputs, not a claim of reversible DB writes.

    Runtime schema/custody checks remain required. Changed migration inputs need
    separate qualified migration evidence and cannot use image-only rollback.
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
