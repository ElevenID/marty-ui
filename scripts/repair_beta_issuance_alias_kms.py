"""Narrow configuration repair for the native HTTP alias; caller owns beta lock."""
import json
import os
from pathlib import Path
import subprocess

from recover_unchanged_beta_cutover import docker


def prepare_alias_repair(root, artifacts, runtime_root, current, gateway_env, native):
    expected = {'INTEGRATION_SECRET_KMS_URL': 'https://signing-keys:8018/internal',
                'INTEGRATION_SECRET_KMS_CA_FILE': '/run/secrets/dev_integration_secret_ca'}
    before = dict(item.split('=', 1) for item in current['Config']['Env'])
    if all(before.get(key) == value for key, value in expected.items()):
        return None
    if any(key in before for key in expected):
        raise RuntimeError('Refusing to overwrite an existing alias KMS configuration')
    overlay = artifacts / 'issuance-alias-kms-forward.json'
    overlay.write_text(json.dumps({'services': {'issuance': {'environment': expected,
                       'secrets': ['dev_integration_secret_ca']}}}, indent=2) + '\n', encoding='utf8')
    labels = current['Config']['Labels']
    files = labels['com.docker.compose.project.config_files'].split(',')
    if any(not Path(name).resolve().is_relative_to(root) for name in files):
        raise RuntimeError('Alias Compose inputs must belong to the frozen source checkout')
    env = dict(os.environ, **{key: value for key, value in gateway_env.items()
                              if key in {'MARTY_RELEASE_VERSION', 'MARTY_UI_SHA', 'ELEVENID_STACK_VERSION',
                                         'ELEVENID_COMPONENT_REVISIONS_JSON', 'ELEVENID_IMAGE_DIGESTS_JSON'}})
    env.update(MARTY_NETWORK_NAME='elevenid-beta-network', MARTY_RUNTIME_CONFIG_ROOT=str(runtime_root))
    command = ['docker', 'compose', '--project-name', 'elevenid-beta']
    for name in labels['com.docker.compose.project.environment_file'].split(','):
        command += ['--env-file', name]
    for name in files + [str(overlay)]:
        command += ['-f', name]
    # Capture the resolved secret-bearing configuration in memory only.
    result = subprocess.run(command + ['config', '--format', 'json'], env=env, capture_output=True)
    if result.returncode:
        raise RuntimeError('Could not resolve alias repair Compose configuration')
    resolved = json.loads(result.stdout)
    service = resolved['services']['issuance']
    after = service['environment']
    image_env = dict(item.split('=', 1) for item in json.loads(docker('image', 'inspect', current['Image']))[0]['Config']['Env'])
    final = dict(image_env, **{key: str(value) for key, value in after.items()})
    differences = sorted(key for key in set(before) | set(final) if before.get(key) != final.get(key))
    if differences != sorted(expected) or any(final.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Alias repair would change other environment keys: ' + ', '.join(differences))
    if service['image'] != current['Image'] or service.get('entrypoint') != current['Config']['Entrypoint']:
        raise RuntimeError('Alias repair would change its image or executable')
    def normalized(value):
        return str(value).replace('\\', '/').lower()
    mounts = {}
    for mount in service.get('volumes', []):
        source = mount['source']
        if mount['type'] == 'volume':
            source = resolved['volumes'][source]['name']
        mounts[mount['target']] = (mount['type'], normalized(source), not mount.get('read_only', False))
    for secret in service.get('secrets', []):
        name = secret['source']
        target = secret.get('target', name)
        target = target if target.startswith('/') else '/run/secrets/' + target
        mounts[target] = (
            'bind', normalized(resolved['secrets'][name]['file']), False)
    original = {mount['Destination']: (mount['Type'], normalized(mount.get('Name', mount['Source'])), mount['RW'])
                for mount in current['Mounts']}
    ca = next(mount for mount in native['Mounts'] if mount['Destination'] == expected['INTEGRATION_SECRET_KMS_CA_FILE'])
    original[ca['Destination']] = ('bind', normalized(ca['Source']), False)
    if mounts != original:
        raise RuntimeError('Alias repair would change mounts beyond adding the native trusted CA')
    return command, env, overlay


def apply_alias_repair(prepared):
    command, env, _ = prepared
    result = subprocess.run(command + ['up', '--detach', '--no-build', '--no-deps', '--force-recreate', 'issuance'],
                            env=env, capture_output=True)
    if result.returncode:
        raise RuntimeError('Alias-only forward configuration repair failed; inspect beta')
