"""Bounded post-migration simulator startup; caller owns the beta mutation lock.

Never invokes migrations, bootstrap, token issuance, or database recovery. The
only configuration delta from the frozen Compose model is preservation of the
already provisioned scoped callback token file through the shared entrypoint.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

from recover_unchanged_beta_cutover import docker, inspect, wait_healthy

CALLBACK = {'passport-callback-signer', 'passport-beta-bureau'}
NETWORK = 'elevenid-beta-passport-callback-signing'
CANVAS = {
    'CANVAS_LTI_EXPERIENCE_BASE_URL': 'https://beta.elevenidllc.com',
    'CANVAS_OAUTH_COMPLETION_REDIRECT_URL': 'https://beta.elevenidllc.com/console/org/deploy/canvas',
    'CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID': '00000000-0000-0000-0000-000000000001',
    'CANVAS_LTI_TOOL_ISSUER_DID': 'did:web:beta.elevenidllc.com:orgs:marty',
    'CANVAS_PORTABLE_INTEGRATION_ENABLED': 'true',
    'CANVAS_PILOT_ORGANIZATION_IDS': '00000000-0000-0000-0000-000000000001',
    'CANVAS_LEGACY_EVENT_INGEST_ENABLED': 'false',
    'CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST': 'https://canvas-test.elevenidllc.com',
    'CANVAS_ALLOW_PRIVATE_BASE_URLS': 'false',
    'CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS': 'false',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def environment(container):
    return dict(item.split('=', 1) for item in container['Config']['Env'])


def retained_log(path):
    """Windows PowerShell Tee-Object writes UTF-16; preserve/hash original bytes."""
    raw = path.read_bytes()
    return raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')


def validate_overlay(before, after):
    expected = copy.deepcopy(before)
    env = expected['services']['passport-callback-signer']['environment']
    require('PRESERVE_BAO_TOKEN_FILE' not in env, 'Frozen signer already preserves token file')
    env['PRESERVE_BAO_TOKEN_FILE'] = '1'
    require(after == expected, 'Forward overlay changes more than the scoped token-file flag')


def validate_phase(current, prior, images):
    previous = {row['service']: row for row in prior}
    roles = set(images) - {'ui-prod'}
    require(roles - CALLBACK == set(previous) - {'ui-prod', 'keycloak'},
            'Simulator role selection differs from prior deployment')
    require(len(roles) == 21 and CALLBACK <= roles, 'Unexpected simulator application inventory')
    for role in roles:
        c = current[role]
        if role in CALLBACK:
            require(c['Image'] == images[role] and c['State']['Status'] in {'created', 'restarting', 'running'},
                    'Callback role is not a prepared candidate: ' + role)
        else:
            p = previous[role]
            require(c['Id'].startswith(p['container_id']) and c['Image'] == p['image_id']
                    and not c['State']['Running'] and c['State']['Status'] == 'exited',
                    'Prior application must remain exactly stopped: ' + role)
    ui, old_ui = current['ui-prod'], previous['ui-prod']
    require(ui['Id'].startswith(old_ui['container_id']) and ui['Image'] == old_ui['image_id']
            and not ui['State']['Running'], 'Prior UI must remain exactly stopped')
    kc = current['keycloak']
    require(not kc['Id'].startswith(previous['keycloak']['container_id'])
            and kc['State'].get('Health', {}).get('Status') == 'healthy',
            'New Keycloak must already be healthy')


def validate_network(network, allowed, *, complete=False):
    require(network['Name'] == NETWORK and network['Internal'] is True
            and network['Labels'].get('com.docker.compose.project') == 'elevenid-beta'
            and network['Labels'].get('com.docker.compose.network') == 'passport-callback-signing',
            'Unexpected callback network identity')
    members = set(network.get('Containers') or {})
    require(members <= set(allowed), 'Unexpected callback network authority')
    require(not complete or members == set(allowed), 'Incomplete callback network membership')


def prepare(root, artifacts, runtime_root, source, images, prior, observe, failure_proof):
    require(failure_proof is not None and failure_proof.is_file(), 'Reviewed failed-rollout proof is required')
    failure = json.loads(failure_proof.read_text(encoding='utf-8-sig'))
    require(failure.get('scope') == 'ACTUAL_R31_POST_MIGRATION_CALLBACK_STARTUP_FAILURE'
            and failure.get('sourceId') == source['marty_ui_sha']
            and failure.get('sourceRevision') == next(row['revision'] for row in source['component_revisions']
                                                      if row['component'] == 'marty-ui')
            and failure.get('operatorExitCode') == 1 and failure.get('betaDeployed') is False
            and failure.get('backupPhase') == 'maintenance_quiesced'
            and failure.get('backupFilesHashVerified') == 7
            and failure.get('actualError') == 'inline or shared OpenBao credentials are forbidden',
            'Failure proof does not establish this exact post-migration interruption')
    for name, digest in failure['proofHashes'].items():
        require(hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest,
                'Retained failed-rollout proof input changed')
    failed_runtime = Path(failure['immutableFailedRolloutReceipt'])
    require(hashlib.sha256(failed_runtime.read_bytes()).hexdigest() == failure['failedRolloutReceiptSha256'],
            'Original failed rollout receipt changed')
    current = {role: observe(role) for role in set(images) | {'keycloak'}}
    validate_phase(current, prior, images)
    failed = {row['service']: row for row in failure['observedContainers']}
    require(all(current[role]['Id'] == failed[role]['id']
                and current[role]['Image'] == failed[role]['image']
                for role in set(images) | {'keycloak'}),
            'Interrupted container identities differ from reviewed failure proof')
    signer = current['passport-callback-signer']
    before_env = environment(signer)
    require(before_env.get('BAO_TOKEN_FILE') == '/bao/passport-callback/token'
            and not any(key in before_env for key in ('BAO_TOKEN', 'OPENBAO_SERVICE_TOKEN', 'OPENBAO_SERVICE_TOKEN_FILE')),
            'Prepared callback signer must retain only its scoped file credential')
    old_native = environment(current['issuance-native'])
    # Compare selected preserved runtime contract, never infer broader authority.
    for key, value in CANVAS.items():
        if key in old_native:
            require(old_native[key] == value, 'Retained Canvas configuration differs: ' + key)
    components = {row['component']: row['revision'] for row in source['component_revisions']}
    env = dict(os.environ, **CANVAS, MARTY_NETWORK_NAME='elevenid-beta-network',
               MARTY_RUNTIME_CONFIG_ROOT=str(runtime_root), MARTY_SERVICES_IMAGE=images['passport-callback-signer'],
               MARTY_RELEASE_VERSION=source['release_version'], MARTY_UI_SHA=source['marty_ui_sha'],
               ELEVENID_STACK_VERSION=(root / 'VERSION').read_text().strip(),
               ELEVENID_COMPONENT_REVISIONS_JSON=json.dumps(components, separators=(',', ':')),
               ELEVENID_IMAGE_DIGESTS_JSON=json.dumps(images, separators=(',', ':')))
    labels = signer['Config']['Labels']
    files = labels['com.docker.compose.project.config_files'].split(',')
    require(files and all(Path(name).resolve().is_relative_to(root) and Path(name).is_file() for name in files),
            'Compose inputs must be existing frozen source/artifact files')
    command = ['docker', 'compose', '--project-name', 'elevenid-beta']
    env_files = labels['com.docker.compose.project.environment_file'].split(',')
    for name in env_files:
        require(Path(name).is_absolute() and Path(name).is_file(), 'Missing retained private environment input')
        command += ['--env-file', name]
    for name in files:
        command += ['-f', name]

    def render(args):
        result = subprocess.run(args + ['config', '--format', 'json'], env=env, capture_output=True)
        require(result.returncode == 0, 'Could not resolve retained frozen Compose configuration')
        return json.loads(result.stdout)

    before = render(command)
    image_env = dict(item.split('=', 1) for item in json.loads(
        docker('image', 'inspect', signer['Image']))[0]['Config']['Env'])
    rendered_signer = before['services']['passport-callback-signer']
    require(dict(image_env, **{key: str(value) for key, value in rendered_signer['environment'].items()})
            == before_env, 'Frozen Compose does not reproduce the exact failed signer environment')
    overlay = artifacts / 'passport-callback-token-file-forward.json'
    contents = json.dumps({'services': {'passport-callback-signer': {
        'environment': {'PRESERVE_BAO_TOKEN_FILE': '1'}}}}, indent=2) + '\n'
    if overlay.exists():
        require(overlay.read_text() == contents, 'Existing forward overlay differs')
    else:
        overlay.write_text(contents, encoding='utf8')
    command += ['-f', str(overlay)]
    model = render(command)
    validate_overlay(before, model)
    for role, image in images.items():
        if role != 'ui-prod':
            require(model['services'][role]['image'] == image, 'Rendered role image differs: ' + role)
    gateway_env = model['services']['gateway']['environment']
    require(gateway_env.get('MARTY_UI_SHA') == source['marty_ui_sha']
            and gateway_env.get('MARTY_RELEASE_VERSION') == source['release_version']
            and json.loads(gateway_env['ELEVENID_COMPONENT_REVISIONS_JSON']) == components
            and json.loads(gateway_env['ELEVENID_IMAGE_DIGESTS_JSON']) == images,
            'Rendered release bindings differ')
    from validate_beta_passport_configuration import validate_model
    validate_model(model, passport_enabled=True, files=files,
                   prepared_services_image=images['passport-callback-signer'])
    logs = ['migration-live.log', 'revocation-migration-live.log', 'issuance-migration-live.log',
            'issuance-migration-live-verify.log', 'verification-migration-live.log',
            'keycloak-configurator-kms.log', 'passport-callback-provision-live.log']
    proofs = {}
    for name in logs:
        path = artifacts / 'logs' / name
        require(path.is_file() and path.stat().st_size > 0, 'Missing completed migration/configuration log')
        proofs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    require('Success! Uploaded policy: passport-callback-hmac-service' in
            retained_log(artifacts / 'logs/passport-callback-provision-live.log'),
            'Scoped callback provisioning was not completed')
    bao = observe('openbao')
    require(bao['State']['Running'] and bao['Config']['Cmd'] == ['server', '-config=/bao/config/openbao.hcl']
            and any(m.get('Name') == 'elevenid-beta_openbao_data' and m['Destination'] == '/bao/data'
                    and m['RW'] for m in bao['Mounts']), 'Preserved Raft OpenBao custody differs')
    network = json.loads(docker('network', 'inspect', NETWORK))[0]
    allowed = {bao['Id'], *(current[role]['Id'] for role in CALLBACK)}
    validate_network(network, allowed)
    return dict(current=current, command=command, env=env, overlay=overlay, gateway_env=gateway_env,
                network_id=network['Id'], openbao_id=bao['Id'], migration_logs=proofs,
                failure_proof=str(failure_proof), failure_proof_sha256=hashlib.sha256(failure_proof.read_bytes()).hexdigest(),
                compose_inputs={name: hashlib.sha256(Path(name).read_bytes()).hexdigest()
                                for name in files + env_files + [str(overlay)]})


def apply(prepared, images, observe, record):
    for name, digest in prepared['compose_inputs'].items():
        require(hashlib.sha256(Path(name).read_bytes()).hexdigest() == digest,
                'Prepared Compose/private input changed before completion')
    require(hashlib.sha256(Path(prepared['failure_proof']).read_bytes()).hexdigest()
            == prepared['failure_proof_sha256'], 'Reviewed failed-rollout proof changed')
    for role, previous in prepared['current'].items():
        require(observe(role)['Id'] == previous['Id'], 'Prepared role identity changed')

    def recreate(roles):
        result = subprocess.run(prepared['command'] + ['up', '--detach', '--no-build', '--no-deps',
                                '--force-recreate', *sorted(roles)], env=prepared['env'], capture_output=True)
        require(result.returncode == 0, 'Forward-only application recreation failed; retain pending marker')

    recreate(CALLBACK)
    callbacks = {role: observe(role, images[role]) for role in CALLBACK}
    network = json.loads(docker('network', 'inspect', NETWORK))[0]
    require(network['Id'] == prepared['network_id'], 'Callback network was replaced')
    allowed = {prepared['openbao_id'], *(c['Id'] for c in callbacks.values())}
    validate_network(network, allowed)
    if prepared['openbao_id'] not in (network.get('Containers') or {}):
        docker('network', 'connect', '--alias', 'openbao', network['Id'], prepared['openbao_id'])
    network = json.loads(docker('network', 'inspect', NETWORK))[0]
    validate_network(network, allowed, complete=True)
    endpoint = inspect(prepared['openbao_id'])['NetworkSettings']['Networks'][NETWORK]
    require('openbao' in endpoint['Aliases'], 'OpenBao callback alias is missing')
    wait_healthy([record(role, c) for role, c in callbacks.items()])
    recreate(set(images) - CALLBACK - {'ui-prod'})
    return {role: observe(role, images[role]) for role in set(images) - {'ui-prod'}}
