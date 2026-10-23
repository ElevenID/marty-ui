"""Finish an interrupted local beta application startup without replaying migrations.

Run only through the PowerShell entrypoint, which holds the host mutation mutex
and verifies the retained state volumes and passport boundary. Source and image
bindings come from retained artifacts, never from the running API's claims.
The explicit read-only evidence refresh mode may run directly; it observes the
same containers without invoking startup and writes only fresh evidence files.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.request import Request, urlopen

from bind_deployed_demo_manifest import bind_manifest
from recover_unchanged_beta_cutover import docker, inspect, public_json, wait_healthy
from repair_beta_issuance_alias_kms import prepare_alias_repair, apply_alias_repair


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def observe(role, image=None):
    project = 'elevenid-beta-ui' if role == 'ui-prod' else 'elevenid-beta'
    ids = docker('ps', '-a', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + project,
                 '--filter', 'label=com.docker.compose.service=' + role, '--format', '{{.ID}}').decode().splitlines()
    require(len(ids) == 1, 'Missing or ambiguous beta role: ' + role)
    current = inspect(ids[0])
    require(current['Config']['Labels']['com.docker.compose.project'] == project,
            'Unexpected container owner')
    require(current['Config']['Labels']['com.docker.compose.service'] == role,
            'Unexpected container role')
    require(image is None or current['Image'] == image, 'Candidate image mismatch: ' + role)
    return current


# Same public release markers emitted by the coordinated deployment writer.
MARKER_ENVIRONMENT_NAMES = frozenset({
    'MARTY_RELEASE_VERSION', 'MARTY_UI_SHA', 'ELEVENID_STACK_VERSION',
    'ELEVENID_COMPONENT_REVISIONS_JSON', 'ELEVENID_IMAGE_DIGESTS_JSON',
})


def marker_environment(current):
    result = {}
    for entry in current.get('Config', {}).get('Env', []):
        require(isinstance(entry, str) and '=' in entry, 'Malformed runtime environment observation')
        name, value = entry.split('=', 1)
        if name in MARKER_ENVIRONMENT_NAMES:
            require(name not in result, 'Duplicate runtime marker: ' + name)
            result[name] = value
    return result


def record(role, current):
    return dict(service=role, container_id=current['Id'], container=current['Name'].lstrip('/'),
                configured_image=current['Config']['Image'], image_id=current['Image'],
                status=current['State']['Status'], running=current['State']['Running'],
                started_at=current['State']['StartedAt'], health=current['State'].get('Health', {}).get('Status'),
                compose_project=current['Config']['Labels']['com.docker.compose.project'], compose_service=role,
                runtime_marker_environment=marker_environment(current))


def verify_marker(actual, expected):
    require(all(actual.get(key) == value for key, value in expected.items()),
            'Runtime marker differs from frozen source/image bindings')


def complete(root, artifacts, runtime_root, apply, passport_simulator=False, failure_proof=None):
    require(artifacts.is_relative_to(root / 'tests/artifacts'), 'Artifacts must belong to frozen source checkout')
    source = load(artifacts / 'source-manifest.json')
    subprocess.run(['python', str(root / 'scripts/create_local_release_manifest.py'), '--workspace',
                    str(root.parent), '--verify-manifest', str(artifacts / 'source-manifest.json')], check=True)
    require(source['source_kind'] == 'local-worktree-snapshot' and not source['promotion_eligible'],
            'Completion is restricted to nonpromotable local developer builds')
    backup = load(artifacts / 'backup-manifest.json')
    require(backup['phase'] == 'maintenance_quiesced' and backup['application_writers_stopped'] is True,
            'Quiesced backup is required')
    for item in backup['files']:
        require(Path(item['name']).name == item['name'], 'Invalid backup filename')
        require(sha(artifacts / 'backup' / item['name']) == item['sha256'], 'Retained backup changed')
    images = load(artifacts / 'image-digests.json')
    prior = load(artifacts / 'pre-deploy-containers.json')
    roles = set(images) - {'ui-prod'}
    require(passport_simulator or roles == {row['service'] for row in prior if row['service'] not in {'keycloak', 'ui-prod'}},
            'Candidate role set differs from retained deployment selection')
    require(not docker('ps', '--filter', 'label=com.docker.compose.project=elevenid-beta',
                       '--filter', 'label=com.docker.compose.oneoff=True', '--format', '{{.ID}}').strip(),
            'An active beta one-off job blocks completion')
    components = {row['component']: row['revision'] for row in source['component_revisions']}
    stack = (root / 'VERSION').read_text(encoding='utf8').strip()
    expected = dict(release_version=source['release_version'], marty_ui_sha=source['marty_ui_sha'],
                    deployment_release_marker=source['release_version'], stack_version=stack,
                    mip_version='0.5.0', component_revisions=components, image_digests=images)
    simulator = None
    operator_revision = None
    prior_ids = {row['service']: row['container_id'] for row in prior}
    if passport_simulator:
        operator_root = Path(__file__).resolve().parents[1]
        require(not subprocess.check_output(['git', '-C', str(operator_root), 'status', '--porcelain']),
                'Simulator completion requires a clean reviewable operator checkpoint')
        operator_revision = subprocess.check_output(
            ['git', '-C', str(operator_root), 'rev-parse', 'HEAD'], text=True).strip()
        from complete_beta_passport_simulator import prepare
        simulator = prepare(root, artifacts, runtime_root, source, images, prior, observe, failure_proof)
        candidates = {role: simulator['current'][role] for role in roles}
        gateway_env = simulator['gateway_env']
    else:
        candidates = {role: observe(role, images[role]) for role in sorted(roles)}
        prior_ids = {row['service']: row['container_id'] for row in prior}
        require(all(not current['Id'].startswith(prior_ids[role]) for role, current in candidates.items()),
                'All application roles must already have been recreated by the migration-gated runner')
        gateway_env = dict(item.split('=', 1) for item in candidates['gateway']['Config']['Env'])
        require(gateway_env['MARTY_RELEASE_VERSION'] == source['release_version'] and
                gateway_env['MARTY_UI_SHA'] == source['marty_ui_sha'] and
                json.loads(gateway_env['ELEVENID_COMPONENT_REVISIONS_JSON']) == components and
                json.loads(gateway_env['ELEVENID_IMAGE_DIGESTS_JSON']) == images,
                'Prepared gateway configuration differs from frozen artifacts')
        for role, current in candidates.items():
            require(current['State']['Status'] in {'created', 'running', 'restarting'},
                    'Candidate is not a prepared startup container: ' + role)
    keycloak = observe('keycloak')
    require(not keycloak['Id'].startswith(prior_ids['keycloak']), 'Keycloak recreation phase was not reached')
    require(keycloak['State'].get('Health', {}).get('Status') == 'healthy', 'Keycloak is not healthy')
    ui_image = json.loads(docker('image', 'inspect', images['ui-prod']))[0]
    labels = ui_image['Config']['Labels']
    require(labels['org.opencontainers.image.revision'] == source['marty_ui_sha'] and
            labels['org.opencontainers.image.version'] == source['release_version'], 'UI image metadata mismatch')
    runtime_manifest = runtime_root / 'runtime-config-manifest.json'
    require(runtime_root.name == source['marty_ui_sha'] and runtime_manifest.is_file(),
            'Durable runtime configuration is not bound to candidate source')
    config = load(runtime_manifest)
    require(config['marty_ui_revision'] == source['marty_ui_sha'], 'Runtime configuration source mismatch')
    for item in config['files']:
        path = (runtime_root / item['path']).resolve()
        require(path.is_relative_to(runtime_root) and sha(path) == item['sha256'],
                'Durable runtime configuration bytes changed')
    alias_repair = None if simulator else prepare_alias_repair(
        root, artifacts, runtime_root, candidates['issuance'], gateway_env, candidates['issuance-native'])
    result = dict(scope='LOCAL_BETA_FORWARD_STARTUP', sourceRevision=components['marty-ui'],
                  sourceId=source['marty_ui_sha'], release=source['release_version'],
                  sourceManifestSha256=sha(artifacts / 'source-manifest.json'),
                  candidateContainerCount=len(candidates), applied=False, productionDemoQualified=False)
    if simulator:
        result.update(operatorSourceRevision=operator_revision, operatorScriptSha256=sha(Path(__file__)),
                      simulatorOperatorSha256=sha(Path(__file__).with_name('complete_beta_passport_simulator.py')))
        result['passportSimulatorCompletion'] = dict(
            overlay=str(simulator['overlay']), overlaySha256=sha(simulator['overlay']),
            composeInputHashes=simulator['compose_inputs'], migrationLogHashes=simulator['migration_logs'],
            failedRolloutProof=simulator['failure_proof'], failedRolloutProofSha256=simulator['failure_proof_sha256'],
            priorContainerIds={role: c['Id'] for role, c in simulator['current'].items()},
            callbackNetworkId=simulator['network_id'])
    result['issuanceAliasKmsRepairRequired'] = alias_repair is not None
    if not apply:
        return result
    if simulator:
        from complete_beta_passport_simulator import apply as apply_simulator
        candidates = apply_simulator(simulator, images, observe, record)
    # Recheck each frozen container ID before starting only the unstarted roles.
    for role, current in candidates.items():
        require(observe(role, images[role])['Id'] == current['Id'], 'Candidate replaced during completion')
    unstarted = [current['Id'] for current in candidates.values() if current['State']['Status'] == 'created']
    if unstarted:
        docker('start', *unstarted)
    if alias_repair:
        apply_alias_repair(alias_repair)
        candidates['issuance'] = observe('issuance', images['issuance'])
    wait_healthy([record(role, current) for role, current in candidates.items()])
    # UI is stateless; recreate only this role from the already frozen image.
    import os
    env = dict(os.environ, MARTY_UI_RELEASE_IMAGE=images['ui-prod'], MARTY_NETWORK_NAME='elevenid-beta-network')
    subprocess.run(['docker', 'compose', '--project-name', 'elevenid-beta-ui', '-f',
                    str(root / 'docker-compose.ui-release.yml'), 'up', '--detach', '--no-build',
                    '--force-recreate', 'ui-prod'], env=env, check=True, capture_output=True)
    ui = observe('ui-prod', images['ui-prod'])
    wait_healthy([record('ui-prod', ui)])
    native = json.loads(docker('exec', candidates['issuance-native']['Id'], 'curl', '--fail', '--silent',
                               '--show-error', 'http://127.0.0.1:8005/version'))
    verify_marker(native, dict(service='issuance-service', version=source['release_version'],
                               build_revision=source['marty_ui_sha']))
    markers = {}
    for name, origin in [('local', 'http://127.0.0.1:8000'), ('beta', 'https://beta.elevenidllc.com')]:
        discovery = public_json(origin + '/.well-known/openid-credential-issuer')
        require(all(discovery.get(key) for key in ['credential_issuer', 'credential_endpoint', 'nonce_endpoint']),
                'Incomplete native issuance discovery')
        req = Request(origin + '/v1/issuance/nonce', data=b'{}',
                      headers={'Content-Type': 'application/json', 'User-Agent': 'elevenid-beta-health/1'})
        with urlopen(req, timeout=30) as response:
            nonce = json.load(response)
        require(re.fullmatch('[A-Za-z0-9_-]{43}', nonce.get('c_nonce', '')), 'Invalid issuance nonce')
        markers[name] = public_json(origin + '/.well-known/marty-release')
        verify_marker(markers[name], expected)
    ui_marker = dict(component='ui', release_version=source['release_version'], marty_ui_sha=source['marty_ui_sha'])
    for origin in ['http://127.0.0.1:3002', 'https://beta.elevenidllc.com']:
        verify_marker(public_json(origin + '/marty-ui-release.json'), ui_marker)
    deployed = bind_manifest(load(root / 'ui/public/demos/manifests' / (stack + '.json')), source, images)
    (artifacts / 'deployed-demo-manifest.json').write_text(json.dumps(deployed, indent=2) + '\n', encoding='utf8')
    records = [record(role, observe(role, images[role])) for role in sorted(images)]
    manifest = dict(schema_version=1, release_version=source['release_version'], stack_version=stack,
                    mip_version='0.5.0', source_kind=source['source_kind'], marty_ui_sha=source['marty_ui_sha'],
                    beta_origin='https://beta.elevenidllc.com', passport_provider_mode='simulator' if simulator else 'off',
                    compose_project='elevenid-beta', ui_compose_project='elevenid-beta-ui',
                    network='elevenid-beta-network', promotion_eligible=False, release_ready=False,
                    backup_manifest='backup-manifest.json', source_manifest='source-manifest.json',
                    official_stack_manifest=None, official_stack_manifest_sha256=None,
                    runtime_config_root=str(runtime_manifest.parent), runtime_config_manifest_sha256=sha(runtime_manifest),
                    verification_migration_image=images['verification'], component_revisions=components,
                    deployed_demo_manifest='deployed-demo-manifest.json',
                    deployed_demo_manifest_sha256=sha(artifacts / 'deployed-demo-manifest.json'),
                    services_marker=markers['local'], issuance_native_marker=native, ui_marker=ui_marker,
                    images=records, canvas_portable_configuration=dict(enabled=bool(simulator),
                        canvas_origin='https://canvas-test.elevenidllc.com' if simulator else None,
                        pilot_organization_id='00000000-0000-0000-0000-000000000001' if simulator else None,
                        lti_issuer_did='did:web:beta.elevenidllc.com:orgs:marty' if simulator else None,
                        signing_resolution='organization-scoped-issuer-did' if simulator else None,
                        legacy_event_ingest_enabled=False), deployed_at=datetime.now(timezone.utc).isoformat())
    if alias_repair:
        manifest['forward_configuration_repair'] = dict(file=alias_repair[2].name,
            sha256=sha(alias_repair[2]), operator_script_sha256=sha(Path(__file__)),
            reason='HTTP alias missing native integration-secret KMS URL and trusted CA')
    if simulator:
        manifest['forward_configuration_repair'] = dict(
            file=simulator['overlay'].name, sha256=sha(simulator['overlay']),
            operator_script_sha256=sha(Path(__file__)),
            simulator_operator_sha256=sha(Path(__file__).with_name('complete_beta_passport_simulator.py')),
            operator_source_revision=operator_revision,
            reason='Preserve scoped callback token file through shared services entrypoint',
            migration_replayed=False, kms_bootstrap_replayed=False,
            original_rollout_exit_code=1, callback_network_id=simulator['network_id'])
    (artifacts / 'local-deployment-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    result.update(deploymentManifest=str(artifacts / 'local-deployment-manifest.json'),
                  deploymentManifestSha256=sha(artifacts / 'local-deployment-manifest.json'),
                  selectedRuntime=records)
    result.update(applied=True, apiAndUiBindingsVerified=True, nativeIssuanceProbes='PASS', betaDeployed=True)
    return result


def refresh_runtime_evidence(root, artifacts, completed_proof_file, completed_proof_sha256):
    """Read the unchanged live containers and return a fresh evidence projection.

    Never calls startup, migrations, Compose, KMS, public APIs or feature routes.
    The caller writes only fresh output files, reviews the diff, and separately
    adopts/rebinds it; the original manifest and completed proof stay untouched.
    """
    require(artifacts.is_relative_to(root / 'tests/artifacts'), 'Artifacts must belong to frozen source checkout')
    require(sha(completed_proof_file) == completed_proof_sha256, 'Reviewed completed forward proof changed')
    proof = load(completed_proof_file)
    require(proof.get('scope') == 'LOCAL_BETA_FORWARD_STARTUP'
            and all(proof.get(key) is True for key in ('applied', 'betaDeployed', 'apiAndUiBindingsVerified'))
            and proof.get('nativeIssuanceProbes') == 'PASS', 'Successful completed forward startup proof required')
    original_path = artifacts / 'local-deployment-manifest.json'
    original_sha = sha(original_path)
    require(Path(proof.get('deploymentManifest', '')).resolve() == original_path.resolve()
            and proof.get('deploymentManifestSha256') == original_sha, 'Completed deployment manifest binding changed')
    source = load(artifacts / 'source-manifest.json')
    components = {item['component']: item['revision'] for item in source['component_revisions']}
    require(proof['sourceManifestSha256'] == sha(artifacts / 'source-manifest.json')
            and proof['sourceId'] == source['marty_ui_sha']
            and proof['sourceRevision'] == components['marty-ui']
            and proof['release'] == source['release_version'], 'Completed source binding changed')
    subprocess.run(['python', str(root / 'scripts/create_local_release_manifest.py'), '--workspace',
                    str(root.parent), '--verify-manifest', str(artifacts / 'source-manifest.json')], check=True)
    original = load(original_path)
    require(original.get('marty_ui_sha') == source['marty_ui_sha']
            and original.get('release_version') == source['release_version']
            and original.get('component_revisions') == components, 'Original deployment identity differs')
    images = load(artifacts / 'image-digests.json')
    rows = original.get('images')
    require(isinstance(rows, list) and len(rows) == len(images)
            and {row.get('service') for row in rows} == set(images), 'Exact selected runtime inventory required')
    from check_canvas_oss_portability import REQUIRED_BETA_RUNTIME_IMAGES
    expected = dict(MARTY_UI_SHA=source['marty_ui_sha'], MARTY_RELEASE_VERSION=source['release_version'],
                    ELEVENID_STACK_VERSION=(root / 'VERSION').read_text(encoding='utf8').strip(),
                    ELEVENID_COMPONENT_REVISIONS_JSON=components, ELEVENID_IMAGE_DIGESTS_JSON=images)
    refreshed = copy.deepcopy(original)
    for old, row in zip(rows, refreshed['images'], strict=True):
        role = old['service']
        observed = record(role, observe(role, images[role]))
        require(all(observed.get(key) == value for key, value in old.items()
                    if key != 'runtime_marker_environment'), 'Existing runtime identity or state changed: ' + role)
        require(observed['running'] is True and observed['status'] == 'running'
                and observed['health'] in (None, 'healthy'), 'Current runtime is not healthy: ' + role)
        markers = observed['runtime_marker_environment']
        for key, value in markers.items():
            if key.endswith('_JSON'):
                value = json.loads(value)
            require(value == expected[key], 'Observed release marker differs from frozen source: ' + role + ':' + key)
        if role in REQUIRED_BETA_RUNTIME_IMAGES:
            require({'MARTY_UI_SHA', 'MARTY_RELEASE_VERSION'} <= set(markers), 'Required Canvas runtime markers missing: ' + role)
        require('runtime_marker_environment' not in old or old['runtime_marker_environment'] == markers,
                'Existing marker evidence differs from actual observation: ' + role)
        row['runtime_marker_environment'] = markers
    require(sha(original_path) == original_sha and sha(completed_proof_file) == completed_proof_sha256,
            'Evidence inputs changed during observation')
    result = dict(scope='LOCAL_BETA_RUNTIME_MARKER_EVIDENCE_REFRESH',
        sourceRevision=components['marty-ui'], sourceId=source['marty_ui_sha'], release=source['release_version'],
        originalManifest=str(original_path), originalManifestSha256=original_sha,
        completedForwardProof=str(completed_proof_file), completedForwardProofSha256=completed_proof_sha256,
        selectedRuntimeCount=len(rows), sameContainerIdentitiesAndState=True,
        onlyManifestChange='images[*].runtime_marker_environment', betaMutationPerformed=False,
        startupReplayed=False, sourceManifestVerified=True, productionDemoQualified=False,
        operatorScriptSha256=sha(Path(__file__)))
    return refreshed, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--source-repo-root', type=Path, required=True)
    parser.add_argument('--runtime-config-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--passport-simulator-completion', action='store_true')
    parser.add_argument('--failed-rollout-proof', type=Path)
    parser.add_argument('--refresh-runtime-evidence', action='store_true')
    parser.add_argument('--completed-forward-proof', type=Path)
    parser.add_argument('--completed-forward-proof-sha256')
    parser.add_argument('--manifest-output', type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), 'Use a new completion receipt path')
    if args.refresh_runtime_evidence:
        require(not args.apply and args.completed_forward_proof and args.completed_forward_proof_sha256
                and args.manifest_output and not args.manifest_output.exists()
                and args.manifest_output.resolve() != args.output.resolve(), 'Read-only refresh requires fresh outputs and reviewed completed proof')
        manifest, result = refresh_runtime_evidence(args.source_repo_root.resolve(), args.artifact_dir.resolve(),
            args.completed_forward_proof.resolve(), args.completed_forward_proof_sha256)
        with args.manifest_output.open('x', encoding='utf8') as output:
            output.write(json.dumps(manifest, indent=2) + '\n')
        result.update(refreshedManifest=str(args.manifest_output.resolve()), refreshedManifestSha256=sha(args.manifest_output))
        with args.output.open('x', encoding='utf8') as output:
            output.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
        return
    result = complete(args.source_repo_root.resolve(), args.artifact_dir.resolve(),
                      args.runtime_config_root.resolve(), args.apply, args.passport_simulator_completion,
                      args.failed_rollout_proof.resolve() if args.failed_rollout_proof else None)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
