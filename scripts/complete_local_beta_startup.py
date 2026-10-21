"""Finish an interrupted local beta application startup without replaying migrations.

Run only through the PowerShell entrypoint, which holds the host mutation mutex
and verifies the retained state volumes and passport boundary. Source and image
bindings come from retained artifacts, never from the running API's claims.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.request import Request, urlopen

from bind_deployed_demo_manifest import bind_manifest
from recover_unchanged_beta_cutover import docker, inspect, public_json, wait_healthy


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


def record(role, current):
    return dict(service=role, container_id=current['Id'], container=current['Name'].lstrip('/'),
                configured_image=current['Config']['Image'], image_id=current['Image'],
                status=current['State']['Status'], running=current['State']['Running'],
                started_at=current['State']['StartedAt'], health=current['State'].get('Health', {}).get('Status'),
                compose_project=current['Config']['Labels']['com.docker.compose.project'], compose_service=role)


def verify_marker(actual, expected):
    require(all(actual.get(key) == value for key, value in expected.items()),
            'Runtime marker differs from frozen source/image bindings')


def complete(root, artifacts, runtime_root, apply):
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
    require(roles == {row['service'] for row in prior if row['service'] not in {'keycloak', 'ui-prod'}},
            'Candidate role set differs from retained deployment selection')
    require(not docker('ps', '--filter', 'label=com.docker.compose.project=elevenid-beta',
                       '--filter', 'label=com.docker.compose.oneoff=True', '--format', '{{.ID}}').strip(),
            'An active beta one-off job blocks completion')
    components = {row['component']: row['revision'] for row in source['component_revisions']}
    stack = (root / 'VERSION').read_text(encoding='utf8').strip()
    expected = dict(release_version=source['release_version'], marty_ui_sha=source['marty_ui_sha'],
                    deployment_release_marker=source['release_version'], stack_version=stack,
                    mip_version='0.5.0', component_revisions=components, image_digests=images)
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
    result = dict(scope='LOCAL_BETA_FORWARD_STARTUP', sourceRevision=components['marty-ui'],
                  sourceId=source['marty_ui_sha'], release=source['release_version'],
                  sourceManifestSha256=sha(artifacts / 'source-manifest.json'),
                  candidateContainerCount=len(candidates), applied=False, productionDemoQualified=False)
    if not apply:
        return result
    # Recheck each frozen container ID before starting only the unstarted roles.
    for role, current in candidates.items():
        require(observe(role, images[role])['Id'] == current['Id'], 'Candidate replaced during completion')
    unstarted = [current['Id'] for current in candidates.values() if current['State']['Status'] == 'created']
    if unstarted:
        docker('start', *unstarted)
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
                    beta_origin='https://beta.elevenidllc.com', passport_provider_mode='off',
                    compose_project='elevenid-beta', ui_compose_project='elevenid-beta-ui',
                    network='elevenid-beta-network', promotion_eligible=False, release_ready=False,
                    backup_manifest='backup-manifest.json', source_manifest='source-manifest.json',
                    official_stack_manifest=None, official_stack_manifest_sha256=None,
                    runtime_config_root=str(runtime_manifest.parent), runtime_config_manifest_sha256=sha(runtime_manifest),
                    verification_migration_image=images['verification'], component_revisions=components,
                    deployed_demo_manifest='deployed-demo-manifest.json',
                    deployed_demo_manifest_sha256=sha(artifacts / 'deployed-demo-manifest.json'),
                    services_marker=markers['local'], issuance_native_marker=native, ui_marker=ui_marker,
                    images=records, canvas_portable_configuration=dict(enabled=False, canvas_origin=None,
                        pilot_organization_id=None, lti_issuer_did=None, signing_resolution=None,
                        legacy_event_ingest_enabled=False), deployed_at=datetime.now(timezone.utc).isoformat())
    (artifacts / 'local-deployment-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf8')
    result.update(applied=True, apiAndUiBindingsVerified=True, nativeIssuanceProbes='PASS', betaDeployed=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--source-repo-root', type=Path, required=True)
    parser.add_argument('--runtime-config-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    require(not args.output.exists(), 'Use a new completion receipt path')
    result = complete(args.source_repo_root.resolve(), args.artifact_dir.resolve(),
                      args.runtime_config_root.resolve(), args.apply)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
