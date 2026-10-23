"""Recover exact prior containers only when retained databases are unchanged.

The PowerShell entrypoint owns the host mutex and state-volume checks. This
operator never restores a database, changes KMS state, or runs a migration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import io
from pathlib import Path
import re
import subprocess
import tarfile
import time
import uuid
from urllib.request import Request, urlopen


def docker(*args, input=None):
    result = subprocess.run(['docker', *args], input=input, capture_output=True)
    if result.returncode:
        raise RuntimeError('Docker recovery observation/action failed; inspect beta before retry')
    return result.stdout


def normalized_dump(value: bytes) -> bytes:
    # Preserve every SQL/data/comment/blank line. Only the generated psql nonce
    # pair at the outer boundaries may differ between two native dumps.
    lines = value.split(b'\n')
    for index, line in enumerate(lines[:20]):
        match = re.fullmatch(rb'\\restrict ([A-Za-z0-9]{16,})', line)
        if not match:
            continue
        end = b'\\unrestrict ' + match[1]
        endings = [i for i in range(max(0, len(lines) - 20), len(lines)) if lines[i] == end]
        if len(endings) != 1:
            raise RuntimeError('Unrecognized native pg_dump safety nonce boundary')
        return b'\n'.join(item for i, item in enumerate(lines) if i not in (index, endings[0]))
    return value


def archive_inventory(value: bytes) -> dict:
    """Compare custody bytes/modes, without unstable tar timestamps or headers."""
    inventory = {}
    with tarfile.open(fileobj=io.BytesIO(value), mode='r:*') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.'):
                continue
            if (name.startswith('/') or '..' in name.split('/') or name in inventory
                    or not (member.isfile() or member.isdir())):
                raise RuntimeError('Unrecognized state archive member')
            digest = None
            if member.isfile():
                with archive.extractfile(member) as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            inventory[name] = dict(mode=member.mode, directory=member.isdir(), sha256=digest)
    if not inventory:
        raise RuntimeError('Empty state archive')
    return inventory


def archive_file(value: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(value), mode='r:*') as archive:
        members = archive.getmembers()
        if len(members) != 1 or members[0].name != name or not members[0].isfile():
            raise RuntimeError('Unrecognized Docker state-file transfer')
        return archive.extractfile(members[0]).read()


def raft_state_digest(snapshot: bytes) -> str:
    inventory = archive_inventory(snapshot)
    if set(inventory) != {'meta.json', 'state.bin', 'SHA256SUMS', 'SHA256SUMS.sealed'}:
        raise RuntimeError('Unrecognized native OpenBao snapshot')
    if any(entry['directory'] for entry in inventory.values()):
        raise RuntimeError('Invalid native OpenBao snapshot member')
    # Raft term/index and sealed archive checksums can change for consensus or
    # snapshot transport. Every persisted FSM byte, including key/token state,
    # must match; no KMS domain records are removed or normalized.
    return inventory['state.bin']['sha256']


def require_redis_quiescent(value: bytes) -> None:
    fields = {}
    for line in value.decode('ascii').splitlines():
        if line and not line.startswith('#'):
            name, separator, data = line.partition(':')
            if not separator or name in fields:
                raise RuntimeError('Unrecognized Redis persistence observation')
            fields[name] = data
    for name in ['loading', 'rdb_changes_since_last_save', 'rdb_bgsave_in_progress', 'aof_rewrite_in_progress']:
        if fields.get(name) != '0':
            raise RuntimeError('Redis has unsnapshotted or in-flight state; unchanged recovery is forbidden')


def verify_auxiliary_state(manifest: dict, artifacts: Path) -> dict:
    roles = {}
    for service in ['redis', 'openbao']:
        records = [row for row in manifest['state_volumes'] if row['service'] == service]
        if len(records) != 1:
            raise RuntimeError('Ambiguous persistent state coverage: ' + service)
        row = records[0]
        current = inspect(row['container_id'])
        if (not current['Id'].startswith(row['container_id']) or not current['State']['Running']
                or current['Config']['Labels'].get('com.docker.compose.project') != 'elevenid-beta'
                or current['Config']['Labels'].get('com.docker.compose.service') != service
                or row['volume_name'] not in [m.get('Name') for m in current['Mounts'] if m['Type'] == 'volume']):
            raise RuntimeError('Persistent beta service identity or volume changed')
        roles[service] = row
    redis = roles['redis']['container_id']
    info_command = ('exec', redis, 'sh', '-ec',
                    'test -n "$REDIS_PASSWORD"; export REDISCLI_AUTH="$REDIS_PASSWORD"; exec redis-cli --raw INFO persistence')
    require_redis_quiescent(docker(*info_command))
    current_rdb = archive_file(docker('cp', redis + ':/data/dump.rdb', '-'), 'dump.rdb')
    expected_rdb = (artifacts / 'backup/redis-dump.rdb').read_bytes()
    if current_rdb != expected_rdb:
        raise RuntimeError('Redis snapshot changed; unchanged-state recovery is forbidden')
    require_redis_quiescent(docker(*info_command))

    openbao = roles['openbao']['container_id']
    filename = 'marty-unchanged-recovery-' + uuid.uuid4().hex + '.snap'
    temporary = '/tmp/' + filename
    command = ('BAO_TOKEN=$(cat /bao/data/root.token) BAO_ADDR=https://127.0.0.1:8200 '
               'BAO_CACERT=/bao/data/tls/ca.crt bao operator raft snapshot save ' + temporary)
    try:
        docker('exec', openbao, 'sh', '-ec', command)
        current_snapshot = archive_file(docker('cp', openbao + ':' + temporary, '-'), filename)
    finally:
        docker('exec', openbao, 'rm', '-f', temporary)
    expected_state = raft_state_digest((artifacts / 'backup/openbao-raft.snap').read_bytes())
    if raft_state_digest(current_snapshot) != expected_state:
        raise RuntimeError('OpenBao state changed; unchanged-state recovery is forbidden')
    current_custody = docker('run', '--rm', '--network', 'none', '--mount',
        'type=volume,src=' + roles['openbao']['volume_name'] + ',dst=/source,readonly',
        '--entrypoint', 'sh', 'alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc',
        '-ec', 'cd /source && test -d raft && tar -czf - --exclude=./raft .')
    expected_custody = archive_inventory((artifacts / 'backup/openbao-data.tar.gz').read_bytes())
    if archive_inventory(current_custody) != expected_custody:
        raise RuntimeError('OpenBao static custody changed; unchanged-state recovery is forbidden')
    return dict(redisSnapshotSha256=hashlib.sha256(current_rdb).hexdigest(),
                redisUnsnapshottedChanges=0, openBaoStateSha256=expected_state,
                openBaoStaticCustodyUnchanged=True)


def check_container(record, current, *, stopped=True):
    project = 'elevenid-beta-ui' if record['service'] == 'ui-prod' else 'elevenid-beta'
    reference = record['container_id']
    if (not re.fullmatch('[0-9a-f]{12,64}', reference) or not current['Id'].startswith(reference)
            or current['Image'] != record['image_id']
            or current['Config']['Labels'].get('com.docker.compose.project') != project
            or current['Config']['Labels'].get('com.docker.compose.service') != record['service']
            or current['State']['Running'] is stopped):
        raise RuntimeError('Prior beta container identity, ownership, image or stopped state changed')


def inspect(cid):
    return json.loads(docker('inspect', cid))[0]


def wait_healthy(records):
    deadline = time.monotonic() + 180
    while True:
        pending = []
        for record in records:
            state = inspect(record['container_id'])['State']
            if not state['Running'] or state.get('Health', {}).get('Status', 'healthy') != 'healthy':
                pending.append(record['service'])
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Recovered beta containers are not healthy: ' + ', '.join(pending))
        time.sleep(2)


def public_json(url):
    with urlopen(Request(url, headers={'Cache-Control': 'no-cache', 'User-Agent': 'elevenid-beta-health/1'}), timeout=20) as response:
        return json.load(response)


def verify_recovered_runtime(records):
    for record in records:
        current = inspect(record['container_id'])
        check_container(record, current, stopped=False)
        record['container_id'] = current['Id']
    wait_healthy(records)
    gateway = next(row for row in records if row['service'] == 'gateway')['runtime_marker_environment']
    expected_release = {
        'deployment_release_marker': gateway['MARTY_RELEASE_VERSION'],
        'marty_ui_sha': gateway['MARTY_UI_SHA'], 'stack_version': gateway['ELEVENID_STACK_VERSION'],
        'component_revisions': json.loads(gateway['ELEVENID_COMPONENT_REVISIONS_JSON']),
        'image_digests': json.loads(gateway['ELEVENID_IMAGE_DIGESTS_JSON']),
    }
    for origin in ['http://127.0.0.1:8000', 'https://beta.elevenidllc.com']:
        actual = public_json(origin + '/.well-known/marty-release')
        if any(actual.get(key) != value for key, value in expected_release.items()):
            raise RuntimeError('Recovered API binding differs from the retained prior environment')
    ui = next(row for row in records if row['service'] == 'ui-prod')
    expected_ui = json.loads(docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                                    ui['image_id'], '/usr/share/nginx/html/marty-ui-release.json'))
    for origin in ['http://127.0.0.1:3002', 'https://beta.elevenidllc.com']:
        if public_json(origin + '/marty-ui-release.json') != expected_ui:
            raise RuntimeError('Recovered UI marker differs from its retained immutable image')
    return expected_release['deployment_release_marker']


def recover(artifacts: Path, apply: bool):
    manifest = json.loads((artifacts / 'backup-manifest.json').read_text(encoding='utf-8-sig'))
    if manifest['phase'] != 'maintenance_quiesced' or manifest['application_writers_stopped'] is not True:
        raise RuntimeError('A retained quiesced backup is required')
    for entry in manifest['files']:
        if Path(entry['name']).name != entry['name']:
            raise RuntimeError('Invalid backup file name')
        with (artifacts / 'backup' / entry['name']).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != entry['sha256']:
                raise RuntimeError('Quiesced backup bytes changed')
    records = json.loads((artifacts / 'pre-deploy-containers.json').read_text(encoding='utf-8-sig'))
    records = [record for record in records if record['running']]
    roles = [record['service'] for record in records]
    if len(set(roles)) != len(roles) or not {'gateway', 'keycloak', 'ui-prod'} <= set(roles):
        raise RuntimeError('Prior beta container coverage is ambiguous')
    for record in records:
        current_container = inspect(record['container_id'])
        check_container(record, current_container)
        # The historical UI observer recorded Docker's unique short ID. Freeze
        # its resolved full ID before any subsequent lookup or start action.
        record['container_id'] = current_container['Id']
        matches = docker('ps', '-a', '--no-trunc', '--filter',
                         'label=com.docker.compose.project=' + record['compose_project'], '--filter',
                         'label=com.docker.compose.service=' + record['service'], '--format', '{{.ID}}').decode().splitlines()
        if matches != [record['container_id']]:
            raise RuntimeError('Prior beta role has been replaced or duplicated')
    jobs = docker('ps', '--filter', 'label=com.docker.compose.project=elevenid-beta',
                  '--filter', 'label=com.docker.compose.oneoff=True', '--format', '{{.ID}}')
    if jobs.strip():
        raise RuntimeError('An active beta one-off job blocks recovery')
    comparisons = {}
    postgres = next(row for row in manifest['state_volumes'] if row['service'] == 'postgres')['container_id']
    for database in ['marty', 'keycloak']:
        original = docker('exec', '-i', postgres, 'pg_restore', '--no-owner', '--no-privileges', '--file=-',
                          input=(artifacts / 'backup' / ('postgres-' + database + '.dump')).read_bytes())
        current = docker('exec', postgres, 'pg_dump', '-U', 'postgres', '--no-owner', '--no-privileges', database)
        before, after = normalized_dump(original), normalized_dump(current)
        if before != after:
            raise RuntimeError('Database changed; unchanged-state recovery is forbidden: ' + database)
        comparisons[database] = hashlib.sha256(before).hexdigest()
    applicant = next(row for row in manifest['state_volumes'] if row['service'] == 'applicant')['volume_name']
    data = docker('run', '--rm', '--network', 'none', '--mount',
                  'type=volume,src=' + applicant + ',dst=/source,readonly', '--entrypoint', 'cat',
                  'alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc',
                  '/source/applicant_store.json')
    expected = next(row for row in manifest['files'] if row['name'] == 'applicant_store.json')['sha256']
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Applicant store changed; unchanged-state recovery is forbidden')
    auxiliary_state = verify_auxiliary_state(manifest, artifacts)
    result = {'scope': 'UNCHANGED_LOCAL_BETA_CONTAINER_RECOVERY', 'databases': comparisons,
              'auxiliaryState': auxiliary_state,
              'applicantStoreUnchanged': True, 'priorContainerCount': len(records),
              'databaseRestored': False, 'kmsModifiedByRecovery': False, 'applied': False,
              'productionDemoQualified': False}
    if not apply:
        return result
    # Check identities immediately before starting, then recover dependencies,
    # application processes, and the exact previous UI without recreating them.
    for record in records:
        check_container(record, inspect(record['container_id']))
    for group in [['keycloak'], [role for role in roles if role not in ['keycloak', 'ui-prod']], ['ui-prod']]:
        selected = [row for row in records if row['service'] in group]
        docker('start', *[row['container_id'] for row in selected])
        wait_healthy(selected)
    prior_release = verify_recovered_runtime(records)
    result.update(applied=True, priorRelease=prior_release,
                  apiAndUiBindingsVerified=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError('Use a new recovery receipt path')
    result = recover(args.artifact_dir.resolve(), args.apply)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
