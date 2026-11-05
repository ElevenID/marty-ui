"""Windows candidate renewal through existing Compose/native activation owners.

Not a release-admission, trust-retirement, reboot or unattended recovery tool.
The POSIX activator's platform/project/closure policy is unchanged. This adapter
owns an explicit managed-OpenBao candidate shape and never recreates Bao or runs
initialization. Every publication/admission/cutover gate remains external.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from activate_selfhost_renewed_secrets import (
    checked_secret_mounts, compose_args, healthy, owned_service_closure,
    require_rootless_migration, statuses,
)
from selfhost_windows_inputs import (
    hold_private_generation, hold_private_input, hold_storage_namespace, read_private_bytes,
    write_empty_private_file,
)
from selfhost_windows_renewal_native import preflight as native_preflight

BAO_ROLES = frozenset({'openbao', 'openbao-unseal', 'openbao-tls-init'})
INITIALIZERS = frozenset({'openbao-bootstrap', 'kms-initialize'})
SCHEMA = 'marty.windows-candidate-renewal/v1'


def require(value, message='Windows renewal preflight refused'):
    if not value:
        raise ValueError(message)


def windows_healthy(items, services, model):
    init = [x for x in items if x.get('Service') == 'openbao-tls-init']
    return (len(init) == 1 and init[0].get('State') == 'exited'
            and init[0].get('ExitCode') == 0
            and healthy([x for x in items if x.get('Service') != 'openbao-tls-init'],
                        services - {'openbao-tls-init'}, model))


def owned_roles(model, services):
    require_rootless_migration(model)
    declared = model.get('services', {})
    require(isinstance(declared, dict) and BAO_ROLES <= declared.keys())
    require(not INITIALIZERS & services)
    require(not {'cloudflared', 'cloudflared-beta', 'tunnel-nginx-proxy'} & services,
            'Candidate renewal cannot operate an ingress connector')
    require(declared.get('openbao-bootstrap', {}).get('profiles') == ['kms-init'])
    require(owned_service_closure(set(declared) - {'openbao-bootstrap'}, services))
    require({'keycloak', 'gateway', 'signing-keys', 'postgres'} | BAO_ROLES <= services)
    require(all(not declared[name].get('secrets') for name in BAO_ROLES))
    for spec in declared.values():
        require(isinstance(spec, dict) and not spec.get('build')
                and isinstance(spec.get('image'), str)
                and re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', spec['image']))
        require(spec.get('network_mode') != 'host' and not spec.get('privileged'))
        require(all(isinstance(port, dict) and port.get('host_ip') in {'127.0.0.1', '::1'}
                    for port in spec.get('ports', [])), 'Candidate ports must be loopback only')
    changed = {name for name in services if declared[name].get('secrets')}
    require(changed and not changed & (BAO_ROLES | INITIALIZERS))
    # Recreating only these roles is sufficient only when every generation
    # mount belongs to one of them. Complete mount validation still includes all
    # active/zero-exit roles, including the untouched managed Bao services.
    return changed


def checked_models(old, new, current, renewed, names):
    require(set(old.get('secrets', {})) == set(new.get('secrets', {})) == set(names))
    for model, root in [(old, current), (new, renewed)]:
        require(all(isinstance(v, dict) and Path(v.get('file', '')) == root / name
                    for name, v in model['secrets'].items()))
    normalized = json.loads(json.dumps(new))
    normalized['secrets'] = old['secrets']
    require(normalized == old, 'Compose changed beyond the generation')


def env_body(raw, root):
    lines = raw.decode('utf-8').splitlines()
    matches = [x for x in lines if x.startswith('SELFHOST_SECRET_DIR=')]
    require(len(matches) == 1 and Path(matches[0].split('=', 1)[1]) == root)
    return [x for x in lines if not x.startswith('SELFHOST_SECRET_DIR=')]


def _project(item):
    return (item.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project')


def _service(item):
    return (item.get('Config', {}).get('Labels') or {}).get('com.docker.compose.service')


def observations(items, project, changing):
    return {x['Id']: {'image': x['Image'], 'status': x['State']['Status'],
                     'started': x['State']['StartedAt'], 'restarts': x['RestartCount'],
                     'mounts': x['Mounts']}
            for x in items if _project(x) != project or _service(x) not in changing}


def windows_source(raw):
    """Only documented local-drive bridge spellings; never guess other paths."""
    require(isinstance(raw, str))
    for prefix in ['/run/desktop/mnt/host/', '/host_mnt/', '/mnt/']:
        if raw.startswith(prefix):
            match = re.fullmatch(r'([a-zA-Z])/(.*)', raw[len(prefix):])
            require(match is not None, 'Unresolved Docker bind source')
            raw = match[1] + ':/' + match[2]
            break
    if re.match(r'^[a-zA-Z]:[\\/]', raw) is None:
        return None
    require(all(p not in {'.', '..'} and ':' not in p and p.rstrip(' .') == p
                for p in re.split(r'[\\/]', raw[3:])))
    return Path(raw)


def windows_identity(path):
    resolved = path.resolve(strict=True)
    nodes = [resolved, *resolved.parents]
    identities = []
    for p in nodes:
        info = p.lstat()
        require(not info.st_file_attributes & 0x400 and info.st_ino != 0)
        identities.append((info.st_dev, info.st_ino))
    return resolved, identities[0], set(identities)


def storage_identity(mount, volumes):
    kind, raw = mount.get('Type'), mount.get('Source', '')
    if kind == 'bind':
        path = windows_source(raw)
        if path is not None:
            resolved, identity, ancestors = windows_identity(path)
            return 'windows', (resolved, identity, ancestors)
        if raw == '/run/host-services/docker.proxy.sock' and mount.get('Destination') == '/var/run/docker.sock':
            return 'engine-socket', raw
        # A bind of the exact local volume root is the same storage object as
        # a named volume. Subpaths remain opaque: they might be symlinks.
        matches = [name for name, v in volumes.items() if raw == v.get('Mountpoint')]
        require(len(matches) == 1, 'Unresolved Docker bind source')
        name = matches[0]
    elif kind == 'volume':
        name = mount.get('Name')
        require(name in volumes)
    else:
        raise ValueError('Unresolved Docker storage type')
    volume = volumes[name]
    require(volume.get('Driver') == 'local' and not volume.get('Options')
            and raw == volume.get('Mountpoint')
            and re.fullmatch('/var/lib/docker/volumes/' + re.escape(name) + '/_data', raw),
            'Unresolved Docker volume identity')
    return 'volume', name


def disjoint_storage(items, project, volumes):
    require(all(not (m.get('Type') == 'bind' and m.get('Source') == '/run/host-services/docker.proxy.sock')
                for x in items if _project(x) == project for m in x['Mounts']),
            'Candidate cannot mount the engine control socket')
    owned = [storage_identity(m, volumes) for x in items if _project(x) == project
             for m in x['Mounts'] if m.get('RW')]
    # Read-only consumers also observe data changes made through candidate RW.
    foreign = [storage_identity(m, volumes) for x in items if _project(x) != project for m in x['Mounts']]
    for a, x in owned:
        for b, y in foreign:
            if a != b:
                continue
            overlap = x == y if a != 'windows' else x[1] in y[2] or y[1] in x[2]
            require(not overlap, 'Candidate writable storage overlaps another project')


def data_mounts(items):
    return {_service(x): {'image': x['Image'], 'mounts': sorted(
        [m for m in x['Mounts'] if not m['Destination'].startswith('/run/secrets/')],
        key=lambda m: m['Destination'])} for x in items}


def checked_live_configuration(items, hashes, tls_init):
    """Pin running configuration and the preserved historical TLS init job."""
    require(isinstance(tls_init, dict) and set(tls_init) == {'id', 'image', 'config_hash'})
    for item in items:
        role = _service(item)
        actual = (item['Config'].get('Labels') or {}).get('com.docker.compose.config-hash')
        if role == 'openbao-tls-init':
            # This zero-exit CA creation job can predate signed-image adoption.
            # It is historical evidence, never an activation/recovery action.
            require(item['State']['Status'] == 'exited' and item['State']['ExitCode'] == 0)
            require({'id': item['Id'], 'image': item['Image'], 'config_hash': actual} == tls_init,
                    'Preserved TLS initializer receipt changed')
        else:
            require(actual == hashes.get(role), 'Running Compose configuration differs from retained input')


class Docker:
    def __init__(self, host, engine_id):
        require(host in {'npipe:////./pipe/dockerDesktopLinuxEngine',
                         'npipe:////./pipe/docker_engine'})
        require(isinstance(engine_id, str) and 10 <= len(engine_id) <= 128)
        self.prefix = ['docker', '--host', host]
        info = self.json(['info', '--format', '{{json .}}'])
        require(info['OSType'] == 'linux' and info['ID'] == engine_id
                and info['DockerRootDir'] == '/var/lib/docker')

    def json(self, args):
        p = subprocess.run([*self.prefix, *args], capture_output=True, timeout=60)
        require(p.returncode == 0, 'Owned Docker inspection failed')
        return json.loads(p.stdout)

    def containers(self):
        p = subprocess.run([*self.prefix, 'ps', '-aq'], capture_output=True, timeout=30)
        require(p.returncode == 0)
        ids = p.stdout.decode('ascii').split()
        rows = []
        for start in range(0, len(ids), 64):
            rows.extend(self.json(['inspect', *ids[start:start + 64]]))
        return rows

    def volumes(self):
        p = subprocess.run([*self.prefix, 'volume', 'ls', '-q'], capture_output=True, timeout=30)
        require(p.returncode == 0)
        names = p.stdout.decode('ascii').split()
        # Anonymous volume inventories can exceed CreateProcessW's 32767-char
        # command line. Docker names are bounded; batches of64 stay below it.
        rows = []
        for start in range(0, len(names), 64):
            rows.extend(self.json(['volume', 'inspect', *names[start:start + 64]]))
        return {v['Name']: {k: v.get(k) for k in ['Name', 'Driver', 'Mountpoint', 'Options']} for v in rows}

    def compose(self, project, env, source):
        return [*self.prefix, *compose_args(project, env, source)[1:]]

    def hashes(self, command):
        p = subprocess.run([*command, '--profile', '*', 'config', '--hash', '*'],
                           capture_output=True, timeout=60)
        require(p.returncode == 0)
        pairs = [row.split() for row in p.stdout.decode('ascii').splitlines()]
        require(all(len(row) == 2 and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', row[0])
                    and re.fullmatch(r'[0-9a-f]{64}', row[1]) for row in pairs))
        result = dict(pairs);require(len(result) == len(pairs))
        return result


def bounded_diagnostic(raw):
    text = raw.decode('utf-8', errors='replace').replace('\0', '\\0')
    tail = text.encode('utf-8')[-60000:].decode('utf-8', errors='ignore')
    return 'Bounded Compose diagnostic tail; malformed bytes replaced:\n' + tail


def recreate(docker, command, changing, services, model, log):
    deadline = time.monotonic() + 600
    tail = b''
    try:
        for attempt in range(8):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            p = subprocess.run([*command, 'up', '-d', '--no-deps', '--no-build',
                                '--pull', 'never', *(['--force-recreate'] if attempt == 0 else []),
                                *sorted(changing)], capture_output=True, timeout=min(240, remaining))
            tail = (tail + p.stdout + p.stderr)[-60000:]
            # A nonzero Compose invocation can leave a partially recreated set;
            # inspect authoritative state before deciding to retry or roll back.
            if windows_healthy(statuses(command, cwd=Path.cwd()), services, model):
                return
            time.sleep(5)
        raise RuntimeError('Windows renewal did not become ready')
    finally:
        write_empty_private_file(log, bounded_diagnostic(tail))


def activate(config):
    """Run the candidate transaction with its existing verified native owner.

    Native authority/generation/orphan/certificate checks consume BOTH held byte
    maps through the existing signed Linux operator. No Python substitutes.
    Runtime rollback qualification is required before exposing an operator CLI.
    """
    require(os.name == 'nt', 'Windows host required')
    config = json.loads(json.dumps(config))
    require(config['schema'] == SCHEMA and config['candidate_only'] is True)
    project = config['project']
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', project))
    current, renewed = Path(config['current_secrets']), Path(config['renewed_secrets'])
    require(current != renewed and current.parent == renewed.parent)
    source = Path(config['compose_file']);old_env = Path(config['current_env']);new_env = Path(config['renewed_env'])
    outputs = {name: Path(config[name]) for name in ('intent', 'result', 'new_log', 'rollback_log')}
    require(len(set(outputs.values())) == 4 and len({p.parent for p in outputs.values()}) == 1)
    require(all(not p.is_relative_to(current) and not p.is_relative_to(renewed) for p in outputs.values()))
    lock = current.parent / f'.{project}.renewal.lock'
    started = False
    result = None
    try:
        with ExitStack() as stack:
            stack.enter_context(hold_private_input(lock, exclusive=True))
            raw_model = stack.enter_context(hold_private_input(source, max_bytes=2 * 1024 * 1024))
            require(hashlib.sha256(raw_model).hexdigest() == config['compose_sha256'])
            before_env = stack.enter_context(hold_private_input(old_env))
            after_env = stack.enter_context(hold_private_input(new_env))
            require(env_body(before_env, current) == env_body(after_env, renewed))
            require(all(read_private_bytes(p) == b'' for p in outputs.values()))
            docker = Docker(config['docker_host'], config['engine_id'])
            old = docker.compose(project, old_env, source);new = docker.compose(project, new_env, source)
            old_model = docker.json(old[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
            new_model = docker.json(new[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
            names = sorted(old_model.get('secrets', {}))
            old_bytes = stack.enter_context(hold_private_generation(current, names))
            new_bytes = stack.enter_context(hold_private_generation(renewed, names))
            checked_models(old_model, new_model, current, renewed, names)
            baseline = docker.containers()
            owned = [x for x in baseline if _project(x) == project]
            services = {_service(x) for x in owned}
            require(len(owned) == len(services))
            changing = owned_roles(old_model, services)
            require(owned_roles(new_model, services) == changing)
            old_hashes, new_hashes = docker.hashes(old), docker.hashes(new)
            checked_live_configuration(owned, old_hashes, config['tls_init_receipt'])
            require(windows_healthy(statuses(old, cwd=source.parent), services, old_model))
            checked_secret_mounts(owned, project, current, services, old_model)
            disjoint_storage(baseline, project, docker.volumes())
            for item in owned:
                if _service(item) not in changing:
                    continue
                for mount in item['Mounts']:
                    if mount.get('RW') and mount.get('Type') == 'bind':
                        path = windows_source(mount['Source'])
                        require(path is not None)
                        stack.enter_context(hold_storage_namespace(path))
            data_before = data_mounts(owned)
            protected = observations(baseline, project, changing)
            native_preflight(config['native'], project, old_bytes, new_bytes, docker.prefix)
            write_empty_private_file(outputs['intent'], json.dumps({
                'schema': SCHEMA, 'project': project, 'compose_sha256': config['compose_sha256'],
                'current_env': str(old_env), 'renewed_env': str(new_env),
                'current_secrets': str(current), 'renewed_secrets': str(renewed),
                'owned_before': {str(_service(x)): x['Id'] for x in owned},
                'data_mounts_before': data_before,
                'changing': sorted(changing), 'candidate_only': True}) + '\n')
            started = True
            def verify(command, root, model):
                items = docker.containers()
                require(observations(items, project, changing) == protected,
                        'Unselected container observations changed')
                require(windows_healthy(statuses(command, cwd=source.parent), services, model))
                owned_now = [x for x in items if _project(x) == project]
                require(data_mounts(owned_now) == data_before, 'Data mounts or image identity changed')
                checked_live_configuration(owned_now, new_hashes if root == renewed else old_hashes,
                                            config['tls_init_receipt'])
                return checked_secret_mounts(owned_now, project, root, services, model)
            try:
                recreate(docker, new, changing, services, new_model, outputs['new_log'])
                mounts = verify(new, renewed, new_model)
                result = {'result': 'activated', 'secret_mounts': mounts}
            except Exception:
                recreate(docker, old, changing, services, old_model, outputs['rollback_log'])
                mounts = verify(old, current, old_model)
                result = {'result': 'rolled_back', 'secret_mounts': mounts}
            result.update(schema=SCHEMA, project=project, services=len(services),
                          recreated_roles=sorted(changing), candidate_only=True,
                          production_admission=False, automatic_lifecycle=False)
        # Never publish success before all held-input exit checks have passed.
        write_empty_private_file(outputs['result'], json.dumps(result) + '\n')
    except Exception:
        if started:
            raise RuntimeError('Windows renewal requires operator recovery; preserve intent and generations') from None
        raise
    if result['result'] == 'rolled_back':
        raise RuntimeError('Windows renewal failed; prior generation restored')
    return result
