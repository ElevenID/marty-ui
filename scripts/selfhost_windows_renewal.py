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
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import time

from activate_selfhost_renewed_secrets import (
    checked_secret_mounts, compose_args, healthy, owned_service_closure,
    require_rootless_migration, statuses,
)
from selfhost_windows_inputs import (
    hold_private_generation, hold_private_input, read_private_bytes,
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


def disjoint_storage(items, project):
    owned = [m for x in items if _project(x) == project for m in x['Mounts'] if m.get('RW')]
    foreign = [m for x in items if _project(x) != project for m in x['Mounts'] if m.get('RW')]
    def path(raw):
        p = PureWindowsPath(raw)
        return p if p.drive else PurePosixPath(raw)
    for a in owned:
        for b in foreign:
            if a.get('Type') != b.get('Type'):
                continue
            x, y = path(a['Source']), path(b['Source'])
            require(not (x == y or x.is_relative_to(y) or y.is_relative_to(x)),
                    'Candidate writable storage overlaps another project')


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
        require(info['OSType'] == 'linux' and info['ID'] == engine_id)

    def json(self, args):
        p = subprocess.run([*self.prefix, *args], capture_output=True, timeout=60)
        require(p.returncode == 0, 'Owned Docker inspection failed')
        return json.loads(p.stdout)

    def containers(self):
        p = subprocess.run([*self.prefix, 'ps', '-aq'], capture_output=True, timeout=30)
        require(p.returncode == 0)
        ids = p.stdout.decode('ascii').split()
        return self.json(['inspect', *ids]) if ids else []

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
        write_empty_private_file(log, 'Bounded Compose output (last 60000 bytes):\n'
                                 + tail.decode('utf-8', errors='replace'))


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
            disjoint_storage(baseline, project)
            protected = observations(baseline, project, changing)
            native_preflight(config['native'], project, old_bytes, new_bytes, docker.prefix)
            write_empty_private_file(outputs['intent'], json.dumps({
                'schema': SCHEMA, 'project': project, 'compose_sha256': config['compose_sha256'],
                'current_env': str(old_env), 'renewed_env': str(new_env),
                'current_secrets': str(current), 'renewed_secrets': str(renewed),
                'owned_before': {str(_service(x)): x['Id'] for x in owned},
                'changing': sorted(changing), 'candidate_only': True}) + '\n')
            started = True
            def verify(command, root, model):
                items = docker.containers()
                require(observations(items, project, changing) == protected,
                        'Unselected container observations changed')
                require(windows_healthy(statuses(command, cwd=source.parent), services, model))
                owned_now = [x for x in items if _project(x) == project]
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
