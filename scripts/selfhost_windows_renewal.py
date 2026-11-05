"""Windows candidate renewal through existing Compose/native activation owners.

Not a release-admission, trust-retirement, reboot or unattended recovery tool.
The POSIX activator's platform/project/closure policy is unchanged. This adapter
owns an explicit managed-OpenBao candidate shape and never recreates Bao or runs
initialization. Every publication/admission/cutover gate remains external.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path, PurePosixPath

from activate_selfhost_renewed_secrets import (
    COMPLETED_SERVICES,
    checked_secret_mounts,
    compose_args,
    healthy,
    owned_service_closure,
    require_rootless_migration,
    statuses,
)
from selfhost_windows_inputs import (
    hold_private_generation,
    hold_private_input,
    hold_storage_namespace,
    read_private_bytes,
    write_empty_private_file,
)
from selfhost_windows_renewal_native import preflight as native_preflight

BAO_ROLES = frozenset({'openbao', 'openbao-unseal', 'openbao-tls-init'})
INITIALIZERS = frozenset({'openbao-bootstrap', 'kms-initialize'})
SCHEMA = 'marty.windows-candidate-renewal/v1'
SOCKETS = frozenset({'/run/host-services/docker.proxy.sock', '/var/run/docker.sock'})
VM_VOLUME_ROOT = '/data/docker/volumes/'

# The fixed trusted helper reads one kernel metadata file, never proc root,
# environ, command lines or workload data. No workload volumes are mounted.
MOUNTINFO_WORKER = r'''
import json,pathlib,sys
targets=json.load(sys.stdin)['targets']
with pathlib.Path('/proc/1/mountinfo').open('rb') as f:raw=f.read(2*1024*1024+1)
assert len(raw)<=2*1024*1024
rows=[]
for line in raw.decode().splitlines():
 fields=line.split();separator=fields.index('-')
 assert separator>=6 and len(fields)>=separator+4
 if any(target==fields[4] or target.startswith(fields[4].rstrip('/')+'/') for target in targets):
  rows.append({'id':fields[0],'parent':fields[1],'target':fields[4],'root':fields[3],
               'device':fields[2],'fstype':fields[separator+1]})
print(json.dumps(rows))
'''


def require(value, message='Windows renewal preflight refused'):
    if not value:
        raise ValueError(message)


def recovery_guard(config):
    return Path(config['current_secrets']).parent / ('.'+config['project']+'.recovery-in-progress.json')


def namespace_entry_exists(path):
    """Any entry blocks admission, including a dangling link; never follow it."""
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return False
    return True


def recovery_pending(config):
    return namespace_entry_exists(recovery_guard(config))


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
                     'mounts': canonical_mounts(x['Mounts'])}
            for x in items if _project(x) != project or _service(x) not in changing}


def canonical_mounts(mounts):
    require(isinstance(mounts, list) and all(isinstance(m, dict) for m in mounts))
    # The engine constructs this array from a map; order is not identity.
    # Sorting retains every field and duplicate, so actual changes still refuse.
    return sorted(mounts, key=lambda m: json.dumps(m, sort_keys=True, separators=(',', ':')))


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


def windows_mount_path_equal(actual, expected):
    """Compare only local-drive spellings of the exact held secret path.

    No reparse/junction resolution is used to broaden a secret binding. Expected
    roots/files already have held identity/privacy proof; known bridge prefixes,
    separator and Windows case differences do not select a different path.
    """
    try:
        a, b = windows_source(actual), windows_source(expected)
        if a is None or b is None or a != b:
            return False
        if str(a) == str(b):
            return True
        # NTFS directories can opt into case sensitivity. A differently cased
        # spelling therefore needs object identity, not just PureWindowsPath's
        # case-insensitive equality; never follow a reparse alias to get it.
        for path in [a, *a.parents]:
            if path.lstat().st_file_attributes & 0x400:
                return False
        left, right = a.lstat(), b.lstat()
        return left.st_ino != 0 and (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    except (OSError, ValueError, TypeError):
        return False


def storage_identity(mount, volumes):
    kind, raw = mount.get('Type'), mount.get('Source', '')
    if kind == 'bind':
        path = windows_source(raw)
        if path is not None:
            resolved, identity, ancestors = windows_identity(path)
            return 'windows', (resolved, identity, ancestors)
        if raw in SOCKETS and mount.get('Destination') == '/var/run/docker.sock':
            return 'engine-socket', raw
        # A bind of the exact local volume root is the same storage object as
        # a named volume. Subpaths remain opaque: they might be symlinks.
        matches = [name for name, v in volumes.items() if raw == v.get('Mountpoint')]
        require(len(matches) == 1, 'Unresolved Docker bind source')
        name = matches[0]
    elif kind == 'volume':
        name = mount.get('Name') or (raw if raw in volumes else None)
        require(name in volumes)
    else:
        raise ValueError('Unresolved Docker storage type')
    volume = volumes[name]
    require(volume.get('Driver') == 'local' and not volume.get('Options')
            and raw in {name, volume.get('Mountpoint')}
            and volume.get('Mountpoint') == '/var/lib/docker/volumes/' + name + '/_data',
            'Unresolved Docker volume identity')
    return 'volume', name


def native_bind(mount, volumes):
    raw = mount.get('Source', '')
    if mount.get('Type') != 'bind' or not raw.startswith('/var/lib/docker/volumes/'):
        return None
    for name, v in volumes.items():
        base = v.get('Mountpoint')
        if base and raw.startswith(base + '/'):
            require(v.get('Driver') == 'local' and not v.get('Options')
                    and base == '/var/lib/docker/volumes/' + name + '/_data')
            suffix = raw[len(base):]
            p = PurePosixPath(suffix)
            require(str(p) == suffix and '..' not in p.parts)
            return name, suffix
    return None


def mount_path(value):
    require(isinstance(value, str) and not re.search(r'\\(?!040|011|012|134)', value))
    escapes = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    value = re.sub(r'\\(040|011|012|134)', lambda m: escapes[m[1]], value)
    p = PurePosixPath(value)
    require(p.is_absolute() and str(p) == value and '..' not in p.parts)
    return value


def volume_witnesses(item, rows, volumes):
    """Accept only kernel roots on a device anchored by an ordinary volume."""
    by_target = {}
    by_id = {}
    for raw in rows:
        row = dict(raw);row['target'] = mount_path(row['target']);row['root'] = mount_path(row['root'])
        require(re.fullmatch(r'\d+:\d+', row['device']) and re.fullmatch(r'[1-9]\d*', row['id'])
                and re.fullmatch(r'\d+', row['parent']) and row['id'] not in by_id)
        by_target.setdefault(row['target'], []).append(row)
        by_id[row['id']] = row
    def one(mount):
        found = by_target.get(mount['Destination'], [])
        require(len(found) == 1, 'Mount destination is absent or ambiguous')
        row = found[0];cursor = row;chain = set()
        while True:
            require(cursor['id'] not in chain, 'Mount parent cycle')
            chain.add(cursor['id'])
            if cursor['target'] == '/':
                break
            require(cursor['parent'] in by_id, 'Mount parent evidence absent')
            cursor = by_id[cursor['parent']]
        for ancestor in by_id.values():
            if (row['target'] == ancestor['target']
                    or row['target'].startswith(ancestor['target'].rstrip('/') + '/')):
                require(ancestor['id'] in chain, 'Mount is hidden by an ancestor overmount')
        return row
    devices = set()
    for m in item['Mounts']:
        if m.get('Type') == 'volume':
            kind, name = storage_identity(m, volumes)
            require(kind == 'volume')
            row = one(m)
            if row['fstype'] == 'ext4' and row['root'] == VM_VOLUME_ROOT + name + '/_data':
                devices.add(row['device'])
    result = {}
    for m in item['Mounts']:
        binding = native_bind(m, volumes)
        if binding is None:
            continue
        name, suffix = binding;row = one(m)
        require(row['fstype'] == 'ext4' and row['device'] in devices
                and row['root'] == VM_VOLUME_ROOT + name + '/_data' + suffix,
                'Native bind lacks an anchored kernel identity')
        result[m['Source']] = {'volume': name, 'device': row['device'], 'suffix': suffix}
    return result


def disjoint_storage(items, project, volumes, witnesses=None):
    witnesses = witnesses or {}
    require(all(not (m.get('Type') == 'bind' and m.get('Source') in SOCKETS)
                for x in items if _project(x) == project for m in x['Mounts']),
            'Candidate cannot mount the engine control socket')
    owned = [storage_identity(m, volumes) for x in items if _project(x) == project
             for m in x['Mounts'] if m.get('RW')]
    # Read-only consumers also observe data changes made through candidate RW.
    foreign = []
    for x in items:
        if _project(x) == project:
            continue
        for m in x['Mounts']:
            binding = native_bind(m, volumes)
            if binding is None:
                foreign.append(storage_identity(m, volumes));continue
            evidence = witnesses.get((_project(x), m['Source']))
            require(evidence is not None and evidence['volume'] == binding[0]
                    and evidence['suffix'] == binding[1])
            live = x['Id'] in evidence['live_ids'] and x['State']['Status'] == 'running'
            historical = (isinstance(_project(x), str) and bool(_project(x)) and x['State']['Status'] == 'exited'
                          and x['State'].get('ExitCode') == 0 and evidence['live_ids'])
            require(live or historical, 'Native bind has no live or exact historical witness')
            # Historical reuse is an inference for this exact same-project
            # Source, not a live mount proof or permission to restart that job.
            foreign.append(('volume', evidence['volume']))
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

    def native_witnesses(self, items, project, volumes, helper_image):
        require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', helper_image))
        result = {}
        for x in items:
            if (_project(x) == project or x['State']['Status'] != 'running'
                    or not any(native_bind(m, volumes) for m in x['Mounts'])):
                continue
            require(re.fullmatch(r'[0-9a-f]{64}', x['Id']))
            require(x.get('HostConfig', {}).get('PidMode') in {'', 'private'}
                    and type(x['State'].get('Pid')) is int and x['State']['Pid'] > 0,
                    'Kernel witness requires the target private PID namespace')
            targets = [m['Destination'] for m in x['Mounts']]
            # Match encoded proc paths as well as ordinary paths. The decoder
            # and exact inspect-destination correlation run at the caller.
            encoded = [p.replace('\\', '\\134').replace(' ', '\\040').replace('\t', '\\011').replace('\n', '\\012') for p in targets]
            args = [*self.prefix, 'run', '--rm', '--pull', 'never', '-i',
                    '--pid=container:' + x['Id'], '--network', 'none', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                    '--entrypoint', 'python', helper_image, '-c', MOUNTINFO_WORKER]
            p = subprocess.run(args, input=json.dumps({'targets': encoded}).encode(),
                               capture_output=True, timeout=60)
            require(p.returncode == 0, 'Kernel mount metadata unavailable')
            after = self.json(['inspect', x['Id']])[0]
            require(all(after.get(k) == x.get(k) for k in ['Id', 'Created', 'RestartCount'])
                    and canonical_mounts(after['Mounts']) == canonical_mounts(x['Mounts'])
                    and after.get('HostConfig', {}).get('PidMode') == x['HostConfig']['PidMode']
                    and all(after['State'].get(k) == x['State'].get(k)
                            for k in ['Pid', 'StartedAt', 'Status']), 'Metadata container identity changed')
            for source, evidence in volume_witnesses(x, json.loads(p.stdout), volumes).items():
                key = (_project(x), source)
                previous = result.get(key)
                require(previous is None or all(previous[k] == evidence[k] for k in ['volume', 'device', 'suffix']))
                result[key] = {**evidence, 'live_ids': {x['Id']} | (previous['live_ids'] if previous else set())}
        return result


def bounded_diagnostic(raw):
    text = raw.decode('utf-8', errors='replace').replace('\0', '\\0')
    tail = text.encode('utf-8')[-60000:].decode('utf-8', errors='ignore')
    return 'Bounded Compose diagnostic tail; malformed bytes replaced:\n' + tail


class UncertainComposeMutation(RuntimeError):
    """The mutating CLI did not establish a completed operation boundary."""

    def __init__(self, message):
        super().__init__(message)
        self.stdout = b''
        self.stderr = b''
        self.owned_processes_zero = False


def dependency_layers(model, services, changing):
    """Validate the active graph before intent; each selected role occurs once."""
    require(isinstance(services, set) and changing and changing <= services)
    declared = model['services'];dependencies = {}
    for role in services:
        dep = declared[role].get('depends_on', {})
        require(isinstance(dep, dict), 'Normalized dependency map required')
        for name, spec in dep.items():
            require(isinstance(name, str) and isinstance(spec, dict)
                    and type(spec.get('required', True)) is bool
                    and spec.get('restart', False) is False,
                    'Dependency restart cascades are not qualified')
            condition = spec.get('condition', 'service_started')
            require(condition in {'service_started', 'service_healthy', 'service_completed_successfully'})
            require(name in services or spec.get('required', True) is False,
                    'Required dependency is outside the active closure')
            if name in services and condition == 'service_healthy':
                check = declared[name].get('healthcheck')
                require(isinstance(check, dict) and check.get('disable') is not True)
            if name in services and condition == 'service_completed_successfully':
                require(name in COMPLETED_SERVICES | {'openbao-tls-init'})
        dependencies[role] = set(dep) & services
    pending = set(services);layers = []
    while pending:
        ready = {n for n in pending if not dependencies[n] & pending}
        require(ready, 'Active dependency graph is cyclic')
        if ready & changing:
            layers.append(sorted(ready & changing))
        pending -= ready
    return layers


def run_owned_mutation(arguments, timeout=240, *, stdin_bytes=None):
    """Contain only this gated CLI tree; daemon work remains outside the job.

    No command is sent until its blocked helper belongs to a nonbreakaway,
    noninheritable kill-on-close job. Output drains continuously into bounded
    tails. Every abnormal post-gate outcome is uncertain, never rollback-ready.
    """
    import ctypes
    from ctypes import wintypes as w

    require(os.name == 'nt' and isinstance(arguments, list) and arguments
            and all(isinstance(x, str) and '\0' not in x for x in arguments))
    require(type(timeout) in {int, float} and 0 < timeout <= 240)
    require(stdin_bytes is None or isinstance(stdin_bytes, bytes) and len(stdin_bytes) <= 8 * 1024 * 1024,
            'Owned CLI input too large')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    pointer = ctypes.c_void_p

    class Limits(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_longlong), ('job_time', ctypes.c_longlong),
                    ('flags', w.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                    ('process_limit', w.DWORD), ('affinity', ctypes.c_size_t),
                    ('priority', w.DWORD), ('scheduling', w.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [('basic', Limits), ('io', ctypes.c_ulonglong * 6),
                    ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                    ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]

    class Accounting(ctypes.Structure):
        _fields_ = [('times', ctypes.c_longlong * 4), ('faults', w.DWORD),
                    ('total', w.DWORD), ('active', w.DWORD), ('terminated', w.DWORD)]

    def bind(name, args, result):
        function = getattr(kernel, name);function.argtypes = args;function.restype = result
        return function

    create = bind('CreateJobObjectW', [pointer, w.LPCWSTR], w.HANDLE)
    configure = bind('SetInformationJobObject', [w.HANDLE, ctypes.c_int, pointer, w.DWORD], w.BOOL)
    query = bind('QueryInformationJobObject', [w.HANDLE, ctypes.c_int, pointer, w.DWORD, pointer], w.BOOL)
    inherit = bind('SetHandleInformation', [w.HANDLE, w.DWORD, w.DWORD], w.BOOL)
    assign = bind('AssignProcessToJobObject', [w.HANDLE, w.HANDLE], w.BOOL)
    open_process = bind('OpenProcess', [w.DWORD, w.BOOL, w.DWORD], w.HANDLE)
    terminate = bind('TerminateJobObject', [w.HANDLE, w.UINT], w.BOOL)
    close = bind('CloseHandle', [w.HANDLE], w.BOOL)
    job = create(None, None);require(bool(job), 'Owned CLI job unavailable')
    process = None;gated = False;tails = [bytearray(), bytearray()];threads = [];errors = []
    mutex = threading.Lock()

    def active():
        account = Accounting()
        require(bool(query(job, 1, ctypes.byref(account), ctypes.sizeof(account), None)),
                'Owned CLI accounting unavailable')
        return account.active

    def drain(stream, index):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                with mutex:
                    tails[index].extend(chunk);del tails[index][:-30000]
        except Exception:
            errors.append('output')

    try:
        limits = ExtendedLimits();limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway
        require(bool(inherit(job, 1, 0)) and bool(configure(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))),
                'Owned CLI job configuration unavailable')
        helper = ('import json,sys; d=json.load(sys.stdin); import subprocess,base64; '
                  'body=base64.b64decode(d["input"],validate=True) if d["input"] is not None else None; '
                  'options={"stdin":subprocess.DEVNULL} if body is None else {"input":body}; '
                  'sys.exit(subprocess.run(d["argv"],close_fds=True,**options).returncode)')
        process = subprocess.Popen([sys.executable, '-I', '-S', '-c', helper],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
        handle = open_process(0x0101, False, process.pid)  # SET_QUOTA | TERMINATE, this blocked helper only
        require(bool(handle), 'Owned CLI helper unavailable')
        try:
            require(bool(assign(job, handle)), 'Owned CLI containment unavailable')
        finally:
            close(handle)
        for index, stream in enumerate([process.stdout, process.stderr]):
            thread = threading.Thread(target=drain, args=(stream, index), daemon=True)
            threads.append(thread);thread.start()
        require(len(json.dumps(arguments).encode()) <= 128 * 1024, 'Owned CLI request too large')
        payload = json.dumps({'argv': arguments, 'input': None if stdin_bytes is None
                             else base64.b64encode(stdin_bytes).decode('ascii')}).encode()
        require(len(payload) <= 12 * 1024 * 1024, 'Owned CLI request too large')

        def release_gate():
            try:
                process.stdin.write(payload);process.stdin.close()
            except Exception:
                errors.append('gate')

        writer = threading.Thread(target=release_gate, daemon=True);threads.append(writer)
        gated = True;writer.start()
        code = process.wait(timeout=timeout)
        # The helper process handle may signal just before job accounting drops
        # its final exiting member. Bound that kernel-accounting transition.
        accounting_deadline = time.monotonic() + 1
        while active() and time.monotonic() < accounting_deadline:
            time.sleep(0.01)
        require(active() == 0, 'Owned CLI descendant survived command completion')
        deadline = time.monotonic() + 10
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
        require(not any(thread.is_alive() for thread in threads) and not errors,
                'Owned CLI output did not finish')
        for stream in [process.stdin, process.stdout, process.stderr]:
            stream.close()
        return subprocess.CompletedProcess(arguments, code, bytes(tails[0]), bytes(tails[1]))
    except BaseException:
        if gated:
            # Even a fully terminated CLI tree cannot prove daemon quiescence.
            deadline = time.monotonic() + 10
            zero = False
            try:
                terminated = bool(terminate(job, 124))
                while terminated and time.monotonic() < deadline:
                    if active() == 0:
                        zero = True;break
                    time.sleep(0.05)
                if zero:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                pass  # Keep uncertainty even when containment accounting fails.
            for thread in threads:
                try:
                    thread.join(max(0, deadline - time.monotonic()))
                except BaseException:
                    pass
            error = UncertainComposeMutation('Owned Compose outcome requires operator recovery')
            error.stdout, error.stderr = bytes(tails[0]), bytes(tails[1])
            error.owned_processes_zero = zero
            raise error from None
        if process is not None and not gated:
            # No command bytes were sent; this is only our blocked gate process.
            try:
                process.kill()
                process.wait(timeout=10)
            except BaseException:
                error = UncertainComposeMutation('Blocked owned helper cleanup requires operator recovery')
                error.stdout, error.stderr = bytes(tails[0]), bytes(tails[1])
                raise error from None
        raise
    finally:
        cleanup_complete = False
        try:
            job_closed = bool(close(job))
            cleanup_complete = process is None or (
                not any(thread.is_alive() for thread in threads) and process.poll() is not None)
            if process is not None and cleanup_complete:
                for stream in [process.stdin, process.stdout, process.stderr]:
                    stream.close()
                # CPython's Windows Popen owns this Handle independently of its
                # streams; release it even when a caller retains the Popen object.
                process._handle.Close()
        except BaseException:
            job_closed = False
            cleanup_complete = False
        if not job_closed or not cleanup_complete:
            error = UncertainComposeMutation('Owned Compose resource cleanup requires operator recovery')
            error.stdout, error.stderr = bytes(tails[0]), bytes(tails[1])
            error.owned_processes_zero = False
            raise error from None


def recreate(docker, command, changing, services, model, log, progress=None):
    deadline = time.monotonic() + 600
    tail = b''
    uncertain = False
    ready = services - changing
    try:
        for index, layer in enumerate(dependency_layers(model, services, changing)):
            require(time.monotonic() < deadline, 'Windows renewal phase deadline reached')
            if progress is not None:
                progress('started', index, layer)
            try:
                p = run_owned_mutation([*command, 'up', '-d', '--no-deps', '--no-build',
                                        '--pull', 'never', '--force-recreate', *layer],
                                       timeout=min(240, deadline - time.monotonic()))
            except (subprocess.TimeoutExpired, UncertainComposeMutation) as error:
                uncertain = True
                tail = (tail + (error.stdout or b'') + (error.stderr or b''))[-60000:]
                raise UncertainComposeMutation('Compose timeout requires operator recovery') from None
            tail = (tail + p.stdout + p.stderr)[-60000:]
            selected = ready | set(layer)
            while time.monotonic() < deadline:
                items = statuses(command, cwd=Path.cwd())
                require(time.monotonic() < deadline, 'Windows renewal phase deadline reached')
                present = {x.get('Service') for x in items}
                require(present == services and len(items) == len(services),
                        'Owned creation incomplete; rollback required')
                checked = [x for x in items if x['Service'] in selected]
                if windows_healthy(checked, selected, model):
                    break
                for item in checked:
                    state = item.get('State', '').lower()
                    completed = item['Service'] in COMPLETED_SERVICES | {'openbao-tls-init'}
                    require(state in {'running', 'restarting', 'exited', 'dead'},
                            'Owned role was not started; rollback required')
                    if state in {'dead', 'exited'} and (not completed or item.get('ExitCode') != 0):
                        raise RuntimeError('Owned role exited during renewal')
                time.sleep(2)
            else:
                raise RuntimeError('Windows renewal did not become ready')
            if progress is not None:
                require(time.monotonic() < deadline, 'Windows renewal phase deadline reached')
                progress('completed', index, layer)
                require(time.monotonic() < deadline, 'Windows renewal phase deadline reached')
            ready = selected
    finally:
        try:
            write_empty_private_file(log, bounded_diagnostic(tail))
        except Exception:
            if uncertain:
                raise UncertainComposeMutation('Compose timeout evidence requires operator recovery') from None
            raise


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
            require(not recovery_pending(config), 'An interrupted recovery requires reconciliation')
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
            from selfhost_windows_selection import activation_admission
            stack.enter_context(activation_admission(config, old_bytes, new_bytes, before_env, after_env))
            baseline = docker.containers()
            owned = [x for x in baseline if _project(x) == project]
            services = {_service(x) for x in owned}
            require(len(owned) == len(services))
            changing = owned_roles(old_model, services)
            require(owned_roles(new_model, services) == changing)
            layers = dependency_layers(old_model, services, changing)
            require(dependency_layers(new_model, services, changing) == layers)
            steps = config['step_receipts']
            step_keys = {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'}
            require(isinstance(steps, list) and len(steps) == len(layers)
                    and all(isinstance(s, dict) and set(s) == step_keys for s in steps))
            step_paths = [Path(p) for s in steps for p in s.values()]
            all_paths = [*outputs.values(), *step_paths]
            require(len(set(all_paths)) == len(all_paths)
                    and all(p.parent == outputs['intent'].parent for p in step_paths))
            require(all(read_private_bytes(p) == b'' for p in step_paths))
            old_hashes, new_hashes = docker.hashes(old), docker.hashes(new)
            checked_live_configuration(owned, old_hashes, config['tls_init_receipt'])
            require(windows_healthy(statuses(old, cwd=source.parent), services, old_model))
            checked_secret_mounts(owned, project, current, services, old_model,
                                  path_equal=windows_mount_path_equal)
            volumes = docker.volumes()
            witnesses = docker.native_witnesses(baseline, project, volumes, config['native']['helper_image'])
            disjoint_storage(baseline, project, volumes, witnesses)
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
            require(observations(docker.containers(), project, set()) == observations(baseline, project, set()),
                    'Container observations changed before intent')
            write_empty_private_file(outputs['intent'], json.dumps({
                'schema': SCHEMA, 'project': project, 'compose_sha256': config['compose_sha256'],
                'current_env': str(old_env), 'renewed_env': str(new_env),
                'current_secrets': str(current), 'renewed_secrets': str(renewed),
                'owned_before': {str(_service(x)): x['Id'] for x in owned},
                'data_mounts_before': data_before,
                'changing': sorted(changing), 'layers': layers, 'step_receipts': steps,
                'candidate_only': True}) + '\n')
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
                return checked_secret_mounts(owned_now, project, root, services, model,
                                              path_equal=windows_mount_path_equal)
            try:
                def progress(phase):
                    def record(event, index, layer):
                        require(layer == layers[index] and event in {'started', 'completed'})
                        write_empty_private_file(Path(steps[index][phase + '_' + event]),
                                                 json.dumps({'roles': layer, 'event': event, 'time': time.time()}) + '\n')
                    return record
                recreate(docker, new, changing, services, new_model, outputs['new_log'], progress=progress('new'))
                mounts = verify(new, renewed, new_model)
                result = {'result': 'activated', 'secret_mounts': mounts}
            except UncertainComposeMutation:
                # A daemon may have accepted work and a CLI child may survive.
                # Never race an uncertain operation with an automatic rollback.
                raise
            except Exception:
                recreate(docker, old, changing, services, old_model, outputs['rollback_log'], progress=progress('rollback'))
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
