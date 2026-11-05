"""Private append-only generation selection for the Windows candidate owner.

No producer, scheduler, startup mutation or release admission. Reconciliation
proves the current state; it never replays an interrupted operation.
"""
import hashlib
import json
import math
import re
import threading
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable

import selfhost_windows_renewal as renewal
from selfhost_windows_inputs import _held_private_input
from selfhost_windows_renewal_native import preflight_current

SCHEMA = 'marty.windows-generation-selection/v1'
ENTRY = re.compile(r'([0-9]{6})\.(intent|selection)\.json\Z')
REFUSAL = 'Windows selection requires operator reconciliation; preserve its records'


@dataclass(frozen=True)
class SelectedInputs:
    project: str
    docker_host: str
    engine_id: str
    compose_file: Path
    compose_sha256: str
    env_file: Path
    secrets_dir: Path
    sequence: int
    check_current: Callable = field(repr=False, compare=False)
    recover_existing: Callable = field(repr=False, compare=False)


def require(value):
    if not value:
        raise ValueError(REFUSAL)


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value);value[key] = item
        return value
    def finite(value):
        number = float(value);require(math.isfinite(number));return number
    def constant(_value):
        raise ValueError(REFUSAL)
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=constant)


def packed(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(values):
    return digest(packed({name: digest(raw) for name, raw in values.items()}))


def config_digest(config):
    return digest(packed(config))


def binding(config):
    require(config['schema'] == renewal.SCHEMA and config['candidate_only'] is True)
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', config['project']))
    old, new = Path(config['current_secrets']), Path(config['renewed_secrets'])
    require(old != new and old.is_absolute() and old.parent == new.parent)
    native = config['native']
    require(type(native['minimum_ttl']) is int and native['minimum_ttl'] >= 3600)
    return {'project': config['project'], 'engine_id': config['engine_id'], 'docker_host': config['docker_host'],
            'compose_file': config['compose_file'], 'compose_sha256': config['compose_sha256'],
            'root': str(old.parent), 'native': {k: native[k] for k in [
                'binary', 'binary_sha256', 'source_sha', 'release_tag', 'helper_image',
                'control_volume', 'network', 'bao_addr', 'ca_file']}}


def directory(config):
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', config['project']))
    old, new = Path(config['current_secrets']), Path(config['renewed_secrets'])
    require(old.is_absolute() and old.parent == new.parent)
    return old.parent / ('.'+config['project']+'.generation-selection')


def _read(root, stack):
    names = sorted(p.name for p in root.iterdir())
    require(len(names) <= 513 and all(n == 'owner.json' or ENTRY.fullmatch(n) for n in names))
    raw = {n: stack.enter_context(renewal.hold_private_input(root/n)) for n in names}
    require(sorted(p.name for p in root.iterdir()) == names)
    return raw


def _parse(raw, expected):
    require('owner.json' in raw)
    require(decode(raw['owner.json']) == {'schema': SCHEMA, 'binding': expected})
    intents = {};selections = {};previous = None;prior_record = None
    for name, value in raw.items():
        if name == 'owner.json':continue
        match = ENTRY.fullmatch(name);require(match is not None)
        number = int(match[1]);require(1 <= number <= 256)
        target = intents if match[2] == 'intent' else selections
        require(number not in target);target[number] = decode(value)
    require(intents and set(intents) == set(range(1, len(intents)+1)))
    require(set(selections) == set(range(1, len(selections)+1)))
    require(len(intents)-len(selections) in {0, 1})
    for number in range(1, len(intents)+1):
        intent = intents[number]
        require(isinstance(intent, dict) and set(intent) == {'schema', 'sequence', 'parent', 'config_path', 'config_file_sha256',
                               'config_sha256', 'inputs', 'operation', 'result_before_sha256'})
        require(intent['schema'] == SCHEMA and intent['sequence'] == number and intent['parent'] == previous)
        require(type(intent['sequence']) is int and intent['operation'] in {'adopt', 'activation'})
        require(intent['operation'] == ('adopt' if number == 1 else 'activation'))
        require(isinstance(intent['inputs'], dict) and set(intent['inputs']) == {'old', 'new'})
        for snapshot in intent['inputs'].values():
            require(isinstance(snapshot, dict) and set(snapshot) == {'env_file', 'env_sha256', 'secrets_dir', 'secrets_sha256', 'native_mirror'})
            require(all(isinstance(v, str) for v in snapshot.values()))
            require(Path(snapshot['env_file']).is_absolute() and Path(snapshot['secrets_dir']).parent == Path(expected['root']))
            require(all(re.fullmatch(r'[0-9a-f]{64}', snapshot[k]) for k in ['env_sha256', 'secrets_sha256']))
            mirror = PurePosixPath(snapshot['native_mirror'])
            require(mirror.is_relative_to('/control') and len(mirror.parts) >= 3
                    and '..' not in mirror.parts and str(mirror) == snapshot['native_mirror'])
        require(all(isinstance(intent[k], str) and re.fullmatch(r'[0-9a-f]{64}', intent[k])
                    for k in ['config_sha256', 'config_file_sha256', 'result_before_sha256']))
        require(isinstance(intent['config_path'], str) and Path(intent['config_path']).is_absolute())
        if number > 1:require(intent['result_before_sha256'] == digest(b''))
        if prior_record is not None:require(intent['inputs']['old'] == prior_record['selected'])
        if number in selections:
            record = selections[number]
            require(isinstance(record, dict) and set(record) == {'schema', 'sequence', 'parent', 'intent_sha256', 'decision',
                                   'choice', 'selected', 'data_sha256', 'result_sha256', 'transition_intent_sha256'})
            require(record['schema'] == SCHEMA and record['sequence'] == number and record['parent'] == previous)
            require(type(record['sequence']) is int and all(isinstance(record[k], str) and re.fullmatch(r'[0-9a-f]{64}', record[k])
                    for k in ['data_sha256', 'transition_intent_sha256']))
            require(record['result_sha256'] is None or isinstance(record['result_sha256'], str)
                    and re.fullmatch(r'[0-9a-f]{64}', record['result_sha256']))
            require(record['intent_sha256'] == digest(raw[f'{number:06}.intent.json']))
            require(isinstance(record['choice'], str) and record['choice'] in {'old', 'new'} and record['selected'] == intent['inputs'][record['choice']])
            require(isinstance(record['decision'], str) and record['decision'] in {'adopted', 'activated', 'rolled_back', 'reconciled-old', 'reconciled-new'})
            require((record['decision'] in {'adopted', 'activated', 'reconciled-new'}) == (record['choice'] == 'new'))
            require((number == 1) == (record['decision'] == 'adopted'))
            require(record['result_sha256'] is not None or record['decision'].startswith('reconciled-'))
            if prior_record is not None:require(record['data_sha256'] == prior_record['data_sha256'])
            previous = digest(raw[f'{number:06}.selection.json'])
            prior_record = record
        else:
            require(number == len(intents))
    return intents, selections


def _append(root, raw, name, value, stack):
    require(name not in raw)
    with (root/name).open('xb'):pass
    renewal.write_empty_private_file(root/name, packed(value).decode())
    raw[name] = stack.enter_context(renewal.hold_private_input(root/name))
    require(raw[name] == packed(value))


@contextmanager
def _session(config_path, *, create=False):
    with ExitStack() as stack:
        raw_config = stack.enter_context(renewal.hold_private_input(Path(config_path)))
        config = decode(raw_config);expected = binding(config)
        root = directory(config);parent = root.parent
        stack.enter_context(renewal.hold_private_input(parent/f'.{config["project"]}.renewal.lock', exclusive=True))
        stack.enter_context(renewal.hold_storage_namespace(parent))
        if create and not renewal.namespace_entry_exists(root):
            with _held_private_input(parent, directory=True):pass
            root.mkdir()
        stack.enter_context(renewal.hold_storage_namespace(root))
        with _held_private_input(root, directory=True):pass
        raw = _read(root, stack)
        try:
            yield config, raw_config, expected, root, raw, stack
        finally:
            require(sorted(p.name for p in root.iterdir()) == sorted(raw))
            # New entries are complete before the immutable directory proof.
            stack.enter_context(_held_private_input(root, directory=True))
            require(sorted(p.name for p in root.iterdir()) == sorted(raw))


def _inputs(config, stack):
    raw_model = stack.enter_context(renewal.hold_private_input(Path(config['compose_file']), max_bytes=2*1024*1024))
    require(digest(raw_model) == config['compose_sha256'])
    names = sorted(decode(raw_model)['secrets']);require(names)
    values = {};snapshots = {};envs = {}
    for choice, prefix, mirror in [('old', 'current', 'current'), ('new', 'renewed', 'renewed')]:
        env = stack.enter_context(renewal.hold_private_input(Path(config[prefix+'_env'])))
        envs[choice] = env
        root = Path(config[prefix+'_secrets'])
        values[choice] = stack.enter_context(renewal.hold_private_generation(root, names))
        snapshots[choice] = {'env_file': config[prefix+'_env'], 'env_sha256': digest(env),
                             'secrets_dir': str(root), 'secrets_sha256': fingerprint(values[choice]),
                             'native_mirror': config['native'][mirror]}
    require(snapshots['old']['secrets_sha256'] != snapshots['new']['secrets_sha256'])
    require(renewal.env_body(envs['old'], Path(config['current_secrets']))
            == renewal.env_body(envs['new'], Path(config['renewed_secrets'])))
    return values, snapshots


def _inspect(config, choice, values, stack, *, expected_data=None, require_ready=True):
    """Local/runtime identity and isolation only; never native admission."""
    prefix = 'renewed' if choice == 'new' else 'current'
    docker = renewal.Docker(config['docker_host'], config['engine_id'])
    commands = {c: docker.compose(config['project'], Path(config[p+'_env']), Path(config['compose_file']))
                for c, p in [('old', 'current'), ('new', 'renewed')]}
    models = {c: docker.json(command[len(docker.prefix):]+['--profile', '*', 'config', '--format', 'json'])
              for c, command in commands.items()}
    renewal.checked_models(models['old'], models['new'], Path(config['current_secrets']),
                           Path(config['renewed_secrets']), sorted(values['old']))
    baseline = docker.containers();owned = [x for x in baseline if renewal._project(x) == config['project']]
    services = {renewal._service(x) for x in owned};require(len(services) == len(owned))
    changing = renewal.owned_roles(models[choice], services)
    renewal.dependency_layers(models[choice], services, changing)
    renewal.checked_live_configuration(owned, docker.hashes(commands[choice]), config['tls_init_receipt'])
    mounts = renewal.checked_secret_mounts(owned, config['project'], Path(config[prefix+'_secrets']),
        services, models[choice], path_equal=renewal.windows_mount_path_equal)
    if require_ready:
        require(renewal.windows_healthy(renewal.statuses(commands[choice], cwd=Path(config['compose_file']).parent), services, models[choice]))
    data_hash = digest(packed(renewal.data_mounts(owned)))
    if expected_data is not None:require(data_hash == expected_data)
    intent_raw = stack.enter_context(renewal.hold_private_input(Path(config['intent'])))
    if intent_raw:
        intent = decode(intent_raw)
        require(intent['schema'] == renewal.SCHEMA and intent['project'] == config['project']
                and intent['compose_sha256'] == config['compose_sha256'])
        require(all(intent[k] == config[k] for k in ['current_env', 'renewed_env', 'current_secrets', 'renewed_secrets']))
        require(intent['changing'] == sorted(changing)
                and intent['layers'] == renewal.dependency_layers(models[choice], services, changing)
                and intent['step_receipts'] == config['step_receipts'])
        require(data_hash == digest(packed(intent['data_mounts_before'])))
        require(all(x['Id'] == intent['owned_before'][renewal._service(x)]
                    for x in owned if renewal._service(x) not in changing))
    volumes = docker.volumes()
    witnesses = docker.native_witnesses(baseline, config['project'], volumes, config['native']['helper_image'])
    renewal.disjoint_storage(baseline, config['project'], volumes, witnesses)
    for item in owned:
        for mount in item['Mounts']:
            if mount.get('RW') and mount.get('Type') == 'bind':
                path = renewal.windows_source(mount['Source']);require(path is not None)
                stack.enter_context(renewal.hold_storage_namespace(path))
    require(mounts > 0)
    return {'data_sha256': data_hash, 'docker': docker, 'baseline': baseline,
            'owned': owned, 'services': services, 'model': models[choice], 'command': commands[choice],
            'cwd': Path(config['compose_file']).parent}


def _native_current(config, choice, values, docker, authority_file):
    native = dict(config['native']);native['current'] = native['renewed'] if choice == 'new' else native['current']
    if authority_file is not None:native['token_file'] = authority_file
    preflight_current(native, config['project'], values[choice], docker.prefix)


def _prove(config, choice, values, stack, *, expected_data=None, authority_file=None):
    """Full readiness plus signed native current-custody/lifetime admission."""
    observed = _inspect(config, choice, values, stack, expected_data=expected_data)
    docker = observed['docker']
    _native_current(config, choice, values, docker, authority_file)
    require(renewal.observations(docker.containers(), config['project'], set())
            == renewal.observations(observed['baseline'], config['project'], set()))
    return observed['data_sha256']


def adopt(config_path, *, authority_file=None):
    with _session(config_path, create=True) as (config, raw_config, expected, root, raw, stack):
        require(not renewal.recovery_pending(config))
        require(not raw or set(raw) == {'owner.json'} and decode(raw['owner.json']) == {'schema': SCHEMA, 'binding': expected})
        values, snapshots = _inputs(config, stack)
        result_raw = stack.enter_context(renewal.hold_private_input(Path(config['result'])))
        transition_raw = stack.enter_context(renewal.hold_private_input(Path(config['intent'])))
        require(transition_raw)
        result = decode(result_raw)
        require(result['schema'] == renewal.SCHEMA and result['project'] == config['project']
                and result['result'] == 'activated' and result['candidate_only'] is True
                and result['production_admission'] is False and result['automatic_lifecycle'] is False)
        data_hash = _prove(config, 'new', values, stack, authority_file=authority_file)
        if not raw:_append(root, raw, 'owner.json', {'schema': SCHEMA, 'binding': expected}, stack)
        intent = {'schema': SCHEMA, 'sequence': 1, 'parent': None, 'config_path': str(Path(config_path)),
                  'config_file_sha256': digest(raw_config), 'config_sha256': config_digest(config),
                  'inputs': snapshots, 'operation': 'adopt', 'result_before_sha256': digest(result_raw)}
        _append(root, raw, '000001.intent.json', intent, stack)
        record = {'schema': SCHEMA, 'sequence': 1, 'parent': None,
                  'intent_sha256': digest(raw['000001.intent.json']), 'decision': 'adopted', 'choice': 'new',
                  'selected': snapshots['new'], 'data_sha256': data_hash, 'result_sha256': digest(result_raw),
                  'transition_intent_sha256': digest(transition_raw)}
        _append(root, raw, '000001.selection.json', record, stack)
        _parse(raw, expected)
    return record


def prepare(config_path, *, authority_file=None):
    with _session(config_path) as (config, raw_config, expected, root, raw, stack):
        require(not renewal.recovery_pending(config))
        intents, records = _parse(raw, expected)
        require(len(intents) == len(records) and len(intents) < 256)
        previous = records[len(records)];values, snapshots = _inputs(config, stack)
        require(snapshots['old'] == previous['selected'])
        require(all(renewal.read_private_bytes(Path(config[k])) == b''
                    for k in ['intent', 'result', 'new_log', 'rollback_log']))
        for step in config['step_receipts']:
            require(set(step) == {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'})
            require(all(renewal.read_private_bytes(Path(p)) == b'' for p in step.values()))
        _prove(config, 'old', values, stack, expected_data=previous['data_sha256'], authority_file=authority_file)
        sequence = len(intents)+1
        intent = {'schema': SCHEMA, 'sequence': sequence,
                  'parent': digest(raw[f'{sequence-1:06}.selection.json']), 'config_path': str(Path(config_path)),
                  'config_file_sha256': digest(raw_config), 'config_sha256': config_digest(config),
                  'inputs': snapshots, 'operation': 'activation', 'result_before_sha256': digest(b'')}
        _append(root, raw, f'{sequence:06}.intent.json', intent, stack)
        _parse(raw, expected)
    return sequence


def _reconciliation_choice(config, stack):
    """A healthy snapshot cannot establish an unknown CLI's quiescence.

    No activation intent means no invocation was sent. Otherwise require the
    terminal phase's complete durable boundaries; incomplete mutators stay with
    their operator, even if a transient snapshot looks healthy.
    """
    raw = stack.enter_context(renewal.hold_private_input(Path(config['intent'])))
    if not raw:
        for name in ['new_log', 'rollback_log']:
            require(stack.enter_context(renewal.hold_private_input(Path(config[name]))) == b'')
        for step in config['step_receipts']:
            require(set(step) == {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'})
            for value in step.values():
                require(stack.enter_context(renewal.hold_private_input(Path(value))) == b'')
        return 'old'
    intent = decode(raw)
    require(intent['schema'] == renewal.SCHEMA and intent['project'] == config['project']
            and intent['compose_sha256'] == config['compose_sha256'])
    require(all(intent[k] == config[k] for k in ['current_env', 'renewed_env', 'current_secrets', 'renewed_secrets']))
    layers = intent['layers'];steps = config['step_receipts']
    keys = {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'}
    require(isinstance(layers, list) and layers and isinstance(steps, list) and len(layers) == len(steps)
            and intent['step_receipts'] == steps)
    require(all(isinstance(step, dict) and set(step) == keys and all(isinstance(p, str) and Path(p).is_absolute()
                for p in step.values()) for step in steps))
    require(all(isinstance(layer, list) and layer and all(isinstance(role, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', role)
                for role in layer) for layer in layers))
    paths = [Path(p) for step in steps for p in step.values()]
    require(len(set(paths)) == len(paths) and all(p.parent == Path(config['intent']).parent for p in paths))
    all_roles = [role for layer in layers for role in layer]
    require(all(isinstance(layer, list) and layer == sorted(set(layer)) and layer for layer in layers)
            and len(set(all_roles)) == len(all_roles) and sorted(all_roles) == intent['changing'])
    ready = {'new': [], 'rollback': []};rollback_seen = False
    for layer, step in zip(layers, steps):
        require(set(step) == keys)
        for phase in ['new', 'rollback']:
            values = {}
            for event in ['started', 'completed']:
                value = stack.enter_context(renewal.hold_private_input(Path(step[phase+'_'+event])))
                values[event] = bool(value)
                if value:
                    record = decode(value)
                    require(set(record) == {'roles', 'event', 'time'} and record['roles'] == layer and record['event'] == event)
                    require(type(record['time']) in {int, float} and math.isfinite(record['time']) and record['time'] > 0)
            require(not values['completed'] or values['started'])
            ready[phase].append(values['started'] and values['completed'])
            if phase == 'rollback':rollback_seen |= any(values.values())
    require(all(ready['rollback'] if rollback_seen else ready['new']))
    return 'old' if rollback_seen else 'new'


@contextmanager
def activation_admission(config, old, new, old_env, new_env):
    """Called under the activator's project lock; records stay held throughout."""
    root = directory(config)
    require(not renewal.recovery_pending(config))
    if not renewal.namespace_entry_exists(root):
        yield;return
    with ExitStack() as stack:
        stack.enter_context(renewal.hold_storage_namespace(root))
        stack.enter_context(_held_private_input(root, directory=True))
        raw = _read(root, stack)
        intents, records = _parse(raw, binding(config));require(len(intents) == len(records)+1)
        intent = intents[len(intents)];require(intent['operation'] == 'activation')
        require(intent['config_sha256'] == config_digest(config))
        for choice, data, env, prefix, mirror in [('old', old, old_env, 'current', 'current'), ('new', new, new_env, 'renewed', 'renewed')]:
            require(intent['inputs'][choice] == {'env_file': config[prefix+'_env'], 'env_sha256': digest(env),
                'secrets_dir': str(Path(config[prefix+'_secrets'])), 'secrets_sha256': fingerprint(data),
                'native_mirror': config['native'][mirror]})
        try:yield
        finally:require(sorted(p.name for p in root.iterdir()) == sorted(raw))


def complete(config_path, *, reconcile=False, authority_file=None):
    require(type(reconcile) is bool)
    with _session(config_path) as (config, raw_config, expected, root, raw, stack):
        require(not renewal.recovery_pending(config))
        intents, records = _parse(raw, expected);sequence = len(intents)
        require(sequence == len(records)+1)
        intent = intents[sequence]
        require(intent['config_path'] == str(Path(config_path)) and intent['config_file_sha256'] == digest(raw_config)
                and intent['config_sha256'] == config_digest(config))
        values, snapshots = _inputs(config, stack);require(snapshots == intent['inputs'])
        result_raw = stack.enter_context(renewal.hold_private_input(Path(config['result'])))
        previous = records.get(sequence-1)
        expected_data = previous['data_sha256'] if previous is not None else None
        if sequence == 1:require(result_raw and digest(result_raw) == intent['result_before_sha256'])
        if result_raw:
            result = decode(result_raw)
            require(result['schema'] == renewal.SCHEMA and result['project'] == config['project']
                    and result['candidate_only'] is True and result['result'] in {'activated', 'rolled_back'}
                    and result['production_admission'] is False and result['automatic_lifecycle'] is False)
            choice = 'new' if result['result'] == 'activated' else 'old'
            if sequence == 1:require(choice == 'new')
            decision = 'adopted' if sequence == 1 else result['result']
            data_hash = _prove(config, choice, values, stack, expected_data=expected_data, authority_file=authority_file)
        else:
            require(reconcile)
            choice = _reconciliation_choice(config, stack);decision = 'reconciled-'+choice
            data_hash = _prove(config, choice, values, stack, expected_data=expected_data, authority_file=authority_file)
        record = {'schema': SCHEMA, 'sequence': sequence, 'parent': intent['parent'],
                  'intent_sha256': digest(raw[f'{sequence:06}.intent.json']), 'decision': decision, 'choice': choice,
                  'selected': snapshots[choice], 'data_sha256': data_hash,
                  'result_sha256': digest(result_raw) if result_raw else None,
                  'transition_intent_sha256': digest(renewal.read_private_bytes(Path(config['intent'])))}
        _append(root, raw, f'{sequence:06}.selection.json', record, stack)
        _parse(raw, expected)
    return record


def status(config_path):
    with _session(config_path) as (config, _raw_config, expected, _root, raw, _stack):
        intents, records = _parse(raw, expected)
        if len(intents) != len(records):return {'state': 'pending-reconciliation', 'sequence': len(intents)}
        selected = records[len(records)]
        return {'state': 'selected', 'sequence': len(records), 'project': config['project'],
                'selected': selected['selected'], 'decision': selected['decision']}


@contextmanager
def selected_inputs(config_path):
    """Hold local selection and the project lock for a future recovery owner.

    The explicit callback delegates live readiness/custody checks after Bao is
    available. No startup or Docker mutation is performed by this context.
    """
    completion = []
    with _session(config_path) as (_config, _cfg_raw, expected, _root, raw, stack):
        require(not renewal.recovery_pending(_config))
        intents, records = _parse(raw, expected);require(len(intents) == len(records))
        sequence = len(records);intent = intents[sequence];record = records[sequence]
        cfg_raw = stack.enter_context(renewal.hold_private_input(Path(intent['config_path'])))
        cfg = decode(cfg_raw)
        require(digest(cfg_raw) == intent['config_file_sha256'] and config_digest(cfg) == intent['config_sha256']
                and binding(cfg) == expected)
        values, snapshots = _inputs(cfg, stack);require(snapshots == intent['inputs'])
        transition = stack.enter_context(renewal.hold_private_input(Path(cfg['intent'])))
        result = stack.enter_context(renewal.hold_private_input(Path(cfg['result'])))
        require(digest(transition) == record['transition_intent_sha256'])
        require(digest(result) == record['result_sha256'] if record['result_sha256'] is not None else not result)
        selected = record['selected'];choice = record['choice']
        lease_lock = threading.Lock();active = True
        def check_current(authority_file=None):
            with lease_lock:
                require(active)
                with ExitStack() as proof_stack:
                    return _prove(cfg, choice, values, proof_stack, expected_data=record['data_sha256'], authority_file=authority_file)
        def recover_existing(output_dir, authority_file=None):
            with lease_lock:
                require(active and not completion)
                from selfhost_windows_recovery import start_existing
                with ExitStack() as proof_stack:
                    pending = start_existing(cfg, choice, values, record, output_dir, proof_stack,
                                             authority_file=authority_file)
                completion.append(pending)
                return decode(packed(pending['result']))
        try:
            yield SelectedInputs(cfg['project'], cfg['docker_host'], cfg['engine_id'], Path(cfg['compose_file']),
                cfg['compose_sha256'], Path(selected['env_file']), Path(selected['secrets_dir']), sequence,
                check_current, recover_existing)
        finally:
            with lease_lock:
                active = False;values.clear()
    if completion:
        from selfhost_windows_recovery import finish_existing
        finish_existing(cfg, completion[0])
