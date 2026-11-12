"""Private append-only generation selection for the Windows candidate owner.

Explicit candidate renewal delegates to existing native producers and activation.
No scheduler or release admission. Reconciliation never replays an interrupted operation.
"""
import hashlib
import json
import math
import re
import threading
import uuid
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
STAGE_SCHEMA = 'marty.windows-renewal-staging/v1'
STAGE_PHASES = ('authority','current','prepare','tls','keycloak','export','materialize')
MAX_SELECTIONS = 256


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
    selected_sha256: str
    journal_path: Path
    generation_sequence: int
    check_configuration: Callable = field(repr=False, compare=False)
    check_current: Callable = field(repr=False, compare=False)
    recover_existing: Callable = field(repr=False, compare=False)
    stage_renewal: Callable = field(repr=False, compare=False)
    repair_model: Callable = field(repr=False, compare=False)
    continue_journal: Callable = field(repr=False, compare=False)
    transition_product: Callable = field(repr=False, compare=False)


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
    require('_historical_compose_sha256' not in config)
    require(config['schema'] == renewal.SCHEMA and config['candidate_only'] is True)
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', config['project']))
    old, new = Path(config['current_secrets']), Path(config['renewed_secrets'])
    require(old != new and old.is_absolute() and old.parent == new.parent)
    native = config['native']
    require(type(native['minimum_ttl']) is int and native['minimum_ttl'] >= 3600)
    initial = config.get('initial_current')
    require(initial is None or initial is True)
    return {'project': config['project'], 'engine_id': config['engine_id'], 'docker_host': config['docker_host'],
            'compose_file': config['compose_file'], 'compose_sha256': config['compose_sha256'],
            'root': str(old.parent), 'native': {k: native[k] for k in [
                'binary', 'binary_sha256', 'source_sha', 'release_tag', 'helper_image',
                'control_volume', 'network', 'bao_addr', 'ca_file']},
            **({'initial_current': True} if initial is True else {})}


def directory(config):
    require(re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}', config['project']))
    old, new = Path(config['current_secrets']), Path(config['renewed_secrets'])
    require(old.is_absolute() and old.parent == new.parent)
    return old.parent / ('.'+config['project']+'.generation-selection')


def _read(root, stack):
    from selfhost_windows_continuation import FILES
    from selfhost_windows_product_journal import FILES as product_files
    from selfhost_windows_recovery_journal import FILES as recovery_files
    from selfhost_windows_model import ENTRY as model_entry, LIMIT as model_limit
    names = sorted(p.name for p in root.iterdir())
    require(len(names) <= 2*(MAX_SELECTIONS+model_limit)+1+len(FILES)+len(product_files)+len(recovery_files)
            and all(n == 'owner.json' or n in FILES or n in product_files or n in recovery_files or ENTRY.fullmatch(n) or model_entry.fullmatch(n) for n in names))
    raw = {n: stack.enter_context(renewal.hold_private_input(root/n)) for n in names}
    require(sorted(p.name for p in root.iterdir()) == names)
    return raw


def _parse(raw, expected, *, allow_pending_model=False):
    from selfhost_windows_continuation import FILES, checkpoint
    from selfhost_windows_product_journal import FILES as product_files, SCHEMA as product_schema
    from selfhost_windows_recovery_journal import FILES as recovery_files, SCHEMA as recovery_schema
    from selfhost_windows_model import ENTRY as model_entry, history
    require('owner.json' in raw)
    require(decode(raw['owner.json']) == {'schema': SCHEMA, 'binding': expected})
    carry = checkpoint(raw)
    intents = {};selections = {};previous = None;prior_record = None
    for name, value in raw.items():
        if name == 'owner.json' or name in FILES or name in product_files or name in recovery_files or model_entry.fullmatch(name):continue
        match = ENTRY.fullmatch(name);require(match is not None)
        number = int(match[1]);require(1 <= number <= MAX_SELECTIONS)
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
        require(type(intent['sequence']) is int)
        first_operation = ({product_schema:'product-successor',recovery_schema:'recovery-successor'}.get(carry['schema'],'continuation')) if carry else ('adopt-current' if expected.get('initial_current') else 'adopt')
        require(intent['operation'] == (first_operation if number == 1 else 'activation'))
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
            if number == 1 and carry:
                prefix = {product_schema:'product-selected-',recovery_schema:'recovered-'}.get(carry['schema'],'continued-')
                require(record['decision'] == prefix+record['choice'])
            else:
                decisions = {'adopted', 'activated', 'rolled_back', 'reconciled-old', 'reconciled-new'}
                if expected.get('initial_current'):decisions.add('adopted-current')
                require(isinstance(record['decision'], str) and record['decision'] in decisions)
                require((record['decision'] in {'adopted', 'activated', 'reconciled-new'}) == (record['choice'] == 'new'))
                require((number == 1) == (record['decision'] in {'adopted', 'adopted-current'}))
                if record['decision'] == 'adopted-current':
                    require(number == 1 and record['choice'] == 'old'
                            and record['result_sha256'] == digest(b'')
                            and record['transition_intent_sha256'] == digest(b''))
                if number == 1 and expected.get('initial_current'):
                    require(record['decision'] == 'adopted-current')
            require(record['result_sha256'] is not None or record['decision'].startswith('reconciled-') or number == 1 and carry)
            if prior_record is not None:require(record['data_sha256'] == prior_record['data_sha256'])
            previous = digest(raw[f'{number:06}.selection.json'])
            prior_record = record
        else:
            require(number == len(intents))
    history(raw, expected, selections, allow_pending=allow_pending_model)
    return intents, selections


def _append(root, raw, name, value, stack):
    require(name not in raw)
    with (root/name).open('xb'):pass
    renewal.write_empty_private_file(root/name, packed(value).decode())
    raw[name] = stack.enter_context(renewal.hold_private_input(root/name))
    require(raw[name] == packed(value))


@contextmanager
def _session(config_path, *, create=False, _pending_model_sha256=None, _pending_continuation_sha256=None, _preserve_history=None, _discover_continuation=False, _pending_product_sha256=None, _coordination=None):
    from selfhost_windows_continuation import resolve
    with ExitStack() as stack:
        raw_config = stack.enter_context(renewal.hold_private_input(Path(config_path)))
        config = decode(raw_config);expected = binding(config)
        root = directory(config);parent = root.parent
        require(_coordination is None or isinstance(_coordination, ExitStack))
        coordination=stack if _coordination is None else _coordination
        coordination.enter_context(renewal.hold_private_input(parent/f'.{config["project"]}.renewal.lock', exclusive=True))
        product_guard = renewal.product_transition_guard(config)
        if _pending_product_sha256 is None:
            require(not renewal.namespace_entry_exists(product_guard))
        else:
            require(not create and not _discover_continuation and _pending_model_sha256 is None
                    and _pending_continuation_sha256 is None and type(_pending_product_sha256) is str
                    and re.fullmatch(r'[0-9a-f]{64}', _pending_product_sha256))
            require(digest(stack.enter_context(renewal.hold_private_input(product_guard))) == _pending_product_sha256)
            require(not any(renewal.namespace_entry_exists(getter(config)) for getter in (
                renewal.recovery_guard, renewal.recovery_preparation_guard, renewal.renewal_staging_guard,
                renewal.model_repair_guard, renewal.continuation_guard)))
        stack.enter_context(renewal.hold_storage_namespace(parent))
        if create and not renewal.namespace_entry_exists(root):
            with _held_private_input(parent, directory=True):pass
            root.mkdir()
        stack.enter_context(renewal.hold_storage_namespace(root))
        with _held_private_input(root, directory=True):pass
        raw = _read(root, stack)
        if _discover_continuation:
            require(not create and _pending_model_sha256 is None and _pending_continuation_sha256 is None)
            guard=renewal.continuation_guard(config)
            if renewal.namespace_entry_exists(guard):
                _pending_continuation_sha256=digest(stack.enter_context(renewal.hold_private_input(guard)))
        for cap, guard in [(_pending_model_sha256, renewal.model_repair_guard(config)),
                           (_pending_continuation_sha256, renewal.continuation_guard(config))]:
            if cap is not None:
                require(type(cap) is str and re.fullmatch(r'[0-9a-f]{64}', cap))
                require(digest(stack.enter_context(renewal.hold_private_input(guard))) == cap)
        ancestry=[]
        expected, root, raw, _accepted = resolve(config, root, raw, stack,
            pending_model=_pending_model_sha256 is not None,
            pending_continuation_sha256=_pending_continuation_sha256, ancestry=ancestry,
            discover_pending=_discover_continuation, pending_product_sha256=_pending_product_sha256)
        if _discover_continuation:
            from selfhost_windows_continuation import INTENT, DECISION, validate_marker
            require(INTENT in raw and (DECISION not in raw or _pending_continuation_sha256 is not None))
            marker=validate_marker(raw,expected,root)
            require(raw[INTENT]==packed(marker))
            require(not any(renewal.namespace_entry_exists(getter(config)) for getter in
                (renewal.recovery_guard,renewal.recovery_preparation_guard,
                 renewal.renewal_staging_guard,renewal.model_repair_guard)))
            if not renewal.namespace_entry_exists(guard):_new_private(guard,raw[INTENT])
            require(stack.enter_context(renewal.hold_private_input(guard))==raw[INTENT])
        if _preserve_history is not None:_preserve_history(ancestry)
        try:
            yield config, raw_config, expected, root, raw, stack
        finally:
            for prior_root, prior_raw in ancestry:
                require({p.name for p in prior_root.iterdir()} == set(prior_raw))
                stack.enter_context(_held_private_input(prior_root, directory=True))
                require({p.name for p in prior_root.iterdir()} == set(prior_raw))
            require(sorted(p.name for p in root.iterdir()) == sorted(raw))
            # New entries are complete before the immutable directory proof.
            stack.enter_context(_held_private_input(root, directory=True))
            require(sorted(p.name for p in root.iterdir()) == sorted(raw))


def _inputs(config, stack, *, initial_current=False):
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
    require(type(initial_current) is bool)
    if initial_current:
        require(config.get('initial_current') is True
                and values['old'] == values['new'])
    else:
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
                and intent['compose_sha256'] == config.get('_historical_compose_sha256', config['compose_sha256']))
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
            'context': renewal.ForeignContext(docker, config['project'], set(), baseline, volumes,
                                              config['native']['helper_image']),
            'owned': owned, 'services': services, 'model': models[choice], 'command': commands[choice],
            'cwd': Path(config['compose_file']).parent}


def _initial_current_record(record, origin=None):
    if record is None:
        return False
    if record.get('_initial_current_origin') is True:
        return True
    if record['sequence'] == 1 and record['decision'] == 'adopted-current':
        return True
    if origin is None or origin['sequence'] != 1 or origin['decision'] != 'adopted-current':
        return False
    selected, first = record['selected'], origin['selected']
    return all(selected[key] == first[key]
               for key in ('secrets_dir', 'secrets_sha256', 'native_mirror'))


def _native_current(config, choice, values, docker, authority_file, *, initial_current=False):
    native = dict(config['native']);native['current'] = native['renewed'] if choice == 'new' else native['current']
    if authority_file is not None:native['token_file'] = authority_file
    require(not initial_current or (config.get('initial_current') is True and choice == 'old'))
    if initial_current:
        from selfhost_windows_renewal_native import preflight_initial_current
        preflight_initial_current(native, config['project'], values[choice], docker.prefix)
    else:
        preflight_current(native, config['project'], values[choice], docker.prefix)


def _prove(config, choice, values, stack, *, expected_data=None, authority_file=None,
           initial_current=False):
    """Full readiness plus signed native current-custody/lifetime admission."""
    observed = _inspect(config, choice, values, stack, expected_data=expected_data)
    docker = observed['docker']
    _native_current(config, choice, values, docker, authority_file,
                    initial_current=initial_current)
    observed['context'].check(before_intent=True)
    return observed['data_sha256']


def adopt(config_path, *, authority_file=None):
    with _session(config_path, create=True) as (config, raw_config, expected, root, raw, stack):
        require(config.get('initial_current') is not True)
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


def adopt_current(config_path, *, authority_file=None):
    """Select a verified, already-running initial generation without a fake activation.

    The unused renewed input is an exact private copy of the current files.
    This candidate-only checkpoint allows the existing owner to stage its first
    genuine orphan replacement; it is not production or automatic admission.
    """
    with _session(config_path, create=True) as (config, raw_config, expected, root, raw, stack):
        require(config.get('initial_current') is True and not renewal.recovery_pending(config))
        require(not raw or set(raw) == {'owner.json'} and decode(raw['owner.json']) == {'schema': SCHEMA, 'binding': expected})
        values, snapshots = _inputs(config, stack, initial_current=True)
        transition, result = _empty_initial_activation(config, stack)
        data_hash = _prove(config, 'old', values, stack, authority_file=authority_file,
                           initial_current=True)
        if not raw:_append(root, raw, 'owner.json', {'schema': SCHEMA, 'binding': expected}, stack)
        intent = {'schema': SCHEMA, 'sequence': 1, 'parent': None, 'config_path': str(Path(config_path)),
                  'config_file_sha256': digest(raw_config), 'config_sha256': config_digest(config),
                  'inputs': snapshots, 'operation': 'adopt-current', 'result_before_sha256': digest(result)}
        _append(root, raw, '000001.intent.json', intent, stack)
        record = {'schema': SCHEMA, 'sequence': 1, 'parent': None,
                  'intent_sha256': digest(raw['000001.intent.json']), 'decision': 'adopted-current',
                  'choice': 'old', 'selected': snapshots['old'], 'data_sha256': data_hash,
                  'result_sha256': digest(result), 'transition_intent_sha256': digest(transition)}
        _append(root, raw, '000001.selection.json', record, stack)
        _parse(raw, expected)
    return record


def _empty_initial_activation(config, stack):
    """Hold every activation output empty through initial-current proof."""
    paths = [config[key] for key in ('intent', 'result', 'new_log', 'rollback_log')]
    for step in config['step_receipts']:
        require(set(step) == {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'})
        paths.extend(step.values())
    held = [stack.enter_context(renewal.hold_private_input(Path(path))) for path in paths]
    require(all(not raw for raw in held))
    return held[0], held[1]


def prepare(config_path, *, authority_file=None, staging_sha256=None):
    with _session(config_path) as (config, raw_config, expected, root, raw, stack):
        from selfhost_windows_model import history, model_binding
        if staging_sha256 is None:require(not renewal.recovery_pending(config))
        else:
            require(not renewal.namespace_entry_exists(renewal.recovery_guard(config))
                and not renewal.namespace_entry_exists(renewal.recovery_preparation_guard(config))
                and not renewal.namespace_entry_exists(renewal.model_repair_guard(config))
                and not renewal.namespace_entry_exists(renewal.continuation_guard(config)))
        intents, records = _parse(raw, expected)
        require(len(intents) == len(records) and len(intents) < MAX_SELECTIONS)
        previous = records[len(records)];values, snapshots = _inputs(config, stack)
        require(model_binding(config) == history(raw, expected, records)[1])
        require(snapshots['old'] == previous['selected'])
        if staging_sha256 is not None:
            stage,result=_staging_admission(config,raw_config,previous,stack,staging_sha256)
            require(stage['config_path']==str(Path(config_path))
                and result['secrets_sha256']==snapshots['new']['secrets_sha256']
                and result['env_sha256']==snapshots['new']['env_sha256']
                and result['files']==len(values['new'])
                and result['changed_files']==sum(values['old'][n]!=values['new'][n] for n in values['old']))
            require(authority_file in (None,stage['authority_file']))
            authority_file=stage['authority_file']
            renewal.native_preflight(config['native'],config['project'],values['old'],values['new'],
                                     renewal.Docker(config['docker_host'],config['engine_id']).prefix)
        require(all(renewal.read_private_bytes(Path(config[k])) == b''
                    for k in ['intent', 'result', 'new_log', 'rollback_log']))
        for step in config['step_receipts']:
            require(set(step) == {'new_started', 'new_completed', 'rollback_started', 'rollback_completed'})
            require(all(renewal.read_private_bytes(Path(p)) == b'' for p in step.values()))
        _prove(config, 'old', values, stack, expected_data=previous['data_sha256'],
               authority_file=authority_file,
               initial_current=_initial_current_record(previous, records.get(1)))
        sequence = len(intents)+1
        intent = {'schema': SCHEMA, 'sequence': sequence,
                  'parent': digest(raw[f'{sequence-1:06}.selection.json']), 'config_path': str(Path(config_path)),
                  'config_file_sha256': digest(raw_config), 'config_sha256': config_digest(config),
                  'inputs': snapshots, 'operation': 'activation', 'result_before_sha256': digest(b'')}
        _append(root, raw, f'{sequence:06}.intent.json', intent, stack)
        _parse(raw, expected)
        intent_sha=digest(raw[f'{sequence:06}.intent.json'])
    if staging_sha256 is not None:
        _handoff_staged(config_path,staging_sha256,sequence,intent_sha)
    return sequence


def _unstarted_activation_check(config, intent, stack):
    """Bind an interrupted first boundary to the original, unchanged runtime.

    The writer fsyncs a started receipt before invoking any workload command.
    The caller has held every receipt empty; the project lock excludes a live
    writer. Neither healthy appearance nor a diagnostic log substitutes for this
    durable before-command boundary.
    """
    require(set(intent) == {'schema', 'project', 'compose_sha256', 'current_env', 'renewed_env',
        'current_secrets', 'renewed_secrets', 'owned_before', 'data_mounts_before',
        'changing', 'layers', 'step_receipts', 'candidate_only'} and intent['candidate_only'] is True)
    require(stack.enter_context(renewal.hold_private_input(Path(config['new_log'])))
            == renewal.bounded_diagnostic(b'').encode())
    require(stack.enter_context(renewal.hold_private_input(Path(config['rollback_log']))) == b'')
    expected = intent['owned_before']
    require(isinstance(expected, dict) and expected and all(isinstance(role, str)
        and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', role) and isinstance(cid, str)
        and re.fullmatch(r'[0-9a-f]{64}', cid) for role, cid in expected.items())
        and len(set(expected.values())) == len(expected))
    require(isinstance(intent['data_mounts_before'], dict)
            and set(intent['data_mounts_before']) == set(expected))
    docker = renewal.Docker(config['docker_host'], config['engine_id'])
    command = docker.compose(config['project'], Path(config['current_env']), Path(config['compose_file']))
    model = docker.json(command[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
    services = set(expected)
    changing = renewal.owned_roles(model, services)
    require(sorted(changing) == intent['changing']
            and renewal.dependency_layers(model, services, changing) == intent['layers'])
    def unchanged():
        items = [x for x in docker.containers() if renewal._project(x) == config['project']]
        require(len(items) == len(expected)
                and {renewal._service(x): x['Id'] for x in items} == expected
                and renewal.data_mounts(items) == intent['data_mounts_before'])
    unchanged()
    return unchanged


def _reconciliation_choice(config, stack, *, unstarted_checks=None):
    """A healthy snapshot cannot establish an unknown CLI's quiescence.

    No activation intent means no invocation was sent. Otherwise require the
    terminal phase's complete durable boundaries, or the exact all-empty first
    boundary whose writer could not have reached a workload invocation.
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
    ready = {'new': [], 'rollback': []};rollback_seen = False;any_boundary = False
    for layer, step in zip(layers, steps):
        require(set(step) == keys)
        for phase in ['new', 'rollback']:
            values = {}
            for event in ['started', 'completed']:
                value = stack.enter_context(renewal.hold_private_input(Path(step[phase+'_'+event])))
                values[event] = bool(value)
                any_boundary |= bool(value)
                if value:
                    record = decode(value)
                    require(set(record) == {'roles', 'event', 'time'} and record['roles'] == layer and record['event'] == event)
                    require(type(record['time']) in {int, float} and math.isfinite(record['time']) and record['time'] > 0)
            require(not values['completed'] or values['started'])
            ready[phase].append(values['started'] and values['completed'])
            if phase == 'rollback':rollback_seen |= any(values.values())
    if not any_boundary:
        check = _unstarted_activation_check(config, intent, stack)
        if unstarted_checks is not None:unstarted_checks.append(check)
        return 'old'
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
        from selfhost_windows_continuation import resolve
        ancestry=[]
        _resolved, root, raw, _models = resolve(config, root, raw, stack, ancestry=ancestry)
        stack.enter_context(_held_private_input(root, directory=True))
        from selfhost_windows_model import hold_history, model_binding, owner_binding
        expected = owner_binding(raw, config)
        intents, records = _parse(raw, expected);require(len(intents) == len(records)+1)
        current_model, _accepted = hold_history(raw, expected, records, stack)
        require(model_binding(config) == current_model)
        intent = intents[len(intents)];require(intent['operation'] == 'activation')
        require(intent['config_sha256'] == config_digest(config))
        for choice, data, env, prefix, mirror in [('old', old, old_env, 'current', 'current'), ('new', new, new_env, 'renewed', 'renewed')]:
            require(intent['inputs'][choice] == {'env_file': config[prefix+'_env'], 'env_sha256': digest(env),
                'secrets_dir': str(Path(config[prefix+'_secrets'])), 'secrets_sha256': fingerprint(data),
                'native_mirror': config['native'][mirror]})
        try:yield
        finally:
            require(sorted(p.name for p in root.iterdir()) == sorted(raw))
            for prior_root, prior_raw in ancestry:
                require({p.name for p in prior_root.iterdir()} == set(prior_raw))


def complete(config_path, *, reconcile=False, authority_file=None):
    require(type(reconcile) is bool)
    with _session(config_path) as (config, raw_config, expected, root, raw, stack):
        require(not renewal.recovery_pending(config))
        intents, records = _parse(raw, expected);sequence = len(intents)
        require(sequence == len(records)+1)
        intent = intents[sequence]
        require(intent['config_path'] == str(Path(config_path)) and intent['config_file_sha256'] == digest(raw_config)
                and intent['config_sha256'] == config_digest(config))
        initial_current = sequence == 1 and intent['operation'] == 'adopt-current'
        values, snapshots = _inputs(config, stack, initial_current=initial_current)
        require(snapshots == intent['inputs'])
        result_raw = stack.enter_context(renewal.hold_private_input(Path(config['result'])))
        previous = records.get(sequence-1)
        expected_data = previous['data_sha256'] if previous is not None else None
        if sequence == 1:
            require(digest(result_raw) == intent['result_before_sha256']
                    and (not result_raw if initial_current else bool(result_raw)))
        if initial_current:
            require(not reconcile)
            transition_raw, checked_result = _empty_initial_activation(config, stack)
            require(checked_result == result_raw)
            choice = 'old';decision = 'adopted-current'
            data_hash = _prove(config, choice, values, stack,
                               expected_data=expected_data, authority_file=authority_file,
                               initial_current=True)
        elif result_raw:
            result = decode(result_raw)
            require(result['schema'] == renewal.SCHEMA and result['project'] == config['project']
                    and result['candidate_only'] is True and result['result'] in {'activated', 'rolled_back'}
                    and result['production_admission'] is False and result['automatic_lifecycle'] is False)
            choice = 'new' if result['result'] == 'activated' else 'old'
            if sequence == 1:require(choice == 'new')
            decision = 'adopted' if sequence == 1 else result['result']
            data_hash = _prove(config, choice, values, stack, expected_data=expected_data,
                               authority_file=authority_file,
                               initial_current=choice == 'old' and
                                   _initial_current_record(previous, records.get(1)))
        else:
            require(reconcile)
            unstarted_checks = []
            choice = _reconciliation_choice(config, stack, unstarted_checks=unstarted_checks);decision = 'reconciled-'+choice
            data_hash = _prove(config, choice, values, stack, expected_data=expected_data,
                               authority_file=authority_file,
                               initial_current=choice == 'old' and
                                   _initial_current_record(previous, records.get(1)))
            for check in unstarted_checks:check()
        record = {'schema': SCHEMA, 'sequence': sequence, 'parent': intent['parent'],
                  'intent_sha256': digest(raw[f'{sequence:06}.intent.json']), 'decision': decision, 'choice': choice,
                  'selected': snapshots[choice], 'data_sha256': data_hash,
                  'result_sha256': digest(result_raw) if result_raw or initial_current else None,
                  'transition_intent_sha256': digest(transition_raw if initial_current else
                      renewal.read_private_bytes(Path(config['intent'])))}
        _append(root, raw, f'{sequence:06}.selection.json', record, stack)
        _parse(raw, expected)
    return record


def status(config_path):
    with _session(config_path) as (config, _raw_config, expected, _root, raw, _stack):
        intents, records = _parse(raw, expected)
        if len(intents) != len(records):return {'state': 'pending-reconciliation', 'sequence': len(intents)}
        if renewal.namespace_entry_exists(renewal.renewal_staging_guard(config)):
            return {'state':'pending-staging','sequence':len(records),'project':config['project']}
        selected = records[len(records)]
        result = {'state': 'selected', 'sequence': len(records), 'project': config['project'],
                  'selected': selected['selected'], 'decision': selected['decision']}
        if _root != directory(config):
            from selfhost_windows_continuation import checkpoint
            result.update(journal=str(_root), generation_sequence=checkpoint(raw)['sequence_offset']+len(records))
        if renewal.namespace_entry_exists(renewal.continuation_guard(config)):result['state']='pending-continuation'
        return result


def _stage_names():
    return ['intent.json',*[phase+'.'+event+'.json' for phase in STAGE_PHASES
        for event in ('started','completed')], 'prepare.helper.json','tls.created.json',
        'tls.helper.json','keycloak.helper.json']


def _new_private(path,raw):
    with path.open('xb'):pass
    if raw:renewal.write_empty_private_file(path,raw.decode('utf-8'))
    else:require(renewal.read_private_bytes(path)==b'')


def _stage_configuration(config,choice,record,root,layers):
    """The same immutable configuration for initial staging and reconciliation."""
    prefix='renewed' if choice=='new' else 'current'
    cycle=root.name.removeprefix('windows-renewal-')
    result=decode(packed(config));result.pop('_historical_compose_sha256',None)
    result.update(current_env=config[prefix+'_env'],current_secrets=config[prefix+'_secrets'],
        renewed_env=str(root/'renewed.env'),
        renewed_secrets=str(root.parent/('candidate-secrets-renewal-'+cycle)))
    result['native'].update(current=record['selected']['native_mirror'],
        renewed='/control/windows-renewal-'+cycle+'/generation',
        token_file='/control/recovery-session-'+cycle+'/token')
    for name in ['intent','result','new_log','rollback_log']:result[name]=str(root/'activation'/name)
    result['step_receipts']=[{name:str(root/'activation'/(str(index)+'-'+name))
        for name in ['new_started','new_completed','rollback_started','rollback_completed']}
        for index in range(len(layers))]
    return result


def _stage(config,choice,values,record,root,logical_project,stack):
    # Capacity admission precedes any guard, credential mint or output allocation.
    require(type(record['sequence']) is int and 1<=record['sequence']<MAX_SELECTIONS)
    from selfhost_windows_renewal_native import (
        preflight,
        produce_generation,
        reauthenticate,
    )
    parent=Path(config['current_secrets']).parent;root=Path(root)
    require(root.parent==parent and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name))
    require(not renewal.recovery_pending(config) and not list(root.iterdir()))
    # The signed selfhost-renew TLS helper requires this prefix before it can
    # provision any credentials. Refuse incompatible input before journaling.
    require(re.fullmatch(r'marty-selfhost-[a-z0-9][a-z0-9-]{0,59}',logical_project))
    stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root,directory=True):pass
    observed=_inspect(config,choice,values,stack,expected_data=record['data_sha256'])
    observed['context'].check(before_intent=True)
    docker=observed['docker'];cycle_id=root.name.removeprefix('windows-renewal-')
    secrets=parent/('candidate-secrets-renewal-'+cycle_id)
    require(not renewal.namespace_entry_exists(secrets));secrets.mkdir()
    stack.enter_context(renewal.hold_storage_namespace(secrets))
    with _held_private_input(secrets,directory=True):pass
    activation=root/'activation';activation.mkdir()
    with _held_private_input(activation,directory=True):pass
    layers=renewal.dependency_layers(observed['model'],observed['services'],
        renewal.owned_roles(observed['model'],observed['services']))
    next_config=_stage_configuration(config,choice,record,root,layers)
    authority='/control/recovery-session-'+cycle_id+'/token'
    for name in ['intent','result','new_log','rollback_log']:
        _new_private(Path(next_config[name]),b'')
    for step in next_config['step_receipts']:
        for path in step.values():_new_private(Path(path),b'')
    env=renewal.read_private_bytes(Path(next_config['current_env']));lines=env.splitlines(keepends=True)
    indices=[i for i,line in enumerate(lines) if line.startswith(b'SELFHOST_SECRET_DIR=')];require(len(indices)==1)
    index=indices[0];ending=b'\r\n' if lines[index].endswith(b'\r\n') else b'\n'
    lines[index]=b'SELFHOST_SECRET_DIR='+secrets.as_posix().encode()+ending;renewed_env=b''.join(lines)
    require(renewal.env_body(env,Path(next_config['current_secrets']))==renewal.env_body(renewed_env,secrets))
    _new_private(root/'renewed.env',renewed_env)
    next_path=activation/'config.private.json';next_raw=packed(next_config);_new_private(next_path,next_raw)
    stage={'schema':STAGE_SCHEMA,'project':config['project'],'engine_id':config['engine_id'],
        'sequence':record['sequence']+1,'selected_sha256':digest(packed(record['selected'])),
        'data_sha256':record['data_sha256'],'root':str(root),'config_path':str(next_path),
        'config_sha256':digest(next_raw),'authority_file':authority,'logical_project':logical_project,
        'services_image':observed['model']['services']['signing-keys']['image'],'candidate_only':True}
    names=_stage_names()
    for name in [*names,'result.json','publication.pending.json']:_new_private(root/name,b'')
    guard=renewal.renewal_staging_guard(config);_new_private(guard,packed(stage))
    renewal.write_empty_private_file(root/'intent.json',packed(stage).decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
    def checkpoint(phase,event,metadata):
        require(phase in STAGE_PHASES and event in {'started','completed','created','helper'})
        name=phase+'.'+event+'.json';require(name in names)
        body={'phase':phase,'event':event,'metadata':metadata}
        renewal.write_empty_private_file(root/name,packed(body).decode())
        stack.enter_context(renewal.hold_private_input(root/name))
    checkpoint('authority','started',{})
    require(reauthenticate(config['native'],config['project'],docker.prefix,authority.rsplit('/',1)[0])==authority)
    checkpoint('authority','completed',{})
    checkpoint('current','started',{})
    require(_prove(config,choice,values,stack,expected_data=record['data_sha256'],
                   authority_file=authority,initial_current=_initial_current_record(record))==record['data_sha256'])
    observed['context'].check(before_intent=True)
    checkpoint('current','completed',{})
    renewed=produce_generation(next_config,values[choice],logical_project,cycle_id,stage['services_image'],checkpoint)
    require(set(renewed)==set(values[choice]))
    checkpoint('materialize','started',{})
    for name,value in renewed.items():_new_private(secrets/name,value)
    held=stack.enter_context(renewal.hold_private_generation(secrets,sorted(renewed)));require(held==renewed)
    preflight(next_config['native'],config['project'],values[choice],held,docker.prefix)
    require(_prove(config,choice,values,stack,expected_data=record['data_sha256'],
                   authority_file=authority,initial_current=_initial_current_record(record))==record['data_sha256'])
    items=observed['context'].check(before_intent=True)
    checkpoint('materialize','completed',{})
    receipts={name:renewal.read_private_bytes(root/name) for name in names}
    require(all(receipts.values()))
    _retired_stage_helpers(items,_checked_stage_receipts(stage,config,receipts),cycle_id)
    hashes={name:digest(raw) for name,raw in receipts.items()}
    result={'schema':STAGE_SCHEMA,'guard_sha256':digest(packed(stage)),
        'config_sha256':digest(next_raw),'next_config':str(next_path),'authority_file':authority,
        'files':len(held),'changed_files':sum(values[choice][n]!=held[n] for n in held),
        'secrets_sha256':fingerprint(held),'env_sha256':digest(renewed_env),'phase_sha256':hashes}
    require(set(p.name for p in root.iterdir())==set(names)|{'result.json','publication.pending.json','renewed.env','activation'})
    return {'stage':stage,'result':result}


def _finish_stage(config,pending,*,resume=False):
    """Publish only after selected-lease exit; the staging guard stays active."""
    require(type(resume) is bool)
    stage=pending['stage'];result=pending['result'];root=Path(stage['root'])
    with ExitStack() as held:
        next_config=None
        def memberships():
            marker='publication.json' if renewal.namespace_entry_exists(root/'publication.json') else 'publication.pending.json'
            require(set(p.name for p in root.iterdir())==set(_stage_names())|{'result.json',marker,'renewed.env','activation'})
            if next_config is not None:
                paths=[next_config[n] for n in ('intent','result','new_log','rollback_log')]
                paths += [p for step in next_config['step_receipts'] for p in step.values()]
                require(set(p.name for p in (root/'activation').iterdir())=={'config.private.json',*(Path(p).name for p in paths)})
        held.callback(memberships)
        held.enter_context(renewal.hold_private_input(Path(config['current_secrets']).parent/f'.{config["project"]}.renewal.lock',exclusive=True))
        require(not renewal.namespace_entry_exists(renewal.product_transition_guard(config)))
        held.enter_context(renewal.hold_storage_namespace(root))
        require(digest(held.enter_context(renewal.hold_private_input(renewal.renewal_staging_guard(config))))==result['guard_sha256'])
        for name,sha in result['phase_sha256'].items():
            require(digest(held.enter_context(renewal.hold_private_input(root/name)))==sha)
        next_raw=held.enter_context(renewal.hold_private_input(Path(stage['config_path'])))
        require(digest(next_raw)==stage['config_sha256']);next_config=decode(next_raw)
        require(digest(held.enter_context(renewal.hold_private_input(root/'renewed.env')))==result['env_sha256'])
        model_raw=held.enter_context(renewal.hold_private_input(Path(config['compose_file']),max_bytes=2*1024*1024))
        require(digest(model_raw)==config['compose_sha256'])
        generation=held.enter_context(renewal.hold_private_generation(Path(decode(renewal.read_private_bytes(Path(stage['config_path'])))['renewed_secrets']),
            sorted(decode(model_raw)['secrets'])))
        require(fingerprint(generation)==result['secrets_sha256'])
        with _held_private_input(root,directory=True):
            existing=renewal.read_private_bytes(root/'result.json')
            require(existing==b'' or (resume and existing==packed(result)))
    # Publication must follow every held-input and lock exit check. A failure
    # while releasing any proof above leaves the result empty and inadmissible.
    if not existing:renewal.write_empty_private_file(root/'result.json',packed(result).decode())
    publication=packed({'schema':STAGE_SCHEMA,'result_sha256':digest(packed(result))})
    published=renewal.namespace_entry_exists(root/'publication.json')
    require(resume or not published)
    marker=root/('publication.json' if published else 'publication.pending.json')
    saved=renewal.read_private_bytes(marker)
    require(not saved or (resume and saved==publication))
    require(not published or saved==publication)
    if not saved:renewal.write_empty_private_file(marker,publication.decode())
    with ExitStack() as held:
        held.enter_context(renewal.hold_storage_namespace(root))
        require(held.enter_context(renewal.hold_private_input(root/'result.json'))==packed(result))
        require(held.enter_context(renewal.hold_private_input(marker))==publication)
    # Windows rename refuses an existing destination. Only this final atomic
    # boundary makes the result admissible; failed writers/exit checks retain
    # the pending file and staging guard without an admission marker.
    if marker.name=='publication.pending.json':marker.rename(root/'publication.json')


def _checked_stage_receipts(stage,config,raws,*,materialize_pending=False):
    require(set(raws)==set(_stage_names()) and raws['intent.json']==packed(stage))
    helpers={}
    cycle=Path(stage['root']).name.removeprefix('windows-renewal-')
    for name,raw in raws.items():
        if name=='intent.json':continue
        if materialize_pending and name=='materialize.completed.json' and not raw:continue
        require(raw);phase,event,_=name.split('.')
        item=decode(raw)
        require(set(item)=={'phase','event','metadata'} and item['phase']==phase and item['event']==event)
        metadata=item['metadata']
        if event in {'created','helper'}:
            require(type(metadata) is dict and set(metadata)=={'id','name','image'}
                and type(metadata['id']) is str and re.fullmatch(r'[0-9a-f]{64}',metadata['id'])
                and metadata['name']==config['project']+'-renew-'+phase+'-'+cycle
                and metadata['image']==(stage['services_image'] if phase=='tls' else config['native']['helper_image']))
            helpers[name]=metadata
        else:require(metadata=={})
    require(helpers['tls.created.json']==helpers['tls.helper.json'])
    require(len({helpers[p+'.helper.json']['id'] for p in ('prepare','tls','keycloak')})==3)
    return helpers


def _retired_stage_helpers(items,helpers,cycle):
    """A storage-disjoint helper is still an unfinished producer, not churn."""
    ids={h['id'] for h in helpers.values()};names={'/'+h['name'] for h in helpers.values()}
    require(not any(x['Id'] in ids or x.get('Name') in names
        or (x.get('Config',{}).get('Labels') or {}).get('marty.windows.renewal')==cycle
        for x in items))


def reconcile_materialized(config_path):
    """Reprove fully produced bytes and publish metadata; never mint or activate.

    Earlier/uncertain producer phases, changed inputs and partial activation
    remain blocked. The staging guard is retained for the normal prepare path.
    """
    from selfhost_windows_model import effective_config,history,immutable_binding,model_binding
    from selfhost_windows_continuation import CHECKPOINT,checkpoint
    from selfhost_windows_renewal_native import preflight
    with _session(config_path) as (base,_base_raw,expected,_journal,raw,stack):
        require(not any(renewal.namespace_entry_exists(getter(base)) for getter in
            (renewal.recovery_guard,renewal.recovery_preparation_guard,
             renewal.model_repair_guard,renewal.continuation_guard)))
        intents,records=_parse(raw,expected);require(len(intents)==len(records))
        intent=intents[len(records)];record=records[len(records)]
        require(type(record['sequence']) is int and 1<=record['sequence']<MAX_SELECTIONS)
        cfg_raw=stack.enter_context(renewal.hold_private_input(Path(intent['config_path'])))
        config=decode(cfg_raw)
        require(digest(cfg_raw)==intent['config_file_sha256'] and config_digest(config)==intent['config_sha256']
            and immutable_binding(binding(config))==immutable_binding(expected))
        _models,current_model,accepted=history(raw,expected,records)
        if CHECKPOINT in raw:accepted.append(checkpoint(raw)['generation_model'])
        require(model_binding(config) in accepted);config=effective_config(config,current_model)
        initial_current = record['sequence'] == 1 and record['decision'] == 'adopted-current'
        if _initial_current_record(record, records.get(1)):
            record = dict(record, _initial_current_origin=True)
        values,snapshots=_inputs(config,stack,initial_current=initial_current)
        require(snapshots==intent['inputs'])
        transition=stack.enter_context(renewal.hold_private_input(Path(config['intent'])))
        previous_result=stack.enter_context(renewal.hold_private_input(Path(config['result'])))
        require(digest(transition)==record['transition_intent_sha256'])
        require(digest(previous_result)==record['result_sha256'] if record['result_sha256'] is not None else not previous_result)
        guard=stack.enter_context(renewal.hold_private_input(renewal.renewal_staging_guard(config)))
        stage=decode(guard);root=Path(stage['root'])
        require(root.parent==Path(config['current_secrets']).parent
            and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name))
        stack.enter_context(renewal.hold_storage_namespace(root))
        with _held_private_input(root,directory=True):pass
        published=renewal.namespace_entry_exists(root/'publication.json')
        marker='publication.json' if published else 'publication.pending.json'
        expected_names=set(_stage_names())|{'result.json',marker,'renewed.env','activation'}
        def root_membership():require(set(p.name for p in root.iterdir())==expected_names)
        root_membership();stack.callback(root_membership)
        activation_names=None
        def activation_membership():
            if activation_names is not None:require(set(p.name for p in (root/'activation').iterdir())==activation_names)
        stack.callback(activation_membership)
        receipts={name:(renewal.read_private_bytes(root/name) if name=='materialize.completed.json'
            else stack.enter_context(renewal.hold_private_input(root/name))) for name in _stage_names()}
        helpers=_checked_stage_receipts(stage,config,receipts,materialize_pending=True)
        next_raw=stack.enter_context(renewal.hold_private_input(root/'activation/config.private.json'))
        next_config=decode(next_raw)
        # The current inspection supplies validated service closure and layers.
        observed=_inspect(config,record['choice'],values,stack,expected_data=record['data_sha256'])
        layers=renewal.dependency_layers(observed['model'],observed['services'],
            renewal.owned_roles(observed['model'],observed['services']))
        require(next_raw==packed(_stage_configuration(config,record['choice'],record,root,layers)))
        cycle=root.name.removeprefix('windows-renewal-')
        expected_stage={'schema':STAGE_SCHEMA,'project':config['project'],'engine_id':config['engine_id'],
            'sequence':record['sequence']+1,'selected_sha256':digest(packed(record['selected'])),
            'data_sha256':record['data_sha256'],'root':str(root),'config_path':str(root/'activation/config.private.json'),
            'config_sha256':digest(next_raw),'authority_file':'/control/recovery-session-'+cycle+'/token',
            'logical_project':stage['logical_project'],
            'services_image':observed['model']['services']['signing-keys']['image'],'candidate_only':True}
        require(stage==expected_stage and re.fullmatch(r'marty-(?:selfhost|production)-[a-z0-9][a-z0-9-]{0,59}',stage['logical_project']))
        paths=[Path(next_config[n]) for n in ('intent','result','new_log','rollback_log')]
        paths += [Path(p) for step in next_config['step_receipts'] for p in step.values()]
        activation_names={'config.private.json',*(p.name for p in paths)}
        activation_membership()
        for path in paths:require(stack.enter_context(renewal.hold_private_input(path))==b'')
        env=stack.enter_context(renewal.hold_private_input(root/'renewed.env'))
        old_env=renewal.read_private_bytes(Path(next_config['current_env']))
        require(renewal.env_body(env,Path(next_config['renewed_secrets']))
            ==renewal.env_body(old_env,Path(next_config['current_secrets'])))
        new=stack.enter_context(renewal.hold_private_generation(Path(next_config['renewed_secrets']),sorted(values[record['choice']])))
        docker=observed['docker']
        _retired_stage_helpers(docker.containers(),helpers,cycle)
        _native_current(config,record['choice'],values,docker,stage['authority_file'],
                        initial_current=_initial_current_record(record))
        preflight(next_config['native'],config['project'],values[record['choice']],new,docker.prefix)
        _retired_stage_helpers(observed['context'].check(before_intent=True),helpers,cycle)
        completed=packed({'phase':'materialize','event':'completed','metadata':{}})
        require(receipts['materialize.completed.json'] in (b'',completed))
        if not receipts['materialize.completed.json']:
            renewal.write_empty_private_file(root/'materialize.completed.json',completed.decode())
        receipts['materialize.completed.json']=stack.enter_context(renewal.hold_private_input(root/'materialize.completed.json'))
        _checked_stage_receipts(stage,config,receipts)
        result={'schema':STAGE_SCHEMA,'guard_sha256':digest(guard),'config_sha256':digest(next_raw),
            'next_config':stage['config_path'],'authority_file':stage['authority_file'],
            'files':len(new),'changed_files':sum(values[record['choice']][n]!=new[n] for n in new),
            'secrets_sha256':fingerprint(new),'env_sha256':digest(env),
            'phase_sha256':{n:digest(v) for n,v in receipts.items()}}
        saved=stack.enter_context(renewal.hold_private_input(root/'result.json'))
        publication=stack.enter_context(renewal.hold_private_input(root/marker))
        require(saved in (b'',packed(result)))
        require(publication in (b'',packed({'schema':STAGE_SCHEMA,'result_sha256':digest(packed(result))})))
        require(not publication or saved)
        require(not published or (saved and publication))
    # Every selected ancestry/input exit must succeed before admission metadata.
    _finish_stage(config,{'stage':stage,'result':result},resume=True)
    return result


def _staging_admission(config,raw_config,previous,stack,sha):
    require(type(sha) is str and re.fullmatch(r'[0-9a-f]{64}',sha))
    guard_raw=stack.enter_context(renewal.hold_private_input(renewal.renewal_staging_guard(config)))
    require(digest(guard_raw)==sha);stage=decode(guard_raw)
    require(stage['schema']==STAGE_SCHEMA and stage['candidate_only'] is True
        and stage['project']==config['project'] and stage['engine_id']==config['engine_id']
        and stage['sequence']==previous['sequence']+1 and stage['selected_sha256']==digest(packed(previous['selected']))
        and stage['data_sha256']==previous['data_sha256'])
    root=Path(stage['root']);require(root.parent==Path(config['current_secrets']).parent
        and re.fullmatch(r'windows-renewal-[0-9a-f]{32}',root.name))
    cycle=root.name.removeprefix('windows-renewal-')
    require(config['renewed_secrets']==str(root.parent/('candidate-secrets-renewal-'+cycle))
        and config['renewed_env']==str(root/'renewed.env')
        and config['native']['renewed']=='/control/windows-renewal-'+cycle+'/generation'
        and stage['authority_file']=='/control/recovery-session-'+cycle+'/token')
    require(Path(stage['config_path'])==root/'activation/config.private.json'
        and digest(raw_config)==stage['config_sha256']
        and config['native']['token_file']==stage['authority_file'])
    require(stack.enter_context(renewal.hold_private_input(root/'intent.json'))==guard_raw)
    result=decode(stack.enter_context(renewal.hold_private_input(root/'result.json')))
    require(stack.enter_context(renewal.hold_private_input(root/'publication.json'))
        ==packed({'schema':STAGE_SCHEMA,'result_sha256':digest(packed(result))}))
    require(result['schema']==STAGE_SCHEMA and result['guard_sha256']==sha
        and result['next_config']==stage['config_path'] and result['config_sha256']==digest(raw_config)
        and result['authority_file']==stage['authority_file'] and set(result['phase_sha256'])==set(_stage_names()))
    receipts={}
    for name,expected in result['phase_sha256'].items():
        raw=stack.enter_context(renewal.hold_private_input(root/name));require(raw and digest(raw)==expected)
        receipts[name]=raw
    _checked_stage_receipts(stage,config,receipts)
    require(set(p.name for p in root.iterdir())==set(_stage_names())|{'result.json','publication.json','renewed.env','activation'})
    return stage,result


def _handoff_staged(config_path,sha,sequence,intent_sha):
    """A registered pending intent is durable before staging loses authority."""
    with _session(config_path) as (config,raw_config,expected,root,raw,stack):
        require(not any(renewal.namespace_entry_exists(getter(config)) for getter in
            (renewal.recovery_guard,renewal.recovery_preparation_guard,
             renewal.model_repair_guard,renewal.continuation_guard)))
        guard=renewal.renewal_staging_guard(config)
        require(digest(stack.enter_context(renewal.hold_private_input(guard)))==sha)
        intents,records=_parse(raw,expected)
        require(len(intents)==sequence==len(records)+1
            and digest(raw[f'{sequence:06}.intent.json'])==intent_sha
            and intents[sequence]['config_path']==str(Path(config_path))
            and intents[sequence]['config_file_sha256']==digest(raw_config))
    # Any late proof failure above leaves the staging guard. After this point,
    # the pending journal independently blocks new recovery/production attempts.
    require(digest(renewal.read_private_bytes(root/f'{sequence:06}.intent.json'))==intent_sha)
    require(digest(renewal.read_private_bytes(guard))==sha)
    guard.unlink()


def renew_once(config_path,logical_project):
    """One online candidate cycle; never retry a pending/uncertain operation."""
    with selected_inputs(config_path) as lease:
        continued=lease.sequence>=MAX_SELECTIONS
        if continued:lease.continue_journal()
        else:
            next_generation=lease.generation_sequence+1;journal=lease.journal_path
            root=lease.secrets_dir.parent/('windows-renewal-'+uuid.uuid4().hex)
            root.mkdir()
            staged=lease.stage_renewal(root,logical_project)
    if continued:
        with selected_inputs(config_path) as lease:
            require(lease.sequence<MAX_SELECTIONS)
            next_generation=lease.generation_sequence+1;journal=lease.journal_path
            root=lease.secrets_dir.parent/('windows-renewal-'+uuid.uuid4().hex)
            root.mkdir()
            staged=lease.stage_renewal(root,logical_project)
    path=Path(staged['next_config']);authority=staged['authority_file']
    prepare(path,authority_file=authority,staging_sha256=staged['guard_sha256'])
    cfg=decode(renewal.read_private_bytes(path))
    try:
        result=renewal.activate(cfg)
    except BaseException:
        saved=renewal.read_private_bytes(Path(cfg['result']))
        if saved and decode(saved).get('result')=='rolled_back':complete(path,authority_file=authority)
        raise
    require(result['result']=='activated')
    selected=complete(path,authority_file=authority)
    return {'schema':STAGE_SCHEMA,'project':cfg['project'],'result':'renewed-and-selected',
        'sequence':selected['sequence'],'generation_sequence':next_generation,'journal':str(journal),
        'config_path':str(path),'staging_root':str(root),
        'production_admission':False,'automatic_lifecycle':False}


@contextmanager
def _selected_inputs(config_path, *, terminal_guard_sha256=None):
    """Hold local selection and the project lock for a future recovery owner.

    The explicit callback delegates live readiness/custody checks after Bao is
    available. No startup or Docker mutation is performed by this context.
    """
    completion = [];staging=[];model_completion=[];continuation=[];continuation_started=False
    product_completion=[];product_started=False
    with _session(config_path) as (_config, _cfg_raw, expected, _root, raw, stack):
        if terminal_guard_sha256 is None:
            require(not renewal.recovery_pending(_config))
        else:
            require(type(terminal_guard_sha256) is str and re.fullmatch(r'[0-9a-f]{64}', terminal_guard_sha256))
            require(not renewal.namespace_entry_exists(renewal.recovery_preparation_guard(_config)))
            require(not renewal.namespace_entry_exists(renewal.renewal_staging_guard(_config)))
            require(not renewal.namespace_entry_exists(renewal.model_repair_guard(_config)))
            require(not renewal.namespace_entry_exists(renewal.continuation_guard(_config)))
            guard_raw = stack.enter_context(renewal.hold_private_input(renewal.recovery_guard(_config)))
            require(digest(guard_raw) == terminal_guard_sha256)
        intents, records = _parse(raw, expected);require(len(intents) == len(records))
        sequence = len(records);intent = intents[sequence];record = records[sequence]
        if _initial_current_record(record, records.get(1)):
            record = dict(record, _initial_current_origin=True)
        cfg_raw = stack.enter_context(renewal.hold_private_input(Path(intent['config_path'])))
        cfg = decode(cfg_raw)
        from selfhost_windows_model import effective_config, history, immutable_binding, model_binding
        require(digest(cfg_raw) == intent['config_file_sha256'] and config_digest(cfg) == intent['config_sha256']
                and immutable_binding(binding(cfg)) == immutable_binding(expected))
        _models, current_model, accepted_models = history(raw, expected, records)
        from selfhost_windows_continuation import CHECKPOINT, checkpoint
        if CHECKPOINT in raw:accepted_models.append(checkpoint(raw)['generation_model'])
        require(model_binding(cfg) in accepted_models)
        cfg = effective_config(cfg, current_model)
        initial_current = sequence == 1 and intent['operation'] == 'adopt-current'
        values, snapshots = _inputs(cfg, stack, initial_current=initial_current)
        require(snapshots == intent['inputs'])
        transition = stack.enter_context(renewal.hold_private_input(Path(cfg['intent'])))
        result = stack.enter_context(renewal.hold_private_input(Path(cfg['result'])))
        require(digest(transition) == record['transition_intent_sha256'])
        require(digest(result) == record['result_sha256'] if record['result_sha256'] is not None else not result)
        selected = record['selected'];choice = record['choice']
        lease_lock = threading.Lock();active = True
        def check_current(authority_file=None):
            with lease_lock:
                require(active and not model_completion and not continuation_started and not product_started)
                with ExitStack() as proof_stack:
                    return _prove(cfg, choice, values, proof_stack,
                                  expected_data=record['data_sha256'], authority_file=authority_file,
                                  initial_current=_initial_current_record(record))
        def check_configuration():
            with lease_lock:
                require(active and not model_completion and not continuation_started and not product_started)
                with ExitStack() as proof_stack:
                    observed=_inspect(cfg,choice,values,proof_stack,
                        expected_data=record['data_sha256'],require_ready=False)
                    from selfhost_windows_recovery import plan
                    plan(observed)
                    observed['context'].check(before_intent=True)
                    return {'services':len(observed['services']),'configuration_verified':True,
                            'native_admission':False,'runtime_readiness':False}
        def recover_existing(output_dir, authority_file=None, *, preparation_sha256=None, fresh_authority=False):
            with lease_lock:
                require(active and not completion and not staging and not model_completion and not continuation_started and not product_started and terminal_guard_sha256 is None)
                from selfhost_windows_recovery import start_existing
                with ExitStack() as proof_stack:
                    pending = start_existing(cfg, choice, values, record, output_dir, proof_stack,
                                             authority_file=authority_file, preparation_sha256=preparation_sha256,
                                             fresh_authority=fresh_authority)
                completion.append(pending)
                return decode(packed(pending['result']))
        def stage_renewal(output_dir,logical_project):
            with lease_lock:
                require(active and not completion and not staging and not model_completion and not continuation_started and not product_started and terminal_guard_sha256 is None)
                with ExitStack() as proof_stack:
                    pending=_stage(cfg,choice,values,record,output_dir,logical_project,proof_stack)
                staging.append(pending)
                return decode(packed(pending['result']))
        def repair_model(new_model, output_dir):
            with lease_lock:
                require(active and not completion and not staging and not model_completion
                        and not continuation_started and not product_started and terminal_guard_sha256 is None)
                from selfhost_windows_model import repair
                with ExitStack() as proof_stack:
                    pending = repair(cfg, choice, values, record, intent, raw, _root,
                                     new_model, output_dir, proof_stack)
                model_completion.append(pending)
                return decode(packed(pending['result']))
        def continue_journal():
            nonlocal continuation_started
            with lease_lock:
                require(active and not completion and not staging and not model_completion
                        and not continuation_started and not product_started and terminal_guard_sha256 is None)
                require(not _initial_current_record(record))
                continuation_started=True
                from selfhost_windows_continuation import start
                with ExitStack() as proof_stack:
                    pending=start(cfg,choice,values,record,raw,_root,proof_stack)
                continuation.append(pending)
                return decode(packed(pending['result']))
        def transition_product(assets, *, gh, cosign, registry_config):
            nonlocal product_started
            with lease_lock:
                require(active and not completion and not staging and not model_completion
                        and not continuation_started and not product_started and terminal_guard_sha256 is None)
                require(not _initial_current_record(record))
                product_started=True
                from selfhost_windows_product_deploy import start
                with ExitStack() as proof_stack:
                    pending=start(cfg,choice,values,record,raw,_root,assets,
                        gh=gh,cosign=cosign,registry_config=registry_config,stack=proof_stack)
                product_completion.append(pending)
                return decode(packed(pending['result']))
        from selfhost_windows_continuation import CHECKPOINT, checkpoint
        generation_sequence=sequence+(checkpoint(raw)['sequence_offset'] if CHECKPOINT in raw else 0)
        try:
            yield SelectedInputs(cfg['project'], cfg['docker_host'], cfg['engine_id'], Path(cfg['compose_file']),
                cfg['compose_sha256'], Path(selected['env_file']), Path(selected['secrets_dir']), sequence,
                digest(packed(selected)), _root, generation_sequence,
                check_configuration, check_current, recover_existing, stage_renewal, repair_model, continue_journal, transition_product)
        finally:
            with lease_lock:
                active = False;values.clear()
    if completion:
        from selfhost_windows_recovery import finish_existing
        finish_existing(cfg, completion[0])
    if staging:_finish_stage(cfg,staging[0])
    if model_completion:
        from selfhost_windows_model import finish
        finish(cfg,model_completion[0])
    if continuation:
        from selfhost_windows_continuation import finish
        finish(cfg,config_path,continuation[0])
    if product_completion:
        from selfhost_windows_product_journal import finish
        pending=product_completion[0]
        finish(config_path,pending['marker'],pending['phases'],authority_file=pending['authority_file'])


@contextmanager
def selected_inputs(config_path):
    """Hold selected inputs for current proof or guarded existing-ID recovery."""
    with _selected_inputs(config_path) as lease:
        yield lease


def reconcile_existing(config_path, *, authority_file=None):
    """Read-only terminal reconciliation; unfinished commands remain blocked."""
    config = decode(renewal.read_private_bytes(Path(config_path)))
    binding(config)
    guard_raw = renewal.read_private_bytes(renewal.recovery_guard(config))
    from selfhost_windows_recovery import finish_terminal, verify_terminal
    with _selected_inputs(config_path, terminal_guard_sha256=digest(guard_raw)) as lease:
        require(lease.project == config['project'] and lease.secrets_dir.parent == Path(config['current_secrets']).parent)
        pending = verify_terminal(lease, guard_raw, authority_file=authority_file)
    finish_terminal(config, pending)
    return decode(packed(pending['decision']))
