"""Append-only, candidate-only repair of the Applicant issuance file binding.

The generation journal stays authoritative. No original config, model, generation
or receipt is rewritten; incomplete model operations never admit a fallback.
"""
from copy import deepcopy
from pathlib import Path
import re
import uuid
from contextlib import ExitStack

import selfhost_windows_selection as selection

SCHEMA = 'marty.windows-model-repair/v1'
ENTRY = re.compile(r'([0-9]{6})\.(model-intent|model-selection)\.json\Z')
LIMIT = 64
MODEL_KEYS = {'compose_file', 'compose_sha256'}
NAMES = {'intent.json', 'result.json', 'new.log', 'rollback.log',
         'authority.started.json', 'authority.completed.json',
         'new.started.json', 'new.completed.json',
         'rollback.started.json', 'rollback.completed.json'}


def require(value):
    selection.require(value)


def model_binding(config):
    return {key: config[key] for key in MODEL_KEYS}


def immutable_binding(value):
    return {key: item for key, item in value.items() if key not in MODEL_KEYS}


def owner_binding(raw, config):
    supplied = selection.binding(config)
    if not raw:
        return supplied
    owner = selection.decode(raw['owner.json'])
    require(set(owner) == {'schema', 'binding'} and owner['schema'] == selection.SCHEMA)
    expected = owner['binding']
    require(set(expected) == set(supplied)
            and immutable_binding(expected) == immutable_binding(supplied))
    return expected


def check_repair(before, after):
    """Exactly the existing Issuance credential, never a generic model upgrade."""
    expected = deepcopy(before)
    require('issuance_api_key' in expected['secrets'])
    app = expected['services']['applicant']
    require('ISSUANCE_API_KEY_FILE' not in app['environment']
            and not app['environment'].get('ISSUANCE_API_KEY'))
    require(not any(item['source'] == 'issuance_api_key' for item in app['secrets']))
    app['environment']['ISSUANCE_API_KEY_FILE'] = '/run/secrets/issuance_api_key'
    app['secrets'].append({'source': 'issuance_api_key', 'target': '/run/secrets/issuance_api_key'})
    require(expected == after)


def history(raw, expected, records, *, allow_pending=False):
    intents = {}
    decisions = {}
    for name, value in raw.items():
        match = ENTRY.fullmatch(name)
        if not match:
            continue
        number = int(match[1])
        require(1 <= number <= LIMIT)
        target = intents if match[2] == 'model-intent' else decisions
        require(number not in target)
        target[number] = selection.decode(value)
    require(set(intents) == set(range(1, len(intents)+1))
            and set(decisions) == set(range(1, len(decisions)+1)))
    require(len(intents)-len(decisions) in ({0, 1} if allow_pending else {0}))
    current = model_binding(expected)
    accepted = [current]
    parent = None
    result = []
    for number in range(1, len(intents)+1):
        intent = intents[number]
        require(set(intent) == {'schema', 'sequence', 'parent', 'project', 'engine_id',
                'generation_sequence', 'generation_sha256', 'config_path', 'config_file_sha256',
                'old', 'new', 'attempt_dir', 'authority_file', 'data_sha256', 'owned_before',
                'protected_sha256', 'candidate_only'})
        require(intent['schema'] == SCHEMA and intent['candidate_only'] is True
                and type(intent['sequence']) is int and intent['sequence'] == number
                and intent['parent'] == parent and intent['project'] == expected['project']
                and intent['engine_id'] == expected['engine_id'] and intent['old'] == current)
        anchor = intent['generation_sequence']
        require(type(anchor) is int and anchor in records
                and intent['generation_sha256'] == selection.digest(raw[f'{anchor:06}.selection.json'])
                and intent['data_sha256'] == records[anchor]['data_sha256'])
        generation_intent = selection.decode(raw[f'{anchor:06}.intent.json'])
        require(intent['config_path'] == generation_intent['config_path']
                and intent['config_file_sha256'] == generation_intent['config_file_sha256'])
        for model in (intent['old'], intent['new']):
            require(type(model) is dict and set(model) == MODEL_KEYS
                    and type(model['compose_file']) is str and Path(model['compose_file']).is_absolute()
                    and type(model['compose_sha256']) is str
                    and re.fullmatch(r'[0-9a-f]{64}', model['compose_sha256']))
        require(Path(intent['new']['compose_file']).parent == Path(current['compose_file']).parent
                and intent['new']['compose_file'] != current['compose_file'])
        require(type(intent['owned_before']) is dict and 'applicant' in intent['owned_before']
                and all(type(k) is str and re.fullmatch(r'[a-z0-9_-]+', k)
                        and type(v) is str and re.fullmatch(r'[0-9a-f]{64}', v)
                        for k, v in intent['owned_before'].items())
                and type(intent['protected_sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', intent['protected_sha256']))
        root = Path(intent['attempt_dir'])
        require(root.parent == Path(expected['root'])
                and re.fullmatch(r'windows-model-[0-9a-f]{32}', root.name)
                and intent['authority_file'] == '/control/recovery-session-'+root.name[14:]+'/token')
        decision = decisions.get(number)
        if decision is None:
            require(number == len(intents))
        else:
            require(set(decision) == {'schema', 'sequence', 'intent_sha256', 'result',
                                     'selected', 'phase_sha256', 'candidate_only'})
            require(decision['schema'] == SCHEMA and decision['candidate_only'] is True
                    and type(decision['sequence']) is int and decision['sequence'] == number
                    and decision['intent_sha256'] == selection.digest(raw[f'{number:06}.model-intent.json'])
                    and decision['result'] in {'model-repaired', 'rolled-back'}
                    and decision['selected'] == intent['new' if decision['result'] == 'model-repaired' else 'old'])
            require(type(decision['phase_sha256']) is dict and set(decision['phase_sha256']) == NAMES
                    and all(type(v) is str and re.fullmatch(r'[0-9a-f]{64}', v)
                            for v in decision['phase_sha256'].values()))
            current = decision['selected']
            accepted.append(current)
            parent = selection.digest(raw[f'{number:06}.model-selection.json'])
        result.append((intent, decision))
    return result, current, accepted


def hold_history(raw, expected, records, stack, *, allow_pending=False):
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_renewal import hold_private_input, hold_storage_namespace
    items, current, accepted = history(raw, expected, records, allow_pending=allow_pending)
    for intent, decision in items:
        if decision is None:
            continue
        models = []
        for model in (intent['old'], intent['new']):
            body = stack.enter_context(hold_private_input(Path(model['compose_file']), max_bytes=2*1024*1024))
            require(selection.digest(body) == model['compose_sha256'])
            models.append(selection.decode(body))
        check_repair(*models)
        root = Path(intent['attempt_dir'])
        stack.enter_context(hold_storage_namespace(root))
        stack.enter_context(_held_private_input(root, directory=True))
        require({p.name for p in root.iterdir()} == NAMES)
        bodies = {name: stack.enter_context(hold_private_input(root/name)) for name in NAMES}
        require(all(selection.digest(body) == decision['phase_sha256'][name] for name, body in bodies.items()))
        require(selection.decode(bodies['intent.json']) == intent)
        result = selection.decode(bodies['result.json'])
        require(result == {'schema': SCHEMA, 'project': expected['project'], 'result': decision['result'],
                'generation_sequence': intent['generation_sequence'], 'model_sequence': intent['sequence'],
                'candidate_only': True, 'production_admission': False, 'automatic_lifecycle': False})
        for phase in ('authority', 'new' if decision['result'] == 'model-repaired' else 'rollback'):
            for event in ('started', 'completed'):
                receipt = selection.decode(bodies[phase+'.'+event+'.json'])
                require(receipt == {'phase': phase, 'event': event})
    return current, accepted


def effective_config(config, model):
    result = deepcopy(config)
    if model_binding(config) != model:
        result['_historical_compose_sha256'] = config['compose_sha256']
        result.update(model)
    return result


def repair(config, choice, values, record, generation_intent, raw, journal, new_path, root, stack):
    """Called only by the active selected lease under the shared project lock."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_renewal_native import reauthenticate
    # Existing history was already parsed and held by the selected owner.
    number = 1+sum(name.endswith('.model-selection.json') for name in raw)
    require(number <= LIMIT and not renewal.recovery_pending(config))
    root = Path(root);new_path = Path(new_path)
    parent = Path(config['current_secrets']).parent
    require(root.parent == parent and re.fullmatch(r'windows-model-[0-9a-f]{32}', root.name)
            and not list(root.iterdir()) and new_path.is_absolute()
            and new_path.parent == Path(config['compose_file']).parent
            and str(new_path) != config['compose_file'])
    stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root, directory=True):
        pass
    old_raw = stack.enter_context(renewal.hold_private_input(Path(config['compose_file']), max_bytes=2*1024*1024))
    new_raw = stack.enter_context(renewal.hold_private_input(new_path, max_bytes=2*1024*1024))
    require(selection.digest(old_raw) == config['compose_sha256'])
    check_repair(selection.decode(old_raw), selection.decode(new_raw))
    observed = selection._inspect(config, choice, values, stack, expected_data=record['data_sha256'])
    docker = observed['docker'];services = observed['services']
    prefix = 'renewed' if choice == 'new' else 'current'
    command = docker.compose(config['project'], Path(config[prefix+'_env']), new_path)
    new_model = docker.json(command[len(docker.prefix):]+['--profile', '*', 'config', '--format', 'json'])
    check_repair(observed['model'], new_model)
    old_hashes = docker.hashes(observed['command']);new_hashes = docker.hashes(command)
    require(set(old_hashes) == set(new_hashes)
            and {name for name in old_hashes if old_hashes[name] != new_hashes[name]} == {'applicant'})
    renewal.owned_roles(new_model, services)
    protected = renewal.observations(observed['baseline'], config['project'], {'applicant'})
    authority = '/control/recovery-session-'+root.name[14:]+'/token'
    intent = {'schema': SCHEMA, 'sequence': number,
        'parent': selection.digest(raw[f'{number-1:06}.model-selection.json']) if number > 1 else None,
        'project': config['project'], 'engine_id': config['engine_id'],
        'generation_sequence': record['sequence'],
        'generation_sha256': selection.digest(raw[f'{record["sequence"]:06}.selection.json']),
        'config_path': generation_intent['config_path'],
        'config_file_sha256': generation_intent['config_file_sha256'],
        'old': model_binding(config), 'new': {'compose_file': str(new_path), 'compose_sha256': selection.digest(new_raw)},
        'attempt_dir': str(root), 'authority_file': authority, 'data_sha256': record['data_sha256'],
        'owned_before': {renewal._service(x): x['Id'] for x in observed['owned']},
        'protected_sha256': selection.digest(selection.packed(protected)), 'candidate_only': True}
    for name in NAMES:
        selection._new_private(root/name, b'')
    selection._append(journal, raw, f'{number:06}.model-intent.json', intent, stack)
    guard = renewal.model_repair_guard(config)
    selection._new_private(guard, selection.packed(intent))
    renewal.write_empty_private_file(root/'intent.json', selection.packed(intent).decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
    def boundary(phase, event):
        path = root/(phase+'.'+event+'.json')
        renewal.write_empty_private_file(path, selection.packed({'phase': phase, 'event': event}).decode())
        stack.enter_context(renewal.hold_private_input(path))
    boundary('authority', 'started')
    require(reauthenticate(config['native'], config['project'], docker.prefix, authority.rsplit('/', 1)[0]) == authority)
    boundary('authority', 'completed')
    require(selection._prove(config, choice, values, stack, expected_data=record['data_sha256'], authority_file=authority) == record['data_sha256'])
    changed_config = effective_config(config, intent['new'])
    def verify(cfg):
        require(renewal.observations(docker.containers(), config['project'], {'applicant'}) == protected)
        require(selection._prove(cfg, choice, values, stack, expected_data=record['data_sha256'], authority_file=authority) == record['data_sha256'])
        require(renewal.observations(docker.containers(), config['project'], {'applicant'}) == protected)
    def apply(phase, cmd, model):
        renewal.recreate(docker, cmd, {'applicant'}, services, model, root/(phase+'.log'),
                         progress=lambda event, _index, layer: (require(layer == ['applicant']), boundary(phase, event)))
    try:
        apply('new', command, new_model)
        verify(changed_config)
        decision = 'model-repaired'
    except renewal.UncertainComposeMutation:
        raise
    except Exception:
        apply('rollback', observed['command'], observed['model'])
        verify(config)
        decision = 'rolled-back'
    result = {'schema': SCHEMA, 'project': config['project'], 'result': decision,
              'generation_sequence': record['sequence'], 'model_sequence': number,
              'candidate_only': True, 'production_admission': False, 'automatic_lifecycle': False}
    renewal.write_empty_private_file(root/'result.json', selection.packed(result).decode())
    bodies = {name: stack.enter_context(renewal.hold_private_input(root/name)) for name in NAMES}
    require({p.name for p in root.iterdir()} == NAMES)
    selected = intent['new' if decision == 'model-repaired' else 'old']
    completion = {'schema': SCHEMA, 'sequence': number,
        'intent_sha256': selection.digest(selection.packed(intent)), 'result': decision,
        'selected': selected, 'phase_sha256': {name: selection.digest(body) for name, body in bodies.items()},
        'candidate_only': True}
    return {'intent': intent, 'decision': completion, 'result': result, 'journal': str(journal)}


def finish(config, pending):
    """The guard remains authoritative until publication and every held exit."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    intent = pending['intent'];decision = pending['decision']
    sha = selection.digest(selection.packed(intent))
    path = Path(intent['config_path']);root = Path(intent['attempt_dir'])
    journal = Path(pending['journal'])
    guard = renewal.model_repair_guard(config)
    decision_name = f'{intent["sequence"]:06}.model-selection.json'
    from selfhost_windows_continuation import hold_ancestry, check_ancestry
    earlier = []
    with ExitStack() as protected:
        protected.enter_context(renewal.hold_storage_namespace(root.parent))
        protected.enter_context(renewal.hold_storage_namespace(root))
        protected.enter_context(renewal.hold_storage_namespace(journal))
        protected.enter_context(_held_private_input(root, directory=True))
        with ExitStack() as receipts:
            with selection._session(path, _pending_model_sha256=sha,
                _preserve_history=lambda items: hold_ancestry(items, receipts, protected, earlier)) as (cfg, raw_cfg, expected, session_journal, raw, stack):
                require(session_journal == journal and selection.digest(raw_cfg) == intent['config_file_sha256']
                        and not renewal.namespace_entry_exists(renewal.recovery_guard(cfg))
                        and not renewal.namespace_entry_exists(renewal.recovery_preparation_guard(cfg))
                        and not renewal.namespace_entry_exists(renewal.renewal_staging_guard(cfg)))
                _generations, records = selection._parse(raw, expected, allow_pending_model=True)
                items, _current, _accepted = history(raw, expected, records, allow_pending=True)
                require(items[-1] == (intent, None)
                        and selection.digest(raw[f'{intent["sequence"]:06}.model-intent.json']) == sha)
                originals = dict(raw)
                for name, body in originals.items():
                    require(receipts.enter_context(renewal.hold_private_input(journal/name)) == body)
                require(selection.digest(receipts.enter_context(renewal.hold_private_input(guard))) == sha)
                require({p.name for p in root.iterdir()} == NAMES)
                for name, expected_sha in decision['phase_sha256'].items():
                    require(selection.digest(receipts.enter_context(renewal.hold_private_input(root/name))) == expected_sha)
                selection._append(journal, raw, decision_name, decision, stack)
                hold_history(raw, expected, records, stack)
                require(protected.enter_context(renewal.hold_private_input(journal/decision_name)) == selection.packed(decision))
                protected.enter_context(_held_private_input(journal, directory=True))
                names = set(originals)|{decision_name}
            # Original records, guard and receipts survive the publication-lock
            # exit; the decision and directory proofs survive receipt exits.
            require({p.name for p in journal.iterdir()} == names)
            require({p.name for p in root.iterdir()} == NAMES)
        require({p.name for p in journal.iterdir()} == names)
        require({p.name for p in root.iterdir()} == NAMES)
    require({p.name for p in journal.iterdir()} == names)
    require(all(renewal.read_private_bytes(journal/name) == body for name, body in originals.items()))
    require(renewal.read_private_bytes(root/'result.json') == selection.packed(pending['result']))
    require({p.name for p in root.iterdir()} == NAMES)
    require(all(selection.digest(renewal.read_private_bytes(root/name)) == expected_sha
                for name, expected_sha in decision['phase_sha256'].items()))
    require(selection.digest(renewal.read_private_bytes(guard)) == sha)
    require(selection.digest(renewal.read_private_bytes(journal/decision_name))
            == selection.digest(selection.packed(decision)))
    check_ancestry(earlier)
    guard.unlink()


def repair_once(config_path, new_model):
    with selection.selected_inputs(config_path) as lease:
        root = lease.secrets_dir.parent/('windows-model-'+uuid.uuid4().hex)
        root.mkdir()
        result = lease.repair_model(Path(new_model), root)
    if result['result'] == 'rolled-back':
        raise RuntimeError('Model repair rolled back; preserve its records')
    return result
