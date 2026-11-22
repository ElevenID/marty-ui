"""Derive a sealed website successor of the existing Windows selection journal."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path

from selfhost_windows_inputs import _held_private_input, _path_identities
import selfhost_windows_product_journal as product
import selfhost_windows_selection as selection
import selfhost_windows_website_forward as forward
import selfhost_windows_website_guard as guard
import selfhost_windows_website_store as store

SCHEMA = 'marty.windows-website-owner-selection/v1'
INTENT = 'website-forward.intent.json'
DECISION = 'website-forward.selection.json'
PENDING = 'website-forward.selection.pending.json'
FORWARD_FILES = INTENT, DECISION, PENDING
COMBINED_SCHEMA = 'marty.windows-website-combined-selection/v1'
COMBINED_INTENT = 'website-combined.intent.json'
COMBINED_DECISION = 'website-combined.selection.json'
COMBINED_PENDING = 'website-combined.selection.pending.json'
COMBINED_FILES = COMBINED_INTENT, COMBINED_DECISION, COMBINED_PENDING
FILES = {*FORWARD_FILES, *COMBINED_FILES}
require = selection.require
renewal = selection.renewal


def marker(raw, expected, source, attempt, *, terminal_sha256, candidate_sha256, qualification_sha256):
    attempt = Path(attempt)
    cycle = attempt.name.removeprefix('windows-website-')
    require(attempt.is_absolute() and attempt.parent == source.parent == Path(expected['root'])
            and len(cycle) == 32 and all(char in '0123456789abcdef' for char in cycle)
            and attempt.name == 'windows-website-' + cycle)
    return {
        'schema': SCHEMA, 'source_dir': str(source), 'attempt_dir': str(attempt),
        'target_dir': str(attempt.with_name('.' + expected['project'] + '.generation-website-' + cycle)),
        'source_sha256': {name: selection.digest(body) for name, body in raw.items() if name not in FORWARD_FILES},
        'terminal_sha256': terminal_sha256, 'candidate_sha256': candidate_sha256,
        'qualification_sha256': qualification_sha256,
    }


def validate_marker(raw, expected, source):
    value = selection.decode(raw[INTENT])
    require(type(value) is dict and raw[INTENT] == selection.packed(value))
    pins = {key: value[key] for key in ('terminal_sha256', 'candidate_sha256', 'qualification_sha256')}
    require(all(product.sha(pin) for pin in pins.values())
            and value == marker(raw, expected, source, value['attempt_dir'], **pins))
    return value


def _sealed_evidence(plan, link, pinned_candidate, stack, *, historical_forward):
    phase = 'seal-forward'
    records, anchors = store.namespace_paths(plan)
    require(records.parent == Path(link['attempt_dir']))
    status, evidence = store.hold_terminal_evidence(plan, expected_anchor_sha256=link['terminal_sha256'],
        classification='forward-evidence-complete', held=stack, historical_forward=historical_forward, references={
            'route-website-after.json': ('route-website', 'completed'),
            'verify-website-after.json': ('verify-website', 'completed'),
            'seal-forward-before.json': (phase, 'started'), 'seal-forward-after.json': (phase, 'completed')})
    # The candidate was prepared one completed phase before the seal. Bind both
    # of its saved verification pins to that specific retained prefix.
    previous_anchor = stack.enter_context(renewal.hold_private_input(anchors / store._tail_name(status['record_count'] - 2)))
    require(selection.digest(previous_anchor) == pinned_candidate['verified_anchor_sha256']
            and selection.decode(previous_anchor)['record_sha256'] == pinned_candidate['verified_tail_sha256'])

    verified = evidence['verify-website-after.json']['runtime_after']
    routed = evidence['route-website-after.json']
    before, after = evidence['seal-forward-before.json'], evidence['seal-forward-after.json']
    foreign = after['foreign_storage']
    native = {key: plan['owner'][key] for key in ('native_sha256', 'selected_sha256')}
    require(before['owner_lease'] == {'owner': plan['owner'], 'guard_sha256': pinned_candidate['guard_sha256']}
            and before['native_custody'] == after['native_custody'] == native
            and before['runtime_before'] == {'containers': verified, 'edge_configuration': routed['edge_configuration']}
            and after['runtime_after'] == verified == routed['runtime_after']
            and routed['mounted_template'] == plan['edge_template']
            and before['foreign_storage'] == foreign
            and set(foreign) == {'engine_id', 'inventory_sha256', 'changes_sha256', 'changes'}
            and foreign['engine_id'] == plan['owner']['engine_id'] and product.sha(foreign['inventory_sha256'])
            and type(foreign['changes']) is int and foreign['changes'] >= 0
            and (product.sha(foreign['changes_sha256']) if foreign['changes'] else foreign['changes_sha256'] is None)
            and after['successor_candidate'] == {key: link[key] for key in ('candidate_sha256', 'qualification_sha256')})
    return verified, foreign


def _held_json(path, stack, *, maximum=65536, canonical=True):
    raw = stack.enter_context(renewal.hold_private_input(path, max_bytes=maximum))
    value = selection.decode(raw)
    require(type(value) is dict and (not canonical or raw == selection.packed(value)))
    return raw, value


def _hold_successor(raw, expected, current_model, link, stack, *, admission, historical_forward):
    from selfhost_windows_model import effective_config, immutable_binding

    attempt = Path(link['attempt_dir'])
    for path in (attempt, attempt / 'successor', attempt / 'successor' / 'proofs'):
        stack.enter_context(renewal.hold_storage_namespace(path))
        # A historical forward proof keeps its files immutable while the
        # existing attempt directory receives the separate reverse owner.
        stack.enter_context(_held_private_input(path, directory=True,
                                               mutable_directory=historical_forward and path == attempt))
    _plan_raw, plan = _held_json(attempt / 'journal' / store.PLAN, stack, maximum=2*1024*1024)
    root = attempt / 'successor'
    _candidate_raw, candidate = _held_json(root / 'candidate.json', stack)
    require(forward.contract.digest(candidate) == link['candidate_sha256'])
    qualification_path = attempt / ('forward-qualification-' + link['qualification_sha256'] + '.json')
    _qualification_raw, qualification = _held_json(qualification_path, stack)
    require(forward.contract.digest(qualification) == link['qualification_sha256'])

    first, prior, generation = product.anchor(raw, expected)
    old_config_raw, old_config = _held_json(Path(first['config_path']), stack, canonical=False)
    require(selection.digest(old_config_raw) == first['config_file_sha256']
            and selection.config_digest(old_config) == first['config_sha256']
            and immutable_binding(selection.binding(old_config)) == immutable_binding(expected))
    old_config = effective_config(old_config, current_model)
    combined_raw, combined = _held_json(Path(current_model['compose_file']), stack, maximum=forward.MODEL_LIMIT, canonical=False)
    require(selection.digest(combined_raw) == current_model['compose_sha256'])
    owner = {
        'project': expected['project'], 'engine_id': expected['engine_id'], 'docker_host': old_config['docker_host'],
        'root': expected['root'], 'selection_sequence': prior['sequence'], 'generation_sequence': generation,
        'binding_sha256': forward.contract.digest(expected), 'journal_sha256': forward.contract.digest(link['source_sha256']),
        'configuration_sha256': selection.digest(old_config_raw),
        'selection_sha256': selection.digest(raw[f'{prior["sequence"]:06}.selection.json']),
        'selected_sha256': forward.contract.digest(prior['selected']), 'native_sha256': forward.contract.digest(expected['native']),
        'historical_tls_sha256': forward.contract.digest(old_config['tls_init_receipt']),
        'data_sha256': prior['data_sha256'], 'model_sha256': forward.contract.digest(combined),
    }
    require(plan['owner'] == owner == candidate['owner']
            and candidate['plan_sha256'] == plan['plan_sha256']
            and candidate['guard_sha256'] == forward.contract.digest(guard.marker(plan))
            and candidate['schema'] == forward.SCHEMA
            and candidate['combined'] == {**current_model, 'data_sha256': prior['data_sha256']})
    split = candidate['split']
    source = Path(current_model['compose_file'])
    split_path = source.with_name('website-' + attempt.name.removeprefix('windows-website-') + '.compose.json')
    require(set(split) == {'compose_file', 'compose_sha256', 'data_sha256'}
            and split['compose_file'] == str(split_path)
            and split['data_sha256'] == plan['states']['split']['data_sha256'])
    split_raw, _split_value = _held_json(split_path, stack, maximum=forward.MODEL_LIMIT)
    require(selection.digest(split_raw) == split['compose_sha256'])

    configuration = root / 'config.private.json'
    config_raw, config = _held_json(configuration, stack)
    model = {key: split[key] for key in ('compose_file', 'compose_sha256')}
    require(config == product.successor_configuration(old_config, model, root)
            and immutable_binding(selection.binding(config)) == immutable_binding(expected)
            and candidate['configuration'] == {'path': str(configuration), 'sha256': forward.contract.digest(config)})
    outputs = [Path(config[key]) for key in ('intent', 'result', 'new_log', 'rollback_log')]
    outputs += [Path(path) for step in config['step_receipts'] for path in step.values()]
    require(len(set(outputs)) == len(outputs)
            and candidate['activation_outputs'] == {str(path): selection.digest(b'') for path in outputs})
    if admission:
        stack.enter_context(_held_private_input(root / 'activation', directory=True))
        require({path.name for path in (root / 'activation').iterdir()} == {path.name for path in outputs}
                and all(stack.enter_context(renewal.hold_private_input(path)) == b'' for path in outputs))

    proofs = root / 'proofs'
    require(str(proofs) == candidate['proof_directory'] and candidate['proof_sha256'] == plan['proof_sha256']
            and set(plan['proof_sha256']) == product.ARTIFACTS
            and all(product.sha(pin) for pin in plan['proof_sha256'].values())
            and {item.name for item in proofs.iterdir()} == set(plan['proof_sha256']))
    for name, pin in plan['proof_sha256'].items():
        limit = 256*1024*1024 if name == 'web-composition.zip' else 4*1024*1024
        proof = stack.enter_context(renewal.hold_private_input(proofs / name, max_bytes=limit))
        require(selection.digest(proof) == pin)

    runtime, foreign = _sealed_evidence(plan, link, candidate, stack, historical_forward=historical_forward)
    require(qualification['schema'] == forward.SCHEMA and qualification['candidate_sha256'] == link['candidate_sha256']
            and qualification['runtime_sha256'] == forward.contract.digest(runtime)
            and all(product.sha(qualification[key]) for key in (
                'public_routes_sha256', 'anonymous_handoff_sha256',
                'authenticated_account_sha256', 'authenticated_organization_sha256'))
            and qualification['native_sha256'] == owner['native_sha256']
            and qualification['selected_sha256'] == owner['selected_sha256']
            and qualification['foreign_storage_sha256'] == foreign['changes_sha256']
            and qualification['foreign_storage_changes'] == foreign['changes']
            and all(qualification['authenticated_application'][key] is True for key in (
                'account_matched', 'organization_matched', 'authenticated_application_exercised')))
    return configuration, config_raw, config, model, split['data_sha256'], first, prior, generation


def seed(raw, expected, current_model, source, link, stack, *, admission=False, historical_forward=False):
    """Keep the exact credential selection and generation at the new Compose owner."""
    require(validate_marker(raw, expected, source) == link)
    configuration, config_raw, config, model, data, first, prior, generation = _hold_successor(
        raw, expected, current_model, link, stack, admission=admission, historical_forward=historical_forward)
    return _owner_seed(expected, link, configuration, config_raw, config, model, data, first, prior, generation,
                       operation='website-successor', choice_prefix='website-selected-')


def _owner_seed(expected, link, configuration, config_raw, config, model, data, first, prior, generation, *,
                operation, choice_prefix):
    from selfhost_windows_continuation import CHECKPOINT

    empty = selection.digest(b'')
    first = deepcopy(first)
    first.update(sequence=1, parent=None, operation=operation, config_path=str(configuration),
                 config_file_sha256=selection.digest(config_raw), config_sha256=selection.config_digest(config),
                 result_before_sha256=empty)
    selected = dict(prior, sequence=1, parent=None, intent_sha256=forward.contract.digest(first),
                    decision=choice_prefix + prior['choice'], data_sha256=data,
                    result_sha256=empty, transition_intent_sha256=empty)
    checkpoint = {'schema': link['schema'], 'source_dir': link['source_dir'], 'intent_sha256': forward.contract.digest(link),
                  'sequence_offset': generation - 1, 'generation_model': model,
                  'first_intent': first, 'first_selection': selected}
    return {
        'owner.json': selection.packed({'schema': selection.SCHEMA, 'binding': dict(expected, **model)}),
        CHECKPOINT: selection.packed(checkpoint), '000001.intent.json': selection.packed(first),
        '000001.selection.json': selection.packed(selected),
    }


def decision(link, initial):
    return {'schema': link['schema'], 'intent_sha256': forward.contract.digest(link),
            'target_entries_sha256': {name: selection.digest(body) for name, body in initial.items()}}


def hold_published_split(raw, expected, current_model, source, plan, intent_sha256, held):
    """Verify and hold the exact untouched selected split for guarded backout."""
    require(INTENT in raw and DECISION in raw and PENDING not in raw
            and selection.digest(raw[INTENT]) == intent_sha256)
    link = validate_marker(raw, expected, source)
    require(link['attempt_dir'] == plan['attempt_directory'])
    # The phase directories must remain appendable under the owner lock.
    # Hold the committed source and selected leaf across the backout action.
    with ExitStack() as prefix:
        initial = seed(raw, expected, current_model, source, link, prefix, admission=True, historical_forward=True)
        require(raw[DECISION] == selection.packed(decision(link, initial)))
    target = Path(link['target_dir'])
    held.enter_context(renewal.hold_storage_namespace(target))
    held.enter_context(_held_private_input(target, directory=True))
    require(selection._read(target, held) == initial)
    return _published_binding(raw, link, initial)


def _published_binding(original_raw, forward_link, split_raw):
    return {'intent_sha256': selection.digest(original_raw[INTENT]),
            'selection_sha256': selection.digest(original_raw[DECISION]),
            'sealed_anchor_sha256': forward_link['terminal_sha256'],
            'split_selection_sha256': selection.digest(split_raw['000001.selection.json'])}


def verify_backout_binding(plan, status, published, held):
    """Bind the later backout to the already selected split and original guard."""
    require(status['completed_phases'][:len(store.journal.FORWARD)] == list(store.journal.FORWARD)
            and 'restore-combined' in status['completed_phases'])
    name = 'restore-combined-before.json'
    receipt = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'],
                                  references={name: ('restore-combined', 'started')}, held=held)[name]
    require(receipt['owner_lease'] == {'guard_sha256': status['guard_sha256'], 'owner': plan['owner'],
                                       'published_selection': published})
    from selfhost_windows_website_abort_release import READMISSION, hold_readmission
    before = receipt['runtime_before']
    pin = before.get('readmission_sha256')
    require(renewal.namespace_entry_exists(Path(plan['attempt_directory']) / READMISSION) == (pin is not None))
    if pin is not None:
        require(forward.contract.sha(pin))
        sealed = {'guard_sha256': status['guard_sha256'], 'anchor_sha256': published['sealed_anchor_sha256']}
        _, baseline = hold_readmission(plan, sealed, published, held, expected_sha256=pin)
        require(before['containers'] == baseline['runtime_after']
                and before['edge_configuration'] == baseline['edge_configuration'])


def finish(config_path, plan, *, guard_sha256, terminal_sha256, candidate_sha256,
           qualification_sha256, check_live, authority_file=None, intent_sha256=None):
    """Publish the checked successor while the existing website guard stays held.

    The guarded phase owner supplies a live checker for the sealed runtime,
    signed composition, edge and authenticated application. Reconcile with the
    exact existing intent pin after an interrupted publication.
    """
    from selfhost_windows_model import effective_config, history

    with ExitStack() as coordination:
        with selection._session(config_path, _coordination=coordination,
                _pending_website_sha256=guard_sha256,
                _pending_website_selection_sha256=intent_sha256) as (base, _, expected, source, raw, stack):
            records, _anchors = store.namespace_paths(plan)
            active_guard = stack.enter_context(renewal.hold_private_input(renewal.product_transition_guard(base)))
            require(selection.digest(active_guard) == guard_sha256
                    and active_guard == selection.packed(guard.marker(plan)))
            require(stack.enter_context(renewal.hold_private_input(records / store.PLAN, max_bytes=2*1024*1024))
                    == selection.packed(plan))
            intents, selections = selection._parse(raw, expected)
            require(len(intents) == len(selections))
            from selfhost_windows_continuation import INTENT as continuation_intent
            from selfhost_windows_recovery_journal import INTENT as recovery_intent
            require(not any(name in raw for name in (continuation_intent, recovery_intent, product.INTENT)))
            _, current_model, _accepted = history(raw, expected, selections)

            link = marker(raw, expected, source, records.parent, terminal_sha256=terminal_sha256,
                          candidate_sha256=candidate_sha256, qualification_sha256=qualification_sha256)
            link_raw = selection.packed(link)
            link_sha256 = selection.digest(link_raw)
            if INTENT in raw:
                require(raw[INTENT] == link_raw and intent_sha256 == link_sha256)
            else:
                require(intent_sha256 is None)
            prospective = dict(raw, **{INTENT: link_raw})
            initial = seed(prospective, expected, current_model, source, link, stack, admission=True)
            first = selection.decode(initial['000001.intent.json'])
            selected = selection.decode(initial['000001.selection.json'])
            config = selection.decode(stack.enter_context(renewal.hold_private_input(Path(first['config_path']))))
            values, snapshots = selection._inputs(config, stack)
            require(snapshots == first['inputs'])
            require(selection._prove(config, selected['choice'], values, stack, expected_data=selected['data_sha256'],
                                     authority_file=authority_file) == selected['data_sha256'])
            original_intent = intents[len(selections)]
            original_path = Path(original_intent['config_path'])
            original = selection.decode(stack.enter_context(renewal.hold_private_input(original_path)))
            check_live(effective_config(original, current_model), selected['choice'], values,
                       selections[len(selections)], link, stack)

            pending = _stage_selection(source, raw, link, initial, stack, coordination, FORWARD_FILES)
        _commit_selection(source, pending, FORWARD_FILES)

    target = Path(link['target_dir'])
    with selection._session(config_path, _pending_website_sha256=guard_sha256) as (_, _, _, active, entries, _stack):
        require(active == target and all(entries.get(name) == body for name, body in initial.items()))
    return {'schema': SCHEMA, 'result': 'website-selected-guarded', 'guard_sha256': guard_sha256,
            'intent_sha256': link_sha256, 'journal': str(target), 'guards_retained': True,
            'generation_sequence': plan['owner']['generation_sequence'],
            'selected_sha256': forward.contract.digest(selected['selected'])}


def _stage_selection(source, raw, link, initial, stack, coordination, names):
    """Hold the complete prepared target across the decision rename."""
    intent_name, decision_name, pending_name = names
    if intent_name not in raw:
        selection._append(source, raw, intent_name, link, stack)
    target = Path(link['target_dir'])
    if not renewal.namespace_entry_exists(target):
        target.mkdir()
    coordination.enter_context(renewal.hold_storage_namespace(target))
    with _held_private_input(target, directory=True):
        require({path.name for path in target.iterdir()} <= set(initial))
    for name, body in initial.items():
        path = target / name
        if not renewal.namespace_entry_exists(path):
            selection._new_private(path, body)
        elif renewal.read_private_bytes(path) == b'':
            renewal.write_empty_private_file(path, body.decode())
        require(coordination.enter_context(renewal.hold_private_input(path)) == body)
    coordination.enter_context(_held_private_input(target, directory=True))
    require({path.name for path in target.iterdir()} == set(initial))

    publication = decision(link, initial)
    publication_raw = selection.packed(publication)
    if decision_name in raw:
        require(raw[decision_name] == publication_raw)
        return None
    if pending_name not in raw:
        selection._append(source, raw, pending_name, publication, stack)
    require(raw[pending_name] == publication_raw)
    return publication_raw, _path_identities(source / pending_name)


def _commit_selection(source, pending, names):
    # All admission/input handles have exited. The common project lock and
    # prepared target remain held across the exact no-overwrite rename.
    if pending is not None:
        raw, identity = pending
        _, decision_name, pending_name = names
        with _held_private_input(source / pending_name, _rename_to=source / decision_name,
                                 _expected_identities=identity) as body:
            require(body == raw)
        require(_path_identities(source / decision_name) == identity)


def combined_marker(raw, expected, source, origin, *, forward_intent_sha256, guard_sha256, terminal_sha256):
    from selfhost_windows_continuation import CHECKPOINT, checkpoint

    require(set(raw) - set(COMBINED_FILES) == {
        'owner.json', CHECKPOINT, '000001.intent.json', '000001.selection.json'})
    carry = checkpoint(raw)
    require(carry['schema'] == SCHEMA and carry['intent_sha256'] == forward_intent_sha256
            and carry['source_dir'] == str(origin[0]))
    original_source, original_raw = origin
    original_owner = selection.decode(original_raw['owner.json'])['binding']
    forward_link = validate_marker(original_raw, original_owner, original_source)
    require(selection.digest(original_raw[INTENT]) == forward_intent_sha256 and DECISION in original_raw
            and Path(forward_link['target_dir']) == source
            and source.parent == original_source.parent == Path(expected['root']))
    attempt = Path(forward_link['attempt_dir'])
    cycle = attempt.name.removeprefix('windows-website-')
    return {'schema': COMBINED_SCHEMA, 'source_dir': str(source), 'attempt_dir': str(attempt),
            'target_dir': str(attempt.with_name('.' + expected['project'] + '.generation-website-combined-' + cycle)),
            'source_sha256': {name: selection.digest(body) for name, body in raw.items() if name not in COMBINED_FILES},
            'forward_intent_sha256': forward_intent_sha256, 'guard_sha256': guard_sha256,
            'terminal_sha256': terminal_sha256}


def validate_combined_marker(raw, expected, source, origin):
    link = selection.decode(raw[COMBINED_INTENT])
    require(type(link) is dict and raw[COMBINED_INTENT] == selection.packed(link))
    pins = {key: link[key] for key in ('forward_intent_sha256', 'guard_sha256', 'terminal_sha256')}
    require(all(product.sha(pin) for pin in pins.values())
            and link == combined_marker(raw, expected, source, origin, **pins))
    return link


def combined_seed(raw, expected, source, origin, link, stack, *, prepare=False):
    """Derive the reverse owner from the original configuration and terminal backout."""
    from selfhost_windows_model import effective_config, history, immutable_binding, model_binding
    from selfhost_windows_website_backout import CLASSIFICATION, hold_retirement

    require(validate_combined_marker(raw, expected, source, origin) == link)
    original_source, original_raw = origin
    original_owner = selection.decode(original_raw['owner.json'])['binding']
    forward_link = validate_marker(original_raw, original_owner, original_source)
    original_intent, original_record, generation = product.anchor(original_raw, original_owner)
    original_records = selection._parse(original_raw, original_owner)[1]
    combined_model = history(original_raw, original_owner, original_records)[1]
    original_bytes, original = _held_json(Path(original_intent['config_path']), stack, canonical=False)
    require(selection.digest(original_bytes) == original_intent['config_file_sha256']
            and selection.config_digest(original) == original_intent['config_sha256'])
    config = effective_config(original, combined_model)
    split_intent, split_record, split_generation = product.anchor(raw, expected)
    require(split_intent['inputs'] == original_intent['inputs'] and split_generation == generation
            and split_record['choice'] == original_record['choice']
            and split_record['selected'] == original_record['selected']
            and immutable_binding(expected) == immutable_binding(original_owner))

    attempt = Path(link['attempt_dir'])
    _, plan = _held_json(attempt / 'journal' / store.PLAN, stack, maximum=2*1024*1024)
    require(plan['attempt_directory'] == str(attempt) and link['guard_sha256'] == forward.contract.digest(guard.marker(plan))
            and plan['owner']['data_sha256'] == original_record['data_sha256']
            and plan['owner']['selected_sha256'] == forward.contract.digest(original_record['selected']))
    status = store.inspect(plan, expected_anchor_sha256=link['terminal_sha256'])
    require(status['classification'] == CLASSIFICATION)
    status['guard_sha256'] = link['guard_sha256']
    verify_backout_binding(plan, status, _published_binding(original_raw, forward_link, raw), stack)
    retained, _receipt = hold_retirement(plan, status, stack)

    root = attempt / 'combined-successor'
    configuration = root / 'config.private.json'
    combined = product.successor_configuration(config, combined_model, root)
    paths = [Path(combined[key]) for key in ('intent', 'result', 'new_log', 'rollback_log')]
    paths += [Path(path) for step in combined['step_receipts'] for path in step.values()]
    require(len(set(paths)) == len(paths) and all(path.parent == root / 'activation' for path in paths))
    if prepare:
        for directory in (root, root / 'activation'):
            forward._directory(directory, stack)
        for path in paths:
            if not renewal.namespace_entry_exists(path):
                selection._new_private(path, b'')
            require(stack.enter_context(renewal.hold_private_input(path)) == b'')
        forward._inventory(root / 'activation', {path.name for path in paths}, stack)
        forward.stage._material(configuration, combined, stack)
    else:
        stack.enter_context(renewal.hold_storage_namespace(root))
        stack.enter_context(_held_private_input(root, directory=True))
    config_raw, checked = _held_json(configuration, stack)
    require(checked == combined and model_binding(checked) == combined_model
            and immutable_binding(selection.binding(checked)) == immutable_binding(expected))
    forward._inventory(root, {'activation', 'config.private.json'}, stack)
    initial = _owner_seed(expected, link, configuration, config_raw, combined, combined_model,
        original_record['data_sha256'], split_intent, split_record, generation,
        operation='website-combined-successor', choice_prefix='website-combined-')
    return initial, plan, retained, config, original_record


def finish_combined(config_path, plan, *, guard_sha256, terminal_sha256, forward_intent_sha256, assets, gh, cosign,
                    registry_config, authority_file=None, intent_sha256=None):
    """Select the restored combined configuration while retaining the website guard."""
    from selfhost_windows_website_abort_release import _refresh

    require(all(product.sha(pin) for pin in (guard_sha256, terminal_sha256, forward_intent_sha256)))
    ancestry = []

    with ExitStack() as coordination:
        with selection._session(config_path, _coordination=coordination, _pending_website_sha256=guard_sha256,
                _pending_website_selection_sha256=intent_sha256,
                _preserve_history=ancestry.extend) as (base, _, expected, source, raw, stack):
            require(ancestry)
            active_guard = stack.enter_context(renewal.hold_private_input(renewal.product_transition_guard(base)))
            require(active_guard == selection.packed(guard.marker(plan)))
            origin = ancestry[-1]
            link = combined_marker(raw, expected, source, origin, forward_intent_sha256=forward_intent_sha256,
                                   guard_sha256=guard_sha256, terminal_sha256=terminal_sha256)
            link_raw = selection.packed(link)
            link_pin = selection.digest(link_raw)
            if COMBINED_INTENT in raw:
                require(raw[COMBINED_INTENT] == link_raw and intent_sha256 == link_pin)
            else:
                require(intent_sha256 is None)
            prospective = dict(raw, **{COMBINED_INTENT: link_raw})
            initial, retained_plan, retained, original_cfg, record = combined_seed(
                prospective, expected, source, origin, link, stack, prepare=True)
            require(plan == retained_plan)
            first = selection.decode(initial['000001.intent.json'])
            config = selection.decode(stack.enter_context(renewal.hold_private_input(Path(first['config_path']))))
            values, snapshots = selection._inputs(config, stack)
            require(snapshots == first['inputs'])
            _refresh(original_cfg, record['choice'], values, record, plan, retained, Path(link['attempt_dir']),
                assets=assets, gh=gh, cosign=cosign, registry_config=registry_config, authority_file=authority_file,
                held=stack)
            pending = _stage_selection(source, raw, link, initial, stack, coordination, COMBINED_FILES)
        _commit_selection(source, pending, COMBINED_FILES)

    target = Path(link['target_dir'])
    with selection._session(config_path, _pending_website_sha256=guard_sha256) as (_, _, _, active, entries, _stack):
        require(active == target and all(entries.get(name) == body for name, body in initial.items()))
    return {'schema': COMBINED_SCHEMA, 'result': 'website-combined-selected-guarded', 'guard_sha256': guard_sha256,
            'forward_intent_sha256': forward_intent_sha256, 'intent_sha256': link_pin, 'journal': str(target),
            'guards_retained': True, 'generation_sequence': plan['owner']['generation_sequence'],
            'selected_sha256': plan['owner']['selected_sha256']}
