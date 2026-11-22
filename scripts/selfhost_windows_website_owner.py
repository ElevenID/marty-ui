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
FILES = {INTENT, DECISION, PENDING}
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
        'source_sha256': {name: selection.digest(body) for name, body in raw.items() if name not in FILES},
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


def _sealed_evidence(plan, link, pinned_candidate, stack):
    phase = 'seal-forward'
    records, anchors = store.namespace_paths(plan)
    require(records.parent == Path(link['attempt_dir']))
    status, evidence = store.hold_terminal_evidence(plan, expected_anchor_sha256=link['terminal_sha256'],
        classification='forward-evidence-complete', held=stack, references={
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


def _hold_successor(raw, expected, current_model, link, stack, *, admission):
    from selfhost_windows_model import effective_config, immutable_binding

    attempt = Path(link['attempt_dir'])
    for path in (attempt, attempt / 'successor', attempt / 'successor' / 'proofs'):
        stack.enter_context(renewal.hold_storage_namespace(path))
        stack.enter_context(_held_private_input(path, directory=True))
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

    runtime, foreign = _sealed_evidence(plan, link, candidate, stack)
    require(qualification['schema'] == forward.SCHEMA and qualification['candidate_sha256'] == link['candidate_sha256']
            and qualification['runtime_sha256'] == forward.contract.digest(runtime)
            and product.sha(qualification['public_routes_sha256']) and product.sha(qualification['anonymous_handoff_sha256'])
            and qualification['native_sha256'] == owner['native_sha256']
            and qualification['selected_sha256'] == owner['selected_sha256']
            and qualification['foreign_storage_sha256'] == foreign['changes_sha256']
            and qualification['foreign_storage_changes'] == foreign['changes']
            and all(qualification['authenticated_application'][key] is True for key in (
                'account_matched', 'organization_matched', 'authenticated_application_exercised')))
    return configuration, config_raw, config, model, split['data_sha256'], first, prior, generation


def seed(raw, expected, current_model, source, link, stack, *, admission=False):
    """Keep the exact credential selection and generation at the new Compose owner."""
    from selfhost_windows_continuation import CHECKPOINT

    require(validate_marker(raw, expected, source) == link)
    configuration, config_raw, config, model, data, first, prior, generation = _hold_successor(
        raw, expected, current_model, link, stack, admission=admission)
    empty = selection.digest(b'')
    first = deepcopy(first)
    first.update(sequence=1, parent=None, operation='website-successor', config_path=str(configuration),
                 config_file_sha256=selection.digest(config_raw), config_sha256=selection.config_digest(config),
                 result_before_sha256=empty)
    selected = dict(prior, sequence=1, parent=None, intent_sha256=forward.contract.digest(first),
                    decision='website-selected-' + prior['choice'], data_sha256=data,
                    result_sha256=empty, transition_intent_sha256=empty)
    checkpoint = {'schema': SCHEMA, 'source_dir': link['source_dir'], 'intent_sha256': forward.contract.digest(link),
                  'sequence_offset': generation - 1, 'generation_model': model,
                  'first_intent': first, 'first_selection': selected}
    return {
        'owner.json': selection.packed({'schema': selection.SCHEMA, 'binding': dict(expected, **model)}),
        CHECKPOINT: selection.packed(checkpoint), '000001.intent.json': selection.packed(first),
        '000001.selection.json': selection.packed(selected),
    }


def decision(link, initial):
    return {'schema': SCHEMA, 'intent_sha256': forward.contract.digest(link),
            'target_entries_sha256': {name: selection.digest(body) for name, body in initial.items()}}


def finish(config_path, plan, *, guard_sha256, terminal_sha256, candidate_sha256,
           qualification_sha256, check_live, authority_file=None, intent_sha256=None):
    """Publish the checked successor while the existing website guard stays held.

    The guarded phase owner supplies a live checker for the sealed runtime,
    signed composition, edge and authenticated application. Reconcile with the
    exact existing intent pin after an interrupted publication.
    """
    from selfhost_windows_model import history

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
            check_live(config, selected, link, stack)

            if INTENT not in raw:
                selection._append(source, raw, INTENT, link, stack)
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
            if DECISION in raw:
                require(raw[DECISION] == publication_raw)
            else:
                if PENDING not in raw:
                    selection._append(source, raw, PENDING, publication, stack)
                require(raw[PENDING] == publication_raw)
                pending_identity = _path_identities(source / PENDING)
        # Complete every held proof before the same-handle publication. The
        # pre-existing shared renewal lock remains held across this boundary.
        if DECISION not in raw:
            with _held_private_input(source / PENDING, _rename_to=source / DECISION,
                                     _expected_identities=pending_identity) as body:
                require(body == publication_raw)
            require(_path_identities(source / DECISION) == pending_identity)

    with selection._session(config_path, _pending_website_sha256=guard_sha256) as (_, _, _, active, entries, _stack):
        require(active == target and all(entries.get(name) == body for name, body in initial.items()))
    return {'schema': SCHEMA, 'result': 'website-selected-guarded', 'guard_sha256': guard_sha256,
            'intent_sha256': link_sha256, 'journal': str(target), 'guards_retained': True,
            'generation_sequence': plan['owner']['generation_sequence'],
            'selected_sha256': forward.contract.digest(selected['selected'])}
