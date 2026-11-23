"""Archive the website guard after the exact selected owner qualifies."""
from contextlib import ExitStack
from pathlib import Path

from selfhost_windows_inputs import _held_private_input, _path_identities
import selfhost_windows_selection as selection
import selfhost_windows_website as website
import selfhost_windows_website_edge as edge
import selfhost_windows_website_guard as guard
import selfhost_windows_website_journal as journal
import selfhost_windows_website_plan as contract
import selfhost_windows_website_reconcile as reconcile
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import selfhost_windows_website_verify as verify


SCHEMA = 'marty.windows-website-abort-release/v1'
RELEASE = 'abort-release.json'
BACKOUT_RELEASE = 'backout-release.json'
READMISSION = 'forward-backout-readmission.json'
READMISSION_SCHEMA = 'marty.windows-website-forward-backout-readmission/v1'
MODES = {
    'abort': (SCHEMA, RELEASE),
    'backout': ('marty.windows-website-backout-release/v1', BACKOUT_RELEASE),
    'forward': ('marty.windows-website-forward-owner-release/v1', 'forward-owner-release.json'),
    'combined': ('marty.windows-website-combined-owner-release/v1', 'combined-owner-release.json'),
}
require = selection.require
renewal = selection.renewal


def _paths(config, plan, mode='abort'):
    records, _anchors = store.namespace_paths(plan)
    attempt = records.parent
    owner = plan['owner']
    active = renewal.product_transition_guard(config)
    require(attempt.parent == active.parent == Path(owner['root']) and config['project'] == owner['project'])
    require(config['engine_id'] == owner['engine_id'] and config['docker_host'] == owner['docker_host'])
    require(mode in MODES)
    cycle = attempt.name.removeprefix('windows-website-')
    archive = active.parent / ('.' + owner['project'] + '.website-' + mode + '-retired-' + cycle + '.json')
    return attempt, active, archive


def _abort_inputs(plan, status, attempt, held):
    observed_status, receipt = store.hold_terminal_abort(plan, expected_anchor_sha256=status['anchor_sha256'], held=held)
    require(observed_status['tail_sha256'] == status['tail_sha256'])
    retained = store.hold_abort_observations(attempt, receipt['observations_sha256'], held)
    actions = observed_status['stage_actions']
    references = {'stage-before.json': (stage.PHASE, 'started'),
                  **{reconcile.ACTION_FILES[name]: (stage.PHASE, name) for name in actions}}
    inputs = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], references=references, held=held)
    before = inputs['stage-before.json']
    owner = plan['owner']
    owner_lease = {'guard_sha256': status['guard_sha256'], 'owner': owner}
    require(before['owner_lease'] == {**owner_lease, 'dispatch_schema': stage.DISPATCH_SCHEMA}
            and retained['owner_lease'] == owner_lease and retained['runtime_after'] == before['runtime_before'])
    require(retained['native_custody'] == {'selected_sha256': owner['selected_sha256'], 'native_sha256': owner['native_sha256']}
            and retained['selected_credentials'] == {'selected_sha256': owner['selected_sha256']}
            and retained['candidate_absence'] == {'slot': contract.SLOT, 'engine': owner['engine_id'], 'absent': True}
            and retained['mounted_template'] == plan['edge_template']
            and retained['retained_product'] == {'composition_id': plan['composition_id'], 'data_sha256': owner['data_sha256']})
    if receipt['candidate_outcome'] == 'created-then-compensated':
        require(actions == list(journal.STAGE_ACTION_ORDER))
        custody = inputs[reconcile.ACTION_FILES['compensation-authorized']]['candidate_compensation']
        result = inputs[reconcile.ACTION_FILES['compensation-returned']]['compensation_result']
        container = custody['candidate_id']
        require(custody['remove_command'] == ['container', 'rm', container] and result['candidate_id'] == container
                and result['candidate_absent'] is True and result['completed_cli_job'] is True and result['remove_returncode'] == 0
                and retained['candidate_compensation'] == {'intent': custody, 'result': result})
    else:
        require(receipt['candidate_outcome'] == 'never-created' and not actions)
    return retained, receipt


def _refresh(config, choice, values, record, plan, retained, attempt, *, assets, gh, cosign, registry_config,
             authority_file, held, proposal=None):
    route_directory = Path(plan['route_directory'])
    expected_routes = retained.get('retained_route_directory', 'absent')
    if expected_routes == 'absent':
        require(not renewal.namespace_entry_exists(route_directory))
    inspected = selection._inspect(config, choice, values, held, expected_data=record['data_sha256'])
    docker, model, context = inspected['docker'], inspected['model'], inspected['context']
    require(not website.WEBSITE_ROLES.intersection(inspected['services'])
            and retained['normalized_model'] == {'sha256': contract.digest(model)})
    require(renewal.context_snapshot(inspected['owned']) == retained['runtime_after'])
    data = renewal.data_mounts(inspected['owned'])
    require(contract.digest(data) == plan['states']['combined']['data_sha256'] == record['data_sha256'])
    if proposal is None:
        rebuilt, proposal = website.inspect_composition(config, choice, values, record, assets, gh=gh, cosign=cosign,
            registry_config=registry_config, owner_root=attempt.parent, held=held, plan_owner=plan['owner'],
            plan_attempt_directory=attempt, held_plan_only=True, guarded_attempt=True,
            retained_edge_inputs=(docker, model, data), include_http=True)
        require(rebuilt == plan)
    routes = proposal['routes']['split'] if expected_routes != 'absent' else b''
    actual_routes, check_routes = edge._hold_inactive_routes(route_directory, routes, held)
    require(actual_routes == expected_routes)
    selection._native_current(config, choice, values, docker, authority_file)
    first = edge._edge(edge._owned(context.check(before_intent=True), config['project']))
    observed = edge._probe(docker, first, proposal, 'combined')
    require(observed == retained['edge_configuration'])
    public, application = verify._observe(first, model, proposal['http'], 'combined')
    last = edge._edge(edge._owned(context.check(before_intent=True), config['project']))
    require(verify._installed_ingress(first, model) == verify._installed_ingress(last, model)
            and edge._probe(docker, last, proposal, 'combined') == observed)
    check_routes()
    return {'runtime_sha256': contract.digest(retained['runtime_after']), 'edge_sha256': contract.digest(observed),
            'public_routes_sha256': contract.digest(public), 'application_handoffs_sha256': contract.digest(application),
            'native_sha256': plan['owner']['native_sha256'], 'foreign_storage_sha256': context.proof_sha256,
            'foreign_storage_changes': context.proof_count}


def _terminal_inputs(plan, status, attempt, held, mode):
    if mode == 'abort':
        return _abort_inputs(plan, status, attempt, held)
    from selfhost_windows_website_backout import hold_retirement
    return hold_retirement(plan, status, held)


def _release_checkpoints(plan, status, receipt, mode):
    evidence = 'abort_receipt_sha256' if mode == 'abort' else 'retirement_sha256'
    return {'schema': MODES[mode][0], 'plan_sha256': plan['plan_sha256'], 'guard_sha256': status['guard_sha256'],
            'anchor_sha256': status['anchor_sha256'], 'terminal_record_sha256': status['tail_sha256'],
            evidence: contract.digest(receipt), 'candidate_outcome': receipt['candidate_outcome'],
            'selected_sha256': plan['owner']['selected_sha256'], 'generation_sequence': plan['owner']['generation_sequence']}


def _hold_release(attempt, expected, held, mode):
    raw = held.enter_context(renewal.hold_private_input(attempt / MODES[mode][1]))
    record = selection.decode(raw)
    require(record == {**expected, 'qualification_sha256': record['qualification_sha256']}
            and contract.sha(record['qualification_sha256']) and raw == selection.packed(record))
    proof = held.enter_context(renewal.hold_private_input(attempt / (mode + '-release-proof-' + record['qualification_sha256'] + '.json')))
    observed = selection.decode(proof)
    require(selection.digest(proof) == record['qualification_sha256'] and proof == selection.packed(observed))
    return record, observed


def _read_release(attempt, expected, retained, owner, held, mode):
    record, observed = _hold_release(attempt, expected, held, mode)
    _verify_qualification(observed, retained, owner)
    return record


def _record_release(attempt, expected, qualification, held, mode):
    release_path = attempt / MODES[mode][1]
    if not renewal.namespace_entry_exists(release_path):
        pin = contract.digest(qualification)
        stage._material(attempt / (mode + '-release-proof-' + pin + '.json'), qualification, held)
        stage._material(release_path, {**expected, 'qualification_sha256': pin}, held)


def _verify_qualification(observed, retained, owner):
    require(set(observed) == {'runtime_sha256', 'edge_sha256', 'public_routes_sha256', 'application_handoffs_sha256',
                                  'native_sha256', 'foreign_storage_sha256', 'foreign_storage_changes'}
            and observed['runtime_sha256'] == contract.digest(retained['runtime_after'])
            and observed['edge_sha256'] == contract.digest(retained['edge_configuration'])
            and observed['native_sha256'] == owner['native_sha256']
            and all(contract.sha(observed[name]) for name in ('public_routes_sha256', 'application_handoffs_sha256')))
    count = observed['foreign_storage_changes']
    foreign = observed['foreign_storage_sha256']
    require(type(count) is int and ((count == 0 and foreign is None) or (count > 0 and contract.sha(foreign))))


def prepare(config, choice, values, record, plan, status, phase, *, assets, gh, cosign, registry_config,
            authority_file, held):
    """Qualify a terminal combined layout under the selection input handles."""
    require(phase in {'release-abort', 'release-backout'})
    mode = phase.removeprefix('release-')
    attempt, active, archive = _paths(config, plan, mode)
    require(not renewal.namespace_entry_exists(archive))
    identities = _path_identities(active)
    held.enter_context(renewal.hold_storage_namespace(attempt))
    held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
    retained, receipt = _terminal_inputs(plan, status, attempt, held, mode)
    qualification = _refresh(config, choice, values, record, plan, retained, attempt, assets=assets, gh=gh,
                             cosign=cosign, registry_config=registry_config, authority_file=authority_file, held=held)
    expected = _release_checkpoints(plan, status, receipt, mode)
    _record_release(attempt, expected, qualification, held, mode)
    release = _read_release(attempt, expected, retained, plan['owner'], held, mode)
    return release, identities


def finalize(config_path, plan, *, guard_sha256, expected_anchor_sha256, assets, gh, cosign, registry_config,
             authority_file=None, mode='abort'):
    """Close the verification handles before archiving, with coordination still held."""
    config = selection.decode(renewal.read_private_bytes(Path(config_path)))
    selection.binding(config)
    attempt, active, archive = _paths(config, plan, mode)
    original = selection.packed(guard.marker(plan))
    require(selection.digest(original) == guard_sha256 and contract.sha(expected_anchor_sha256))
    with ExitStack() as coordination:
        if renewal.namespace_entry_exists(active):
            with selection._selected_inputs(config_path, _coordination=coordination,
                    _pending_website=(plan, guard_sha256, expected_anchor_sha256),
                    _website_edge=('release-' + mode, assets, gh, cosign, registry_config, authority_file)) as decision:
                release, identities = decision
                coordination.enter_context(renewal.hold_storage_namespace(attempt))
            _archive_guard(config, active, archive, original, identities, coordination)
        else:
            # A repeat verifies the historical release without requalifying or mutating the current selection.
            with selection._selected_inputs(config_path, _coordination=coordination) as lease:
                owner = plan['owner']
                require(lease.project == owner['project'] and lease.engine_id == owner['engine_id']
                        and lease.docker_host == owner['docker_host'] and lease.journal_path.parent == attempt.parent)
                require(coordination.enter_context(renewal.hold_private_input(archive)) == original)
                status = store.inspect(plan, expected_anchor_sha256=expected_anchor_sha256)
                status = {**status, 'anchor_sha256': expected_anchor_sha256, 'guard_sha256': guard_sha256}
                retained, receipt = _terminal_inputs(plan, status, attempt, coordination, mode)
                release = _read_release(attempt, _release_checkpoints(plan, status, receipt, mode), retained, owner, coordination, mode)
        require(not renewal.namespace_entry_exists(active))
    return {**release, 'result': 'website-' + mode + '-guard-archived', 'guard_archived': True}


def _archive_guard(config, active, archive, original, identities, coordination):
    # Coordination keeps the existing project lock held across the rename.
    require(not renewal.namespace_entry_exists(archive) and not any(
        renewal.namespace_entry_exists(other(config)) for other in (renewal.recovery_guard,
            renewal.recovery_preparation_guard, renewal.renewal_staging_guard,
            renewal.model_repair_guard, renewal.continuation_guard)))
    with _held_private_input(active, _rename_to=archive, _expected_identities=identities) as body:
        require(body == original)
    require(_path_identities(archive) == identities)
    require(coordination.enter_context(renewal.hold_private_input(archive)) == original)


def _selected_lineage(ancestry, current, intent_sha256, mode):
    from selfhost_windows_continuation import CHECKPOINT, checkpoint
    from selfhost_windows_website_owner import (
        COMBINED_FILES, FORWARD_FILES, decision, validate_combined_marker, validate_marker,
    )

    names = FORWARD_FILES if mode == 'forward' else COMBINED_FILES
    intent_name, decision_name, _ = names
    matches = [index for index, (_root, entries) in enumerate(ancestry)
               if intent_name in entries and selection.digest(entries[intent_name]) == intent_sha256]
    require(len(matches) == 1)
    index = matches[0]
    source, raw = ancestry[index]
    source_owner = selection.decode(raw['owner.json'])['binding']
    if mode == 'forward':
        origin = (source, raw)
        link = validate_marker(raw, source_owner, source)
    else:
        require(index >= 1)
        origin = ancestry[index - 1]
        link = validate_combined_marker(raw, source_owner, source, origin)
    target, selected_raw = (ancestry + [current])[index + 1]
    require(target == Path(link['target_dir']))
    initial = {name: selected_raw[name] for name in ('owner.json', CHECKPOINT, '000001.intent.json', '000001.selection.json')}
    require(raw[decision_name] == selection.packed(decision(link, initial))
            and checkpoint(initial)['intent_sha256'] == intent_sha256)
    return origin, link, (target, initial), selection.digest(raw[decision_name])


def _refresh_selected(plan, origin, initial, stack, mode, link, retained, **options):
    from selfhost_windows_model import effective_config, history
    from selfhost_windows_product_journal import anchor
    from selfhost_windows_website_forward import check_publication

    _, original_raw = origin
    owner = selection.decode(original_raw['owner.json'])['binding']
    original_intent, original_record, generation = anchor(original_raw, owner)
    _, records = selection._parse(original_raw, owner)
    _, model, _ = history(original_raw, owner, records)
    original_config = selection.decode(stack.enter_context(renewal.hold_private_input(Path(original_intent['config_path']))))
    original_config = effective_config(original_config, model)
    first = selection.decode(initial['000001.intent.json'])
    record = selection.decode(initial['000001.selection.json'])
    config = selection.decode(stack.enter_context(renewal.hold_private_input(Path(first['config_path']))))
    values, snapshots = selection._inputs(config, stack)
    require(snapshots == first['inputs'] == original_intent['inputs'] and record['selected'] == original_record['selected']
            and generation == plan['owner']['generation_sequence'])
    if mode == 'forward':
        return check_publication(original_config, original_record['choice'], values, original_record, plan, link,
                                 guard_sha256=contract.digest(guard.marker(plan)), held=stack, **options)
    return _refresh(original_config, original_record['choice'], values, original_record, plan, retained,
                    Path(link['attempt_dir']), held=stack, **options)


def finalize_selected(config_path, plan, *, guard_sha256, expected_anchor_sha256, intent_sha256, mode,
                      assets, gh, cosign, registry_config, authority_file=None, **forward_options):
    """Release the guard only for a verified and durably selected website owner."""
    from selfhost_windows_website_forward import _pinned_qualification, verify_qualification

    require(mode in {'forward', 'combined'} and all(
        contract.sha(pin) for pin in (guard_sha256, expected_anchor_sha256, intent_sha256)))
    config = selection.decode(renewal.read_private_bytes(Path(config_path)))
    selection.binding(config)
    attempt, active, archive = _paths(config, plan, mode)
    original = selection.packed(guard.marker(plan))
    require(selection.digest(original) == guard_sha256)
    ancestry = []

    with ExitStack() as coordination:
        active_present = renewal.namespace_entry_exists(active)
        with selection._session(config_path, _coordination=coordination, _preserve_history=ancestry.extend,
                _pending_website_sha256=guard_sha256 if active_present else None) as (base, _, _, current, raw, stack):
            require(_paths(base, plan, mode) == (attempt, active, archive))
            guard_path = active if active_present else archive
            require(stack.enter_context(renewal.hold_private_input(guard_path)) == original)
            origin, link, (target, initial), decision_sha256 = _selected_lineage(ancestry, (current, raw), intent_sha256, mode)
            require(link['attempt_dir'] == str(attempt) and link['terminal_sha256'] == expected_anchor_sha256)
            status = store.inspect(plan, expected_anchor_sha256=expected_anchor_sha256)
            status['guard_sha256'] = guard_sha256
            expected = _selection_release_checkpoints(plan, status, intent_sha256, decision_sha256, target, initial, mode)
            retained = pinned = None
            if mode == 'forward':
                require(status['classification'] == 'forward-evidence-complete')
                pinned = _pinned_qualification(attempt, link['candidate_sha256'], link['qualification_sha256'], stack)
            else:
                from selfhost_windows_website_backout import hold_retirement
                retained, _ = hold_retirement(plan, status, stack)

            if active_present:
                require(current == target and raw == initial and not renewal.namespace_entry_exists(archive)
                        and (mode != 'forward' or not renewal.namespace_entry_exists(attempt / READMISSION)))
                identities = _path_identities(active)
                fresh = _refresh_selected(plan, origin, initial, stack, mode, link, retained,
                    assets=assets, gh=gh, cosign=cosign, registry_config=registry_config,
                    authority_file=authority_file, **forward_options)
                _record_release(attempt, expected, fresh, stack, mode)
                for name, body in initial.items():
                    require(coordination.enter_context(renewal.hold_private_input(target / name)) == body)
                coordination.enter_context(_held_private_input(target, directory=True))
            release, observed = _hold_release(attempt, expected, coordination, mode)
            if mode == 'forward':
                verify_qualification(observed, pinned)
            else:
                _verify_qualification(observed, retained, plan['owner'])
            coordination.enter_context(renewal.hold_storage_namespace(attempt))
        if active_present:
            _archive_guard(config, active, archive, original, identities, coordination)
        else:
            require(coordination.enter_context(renewal.hold_private_input(archive)) == original)
        require(not renewal.namespace_entry_exists(active))
    return {**release, 'result': 'website-' + mode + '-guard-archived', 'guard_archived': True,
            'release_sha256': contract.digest(release)}


def _selection_release_checkpoints(plan, status, intent_pin, decision_pin, target, initial, mode):
    body = initial['000001.selection.json']
    require(contract.digest(selection.decode(body)['selected']) == plan['owner']['selected_sha256'])
    return {'schema': MODES[mode][0], 'plan_sha256': plan['plan_sha256'], 'guard_sha256': status['guard_sha256'],
            'anchor_sha256': status['anchor_sha256'], 'terminal_record_sha256': status['tail_sha256'],
            'intent_sha256': intent_pin, 'decision_sha256': decision_pin, 'selection_sha256': selection.digest(body),
            'journal': str(target), 'selected_sha256': plan['owner']['selected_sha256'],
            'generation_sequence': plan['owner']['generation_sequence']}


def _readmission_binding(plan, status, published, release_pin):
    return {'schema': READMISSION_SCHEMA, 'plan_sha256': plan['plan_sha256'], 'guard_sha256': status['guard_sha256'],
            'sealed_anchor_sha256': status['anchor_sha256'], 'published_selection': published,
            'release_sha256': release_pin}


def _hold_record(path, held):
    raw = held.enter_context(renewal.hold_private_input(path))
    value = selection.decode(raw)
    require(type(value) is dict and raw == selection.packed(value))
    return raw, value


def hold_readmission(plan, status, published, held, *, expected_sha256=None, release_sha256=None):
    """Verify the exact re-admission receipt and its separately retained runtime."""
    attempt = Path(plan['attempt_directory'])
    raw, receipt = _hold_record(attempt / READMISSION, held)
    if expected_sha256 is not None:
        require(selection.digest(raw) == expected_sha256)
    release_raw, _release = _hold_record(attempt / MODES['forward'][1], held)
    release_pin = selection.digest(release_raw)
    require(release_sha256 is None or release_pin == release_sha256)
    binding = _readmission_binding(plan, status, published, release_pin)
    pin = receipt['runtime_sha256']
    require(contract.sha(pin) and receipt == {**binding, 'runtime_sha256': pin})
    runtime_raw, runtime = _hold_record(attempt / ('forward-backout-runtime-' + pin + '.json'), held)
    require(selection.digest(runtime_raw) == pin
            and set(runtime) == {'runtime_after', 'edge_configuration', 'native_custody', 'foreign_storage'}
            and runtime['native_custody'] == {key: plan['owner'][key] for key in ('selected_sha256', 'native_sha256')}
            and contract.digest(edge._retained_data(runtime['runtime_after'])) == plan['states']['split']['data_sha256'])
    foreign = runtime['foreign_storage']
    count = foreign['changes']
    require(set(foreign) == {'engine_id', 'inventory_sha256', 'changes_sha256', 'changes'}
            and foreign['engine_id'] == plan['owner']['engine_id'] and contract.sha(foreign['inventory_sha256'])
            and type(count) is int and ((count == 0 and foreign['changes_sha256'] is None)
                                       or (count > 0 and contract.sha(foreign['changes_sha256']))))
    return receipt, runtime


def _qualify_released_split(config, choice, values, record, plan, status, *, held, **options):
    """Re-derive the active split under the saved plan, including after a restart."""
    context, proposal, _previous, check_routes = edge._prepare(config, choice, values, record, plan, status,
        prior_phase=edge.FORWARD, current='split', target='split', create_routes=False, candidate_ready=False,
        include_http=True, qualify_restarted_split=True, held=held, **options)
    items = context.check(before_intent=True)
    original = edge._edge(edge._owned(items, config['project']))
    _, layout, _ = context.layouts['split']
    ingress = verify._installed_ingress(original, layout)
    observed = edge._probe(context.docker, original, proposal, 'split')
    final = context.check(before_intent=True)
    selected = edge._edge(edge._owned(final, config['project']))
    require(verify._installed_ingress(selected, layout) == ingress
            and edge._probe(context.docker, selected, proposal, 'split') == observed)
    check_routes()
    witness = edge._start_observation(plan, status, context, final, observed)
    return {'runtime_after': witness['runtime_before']['containers'], 'edge_configuration': observed,
            'native_custody': witness['native_custody'], 'foreign_storage': witness['foreign_storage']}


def readmit_forward_backout(config_path, plan, *, guard_sha256, expected_anchor_sha256, intent_sha256, release_sha256,
                           assets, gh, cosign, registry_config, authority_file=None):
    """Re-open the verified rollback guard at the still-selected credential generation."""
    from selfhost_windows_model import effective_config, history
    from selfhost_windows_product_journal import anchor
    from selfhost_windows_website_forward import _pinned_qualification, verify_qualification
    from selfhost_windows_website_owner import _published_binding

    require(all(contract.sha(pin) for pin in (guard_sha256, expected_anchor_sha256, intent_sha256, release_sha256)))
    config = selection.decode(renewal.read_private_bytes(Path(config_path)))
    selection.binding(config)
    attempt, active, archive = _paths(config, plan, 'forward')
    original = selection.packed(guard.marker(plan))
    require(selection.digest(original) == guard_sha256)
    ancestry = []

    with ExitStack() as coordination:
        active_present = renewal.namespace_entry_exists(active)
        with selection._session(config_path, _coordination=coordination, _preserve_history=ancestry.extend,
                _pending_website_sha256=guard_sha256 if active_present else None) as (base, _, _, current, raw, stack):
            require(_paths(base, plan, 'forward') == (attempt, active, archive))
            require(renewal.namespace_entry_exists(archive) != active_present
                    and (active_present or not renewal.recovery_pending(base)))
            guard_path = active if active_present else archive
            require(stack.enter_context(renewal.hold_private_input(guard_path)) == original)
            origin, link, (target, initial), decision_pin = _selected_lineage(ancestry, (current, raw), intent_sha256, 'forward')
            require(current == target and raw == initial and link['attempt_dir'] == str(attempt)
                    and link['terminal_sha256'] == expected_anchor_sha256)
            status = store.inspect(plan, expected_anchor_sha256=expected_anchor_sha256)
            require(status['classification'] == 'forward-evidence-complete')
            status['guard_sha256'] = guard_sha256
            expected = _selection_release_checkpoints(plan, status, intent_sha256, decision_pin, target, initial, 'forward')
            release, observed = _hold_release(attempt, expected, coordination, 'forward')
            require(contract.digest(release) == release_sha256)
            pinned = _pinned_qualification(attempt, link['candidate_sha256'], link['qualification_sha256'], stack)
            verify_qualification(observed, pinned)
            published = _published_binding(origin[1], link, initial)
            if not active_present:
                _, original_raw = origin
                owner = selection.decode(original_raw['owner.json'])['binding']
                first, original_record, generation = anchor(original_raw, owner)
                records = selection._parse(original_raw, owner)[1]
                _, combined_model, _ = history(original_raw, owner, records)
                original_config = selection.decode(stack.enter_context(renewal.hold_private_input(Path(first['config_path']))))
                original_config = effective_config(original_config, combined_model)
                values, snapshots = selection._inputs(original_config, stack)
                require(snapshots == first['inputs'] == selection.decode(initial['000001.intent.json'])['inputs']
                        and generation == plan['owner']['generation_sequence'])
                runtime = _qualify_released_split(original_config, original_record['choice'], values, original_record,
                    plan, status, assets=assets, gh=gh, cosign=cosign, registry_config=registry_config,
                    authority_file=authority_file, held=stack)
                pin = contract.digest(runtime)
                stage._material(attempt / ('forward-backout-runtime-' + pin + '.json'), runtime, stack)
                stage._material(attempt / READMISSION, {**_readmission_binding(plan, status, published, release_sha256),
                                'runtime_sha256': pin}, stack)
                identities = _path_identities(archive)
            receipt, _runtime = hold_readmission(plan, status, published, coordination, release_sha256=release_sha256)
            for name, body in initial.items():
                require(coordination.enter_context(renewal.hold_private_input(target / name)) == body)
            coordination.enter_context(_held_private_input(target, directory=True))
        if not active_present:
            _archive_guard(config, archive, active, original, identities, coordination)
        else:
            require(coordination.enter_context(renewal.hold_private_input(active)) == original)
        require(not renewal.namespace_entry_exists(archive))
    return {**receipt, 'result': 'website-forward-backout-readmitted', 'readmission_sha256': contract.digest(receipt)}
