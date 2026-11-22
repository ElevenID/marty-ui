"""Plan and restore edge routing under the renewed, still-selected split owner."""
from contextlib import ExitStack
from pathlib import Path

import selfhost_windows_continuation as continuation
import selfhost_windows_model as model
import selfhost_windows_selection as selection
import selfhost_windows_website_abort_release as release
import selfhost_windows_website_edge as edge
import selfhost_windows_website_forward as forward
import selfhost_windows_website_guard as guard
import selfhost_windows_website_plan as contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import selfhost_windows_website_verify as verify


SCHEMA = 'marty.windows-website-current-backout-plan/v2'
GUARD_SCHEMA = 'marty.windows-website-current-edge-guard/v1'
require = selection.require
renewal = selection.renewal


def edge_guard(plan, current_plan_sha256):
    require(contract.sha(current_plan_sha256))
    return {'schema': GUARD_SCHEMA, 'historical_plan_sha256': plan['plan_sha256'],
            'attempt_directory': plan['attempt_directory'], 'current_plan_sha256': current_plan_sha256}


def _history(config, current, ancestry, historical_plan, *, guard_sha256, expected_anchor_sha256,
             intent_sha256, release_sha256, active_guard, held):
    """Recheck the prior release and retain only its exact combined model."""
    attempt, active, archive = release._paths(config, historical_plan, 'forward')
    if active_guard is None:
        require(not renewal.namespace_entry_exists(active))
    else:
        require(held.enter_context(renewal.hold_private_input(active)) == selection.packed(active_guard))
    marker = selection.packed(guard.marker(historical_plan))
    require(selection.digest(marker) == guard_sha256
            and held.enter_context(renewal.hold_private_input(archive)) == marker)
    origin, link, (target, initial), decision_pin = release._selected_lineage(ancestry, current, intent_sha256, 'forward')
    require(link['attempt_dir'] == str(attempt) and link['terminal_sha256'] == expected_anchor_sha256)
    status, evidence = store.hold_terminal_evidence(historical_plan, expected_anchor_sha256=expected_anchor_sha256,
        classification='forward-evidence-complete', held=held,
        references={'stage-before.json': ('stage-candidate', 'started')})
    data = edge._retained_data(evidence['stage-before.json']['runtime_before'])
    require(contract.digest(data) == historical_plan['states']['combined']['data_sha256'])
    status.update(guard_sha256=guard_sha256, anchor_sha256=expected_anchor_sha256)
    expected = release._selection_release_checkpoints(
        historical_plan, status, intent_sha256, decision_pin, target, initial, 'forward')
    recorded, qualification = release._hold_release(attempt, expected, held, 'forward')
    require(contract.digest(recorded) == release_sha256)
    pinned = forward._pinned_qualification(attempt, link['candidate_sha256'], link['qualification_sha256'], held)
    forward.verify_qualification(qualification, pinned)

    # Credential renewal can continue into a later journal segment. Product,
    # model, and website transitions require a new reviewed restoration.
    history = ancestry + [current]
    paths = [path for path, _ in history]
    target_index = paths.index(target)
    for path, entries in history[target_index:]:
        require(not any(model.ENTRY.fullmatch(name) for name in entries))
        if path != current[0]:
            require(continuation.INTENT in entries and continuation.DECISION in entries)
    initial_owner = selection.decode(initial['owner.json'])['binding']
    require(model.model_binding(config) == model.model_binding(initial_owner))
    _, original = origin
    original_owner = selection.decode(original['owner.json'])['binding']
    _, records = selection._parse(original, original_owner)
    _, original_model, _ = model.history(original, original_owner, records)
    plan_record = {'plan_sha256': historical_plan['plan_sha256'], 'guard_sha256': guard_sha256,
                   'sealed_anchor_sha256': expected_anchor_sha256, 'intent_sha256': intent_sha256,
                   'release_sha256': release_sha256, 'selection_decision_sha256': decision_pin}
    return original_model, attempt, plan_record, data


def _layouts(config, combined, choice, values, record, historical_plan, attempt, data, held, *,
             assets, gh, cosign, registry_config):
    """Render the old combined source and approved overlays under both current environments."""
    for name in ('stage.compose.json', 'route.compose.json'):
        # Existing overlay helpers also support first materialization. Planning
        # must fail on a missing retained overlay instead of recreating it.
        held.enter_context(renewal.hold_private_input(attempt / name))
    _, selected_commands, split_models = selection._compose_models(config, values)
    docker, commands, combined_models = selection._compose_models(combined, values)
    reconstructed, proposal = edge.website.inspect_composition(combined, choice, values, record, assets,
        gh=gh, cosign=cosign, registry_config=registry_config, owner_root=attempt.parent, held=held,
        plan_owner=historical_plan['owner'], plan_attempt_directory=attempt, held_plan_only=True,
        guarded_attempt=True, retained_edge_inputs=(docker, combined_models[choice], data), include_http=True)
    require(reconstructed == historical_plan)
    layouts = {'old': {}, 'new': {}}
    for side, configured in combined_models.items():
        base = commands[side]
        layouts[side]['combined'] = (base, configured, docker.hashes(base))
        staged = stage._stage_model(docker, base, configured, proposal, attempt, held)
        layouts[side]['staged'] = staged
        split = edge._split_model(docker, *staged, proposal, attempt, held)
        require(split[1] == split_models[side] and split[2] == docker.hashes(selected_commands[side]))
        layouts[side]['split'] = split
    return docker, layouts, proposal


def _context(config, choice, values, record, historical_plan, docker, layouts, proposal, held, authority_file, state):
    routes = edge._held_routes(Path(historical_plan['route_directory']), proposal['routes']['split'], held, create=False)
    baseline = docker.containers()
    owned = edge._owned(baseline, config['project'])
    for row in owned:
        for mount in row['Mounts']:
            if mount.get('RW') and mount.get('Type') == 'bind':
                source = renewal.windows_source(mount['Source'])
                require(source is not None)
                held.enter_context(renewal.hold_storage_namespace(source))
    current = layouts[choice]
    retained_roles = {renewal._service(row) for row in owned} - {contract.SLOT}
    changing = renewal.owned_roles(current['combined'][1], retained_roles)
    renewal.dependency_layers(current['combined'][1], retained_roles, changing)
    context = edge.EdgeContext(docker, config, baseline, docker.volumes(), proposal, current, state, 'staged',
        Path(record['selected']['secrets_dir']), require_candidate_ready=False)
    selection._native_current(config, choice, values, docker, authority_file)
    return context, routes


def _observe(context, proposal, routes, state, *, before_intent):
    layout = context.layouts[state][1]
    first = edge._edge(edge._owned(context.check(before_intent=before_intent), context.project))
    ingress = verify._installed_ingress(first, layout)
    configured = edge._probe(context.docker, first, proposal, state)
    items = context.check(before_intent=before_intent)
    owned = edge._owned(items, context.project)
    last = edge._edge(owned)
    require(ingress == verify._installed_ingress(last, layout)
            and configured == edge._probe(context.docker, last, proposal, state))
    routes()
    runtime = renewal.context_snapshot(owned)
    return runtime, {'runtime_sha256': contract.digest(runtime),
            'protected_runtime_sha256': contract.digest({k: v for k, v in runtime.items() if v['service'] != 'edge'}),
            'edge_configuration': configured, 'ingress_sha256': contract.digest(ingress),
            'networks': sorted(last['NetworkSettings']['Networks']),
            'foreign_storage_sha256': context.proof_sha256, 'foreign_storage_changes': context.proof_count}


def prepare(config, choice, values, record, owner, current, ancestry, historical_plan, *, guard_sha256,
            expected_anchor_sha256, intent_sha256, release_sha256, assets, gh, cosign, registry_config,
            authority_file=None, held, operation='plan', current_plan_sha256=None):
    """Qualify the current owner before planning, dispatching or reconciling edge restoration."""
    require(operation in {'plan', 'restore', 'reconcile'})
    require(current_plan_sha256 is None if operation == 'plan' else contract.sha(current_plan_sha256))
    require(all(contract.sha(pin) for pin in (guard_sha256, expected_anchor_sha256, intent_sha256, release_sha256)))
    require(owner['generation_sequence'] > historical_plan['owner']['generation_sequence']
            and owner['data_sha256'] == historical_plan['states']['split']['data_sha256']
            and owner['historical_tls_sha256'] == historical_plan['owner']['historical_tls_sha256'])
    original, attempt, lineage, data = _history(config, current, ancestry, historical_plan, guard_sha256=guard_sha256,
        expected_anchor_sha256=expected_anchor_sha256, intent_sha256=intent_sha256, release_sha256=release_sha256,
        active_guard=edge_guard(historical_plan, current_plan_sha256) if operation == 'reconcile' else None, held=held)
    combined = model.effective_config(config, original)
    for cfg in (combined, config):
        raw = held.enter_context(renewal.hold_private_input(Path(cfg['compose_file']), max_bytes=forward.MODEL_LIMIT))
        require(selection.digest(raw) == cfg['compose_sha256'])
    docker, layouts, proposal = _layouts(config, combined, choice, values, record, historical_plan, attempt, data, held,
        assets=assets, gh=gh,
        cosign=cosign, registry_config=registry_config)
    states = {name: {'data_sha256': historical_plan['states'][name]['data_sha256'],
                    'normalized_sha256': {side: contract.digest(layouts[side][name][1]) for side in layouts},
                    'configuration_hashes_sha256': {side: contract.digest(layouts[side][name][2]) for side in layouts}}
              for name in ('combined', 'staged', 'split')}
    value = {'schema': SCHEMA, 'operation': 'restore-combined-current-generation', 'owner': owner,
             'selected_journal': str(current[0]), 'historical_release': lineage,
             'configuration': {'combined': original, 'split': model.model_binding(config)},
             'states': states}
    state = 'staged' if operation == 'reconcile' else 'split'
    context, routes = _context(config, choice, values, record, historical_plan, docker, layouts, proposal, held,
                               authority_file, state)
    if operation == 'reconcile':
        return _reconcile(value, current_plan_sha256, historical_plan, context, routes, proposal, held)
    _, observation = _observe(context, proposal, routes, state, before_intent=True)
    value['observation'] = observation
    plan = {**value, 'plan_sha256': contract.digest(value)}
    if operation == 'plan':
        return plan
    require(plan['plan_sha256'] == current_plan_sha256)
    return _restore(plan, historical_plan, context, routes, proposal, config, held)


def _evidence_path(historical, pin, name):
    require(contract.sha(pin))
    return Path(historical['attempt_directory']) / ('current-edge-' + pin + '-' + name + '.json')


def _finish(plan, historical, context, routes, proposal, held, *, resumed):
    runtime, observed = _observe(context, proposal, routes, 'staged', before_intent=resumed)
    before = plan['observation']
    previous, restored = before['edge_configuration'], observed['edge_configuration']
    require(all(observed[key] == before[key] for key in ('protected_runtime_sha256', 'ingress_sha256', 'networks')))
    require(previous['container_id'] != restored['container_id'] and previous['container_id'] not in runtime
            and runtime[restored['container_id']]['service'] == 'edge' and runtime[restored['container_id']]['restarts'] == 0
            and restored['default_sha256'] == previous['default_sha256']
            and restored['routes_sha256'] == historical['states']['staged']['routes_sha256'])
    pin = plan['plan_sha256']
    # The storage proof chain describes one observation session. Each replay
    # requalifies storage independently. Only owned state identifies the result.
    restored_state = {key: observed[key] for key in (
        'runtime_sha256', 'protected_runtime_sha256', 'ingress_sha256', 'networks', 'edge_configuration')}
    receipt = {'schema': 'marty.windows-website-current-edge-restored/v1', 'current_plan_sha256': pin,
               'guard_sha256': contract.digest(edge_guard(historical, pin)), 'selected_sha256': plan['owner']['selected_sha256'],
               'generation_sequence': plan['owner']['generation_sequence'], 'observation': restored_state}
    stage._material(_evidence_path(historical, pin, 'restored'), receipt, held)
    return {'result': 'current-generation-edge-restored', 'guard_retained': True, 'receipt_sha256': contract.digest(receipt),
            'current_plan_sha256': pin, 'generation_sequence': receipt['generation_sequence']}


def _returned(pin, command, returncode):
    return {'current_plan_sha256': pin, 'command_sha256': contract.digest(command),
            'completed_cli_job': True, 'returncode': returncode}


def _restore(plan, historical, context, routes, proposal, config, held):
    pin = plan['plan_sha256']
    marker = edge_guard(historical, pin)
    active = renewal.product_transition_guard(config)
    pending = active.with_name(active.name + '.' + pin + '.prepared')
    returned = _evidence_path(historical, pin, 'returned')
    require(not renewal.recovery_pending(config) and not renewal.namespace_entry_exists(returned)
            and not renewal.namespace_entry_exists(_evidence_path(historical, pin, 'restored')))
    stage._material(_evidence_path(historical, pin, 'plan'), plan, held)
    with ExitStack() as preparation:
        stage._material(pending, marker, preparation)
        identities = release._path_identities(pending)
    # Once the verified guard is visible, every fresh dispatch refuses. An
    # interruption or an unreturned CLI result leaves the original intent held.
    release._archive_guard(config, pending, active, selection.packed(marker), identities, held)
    _, ready = _observe(context, proposal, routes, 'split', before_intent=True)
    require(ready == plan['observation'])
    command = edge.recreate_command(context.layouts['staged'][0])
    outcome = renewal.run_owned_mutation(command, timeout=120)
    stage._material(returned, _returned(pin, command, outcome.returncode), held)
    if outcome.returncode != 0:
        raise renewal.UncertainComposeMutation('Current-generation edge restore requires operator reconciliation')
    return _finish(plan, historical, context, routes, proposal, held, resumed=False)


def _reconcile(binding, pin, historical, context, routes, proposal, held):
    """Read back a returned command under its exact guard without dispatching again."""
    raw = held.enter_context(renewal.hold_private_input(_evidence_path(historical, pin, 'plan')))
    plan = selection.decode(raw)
    require(raw == selection.packed(plan) and plan['plan_sha256'] == pin
            and contract.digest({**binding, 'observation': plan['observation']}) == pin
            and plan == {**binding, 'observation': plan['observation'], 'plan_sha256': pin})
    command = edge.recreate_command(context.layouts['staged'][0])
    require(held.enter_context(renewal.hold_private_input(_evidence_path(historical, pin, 'returned')))
            == selection.packed(_returned(pin, command, 0)))
    return _finish(plan, historical, context, routes, proposal, held, resumed=True)
