"""Qualify a fresh rollback plan against a renewed, still-selected split."""
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


SCHEMA = 'marty.windows-website-current-backout-plan/v1'
require = selection.require
renewal = selection.renewal


def _history(config, current, ancestry, historical_plan, *, guard_sha256, expected_anchor_sha256,
             intent_sha256, release_sha256, held):
    """Recheck the prior release and retain only its exact combined model."""
    attempt, active, archive = release._paths(config, historical_plan, 'forward')
    require(not renewal.namespace_entry_exists(active))
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


def _observe(config, choice, values, record, historical_plan, docker, layouts, proposal, held, authority_file):
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
    context = edge.EdgeContext(docker, config, baseline, docker.volumes(), proposal, current, 'split', 'staged',
        Path(record['selected']['secrets_dir']), require_candidate_ready=False)
    selection._native_current(config, choice, values, docker, authority_file)
    first = edge._edge(edge._owned(context.check(before_intent=True), config['project']))
    ingress = verify._installed_ingress(first, current['split'][1])
    configured = edge._probe(docker, first, proposal, 'split')
    items = context.check(before_intent=True)
    last = edge._edge(edge._owned(items, config['project']))
    require(ingress == verify._installed_ingress(last, current['split'][1])
            and configured == edge._probe(docker, last, proposal, 'split'))
    routes()
    return {'runtime_sha256': contract.digest(renewal.context_snapshot(edge._owned(items, config['project']))),
            'edge_configuration': configured, 'ingress_sha256': contract.digest(ingress),
            'foreign_storage_sha256': context.proof_sha256, 'foreign_storage_changes': context.proof_count}


def prepare(config, choice, values, record, owner, current, ancestry, historical_plan, *, guard_sha256,
            expected_anchor_sha256, intent_sha256, release_sha256, assets, gh, cosign, registry_config,
            authority_file=None, held):
    """Bind a rollback to the current generation without changing the live owner."""
    require(all(contract.sha(pin) for pin in (guard_sha256, expected_anchor_sha256, intent_sha256, release_sha256)))
    require(owner['generation_sequence'] > historical_plan['owner']['generation_sequence']
            and owner['data_sha256'] == historical_plan['states']['split']['data_sha256']
            and owner['historical_tls_sha256'] == historical_plan['owner']['historical_tls_sha256'])
    original, attempt, lineage, data = _history(config, current, ancestry, historical_plan, guard_sha256=guard_sha256,
        expected_anchor_sha256=expected_anchor_sha256, intent_sha256=intent_sha256, release_sha256=release_sha256, held=held)
    combined = model.effective_config(config, original)
    for cfg in (combined, config):
        raw = held.enter_context(renewal.hold_private_input(Path(cfg['compose_file']), max_bytes=forward.MODEL_LIMIT))
        require(selection.digest(raw) == cfg['compose_sha256'])
    docker, layouts, proposal = _layouts(config, combined, choice, values, record, historical_plan, attempt, data, held,
        assets=assets, gh=gh,
        cosign=cosign, registry_config=registry_config)
    observation = _observe(config, choice, values, record, historical_plan, docker, layouts, proposal, held, authority_file)
    states = {name: {'data_sha256': historical_plan['states'][name]['data_sha256'],
                    'normalized_sha256': {side: contract.digest(layouts[side][name][1]) for side in layouts},
                    'configuration_hashes_sha256': {side: contract.digest(layouts[side][name][2]) for side in layouts}}
              for name in ('combined', 'staged', 'split')}
    value = {'schema': SCHEMA, 'operation': 'restore-combined-current-generation', 'owner': owner,
             'selected_journal': str(current[0]), 'historical_release': lineage,
             'configuration': {'combined': original, 'split': model.model_binding(config)},
             'states': states, 'observation': observation}
    return {**value, 'plan_sha256': contract.digest(value)}
