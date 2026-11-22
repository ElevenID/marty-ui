"""Return the selected combined owner to service after a verified abort or rollback."""
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
MODES = {'abort': (SCHEMA, RELEASE), 'backout': ('marty.windows-website-backout-release/v1', BACKOUT_RELEASE)}
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


def _read_release(attempt, expected, retained, owner, held, mode):
    raw = held.enter_context(renewal.hold_private_input(attempt / MODES[mode][1]))
    record = selection.decode(raw)
    require(record == {**expected, 'qualification_sha256': record['qualification_sha256']}
            and contract.sha(record['qualification_sha256']) and raw == selection.packed(record))
    proof = held.enter_context(renewal.hold_private_input(attempt / (mode + '-release-proof-' + record['qualification_sha256'] + '.json')))
    observed = selection.decode(proof)
    require(selection.digest(proof) == record['qualification_sha256'] and proof == selection.packed(observed))
    _verify_qualification(observed, retained, owner)
    return record


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
    release_path = attempt / MODES[mode][1]
    if not renewal.namespace_entry_exists(release_path):
        pin = contract.digest(qualification)
        stage._material(attempt / (mode + '-release-proof-' + pin + '.json'), qualification, held)
        stage._material(release_path, {**expected, 'qualification_sha256': pin}, held)
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
            # Keep the project lock through the exact, no-overwrite rename.
            require(not renewal.namespace_entry_exists(archive) and not any(
                renewal.namespace_entry_exists(other(config)) for other in (renewal.recovery_guard,
                    renewal.recovery_preparation_guard, renewal.renewal_staging_guard,
                    renewal.model_repair_guard, renewal.continuation_guard)))
            with _held_private_input(active, _rename_to=archive, _expected_identities=identities) as body:
                require(body == original)
            require(_path_identities(archive) == identities)
            require(coordination.enter_context(renewal.hold_private_input(archive)) == original)
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
