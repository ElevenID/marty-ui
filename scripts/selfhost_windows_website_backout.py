"""Retire the owned website slot after verified restoration of combined routing."""
from pathlib import Path
import re

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website_abort_release as owner_release
import selfhost_windows_website_edge as edge
import selfhost_windows_website_journal as journal
import selfhost_windows_website_plan as contract
import selfhost_windows_website_reconcile as reconcile
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store


PHASE = 'retire-candidate'
CLASSIFICATION = 'combined-backout-evidence-complete'
BEFORE = 'retire-candidate-before.json'
RETURNED = 'retire-candidate-returned.json'
AFTER = 'retire-candidate-after.json'
HISTORY = {'stage-after.json': ('stage-candidate', 'completed'),
           'restore-combined-before.json': (edge.BACKOUT, 'started'),
           'restore-combined-after.json': (edge.BACKOUT, 'completed'),
           'verify-combined-after.json': ('verify-combined', 'completed')}
RETIREMENT = {BEFORE: (PHASE, 'started'), RETURNED: (PHASE, journal.RETIRE_RETURNED)}
require = selection.require
renewal = selection.renewal


def _verified_candidate(plan, evidence):
    stage_after = evidence['stage-after.json']
    routed = evidence['restore-combined-after.json']
    verified = evidence['verify-combined-after.json']
    candidate_id = stage_after['candidate_health']['container_id']
    require(re.fullmatch(r'[0-9a-f]{64}', candidate_id) and routed['mounted_template'] == plan['edge_template'])
    staged = verified['runtime_after']
    before = evidence.get('restore-combined-before.json', {}).get('runtime_before', {})
    if 'readmission_sha256' in before:
        require(contract.sha(before['readmission_sha256']))
        baseline = before['containers']
        candidate_ids = [key for key, row in baseline.items() if row['service'] == contract.SLOT]
        require(len(candidate_ids) == 1)
        candidate_id = candidate_ids[0]
    else:
        baseline = stage_after['runtime_after']
    require(re.fullmatch(r'[0-9a-f]{64}', candidate_id)
            and staged == routed['runtime_after'] and staged[candidate_id] == baseline[candidate_id])
    require({key for key, row in staged.items() if row['service'] == contract.SLOT} == {candidate_id})
    require(staged[candidate_id]['project'] == plan['owner']['project'])
    return candidate_id, staged, routed['edge_configuration']


def _retained(plan, status, evidence):
    candidate_id, staged, configuration = _verified_candidate(plan, evidence)
    started = evidence[BEFORE]
    before = started['runtime_before']
    custody = before['candidate_retirement']
    result = evidence[RETURNED]['candidate_retirement']
    owner = plan['owner']
    require(started['owner_lease'] == {'guard_sha256': status['guard_sha256'], 'owner': owner})
    require(before['containers'] == staged and before['edge_configuration'] == configuration
            and custody == {'candidate_id': candidate_id, 'observed_candidate': staged[candidate_id],
                            'remove_command': ['container', 'rm', candidate_id]})
    stop_required = staged[candidate_id]['status'] in {'running', 'restarting'}
    require(type(result.get('remove_returncode')) is int and result['stop_completed'] is stop_required
            and result == {'candidate_id': candidate_id, 'stop_completed': stop_required,
                            'remove_returncode': 0, 'completed_cli_job': True,
        'candidate_absent': True})
    routes = before['retained_route_directory']
    require(contract.sha(before['normalized_model']['sha256']) and routes in {'absent', 'empty', 'materialized'}
            and (edge.FORWARD not in status['completed_phases'] or routes == 'materialized'))
    retained = {'runtime_after': {key: row for key, row in staged.items() if key != candidate_id},
                'normalized_model': before['normalized_model'], 'edge_configuration': configuration,
                'retained_route_directory': routes}
    require(contract.digest(edge._retained_data(retained['runtime_after'])) == owner['data_sha256'])
    return retained, result


def _prepare_removal(config, choice, values, record, plan, status, evidence, attempt, *,
                     assets, gh, cosign, registry_config, authority_file, held):
    candidate_id, staged_snapshot, configuration = _verified_candidate(plan, evidence)
    context, proposal, _prior, _routes = edge._prepare(config, choice, values, record, plan, status,
        prior_phase='verify-combined', current='staged', target='staged', create_routes=False, candidate_ready=False,
        assets=assets, gh=gh, cosign=cosign, registry_config=registry_config, authority_file=authority_file,
        held=held, include_http=True)
    qualified = context.check(before_intent=True)
    project, docker = context.project, context.docker
    owned = edge._owned(qualified, project)
    require(renewal.context_snapshot(owned) == staged_snapshot)
    require(edge._probe(docker, edge._edge(owned), proposal, 'staged') == configuration)
    directory = Path(plan['route_directory'])
    route_state, check_routes = edge._hold_inactive_routes(directory, proposal['routes']['split'], held)
    require(edge.FORWARD not in status['completed_phases'] or route_state == 'materialized')
    candidate = reconcile._candidate_items(qualified, project, candidate_id)
    command, staged, hashes = context.layouts['staged']
    combined = {**staged, 'services': {name: service for name, service in staged['services'].items() if name != contract.SLOT}}
    inspected = {'docker': docker, 'baseline': [row for row in qualified if row is not candidate], 'context': context}
    removal_context = reconcile.AbortContext(inspected, config, combined, staged, hashes, proposal['data']['staged'],
                                              Path(record['selected']['secrets_dir']), candidate_id)
    removal_context.check()
    custody = reconcile._removal_intent(candidate, project, command)
    started = edge._start_observation(plan, status, context, qualified, configuration)
    started['runtime_before'].update(candidate_retirement=custody, normalized_model={'sha256': contract.digest(combined)},
                                     retained_route_directory=route_state)
    authorized = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=PHASE, event='started',
                             evidence_sha256=stage._evidence(attempt / BEFORE, started, held))
    check_routes()
    result = reconcile._remove_candidate(removal_context, custody)
    returned = {'candidate_retirement': result}
    advanced = store.append(plan, expected_anchor_sha256=authorized['anchor_sha256'], phase=PHASE,
                           event=journal.RETIRE_RETURNED, evidence_sha256=stage._evidence(attempt / RETURNED, returned, held))
    return {**advanced, 'guard_sha256': status['guard_sha256']}, {**evidence, BEFORE: started, RETURNED: returned}, proposal


def _completion(plan, retained, result, qualification):
    return {'runtime_after': {**retained, 'candidate_retirement_sha256': contract.digest(result),
                             'qualification': qualification},
            'native_custody': {'native_sha256': plan['owner']['native_sha256'], 'selected_sha256': plan['owner']['selected_sha256']},
            'foreign_storage': {'engine_id': plan['owner']['engine_id'], 'sha256': qualification['foreign_storage_sha256'],
                                'changes': qualification['foreign_storage_changes']}}


def _verify_completion(plan, retained, result, evidence):
    qualification = evidence['runtime_after']['qualification']
    require(evidence == _completion(plan, retained, result, qualification))
    owner_release._verify_qualification(qualification, retained, plan['owner'])


def run(config, choice, values, record, plan, status, phase, *, assets, gh, cosign, registry_config, authority_file, held):
    """Retire after verified routing, or finish a returned removal without replay."""
    require(phase == PHASE and status['model_state'] == 'staged' and status['completed_phases'][-1] == 'verify-combined')
    starting = status['classification'] == 'phase-boundary' and status['permitted_record_phases'] == [PHASE]
    if not starting:
        require(status['classification'] == 'reconciliation-required' and status['pending_phase'] == PHASE)
        if not status['retirement_returned']:
            raise renewal.UncertainComposeMutation('Website retirement authorization has no completed CLI boundary')
    attempt = Path(plan['attempt_directory'])
    held.enter_context(renewal.hold_storage_namespace(attempt))
    held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
    references = HISTORY if starting else {**HISTORY, **RETIREMENT}
    evidence = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], references=references, held=held)
    proposal = None
    if starting:
        status, evidence, proposal = _prepare_removal(config, choice, values, record, plan, status, evidence, attempt,
            assets=assets, gh=gh, cosign=cosign, registry_config=registry_config, authority_file=authority_file, held=held)
    retained, result = _retained(plan, status, evidence)
    fresh = owner_release._refresh(config, choice, values, record, plan, retained, attempt, assets=assets, gh=gh,
        cosign=cosign, registry_config=registry_config, authority_file=authority_file, held=held, proposal=proposal)
    path = attempt / AFTER
    if renewal.namespace_entry_exists(path):
        raw = held.enter_context(renewal.hold_private_input(path))
        observed = selection.decode(raw)
        require(selection.packed(observed) == raw)
        _verify_completion(plan, retained, result, observed)
    else:
        observed = _completion(plan, retained, result, fresh)
    hashes = stage._evidence(path, observed, held)
    completed = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=PHASE,
                             event='completed', evidence_sha256=hashes)
    return {**completed, 'guard_sha256': status['guard_sha256'], 'receipt_contents_verified': True}


def hold_retirement(plan, status, held):
    """Re-read the completed removal and exact combined evidence for guard release."""
    terminal, proof = store.hold_terminal_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], held=held,
        classification=CLASSIFICATION, references={**HISTORY, **RETIREMENT, AFTER: (PHASE, 'completed')})
    require(terminal['tail_sha256'] == status['tail_sha256'] and terminal['retirement_returned'])
    retained, result = _retained(plan, {**terminal, 'guard_sha256': status['guard_sha256']}, proof)
    _verify_completion(plan, retained, result, proof[AFTER])
    return retained, {'candidate_outcome': 'removed-after-combined-rollback', 'retirement': proof[AFTER]}
