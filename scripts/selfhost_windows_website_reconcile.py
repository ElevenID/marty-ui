"""Reconcile a failed initial website stage without replaying its Compose up."""
from pathlib import Path
import re
from types import SimpleNamespace

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website as website
import selfhost_windows_website_edge as edge
import selfhost_windows_website_journal as journal
import selfhost_windows_website_plan as contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store
import selfhost_windows_website_verify as verify


renewal = selection.renewal
require = selection.require
ACTION_FILES = dict(zip(journal.STAGE_ACTION_ORDER,
    ('stage-dispatch.json', 'stage-result.json', 'stage-compensation.json', 'stage-compensation-result.json'), strict=True))
STOPPED = {'created', 'exited', 'dead'}


class AbortContext(stage.StageContext):
    """Refresh the stage's full storage witness and keep the combined runtime ready."""

    def __init__(self, inspected, config, combined, staged, hashes, expected_data, secret_root, candidate_id):
        super().__init__(inspected, config, staged, hashes, expected_data, secret_root)
        self.combined, self.candidate_id = combined, candidate_id

    def _candidate(self, items, *, before_intent):
        rows = stage._candidate_rows(items, self.project)
        require(not rows or (len(rows) == 1 and rows[0]['Id'] == self.candidate_id))
        snapshot = super()._candidate(items, before_intent=before_intent)
        combined = [row for row in edge._owned(items, self.project) if renewal._service(row) != contract.SLOT]
        renewal.checked_live_configuration(combined, self.hashes, self.config['tls_init_receipt'])
        require(renewal.checked_secret_mounts(combined, self.project, self.secret_root,
            self.services, self.combined, path_equal=renewal.windows_mount_path_equal) > 0)
        ready = [{'Service': renewal._service(row), 'State': row['State']['Status'],
                  'ExitCode': row['State']['ExitCode'], 'Health': row['State'].get('Health', {}).get('Status', '')}
                 for row in combined]
        require(renewal.windows_healthy(ready, self.services, self.combined))
        return snapshot


def _compose_candidate(candidate, project, command):
    container = candidate['Id']
    labels = candidate['Config']['Labels']
    inputs = [command[index + 1] for index, item in enumerate(command) if item == '-f']
    observed = labels['com.docker.compose.project.config_files'].split(',')
    require(re.fullmatch(r'[0-9a-f]{64}', container) and candidate['Name'] == f'/{project}-{contract.SLOT}-1'
            and labels['com.docker.compose.container-number'] == '1' and labels['com.docker.compose.oneoff'].lower() == 'false'
            and len(inputs) == len(observed) == 2 and all(renewal.windows_mount_path_equal(a, b)
                 for a, b in zip(observed, inputs, strict=True)))
    return container


def _candidate_items(items, project, expected_id):
    rows = stage._candidate_rows(items, project)
    if expected_id is None:
        require(not rows)
        return None
    require(len(rows) == 1 and rows[0]['Id'] == expected_id)
    return rows[0]


def _record_action(plan, status, name, value, attempt, held):
    hashes = stage._evidence(attempt / ACTION_FILES[name], {journal.STAGE_ACTIONS[name]: value}, held)
    return store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=stage.PHASE,
                        event=name, evidence_sha256=hashes)


def _removal_intent(candidate, project, command):
    container = _compose_candidate(candidate, project, command)
    initial = renewal.context_snapshot([candidate])[container]
    require(initial['status'] in STOPPED | {'running', 'restarting'})
    return {'candidate_id': container, 'observed_candidate': initial, 'remove_command': ['container', 'rm', container]}


def _remove_candidate(context, custody):
    docker, project = context.docker, context.project
    container = custody['candidate_id']
    observed = _candidate_items(context.check(), project, container)
    require(renewal.context_snapshot([observed])[container] == custody['observed_candidate'])
    stopping = observed['State']['Status'] in {'running', 'restarting'}
    if stopping:
        stopped = renewal.run_owned_mutation([*docker.prefix, 'container', 'stop', '--time', '10', container], timeout=30)
        require(stopped.returncode == 0)
        observed = _candidate_items(context.check(), project, container)
    require(observed['State']['Status'] in STOPPED)
    result = renewal.run_owned_mutation([*docker.prefix, *custody['remove_command']], timeout=30)
    if result.returncode != 0:
        raise renewal.UncertainComposeMutation('Website candidate removal requires operator reconciliation')
    _candidate_items(context.check(), project, None)
    return {'candidate_id': container, 'stop_completed': stopping, 'remove_returncode': 0,
            'completed_cli_job': True, 'candidate_absent': True}


def _compensate(plan, status, context, command, candidate, attempt, held):
    custody = _removal_intent(candidate, context.project, command)
    authorized = _record_action(plan, status, 'compensation-authorized', custody, attempt, held)
    returned = _remove_candidate(context, custody)
    status = _record_action(plan, authorized, 'compensation-returned', returned, attempt, held)
    return status, {'intent': custody, 'result': returned}


def _abort_receipt(plan, status, outcome, observed, attempt, held):
    anchor = status['anchor_sha256']
    if 'prepared_abort_sha256' in status:
        receipt = store.read_prepared_abort(plan, expected_anchor_sha256=anchor, held=held)
        require(receipt['candidate_outcome'] == outcome)
        hashes = receipt['observations_sha256']
    else:
        hashes = {name: contract.digest(value) for name, value in observed.items()}
        receipt = {'schema': journal.ABORT_SCHEMA, 'plan_sha256': plan['plan_sha256'],
                   'started_record_sha256': status['started_stage_sha256'],
                   'owner_binding_sha256': plan['owner']['binding_sha256'],
                   'selected_sha256': plan['owner']['selected_sha256'], 'state': plan['states']['combined'],
                   'candidate_outcome': outcome, 'observations_sha256': hashes}
    if 'prepared_abort_sha256' in status:
        retained = store.hold_abort_observations(attempt, hashes, held)
        for name in {'owner_lease', 'native_custody', 'runtime_after', 'normalized_model', 'retained_product',
                     'mounted_template', 'edge_configuration', 'candidate_absence', 'selected_credentials',
                     'candidate_compensation'} & observed.keys():
            require(retained[name] == observed[name])
    else:
        require(stage._evidence(store.abort_observations_path(attempt, hashes), observed, held) == hashes)
    return store.reconciled_abort(plan, expected_anchor_sha256=anchor, receipt=receipt)


def run(config, choice, values, record, plan, status, phase, *, assets, gh, cosign, registry_config,
        authority_file, held):
    """Requalify combined and record a never-dispatched or exactly compensated stage."""
    require(phase == 'reconcile-stage' and status['classification'] == 'reconciliation-required'
            and status['pending_phase'] == stage.PHASE and status['model_state'] == 'combined'
            and not status['completed_phases'])
    actions = status['stage_actions']
    if len(actions) not in {0, 2, 4}:
        raise renewal.UncertainComposeMutation('Website command authorized without a completed CLI boundary')
    project, attempt = config['project'], Path(plan['attempt_directory'])
    held.enter_context(renewal.hold_storage_namespace(attempt))
    held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
    require(not renewal.namespace_entry_exists(Path(plan['route_directory'])))
    references = {'stage-before.json': (stage.PHASE, 'started'),
                  **{ACTION_FILES[name]: (stage.PHASE, name) for name in actions}}
    evidence = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], references=references, held=held)
    before = evidence['stage-before.json']
    require(before['owner_lease'] == {'guard_sha256': status['guard_sha256'], 'owner': plan['owner'],
                                     'dispatch_schema': stage.DISPATCH_SCHEMA})
    original = edge._retained_data(before['runtime_before'])
    require(contract.digest(original) == record['data_sha256'] == plan['owner']['data_sha256'])
    docker, commands, models = selection._compose_models(config, values)
    combined = models[choice]
    rebuilt, proposal = website.inspect_composition(config, choice, values, record, assets,
        gh=gh, cosign=cosign, registry_config=registry_config, owner_root=Path(plan['owner']['root']),
        held=held, plan_owner=plan['owner'], plan_attempt_directory=attempt, held_plan_only=True,
        guarded_attempt=True, retained_edge_inputs=(docker, combined, original), include_http=True)
    require(rebuilt == plan)
    command, staged, hashes = stage._stage_model(docker, commands[choice], combined, proposal, attempt, held)
    if actions:
        dispatch = evidence[ACTION_FILES['dispatch-authorized']]['stage_command']
        returned = evidence[ACTION_FILES['dispatch-returned']]['stage_result']
        require(dispatch == {'arguments_sha256': contract.digest(stage._command(command)), 'timeout_seconds': 120}
                and returned.get('completed_cli_job') is True and type(returned.get('returncode')) is int)
    baseline = docker.containers()
    candidates = stage._candidate_rows(baseline, project)
    require(len(candidates) == int(len(actions) == 2))
    candidate = candidates[0] if candidates else None
    retained = [row for row in baseline if row is not candidate]
    owned = edge._owned(retained, project)
    require(renewal.context_snapshot(owned) == before['runtime_before'] and renewal.data_mounts(owned) == original)
    roles = {renewal._service(row) for row in owned}
    changing = renewal.owned_roles(combined, roles)
    renewal.dependency_layers(combined, roles, changing)
    for row in owned:
        for mount in row['Mounts']:
            if mount.get('RW') and mount.get('Type') == 'bind':
                path = renewal.windows_source(mount['Source'])
                require(path is not None)
                held.enter_context(renewal.hold_storage_namespace(path))
    candidate_id = _compose_candidate(candidate, project, command) if candidate else None
    inspected = {'baseline': retained, 'docker': docker, 'context': SimpleNamespace(volumes=docker.volumes())}
    context = AbortContext(inspected, config, combined, staged, hashes, proposal['data']['staged'],
                           Path(record['selected']['secrets_dir']), candidate_id)
    selection._native_current(config, choice, values, docker, authority_file)
    qualified = context.check()
    candidate = _candidate_items(qualified, project, candidate_id)
    configuration = edge._probe(docker, edge._edge(edge._owned(qualified, project)), proposal, 'combined')
    compensation = {}
    if candidate is not None:
        current, compensation = _compensate(plan, status, context, command, candidate, attempt, held)
        status = {**current, 'guard_sha256': status['guard_sha256']}
    elif actions:
        custody = evidence[ACTION_FILES['compensation-authorized']]['candidate_compensation']
        result = evidence[ACTION_FILES['compensation-returned']]['compensation_result']
        container = custody['candidate_id']
        require(re.fullmatch(r'[0-9a-f]{64}', container) and custody['remove_command'] == ['container', 'rm', container]
                and result['candidate_id'] == container and result['candidate_absent'] is True
                and result['completed_cli_job'] is True and result['remove_returncode'] == 0)
        compensation = {'intent': custody, 'result': result}
    observed = context.check()
    _candidate_items(observed, project, None)
    ingress, handoffs = verify._observe(edge._edge(edge._owned(observed, project)), combined, proposal['http'], 'combined')
    final = context.check()
    _candidate_items(final, project, None)
    require(edge._probe(docker, edge._edge(edge._owned(final, project)), proposal, 'combined') == configuration
            and not renewal.namespace_entry_exists(Path(plan['route_directory'])))
    start = edge._start_observation(plan, status, context, final, configuration)
    outcome = 'created-then-compensated' if compensation else 'never-created'
    observation = {name: start[name] for name in ('owner_lease', 'native_custody', 'foreign_storage')}
    observation.update({'runtime_after': renewal.context_snapshot(edge._owned(final, project)),
        'normalized_model': {'sha256': contract.digest(combined)},
        'retained_product': {'composition_id': plan['composition_id'], 'data_sha256': contract.digest(original)},
        'mounted_template': plan['edge_template'], 'edge_configuration': configuration,
        'public_routes': ingress, 'application_handoffs': handoffs,
        'candidate_absence': {'slot': contract.SLOT, 'engine': plan['owner']['engine_id'], 'absent': True},
        'selected_credentials': {'selected_sha256': plan['owner']['selected_sha256']}})
    if compensation:
        observation['candidate_compensation'] = compensation
    result = _abort_receipt(plan, status, outcome, observation, attempt, held)
    return {**result, 'guard_sha256': status['guard_sha256'], 'receipt_contents_verified': True}
