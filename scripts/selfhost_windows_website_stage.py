"""Run the first guarded website phase on the existing Windows selection."""
from pathlib import Path

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website_plan as plan_contract
import selfhost_windows_website_store as store


renewal = selection.renewal
require = selection.require
PHASE = 'stage-candidate'
DISPATCH_SCHEMA = 'marty.windows-website-stage-dispatch/v1'


def _candidate_rows(items, project):
    return [item for item in items if renewal._project(item) == project
            and renewal._service(item) == plan_contract.SLOT]


class StageContext(renewal.ForeignContext):
    """Use the existing foreign proof while admitting one exact new role."""

    def __init__(self, inspected, config, model, hashes, expected_data, secret_root):
        baseline = inspected['baseline']
        project = config['project']
        super().__init__(inspected['docker'], project, set(), baseline,
                         inspected['context'].volumes, config['native']['helper_image'])
        require(not _candidate_rows(baseline, project))
        self.config, self.model, self.hashes = config, model, hashes
        self.expected_data, self.secret_root = expected_data, secret_root
        edge, = [item for item in self.owned if renewal._service(item) == 'edge']
        self.networks = set(edge['NetworkSettings']['Networks'])
        require(self.networks)

    def _candidate(self, items, *, before_intent):
        candidate = _candidate_rows(items, self.project)
        if not candidate:
            return super()._candidate(items, before_intent=before_intent)
        require(not before_intent and len(candidate) == 1)
        retained = [item for item in items if item is not candidate[0]]
        snapshot = super()._candidate(retained, before_intent=False)
        owned = [item for item in items if renewal._project(item) == self.project]
        require(renewal.data_mounts(owned) == self.expected_data)
        renewal.checked_live_configuration(owned, self.hashes, self.config['tls_init_receipt'])
        renewal.checked_secret_mounts(owned, self.project, self.secret_root,
            self.services | {plan_contract.SLOT}, self.model, path_equal=renewal.windows_mount_path_equal)
        item = candidate[0]
        require(item['Config']['Image'] == self.model['services'][plan_contract.SLOT]['image']
                and not item['HostConfig'].get('Privileged') and not item['HostConfig'].get('PortBindings')
                and set(item['NetworkSettings']['Networks']) == self.networks)
        return {**snapshot, **renewal.context_snapshot(candidate)}


def _material(path, value, held):
    body = selection.packed(value)
    if not renewal.namespace_entry_exists(path):
        selection._new_private(path, body)
    require(held.enter_context(renewal.hold_private_input(path)) == body)


def _stage_model(docker, base_command, base_model, proposal, attempt, held):
    source = proposal['models']['staged']['services'][plan_contract.SLOT]
    overlay = attempt / 'stage.compose.json'
    _material(overlay, {'services': {plan_contract.SLOT: source}}, held)
    command = [*base_command, '-f', str(overlay)]
    model = docker.json(command[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
    services = dict(model['services'])
    website = services.pop(plan_contract.SLOT)
    require({**model, 'services': services} == base_model)
    require(website['image'] == source['image']
            and set(website) <= {'image', 'restart', 'mem_limit', 'environment', 'secrets', 'healthcheck', 'networks',
                                 'command', 'entrypoint'}
            and website.get('command') is None and website.get('entrypoint') is None
            and website.get('restart') == source['restart']
            and str(website.get('mem_limit')) in {source['mem_limit'], str(256 * 1024 * 1024)}
            and website.get('networks') == services['edge']['networks']
            and website['healthcheck']['test'] == source['healthcheck']['test'])
    combined_env = services['ui'].get('environment', {})
    require(website.get('environment', {}) == {key: combined_env[key] for key in source['environment']})
    hashes = docker.hashes(command)
    require(plan_contract.sha(hashes.get(plan_contract.SLOT)))
    return command, model, hashes


def _command(command):
    return [*command, 'up', '--no-deps', '--no-build', '--pull', 'never',
            '--no-recreate', '--wait', '--wait-timeout', '90', plan_contract.SLOT]


def _evidence(path, observations, held):
    _material(path, observations, held)
    return {name: plan_contract.digest(value) for name, value in observations.items()}


def run(config, choice, values, record, plan, proposal, status, *, authority_file, held):
    """Stage website-a while the selected owner's typed guard and lock are held."""
    require(status['classification'] == 'phase-boundary' and status['record_count'] == 1
            and status['model_state'] == 'combined' and status['permitted_record_phases'] == [PHASE])
    models = proposal['models']
    plan_contract.check_models(plan, before=models['combined'], staged=models['staged'], split=models['split'])
    require(plan_contract.digest(proposal['data']['staged']) == plan['states']['staged']['data_sha256'])
    attempt = Path(plan['attempt_directory'])
    held.enter_context(renewal.hold_storage_namespace(attempt))
    held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
    require(not renewal.namespace_entry_exists(Path(plan['route_directory'])))
    inspected = selection._inspect(config, choice, values, held, expected_data=record['data_sha256'])
    command, model, hashes = _stage_model(inspected['docker'], inspected['command'], inspected['model'],
                                          proposal, attempt, held)
    renewal.checked_live_configuration(inspected['owned'], hashes, config['tls_init_receipt'])
    secret_root = Path(record['selected']['secrets_dir'])
    context = StageContext(inspected, config, model, hashes, proposal['data']['staged'], secret_root)
    selection._native_current(config, choice, values, inspected['docker'], authority_file)
    before = context.check(before_intent=True)
    started_evidence = _evidence(attempt / 'stage-before.json', {
        'owner_lease': {'guard_sha256': status['guard_sha256'], 'owner': plan['owner'], 'dispatch_schema': DISPATCH_SCHEMA},
        'native_custody': {'selected_sha256': plan['owner']['selected_sha256'],
                           'native_sha256': plan['owner']['native_sha256']},
        'foreign_storage': {'engine_id': plan['owner']['engine_id'],
                            'inventory_sha256': plan_contract.digest(renewal.context_snapshot(before)),
                            'changes_sha256': context.proof_sha256, 'changes': context.proof_count},
        'runtime_before': renewal.context_snapshot([item for item in before if renewal._project(item) == config['project']]),
    }, held)
    started = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=PHASE,
                           event='started', evidence_sha256=started_evidence)
    context.check(before_intent=True)
    arguments = _command(command)
    authorized = store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase=PHASE,
        event='dispatch-authorized', evidence_sha256=_evidence(attempt / 'stage-dispatch.json', {
            'stage_command': {'arguments_sha256': plan_contract.digest(arguments), 'timeout_seconds': 120},
        }, held))
    result = renewal.run_owned_mutation(arguments, timeout=120)
    returned = store.append(plan, expected_anchor_sha256=authorized['anchor_sha256'], phase=PHASE,
        event='dispatch-returned', evidence_sha256=_evidence(attempt / 'stage-result.json', {
            'stage_result': {'returncode': result.returncode, 'completed_cli_job': True},
        }, held))
    if result.returncode != 0:
        raise renewal.UncertainComposeMutation('Website stage requires operator reconciliation')
    after = context.check()
    candidate, = _candidate_rows(after, config['project'])
    require(candidate['State']['Status'] == 'running' and candidate['RestartCount'] == 0
            and candidate['State']['Health']['Status'] == 'healthy')
    completed_evidence = _evidence(attempt / 'stage-after.json', {
        'runtime_after': renewal.context_snapshot([item for item in after if renewal._project(item) == config['project']]),
        'image_metadata': {'image_id': candidate['Image'], 'release': plan['website']['release_sha256']},
        'candidate_health': {'container_id': candidate['Id'], 'status': 'healthy', 'restart_count': 0},
    }, held)
    completed = store.append(plan, expected_anchor_sha256=returned['anchor_sha256'], phase=PHASE,
                             event='completed', evidence_sha256=completed_evidence)
    return {**completed, 'guard_sha256': status['guard_sha256']}
