"""Apply the guarded edge-only phases of a first Windows website split."""
from copy import deepcopy
from pathlib import Path
import re
import subprocess

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website as website
import selfhost_windows_website_plan as contract
import selfhost_windows_website_stage as stage
import selfhost_windows_website_store as store


renewal = selection.renewal
require = selection.require
FORWARD = 'route-website'
BACKOUT = 'restore-combined'
ACTIVE_ROUTE = contract.ROUTE_TARGET + '/active.conf'
DUMP_SECTION = re.compile(rb'^# configuration file ([^:\n]+):\n', re.MULTILINE)
DEFAULT_CONFIG = b'/etc/nginx/conf.d/default.conf'


def _owned(items, project):
    return [item for item in items if renewal._project(item) == project]


def _edge(items):
    row, = [item for item in items if renewal._service(item) == 'edge']
    return row


def _retained_data(snapshot):
    return {row['service']: {'image': row['image'], 'mounts': sorted(
        (mount for mount in row['mounts'] if not mount['Destination'].startswith('/run/secrets/')),
        key=lambda mount: mount['Destination'])} for row in snapshot.values()}


def _split_model(docker, command, model, staged_hashes, proposal, attempt, held):
    edge_mounts = proposal['models']['split']['services']['edge']['volumes']
    route_mount, = [row for row in edge_mounts if row['target'] == contract.ROUTE_TARGET]
    overlay = attempt / 'route.compose.json'
    stage._material(overlay, {'services': {'edge': {'volumes': [
        {**route_mount, 'bind': {'create_host_path': False}}]}}}, held)
    command = [*command, '-f', str(overlay)]
    rendered = docker.json(command[len(docker.prefix):] + ['--profile', '*', 'config', '--format', 'json'])
    without_route = deepcopy(rendered)
    mounts = without_route['services']['edge']['volumes']
    actual, = [row for row in mounts if row['target'] == contract.ROUTE_TARGET]
    require(actual.get('type') == 'bind' and actual.get('read_only') is True
            and renewal.windows_mount_path_equal(actual['source'], route_mount['source'])
            and not actual.get('bind', {}).get('create_host_path')
            and set(actual) <= {'type', 'source', 'target', 'read_only', 'bind'}
            and set(actual.get('bind', {})) <= {'create_host_path'})
    mounts.remove(actual)
    require(without_route == model)
    hashes = docker.hashes(command)
    require(set(hashes) == set(staged_hashes) and contract.sha(hashes.get('edge')) and
            {role for role, value in hashes.items() if value != staged_hashes[role]} == {'edge'})
    return command, rendered, hashes


def _held_routes(path, routes, held, *, create):
    if create and not renewal.namespace_entry_exists(path):
        path.mkdir()
    held.enter_context(renewal.hold_storage_namespace(path))
    active = path / 'active.conf'
    if create and not renewal.namespace_entry_exists(active):
        with _held_private_input(path, directory=True, mutable_directory=True):
            selection._new_private(active, routes)
    held.enter_context(_held_private_input(path, directory=True))
    require(held.enter_context(renewal.hold_private_input(active)) == routes)

    def inventory():
        require({entry.name for entry in path.iterdir()} == {'active.conf'})

    inventory()
    held.callback(inventory)
    return inventory


def _hold_inactive_routes(path, routes, held):
    """Preserve exact route artifacts even if preparation stopped before routing."""
    if not renewal.namespace_entry_exists(path):
        def check_absent():
            require(not renewal.namespace_entry_exists(path))
        held.callback(check_absent)
        return 'absent', check_absent
    if renewal.namespace_entry_exists(path / 'active.conf'):
        return 'materialized', _held_routes(path, routes, held, create=False)
    held.enter_context(renewal.hold_storage_namespace(path))
    held.enter_context(_held_private_input(path, directory=True))

    def check_empty():
        require(not any(path.iterdir()))

    check_empty()
    held.callback(check_empty)
    return 'empty', check_empty


def _probe(docker, edge, proposal, state):
    container = edge['Id']
    require(re.fullmatch(r'[0-9a-f]{64}', container) is not None)

    def capture(*args):
        try:
            result = subprocess.run([*docker.prefix, 'exec', container, *args], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise ValueError('Managed edge inspection failed') from None
        require(result.returncode == 0 and 0 < len(result.stdout) <= 256*1024)
        return result.stdout

    template = capture('cat', contract.TEMPLATE_TARGET)
    require(selection.digest(template) == proposal['edge_template']['sha256'])
    dump = capture('nginx', '-T')
    matches = list(DUMP_SECTION.finditer(dump))
    sections = {match[1]: dump[match.end():matches[index+1].start() if index+1 < len(matches) else len(dump)]
                for index, match in enumerate(matches)}
    require(len(sections) == len(matches) and DEFAULT_CONFIG in sections)
    default = sections[DEFAULT_CONFIG]
    require(sum(line.strip() == website.composition.EDGE_INCLUDE.encode() for line in default.splitlines()) == 1)
    route_sections = {name: body for name, body in sections.items() if name.startswith(contract.ROUTE_TARGET.encode() + b'/')}
    routes = proposal['routes'][state]
    require(route_sections == ({ACTIVE_ROUTE.encode(): routes + b'\n'} if routes else {}))
    return {'container_id': container, 'template_sha256': selection.digest(template),
            'default_sha256': selection.digest(default), 'routes_sha256': selection.digest(routes)}


class EdgeContext(renewal.ForeignContext):
    """Preserve the full storage witness and admit only the planned edge change."""

    def __init__(self, docker, config, baseline, volumes, proposal, layouts, current, target, secret_root,
                 *, require_candidate_ready):
        super().__init__(docker, config['project'], {'edge'}, baseline, volumes, config['native']['helper_image'])
        self.config, self.data, self.layouts = config, proposal['data'], layouts
        self.current, self.target, self.secret_root = current, target, secret_root
        self.ready_roles = self.services if require_candidate_ready else self.services - {contract.SLOT}
        self.previous = _edge(self.owned)
        self.networks = set(self.previous['NetworkSettings']['Networks'])
        require(self.networks)

    def _candidate(self, items, *, before_intent):
        owned = _owned(items, self.project)
        snapshot = renewal.context_snapshot(owned)
        if before_intent or self.current == self.target:
            snapshot = super()._candidate(items, before_intent=True)
        else:
            require(len(owned) == len(self.services) and {renewal._service(row) for row in owned} == self.services)
            require({key: row for key, row in snapshot.items() if row['service'] != 'edge'} == self.protected)
        state = self.current if before_intent else self.target
        _command, model, hashes = self.layouts[state]
        require(renewal.data_mounts(owned) == self.data[state])
        renewal.checked_live_configuration(owned, hashes, self.config['tls_init_receipt'])
        readiness = [{'Service': renewal._service(row), 'State': row['State']['Status'],
                      'ExitCode': row['State']['ExitCode'], 'Health': row['State'].get('Health', {}).get('Status', '')}
                     for row in owned if renewal._service(row) in self.ready_roles]
        require(renewal.windows_healthy(readiness, self.ready_roles, model))
        require(renewal.checked_secret_mounts(owned, self.project, self.secret_root,
            self.services, model, path_equal=renewal.windows_mount_path_equal) > 0)
        edge = _edge(owned)
        require(edge['Config']['Image'] == model['services']['edge']['image']
                and edge['State']['Status'] == 'running' and edge['State']['Health']['Status'] == 'healthy'
                and set(edge['NetworkSettings']['Networks']) == self.networks)
        require(edge['HostConfig'].get('PortBindings') == self.previous['HostConfig'].get('PortBindings')
                and edge['HostConfig'].get('Privileged') is self.previous['HostConfig'].get('Privileged')
                and not edge['HostConfig'].get('Privileged'))
        if not before_intent and self.current != self.target:
            require(edge['Id'] != self.previous['Id'] and edge['RestartCount'] == 0)
        return snapshot


def _prepare(config, choice, values, record, plan, status, *, prior_phase, current, target,
             create_routes, candidate_ready, assets, gh, cosign, registry_config, authority_file,
             held, include_http=False):
    """Rebuild signed layouts and qualify the exact runtime of an anchored phase."""
    attempt = Path(plan['attempt_directory'])
    held.enter_context(renewal.hold_storage_namespace(attempt))
    held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
    prior = 'stage-after.json' if prior_phase == 'stage-candidate' else prior_phase + '-after.json'
    evidence = store.read_evidence(plan, expected_anchor_sha256=status['anchor_sha256'], held=held, references={
        'stage-before.json': ('stage-candidate', 'started'), prior: (prior_phase, 'completed')})
    original_data = _retained_data(evidence['stage-before.json']['runtime_before'])
    require(contract.digest(original_data) == record['data_sha256'] == plan['owner']['data_sha256'])
    docker, commands, models = selection._compose_models(config, values)
    http_options = {'include_http': True} if include_http else {}
    rebuilt, proposal = website.inspect_composition(config, choice, values, record, assets,
        gh=gh, cosign=cosign, registry_config=registry_config, owner_root=Path(plan['owner']['root']),
        held=held, plan_owner=plan['owner'], plan_attempt_directory=attempt, held_plan_only=True,
        guarded_attempt=True, retained_edge_inputs=(docker, models[choice], original_data), **http_options)
    require(rebuilt == plan)
    staged = stage._stage_model(docker, commands[choice], models[choice], proposal, attempt, held)
    layouts = {'staged': staged}
    check_routes = None
    if 'split' in {current, target}:
        check_routes = _held_routes(Path(plan['route_directory']), proposal['routes']['split'], held,
                                    create=create_routes)
        layouts['split'] = _split_model(docker, *staged, proposal, attempt, held)
    baseline = docker.containers()
    owned = _owned(baseline, config['project'])
    require(renewal.context_snapshot(owned) == evidence[prior]['runtime_after'])
    retained_roles = {renewal._service(row) for row in owned} - {contract.SLOT}
    changing = renewal.owned_roles(models[choice], retained_roles)
    renewal.dependency_layers(models[choice], retained_roles, changing)
    for row in owned:
        for mount in row['Mounts']:
            if mount.get('RW') and mount.get('Type') == 'bind':
                path = renewal.windows_source(mount['Source'])
                require(path is not None)
                held.enter_context(renewal.hold_storage_namespace(path))
    context = EdgeContext(docker, config, baseline, docker.volumes(), proposal, layouts, current, target,
                          Path(record['selected']['secrets_dir']), require_candidate_ready=candidate_ready)
    selection._native_current(config, choice, values, docker, authority_file)
    return context, proposal, evidence[prior], check_routes


def _start_observation(plan, status, context, items, edge_configuration):
    return {
        'owner_lease': {'guard_sha256': status['guard_sha256'], 'owner': plan['owner']},
        'native_custody': {'selected_sha256': plan['owner']['selected_sha256'],
                           'native_sha256': plan['owner']['native_sha256']},
        'foreign_storage': {'engine_id': plan['owner']['engine_id'],
                            'inventory_sha256': contract.digest(renewal.context_snapshot(items)),
                            'changes_sha256': context.proof_sha256, 'changes': context.proof_count},
        'runtime_before': {'containers': renewal.context_snapshot(_owned(items, context.project)),
                           'edge_configuration': edge_configuration},
    }


def run(config, choice, values, record, plan, status, phase, *, assets, gh, cosign, registry_config,
        authority_file, held):
    """Switch or restore edge routing under the independently pinned owner."""
    require(phase in {FORWARD, BACKOUT} and phase in status['permitted_record_phases']
            and (status['classification'] == 'phase-boundary'
                 or phase == BACKOUT and status['classification'] == 'forward-evidence-complete'))
    current = status['model_state']
    target = 'split' if phase == FORWARD else 'staged'
    require(current == 'staged' if phase == FORWARD else current in {'split', 'staged'})
    context, proposal, prior, check_routes = _prepare(config, choice, values, record, plan, status,
        prior_phase=FORWARD if current == 'split' else 'stage-candidate', current=current, target=target,
        create_routes=phase == FORWARD, candidate_ready=phase == FORWARD, assets=assets, gh=gh, cosign=cosign,
        registry_config=registry_config, authority_file=authority_file, held=held)
    docker = context.docker
    attempt = Path(plan['attempt_directory'])
    initial = context.check(before_intent=True)
    original_edge = _probe(docker, _edge(_owned(initial, config['project'])), proposal, current)
    if current == 'split':
        require(original_edge == prior['edge_configuration'])
    started_evidence = stage._evidence(attempt / (phase + '-before.json'),
                                    _start_observation(plan, status, context, initial, original_edge), held)
    started = store.append(plan, expected_anchor_sha256=status['anchor_sha256'], phase=phase,
                           event='started', evidence_sha256=started_evidence)
    ready = context.check(before_intent=True)
    require(_probe(docker, _edge(_owned(ready, config['project'])), proposal, current) == original_edge)
    if check_routes is not None:
        check_routes()
    if current != target:
        command, _model, _hashes = context.layouts[target]
        outcome = renewal.run_owned_mutation([*command, 'up', '--no-deps', '--no-build', '--pull', 'never',
            '--force-recreate', '--wait', '--wait-timeout', '90', 'edge'], timeout=120)
        if outcome.returncode != 0:
            raise renewal.UncertainComposeMutation('Website edge change requires operator reconciliation')
    after = context.check()
    verified = _probe(docker, _edge(_owned(after, config['project'])), proposal, target)
    require(verified['default_sha256'] == original_edge['default_sha256'])
    final = context.check()
    require(renewal.context_snapshot(_owned(final, config['project'])) ==
            renewal.context_snapshot(_owned(after, config['project'])))
    completed_evidence = stage._evidence(attempt / (phase + '-after.json'), {
        'runtime_after': renewal.context_snapshot(_owned(final, config['project'])),
        'mounted_template': plan['edge_template'], 'edge_configuration': verified,
    }, held)
    completed = store.append(plan, expected_anchor_sha256=started['anchor_sha256'], phase=phase,
                             event='completed', evidence_sha256=completed_evidence)
    return {**completed, 'guard_sha256': status['guard_sha256']}
