"""Start existing managed-candidate IDs while its selection lease remains held.

Library only: no task installation, initialization, creation, recreation, restart,
image pulls or public routing. Failed/uncertain attempts retain their guard and
receipts for operator reconciliation; they are never automatically replayed.
"""
import os
import re
import time
from contextlib import ExitStack
from pathlib import Path

import selfhost_windows_renewal as renewal
import selfhost_windows_selection as selection
from selfhost_windows_inputs import _held_private_input

SCHEMA = 'marty.windows-existing-recovery/v1'
COMPLETED = renewal.COMPLETED_SERVICES | {'openbao-tls-init'}
PREPARATION_SCHEMA = 'marty.windows-existing-stop/v1'
STOP_COMPLETION_SCHEMA = 'marty.windows-existing-stop-completion/v1'


def _prepared_stop(config, observed, record, root, stack, expected):
    """Validate an explicit completed-stop handoff; never infer CLI completion."""
    marker = renewal.recovery_preparation_guard(config)
    selection.require(type(expected) is str and re.fullmatch(r'[0-9a-f]{64}', expected))
    with renewal.hold_private_input(marker) as raw:
        selection.require(selection.digest(raw) == expected)
        value = selection.decode(raw)
        selection.require(set(value) == {'schema', 'project', 'engine_id', 'sequence', 'compose_sha256',
            'data_sha256', 'output_dir', 'targets', 'preserved', 'protected_sha256', 'completion_file'})
        selection.require(value['schema'] == PREPARATION_SCHEMA and value['project'] == config['project']
            and value['engine_id'] == config['engine_id'] and type(value['sequence']) is int
            and value['sequence'] == record['sequence'] and value['compose_sha256'] == config['compose_sha256']
            and value['data_sha256'] == record['data_sha256'] and value['output_dir'] == str(root))
        by_role = {renewal._service(x): x for x in observed['owned']}
        targets = {r: x['Id'] for r, x in by_role.items() if r not in COMPLETED}
        preserved = {r: x['Id'] for r, x in by_role.items() if r in COMPLETED}
        selection.require(value['targets'] == targets and value['preserved'] == preserved)
        selection.require(all(by_role[r]['State']['Status'] == 'exited' for r in targets))
        protected = renewal.observations(observed['baseline'], config['project'], set(targets))
        selection.require(value['protected_sha256'] == selection.digest(selection.packed(protected)))
        completion = Path(value['completion_file'])
        selection.require(completion.is_absolute() and completion.name == 'completed.json'
            and completion.parent.parent == root.parent and completion.parent.name.startswith('windows-stop-'))
        stop_raw = stack.enter_context(renewal.hold_private_input(completion))
        stopped = selection.decode(stop_raw)
        selection.require(stopped == {'schema': STOP_COMPLETION_SCHEMA, 'preparation_sha256': expected,
            'stop_cli_returned': True, 'stopped_ids': targets, 'preserved_ids': preserved})
        selection.require(stopped['stop_cli_returned'] is True)
    return ({'marker_sha256': expected, 'completion_file': str(completion),
             'completion_sha256': selection.digest(stop_raw),
             'preparation_copy': 'preparation.json', 'completion_copy': 'stop-completed.json'}, raw, stop_raw)


def plan(observed):
    owned = observed['owned'];services = observed['services'];model = observed['model']
    by_role = {renewal._service(x): x for x in owned}
    selection.require(len(by_role) == len(owned) and set(by_role) == services)
    for role, item in by_role.items():
        selection.require(re.fullmatch(r'[0-9a-f]{64}', item['Id']))
        state = item['State']['Status']
        if role in COMPLETED:
            selection.require(state == 'exited' and item['State']['ExitCode'] == 0)
        else:
            selection.require(state in {'created', 'exited', 'running', 'restarting'})
    running = services - COMPLETED
    selection.require({'openbao', 'openbao-unseal'} <= running)
    renewal.dependency_layers(model, services, running)
    foundation = ['openbao', 'openbao-unseal']
    bao_dependencies = model['services']['openbao'].get('depends_on', {})
    selection.require(set(bao_dependencies) <= COMPLETED)
    selection.require(all(spec.get('condition') == 'service_completed_successfully'
                          for spec in bao_dependencies.values()))
    unseal_dependencies = model['services']['openbao-unseal'].get('depends_on', {})
    selection.require(set(unseal_dependencies) <= {'openbao'} | COMPLETED)
    selection.require(all(spec.get('condition') == ('service_started' if role == 'openbao'
                          else 'service_completed_successfully') for role, spec in unseal_dependencies.items()))
    application = running - set(foundation)
    selection.require(application)
    layers = [foundation, *renewal.dependency_layers(model, services, application)]
    selection.require(set(x for layer in layers for x in layer) == running)
    return by_role, layers


def _unchanged(observed, current, started):
    project = renewal._project(observed['owned'][0])
    owned = [x for x in current if renewal._project(x) == project]
    selection.require({renewal._service(x): x['Id'] for x in owned}
                      == {renewal._service(x): x['Id'] for x in observed['owned']})
    selection.require(renewal.data_mounts(owned) == renewal.data_mounts(observed['owned']))
    selection.require(renewal.observations(current, project, started)
                      == renewal.observations(observed['baseline'], project, started))
    # Config/secret mount identity is also preserved for started IDs; the only
    # permitted changes are runtime state/start time/restart count for those IDs.
    for original in observed['owned']:
        item = next(x for x in owned if x['Id'] == original['Id'])
        selection.require(item['Config'] == original['Config']
                          and renewal.canonical_mounts(item['Mounts']) == renewal.canonical_mounts(original['Mounts']))


def _ready(observed, selected, deadline):
    while True:
        selection.require(time.monotonic() < deadline)
        items = renewal.statuses(observed['command'], cwd=observed['cwd'])
        selection.require(time.monotonic() < deadline)
        selection.require(len(items) == len(observed['services'])
                          and {x['Service'] for x in items} == observed['services'])
        checked = [x for x in items if x['Service'] in selected]
        if renewal.windows_healthy(checked, selected, observed['model']):
            return
        for item in checked:
            state = item['State'].lower()
            if item['Service'] in COMPLETED:
                selection.require(state == 'exited' and item.get('ExitCode') == 0)
            else:
                selection.require(state in {'running', 'restarting'})
        time.sleep(2)


def start_existing(config, choice, values, record, output_dir, stack, *, authority_file=None,
                   preparation_sha256=None):
    """Return a provisional result; publication follows ALL selection exit checks."""
    selection.require(os.name == 'nt')
    guard = renewal.recovery_guard(config)
    selection.require(not renewal.namespace_entry_exists(guard))
    has_preparation = renewal.namespace_entry_exists(renewal.recovery_preparation_guard(config))
    selection.require(has_preparation == (preparation_sha256 is not None))
    root = Path(output_dir)
    generation_root = Path(config['current_secrets']).parent
    selection.require(root.is_absolute() and root.parent == generation_root and root.name.startswith('windows-recovery-'))
    stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root, directory=True):pass
    selection.require(not list(root.iterdir()))
    observed = selection._inspect(config, choice, values, stack,
                                  expected_data=record['data_sha256'], require_ready=False)
    by_role, layers = plan(observed)
    preparation = None;preparation_raw = None;stop_raw = None
    if has_preparation:
        preparation, preparation_raw, stop_raw = _prepared_stop(config, observed, record, root, stack, preparation_sha256)
    docker = observed['docker'];project = config['project']
    names = ['intent.json', 'result.json', 'diagnostic.private.log']
    if preparation is not None:names.extend(['preparation.json', 'stop-completed.json'])
    for index in range(len(layers)):
        names.extend([f'{index:03}.started.json', f'{index:03}.completed.json'])
    for name in names:
        with (root/name).open('xb'):pass
    if preparation is not None:
        renewal.write_empty_private_file(root/'preparation.json', preparation_raw.decode())
        renewal.write_empty_private_file(root/'stop-completed.json', stop_raw.decode())
        stack.enter_context(renewal.hold_private_input(root/'preparation.json'))
        stack.enter_context(renewal.hold_private_input(root/'stop-completed.json'))
    intent = {'schema': SCHEMA, 'project': project, 'engine_id': config['engine_id'],
              'sequence': record['sequence'], 'selected': record['selected'],
              'data_sha256': record['data_sha256'], 'output_dir': str(root),
              'ids': {role: item['Id'] for role, item in by_role.items()}, 'layers': layers,
              'preparation': preparation,
              'candidate_only': True}
    raw_intent = selection.packed(intent)
    # This exclusive marker is shared with renewal/selection admission. Never
    # clear it in a failure path or infer daemon quiescence from a killed CLI.
    with guard.open('xb'):pass
    renewal.write_empty_private_file(guard, raw_intent.decode())
    renewal.write_empty_private_file(root/'intent.json', raw_intent.decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
    if preparation is not None:
        marker = renewal.recovery_preparation_guard(config)
        selection.require(selection.digest(renewal.read_private_bytes(marker)) == preparation_sha256)
        # Core intent and marker are durable before preparation loses authority.
        # A crash at any boundary leaves at least one shared admission marker.
        marker.unlink()
    started = set();ready = observed['services'] & COMPLETED;tail = b'';uncertain = None
    deadline = time.monotonic()+600
    try:
        for index, layer in enumerate(layers):
            selection.require(time.monotonic() < deadline)
            current = docker.containers();_unchanged(observed, current, started)
            current_by_role = {renewal._service(x): x for x in current if renewal._project(x) == project}
            to_start = [role for role in layer if current_by_role[role]['State']['Status'] in {'created', 'exited'}]
            ids = [by_role[role]['Id'] for role in to_start]
            receipt = {'roles': layer, 'started_roles': to_start, 'ids': ids}
            renewal.write_empty_private_file(root/f'{index:03}.started.json', selection.packed(receipt).decode())
            stack.enter_context(renewal.hold_private_input(root/f'{index:03}.started.json'))
            if ids:
                remaining = min(120, deadline-time.monotonic());selection.require(remaining > 0)
                p = renewal.run_owned_mutation([*docker.prefix, 'start', *ids], timeout=remaining)
                tail = (tail+p.stdout+p.stderr)[-60000:]
                selection.require(p.returncode == 0)
                started.update(to_start)
            ready |= set(layer)
            _ready(observed, ready, deadline)
            if index == 0:
                # Bao may have been stopped. Its retained TLS/Raft/unseal IDs
                # can start first; no application start precedes native admission.
                selection._native_current(config, choice, values, docker, authority_file)
                selection.require(time.monotonic() < deadline)
            _unchanged(observed, docker.containers(), started)
            renewal.write_empty_private_file(root/f'{index:03}.completed.json', selection.packed(receipt).decode())
            stack.enter_context(renewal.hold_private_input(root/f'{index:03}.completed.json'))
            selection.require(time.monotonic() < deadline)
        selection.require(selection._prove(config, choice, values, stack,
                          expected_data=record['data_sha256'], authority_file=authority_file) == record['data_sha256'])
        selection.require(time.monotonic() < deadline)
        _unchanged(observed, docker.containers(), started)
        selection.require(time.monotonic() < deadline)
    except renewal.UncertainComposeMutation as error:
        uncertain = error
        tail = (tail+error.stdout+error.stderr)[-60000:]
        raise
    finally:
        try:
            renewal.write_empty_private_file(root/'diagnostic.private.log', renewal.bounded_diagnostic(tail))
        except BaseException:
            if uncertain is not None:raise uncertain
            raise
    selection.require(time.monotonic() < deadline)
    selection.require(sorted(p.name for p in root.iterdir()) == sorted(names))
    hashes = {name: selection.digest(stack.enter_context(renewal.hold_private_input(root/name)))
              for name in names if name != 'result.json'}
    # No other writer may add entries to a private attempt during its lease.
    stack.callback(lambda: selection.require(sorted(p.name for p in root.iterdir()) == sorted(names)))
    result = {'schema': SCHEMA, 'project': project, 'result': 'recovered-existing',
              'sequence': record['sequence'], 'services': len(by_role), 'started_roles': sorted(started),
              'container_ids_retained': True, 'candidate_only': True,
              'production_admission': False, 'automatic_lifecycle': False}
    return {'root': str(root), 'guard_sha256': selection.digest(raw_intent),
            'receipt_sha256': hashes, 'result': result}


def finish_existing(config, pending):
    """Publish only after original generation/config/namespace handles closed."""
    root = Path(pending['root']);guard = renewal.recovery_guard(config)
    parent = Path(config['current_secrets']).parent
    with renewal.hold_private_input(parent/f'.{config["project"]}.renewal.lock', exclusive=True):
        with ExitStack() as held:
            selection.require(not renewal.namespace_entry_exists(renewal.recovery_preparation_guard(config)))
            held.enter_context(renewal.hold_storage_namespace(parent))
            held.enter_context(renewal.hold_storage_namespace(root))
            with _held_private_input(root, directory=True):pass
            selection.require(sorted(p.name for p in root.iterdir())
                              == sorted([*pending['receipt_sha256'], 'result.json']))
            for name, expected in pending['receipt_sha256'].items():
                selection.require(selection.digest(held.enter_context(renewal.hold_private_input(root/name))) == expected)
            raw_guard = renewal.read_private_bytes(guard)
            selection.require(selection.digest(raw_guard) == pending['guard_sha256'])
            selection.require(raw_guard == renewal.read_private_bytes(root/'intent.json'))
            selection.require(renewal.read_private_bytes(root/'result.json') == b'')
        # Keep the project lock across validation exit checks and publication.
        selection.require(selection.digest(renewal.read_private_bytes(guard)) == pending['guard_sha256'])
        renewal.write_empty_private_file(root/'result.json', selection.packed(pending['result']).decode())
    # The marker remains authoritative through the final lock's exit proof.
    # Other mutators refuse it during this gap; removing it is the last action.
    selection.require(selection.digest(renewal.read_private_bytes(guard)) == pending['guard_sha256'])
    guard.unlink()
