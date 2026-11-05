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


def start_existing(config, choice, values, record, output_dir, stack, *, authority_file=None):
    """Return a provisional result; publication follows ALL selection exit checks."""
    selection.require(os.name == 'nt')
    guard = renewal.recovery_guard(config)
    selection.require(not renewal.recovery_pending(config))
    root = Path(output_dir)
    generation_root = Path(config['current_secrets']).parent
    selection.require(root.is_absolute() and root.parent == generation_root and root.name.startswith('windows-recovery-'))
    stack.enter_context(renewal.hold_storage_namespace(root))
    with _held_private_input(root, directory=True):pass
    selection.require(not list(root.iterdir()))
    observed = selection._inspect(config, choice, values, stack,
                                  expected_data=record['data_sha256'], require_ready=False)
    by_role, layers = plan(observed)
    docker = observed['docker'];project = config['project']
    names = ['intent.json', 'result.json', 'diagnostic.private.log']
    for index in range(len(layers)):
        names.extend([f'{index:03}.started.json', f'{index:03}.completed.json'])
    for name in names:
        with (root/name).open('xb'):pass
    intent = {'schema': SCHEMA, 'project': project, 'engine_id': config['engine_id'],
              'sequence': record['sequence'], 'selected': record['selected'],
              'data_sha256': record['data_sha256'], 'output_dir': str(root),
              'ids': {role: item['Id'] for role, item in by_role.items()}, 'layers': layers,
              'candidate_only': True}
    raw_intent = selection.packed(intent)
    # This exclusive marker is shared with renewal/selection admission. Never
    # clear it in a failure path or infer daemon quiescence from a killed CLI.
    with guard.open('xb'):pass
    renewal.write_empty_private_file(guard, raw_intent.decode())
    renewal.write_empty_private_file(root/'intent.json', raw_intent.decode())
    stack.enter_context(renewal.hold_private_input(guard))
    stack.enter_context(renewal.hold_private_input(root/'intent.json'))
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
