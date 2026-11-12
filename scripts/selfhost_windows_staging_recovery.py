"""Evidence validation for a failed Windows current-generation proof.

This module grants no retry or guard-removal authority. A successful evidence
check does not establish current credential validity or admit activation.
"""
import hashlib
import re
from contextlib import contextmanager
from pathlib import Path

from selfhost_windows_selection import _stage_names, packed, require


def failed_current_receipts(raws):
    """Bind the exact pre-producer phase; reject absent or ambiguous evidence.

    Authority login may have minted a scoped session. No credential producer,
    export, materialization, or activation is admitted by these receipts.
    """
    names = set(_stage_names()) - {'intent.json'}
    require(type(raws) is dict and set(raws) == names)
    completed = {'authority.started.json', 'authority.completed.json',
                 'current.started.json'}
    for name, raw in raws.items():
        require(type(raw) is bytes)
        if name not in completed:
            require(raw == b'')
            continue
        phase, event, _ = name.split('.')
        expected = {'phase': phase, 'event': event, 'metadata': {}}
        # Canonical bytes reject duplicate keys and alternate receipt shapes.
        require(raw == packed(expected))
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(raws.items())}


def inspect_failed_current(config_path):
    with _failed_current_inputs(config_path) as lease:
        result = lease['proof']
    return result


@contextmanager
def _failed_current_inputs(config_path):
    """Read-only held proof of the stopped phase, never credential admission.

    The result is published to the caller only after all input/namespace exit
    checks pass. Expired leaves are permitted as evidence, never as live TLS.
    """
    import selfhost_windows_selection as selection
    from selfhost_windows_model import effective_config, history, immutable_binding, model_binding
    from selfhost_windows_continuation import CHECKPOINT, checkpoint
    renewal = selection.renewal
    with selection._session(config_path) as (base, _, expected, _, raw, stack):
        require(not any(renewal.namespace_entry_exists(getter(base)) for getter in (
            renewal.recovery_guard, renewal.recovery_preparation_guard,
            renewal.model_repair_guard, renewal.continuation_guard)))
        intents, records = selection._parse(raw, expected)
        require(len(intents) == len(records) and len(records) > 0)
        intent, record = intents[len(records)], records[len(records)]
        require(1 <= record['sequence'] < selection.MAX_SELECTIONS)
        cfg_raw = stack.enter_context(renewal.hold_private_input(Path(intent['config_path'])))
        config = selection.decode(cfg_raw)
        require(selection.digest(cfg_raw) == intent['config_file_sha256']
                and selection.config_digest(config) == intent['config_sha256']
                and immutable_binding(selection.binding(config)) == immutable_binding(expected))
        _, current_model, accepted = history(raw, expected, records)
        if CHECKPOINT in raw:
            accepted.append(checkpoint(raw)['generation_model'])
        require(model_binding(config) in accepted)
        config = effective_config(config, current_model)
        initial = record['sequence'] == 1 and record['decision'] == 'adopted-current'
        values, snapshots = selection._inputs(config, stack, initial_current=initial)
        require(snapshots == intent['inputs'])
        transition = stack.enter_context(renewal.hold_private_input(Path(config['intent'])))
        previous = stack.enter_context(renewal.hold_private_input(Path(config['result'])))
        require(selection.digest(transition) == record['transition_intent_sha256'])
        require(selection.digest(previous) == record['result_sha256']
                if record['result_sha256'] is not None else not previous)
        guard = stack.enter_context(renewal.hold_private_input(renewal.renewal_staging_guard(config)))
        stage = selection.decode(guard)
        root = Path(stage['root'])
        require(root.parent == Path(config['current_secrets']).parent
                and re.fullmatch(r'windows-renewal-[0-9a-f]{32}', root.name))
        stack.enter_context(renewal.hold_storage_namespace(root))
        stack.enter_context(selection._held_private_input(root, directory=True))
        stack.enter_context(selection._held_private_input(root/'activation', directory=True))
        names = set(_stage_names()) | {'result.json', 'publication.pending.json', 'renewed.env', 'activation'}
        def membership(path, expected_names):
            require(set(p.name for p in path.iterdir()) == expected_names)
        membership(root, names)
        stack.callback(membership, root, names)
        receipts = {name: stack.enter_context(renewal.hold_private_input(root/name))
                    for name in _stage_names()}
        require(receipts.pop('intent.json') == guard == packed(stage))
        receipt_hashes = failed_current_receipts(receipts)
        observed = selection._inspect(config, record['choice'], values, stack,
                                      expected_data=record['data_sha256'], require_ready=False)
        layers = renewal.dependency_layers(observed['model'], observed['services'],
                                           renewal.owned_roles(observed['model'], observed['services']))
        next_raw = stack.enter_context(renewal.hold_private_input(root/'activation/config.private.json'))
        next_config = selection._stage_configuration(config, record['choice'], record, root, layers)
        require(next_raw == packed(next_config))
        cycle = root.name.removeprefix('windows-renewal-')
        require(stage == {'schema': selection.STAGE_SCHEMA, 'project': config['project'],
            'engine_id': config['engine_id'], 'sequence': record['sequence']+1,
            'selected_sha256': selection.digest(packed(record['selected'])),
            'data_sha256': record['data_sha256'], 'root': str(root),
            'config_path': str(root/'activation/config.private.json'),
            'config_sha256': selection.digest(next_raw),
            'authority_file': '/control/recovery-session-'+cycle+'/token',
            'logical_project': stage['logical_project'],
            'services_image': observed['model']['services']['signing-keys']['image'], 'candidate_only': True})
        require(re.fullmatch(r'marty-selfhost-[a-z0-9][a-z0-9-]{0,59}', stage['logical_project']))
        paths = [Path(next_config[name]) for name in ('intent', 'result', 'new_log', 'rollback_log')]
        paths += [Path(p) for step in next_config['step_receipts'] for p in step.values()]
        activation_names = {'config.private.json', *(p.name for p in paths)}
        membership(root/'activation', activation_names)
        stack.callback(membership, root/'activation', activation_names)
        for path in [*paths, root/'result.json', root/'publication.pending.json']:
            require(stack.enter_context(renewal.hold_private_input(path)) == b'')
        candidate = Path(next_config['renewed_secrets'])
        stack.enter_context(renewal.hold_storage_namespace(candidate))
        stack.enter_context(selection._held_private_input(candidate, directory=True))
        membership(candidate, set())
        stack.callback(membership, candidate, set())
        env = stack.enter_context(renewal.hold_private_input(root/'renewed.env'))
        old_env = stack.enter_context(renewal.hold_private_input(Path(next_config['current_env'])))
        require(renewal.env_body(env, candidate) == renewal.env_body(old_env, Path(next_config['current_secrets'])))
        items = observed['context'].check(before_intent=True)
        require(not any((item.get('Config', {}).get('Labels') or {}).get('marty.windows.renewal') == cycle
                        for item in items))
        result = {'schema': 'marty.windows-failed-current-proof/v1', 'project': config['project'],
                  'sequence': record['sequence'], 'guard_sha256': selection.digest(guard),
                  'receipt_sha256': receipt_hashes, 'data_sha256': record['data_sha256'],
                  'guard_retained': True, 'credential_admission': False}
        yield {'proof': result, 'config': config, 'record': record, 'values': values,
               'observed': observed, 'stack': stack, 'failed_root': root}


def stage_recovery_generation(config_path, output_dir, logical_project):
    """Produce one guarded candidate; never publish, select, activate or retry.

    Both the failed staging guard and a new recovery guard remain on success
    and failure. The returned provisional proof requires a separate checked
    publication and activation owner; it is not an activation capability.
    """
    import selfhost_windows_selection as selection
    import selfhost_windows_renewal_native as native
    renewal = selection.renewal
    with _failed_current_inputs(config_path) as lease:
        cfg, record, observed, stack = (lease[name] for name in ('config', 'record', 'observed', 'stack'))
        require(re.fullmatch(r'marty-selfhost-[a-z0-9][a-z0-9-]{0,59}', logical_project))
        root = Path(output_dir)
        require(root.parent == Path(cfg['current_secrets']).parent
                and re.fullmatch(r'windows-renewal-[0-9a-f]{32}', root.name)
                and root != lease['failed_root'])
        stack.enter_context(renewal.hold_storage_namespace(root))
        stack.enter_context(selection._held_private_input(root, directory=True, mutable_directory=True))
        require(not list(root.iterdir()))
        layers = renewal.dependency_layers(observed['model'], observed['services'],
                                           renewal.owned_roles(observed['model'], observed['services']))
        config = selection._stage_configuration(cfg, record['choice'], record, root, layers)
        cycle = root.name.removeprefix('windows-renewal-')
        guard = renewal.recovery_guard(cfg)
        intent = {'schema': 'marty.windows-expired-renewal-staging/v1',
                  'failed_proof': lease['proof'], 'root': str(root),
                  'logical_project': logical_project, 'config_sha256': selection.digest(packed(config)),
                  'credential_admission': False, 'rollback_to_expired': False}
        # Durable exclusion precedes directory allocation, reauthentication,
        # credential producers, or any operation with an uncertain outcome.
        selection._new_private(guard, packed(intent))
        stack.enter_context(renewal.hold_private_input(guard))
        selection._new_private(root/'intent.json', packed(intent))
        stack.enter_context(renewal.hold_private_input(root/'intent.json'))
        for phase in ('authority', 'prepare', 'tls', 'keycloak', 'export', 'materialize', 'candidate'):
            for event in ('started', 'completed'):
                selection._new_private(root/f'{phase}.{event}.json', b'')
        for name in ('prepare.helper.json', 'tls.created.json', 'tls.helper.json', 'keycloak.helper.json'):
            selection._new_private(root/name, b'')
        selection._new_private(root/'config.private.json', packed(config))
        stack.enter_context(renewal.hold_private_input(root/'config.private.json'))
        expected_names = {'intent.json', 'config.private.json',
            *(f'{phase}.{event}.json' for phase in ('authority','prepare','tls','keycloak','export','materialize','candidate')
              for event in ('started','completed')),
            'prepare.helper.json', 'tls.created.json', 'tls.helper.json', 'keycloak.helper.json'}
        def output_membership():
            require({path.name for path in root.iterdir()} == expected_names)
        output_membership()
        stack.callback(output_membership)
        def checkpoint(phase, event, metadata):
            path = root/f'{phase}.{event}.json'
            renewal.write_empty_private_file(path, packed({'phase':phase,'event':event,'metadata':metadata}).decode())
            stack.enter_context(renewal.hold_private_input(path))
        checkpoint('authority', 'started', {})
        authority = native.reauthenticate(config['native'], cfg['project'], observed['docker'].prefix,
                                          '/control/recovery-session-'+cycle)
        require(authority == config['native']['token_file'])
        checkpoint('authority', 'completed', {})
        observed['context'].check(before_intent=True)
        candidate = Path(config['renewed_secrets'])
        require(not renewal.namespace_entry_exists(candidate))
        candidate.mkdir()
        stack.enter_context(renewal.hold_storage_namespace(candidate))
        stack.enter_context(selection._held_private_input(candidate, directory=True, mutable_directory=True))
        renewed = native.produce_recovery_generation(config, lease['values'][record['choice']],
            logical_project, cycle, observed['model']['services']['signing-keys']['image'], checkpoint)
        require(set(renewed) == set(lease['values'][record['choice']]))
        checkpoint('materialize', 'started', {})
        for name, value in renewed.items():
            selection._new_private(candidate/name, value)
        held = stack.enter_context(renewal.hold_private_generation(candidate, sorted(renewed)))
        require(held == renewed)
        checkpoint('materialize', 'completed', {})
        checkpoint('candidate', 'started', {})
        native.preflight_recovery(config['native'], cfg['project'], lease['values'][record['choice']],
                                  held, observed['docker'].prefix)
        observed['context'].check(before_intent=True)
        checkpoint('candidate', 'completed', {})
        provisional = {'schema': intent['schema'], 'result': 'provisional-candidate',
                       'root': str(root), 'guard_sha256': selection.digest(packed(intent)),
                       'generation_sha256': selection.fingerprint(held),
                       'credential_admission': False, 'guards_retained': True}
    return provisional
