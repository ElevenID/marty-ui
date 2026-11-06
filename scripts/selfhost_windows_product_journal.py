"""Typed product successors of the existing Windows credential journal.

This module validates retained transition evidence; it never executes Compose,
verifies a release by declaration, mints credentials or rewrites a predecessor.
The deployment boundary must authenticate the composition and collect real
custody/schema/runtime receipts before publishing a product selection.
"""
from copy import deepcopy
from contextlib import ExitStack
from pathlib import Path
import re

import selfhost_windows_selection as selection

SCHEMA = 'marty.windows-product-successor/v1'
INTENT = 'product.intent.json'
DECISION = 'product.selection.json'
FILES = {INTENT, DECISION}
ARTIFACTS = {'web-composition.json', 'web-composition.json.sigstore.json',
             'web-composition.json.provenance.jsonl', 'web-composition.zip',
             'web-composition.zip.sigstore.json', 'web-composition.zip.provenance.jsonl'}
PHASES = {'intent.json', 'result.json', 'before.json', 'after.json', 'schema-before.json',
          'schema-after.json', 'provider-before.json', 'provider-after.json', 'admission.json', 'new.log',
          'native-before.started.json', 'native-before.completed.json',
          'native-after.started.json', 'native-after.completed.json'}


def require(value):
    selection.require(value)


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def successor_configuration(config, model, root):
    """A new product binding with empty credential-operation outputs, not a rotation."""
    from selfhost_windows_model import MODEL_KEYS
    require(set(model) == MODEL_KEYS and Path(root).is_absolute())
    result = deepcopy(config)
    result.pop('_historical_compose_sha256', None)
    result.update(model)
    for key in ('intent', 'result', 'new_log', 'rollback_log'):
        result[key] = str(Path(root)/'activation'/('credential-'+key+'.json'))
    result['step_receipts'] = [{key: str(Path(root)/'activation'/f'credential-{index:03}-{key}.json')
                               for key in step} for index, step in enumerate(config['step_receipts'])]
    return result


def anchor(raw, expected):
    from selfhost_windows_continuation import checkpoint
    intents, records = selection._parse(raw, expected)
    require(len(intents) == len(records))
    sequence = len(records)
    carry = checkpoint(raw)
    return intents[sequence], records[sequence], sequence+(carry['sequence_offset'] if carry else 0)


def validate_marker(raw, expected, current_model, journal):
    """A dangling product intent seals its predecessor; it never admits fallback."""
    from selfhost_windows_continuation import INTENT as continuation_intent
    value = selection.decode(raw[INTENT])
    require(raw[INTENT] == selection.packed(value))
    require(continuation_intent not in raw)
    require(type(value) is dict and set(value) == {
        'schema', 'project', 'engine_id', 'source_dir', 'target_dir', 'source_sha256',
        'selection_sequence', 'generation_sequence', 'selection_sha256', 'selected_sha256',
        'old', 'new', 'attempt_dir', 'config_sha256', 'composition_sha256',
        'image_ids', 'configuration_hashes', 'data_before_sha256', 'data_after_sha256',
        'observations_before_sha256', 'schema_before_sha256', 'provider_before_sha256',
        'native', 'native_mirror', 'minimum_ttl', 'candidate_only'})
    require(value['schema'] == SCHEMA and value['candidate_only'] is True
            and value['project'] == expected['project'] and value['engine_id'] == expected['engine_id']
            and value['source_dir'] == str(journal) and value['old'] == current_model)
    require(value['source_sha256'] == {name: selection.digest(body) for name, body in raw.items()
                                      if name not in FILES})
    _intent, record, generation = anchor(raw, expected)
    require(type(value['selection_sequence']) is int and value['selection_sequence'] == record['sequence']
            and type(value['generation_sequence']) is int and value['generation_sequence'] == generation
            and value['selection_sha256'] == selection.digest(raw[f'{record["sequence"]:06}.selection.json'])
            and value['selected_sha256'] == selection.digest(selection.packed(record['selected']))
            and value['data_before_sha256'] == record['data_sha256']
            and value['native'] == expected['native'] and value['native_mirror'] == record['selected']['native_mirror']
            and type(value['minimum_ttl']) is int and value['minimum_ttl'] >= 3600)
    require(all(sha(value[key]) for key in ('config_sha256', 'data_before_sha256', 'data_after_sha256',
                'observations_before_sha256', 'schema_before_sha256', 'provider_before_sha256')))
    require(type(value['composition_sha256']) is dict and set(value['composition_sha256']) == ARTIFACTS
            and all(sha(item) for item in value['composition_sha256'].values()))
    target = Path(value['target_dir']);root = Path(value['attempt_dir'])
    require(target.parent == root.parent == Path(expected['root'])
            and re.fullmatch(re.escape('.'+expected['project']+'.generation-product-')+r'[0-9a-f]{32}', target.name)
            and re.fullmatch(r'windows-product-[0-9a-f]{32}', root.name))
    require(type(value['new']) is dict and set(value['new']) == {'compose_file', 'compose_sha256'}
            and sha(value['new']['compose_sha256'])
            and Path(value['new']['compose_file']).parent == Path(current_model['compose_file']).parent
            and value['new']['compose_file'] != current_model['compose_file'])
    return value


def hold_transition(marker, hashes, stack):
    """Retain the earlier owner-verified subjects and real execution evidence.

    Replay checks immutable custody, not new signature admission. A new deploy
    must always use verified_package and authenticate every original subject.
    """
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_renewal import hold_private_input, hold_storage_namespace
    import selfhost_windows_product as product
    root = Path(marker['attempt_dir'])
    stack.enter_context(hold_storage_namespace(root))
    stack.enter_context(_held_private_input(root, directory=True))
    models = []
    for model in (marker['old'], marker['new']):
        body = stack.enter_context(hold_private_input(Path(model['compose_file']), max_bytes=2*1024*1024))
        require(selection.digest(body) == model['compose_sha256'])
        models.append(selection.decode(body))
    inputs = root/'inputs'
    stack.enter_context(_held_private_input(inputs, directory=True))
    require({item.name for item in inputs.iterdir()} == ARTIFACTS)
    artifact_bodies = {}
    for name in sorted(ARTIFACTS):
        maximum = min(product.composition.MAX_ARCHIVE_BYTES, 256*1024*1024) if name == 'web-composition.zip' else 4*1024*1024
        body = stack.enter_context(hold_private_input(inputs/name, max_bytes=maximum))
        require(selection.digest(body) == marker['composition_sha256'][name])
        if name == 'web-composition.json':artifact_bodies[name] = body
    manifest = product.composition.validate_record(selection.decode(artifact_bodies['web-composition.json']))
    change = product.checked_model_change(*models, manifest)
    roles = set(models[0]['services'])-product.renewal.INITIALIZERS
    layers = product.renewal.dependency_layers(models[1], roles, set(change['mutable_roles']))
    names = PHASES | {f'{index:03}.{event}.json' for index in range(len(layers)) for event in ('started', 'completed')}
    require(type(hashes) is dict and set(hashes) == names and all(sha(value) for value in hashes.values()))
    require({item.name for item in root.iterdir()} == names | {'inputs', 'activation', 'config.private.json'})
    bodies = {name: stack.enter_context(hold_private_input(root/name, max_bytes=2*1024*1024)) for name in names}
    require(all(selection.digest(body) == hashes[name] for name, body in bodies.items()))
    require(bodies['intent.json'] == selection.packed(marker))
    require(selection.digest(bodies['before.json']) == marker['observations_before_sha256'])
    require(bodies['admission.json'] == selection.packed({'schema': SCHEMA,
        'composition_id': manifest['composition_id'], 'subjects_verified': True, 'images_verified': True}))
    before = selection.decode(bodies['before.json']);after = selection.decode(bodies['after.json'])
    edge = product.checked_runtime_change(before, after, *models, manifest, marker['image_ids'],
                                           expected_project=marker['project'])
    require(edge['before_sha256'] == marker['data_before_sha256']
            and edge['after_sha256'] == marker['data_after_sha256'])
    # Replaying the exact context also binds actual old/new Compose hashes.
    context = product.ProductContext(None, marker['project'], before, {}, 'retained-proof',
        old_model=models[0], new_model=models[1], admitted=manifest, image_ids=marker['image_ids'],
        configuration_hashes=marker['configuration_hashes'])
    context._candidate(after, before_intent=False)
    for category in ('schema', 'provider'):
        require(selection.digest(bodies[category+'-before.json']) == marker[category+'_before_sha256'])
        require(bodies[category+'-before.json'] == bodies[category+'-after.json'])
        witness = selection.decode(bodies[category+'-before.json'])
        if category == 'schema':
            import selfhost_windows_product_probe as probe
            require(type(witness) is dict and set(witness) == {'schema', 'probe', 'profile', 'consistency', 'database_roles', 'databases'}
                    and witness['schema'] == probe.SCHEMA and witness['probe'] == probe.PROBE
                    and witness['profile'] == probe.PROFILE_ID and witness['consistency'] == probe.CONSISTENCY
                    and type(witness['database_roles']) is dict and set(witness['database_roles']) == {'application', 'keycloak', 'applicants'}
                    and type(witness['databases']) is dict and witness['databases']
                    and all(isinstance(name, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,62}', name)
                            and type(row) is dict and set(row) == {'catalog_sha256', 'migration_sha256'}
                            and all(sha(item) for item in row.values()) for name, row in witness['databases'].items()))
            profile = probe.LedgerProfile(**witness['database_roles'])
            require(set(witness['databases']) == set(profile.tables)
                    and witness['databases'][profile.applicants]['migration_sha256'] == selection.digest(b'{}')
                    and all(witness['databases'][name]['migration_sha256'] != selection.digest(b'{}')
                            for name in (profile.application, profile.keycloak)))
        else:
            require(type(witness) is dict and set(witness) == {'schema', 'cluster_id', 'ca_sha256',
                    'plugin_sha256', 'unseal_sha256', 'ready_sha256', 'bao_sha256', 'bao_version'}
                    and witness['schema'] == 'marty.windows-provider-custody/v1'
                    and isinstance(witness['cluster_id'], str)
                    and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', witness['cluster_id'])
                    and isinstance(witness['bao_version'], str) and witness['bao_version'].startswith('OpenBao v2.5.5 ')
                    and all(sha(witness[key]) for key in ('ca_sha256', 'plugin_sha256', 'unseal_sha256', 'ready_sha256', 'bao_sha256')))
    for index, layer in enumerate(layers):
        for event in ('started', 'completed'):
            require(bodies[f'{index:03}.{event}.json'] == selection.packed({'index': index, 'roles': layer, 'event': event}))
    for side in ('before', 'after'):
        for event in ('started', 'completed'):
            require(bodies[f'native-{side}.{event}.json'] == selection.packed({'schema': SCHEMA,
                'operation': 'native-current', 'side': side, 'event': event, 'native': marker['native'],
                'native_mirror': marker['native_mirror'], 'minimum_ttl': marker['minimum_ttl'],
                'selected_sha256': marker['selected_sha256']}))
    require(bodies['result.json'] == selection.packed({'schema': SCHEMA, 'project': marker['project'],
        'result': 'product-transitioned', 'generation_sequence': marker['generation_sequence'],
        'selected_sha256': marker['selected_sha256'], 'data_sha256': marker['data_after_sha256'],
        'composition_id': manifest['composition_id'], 'credential_rotation': False}))
    return manifest


def seed(raw, expected, current_model, marker, hashes, stack):
    """Derive a product successor with the exact previous credential identity."""
    from selfhost_windows_continuation import CHECKPOINT
    from selfhost_windows_model import effective_config, immutable_binding, model_binding
    from selfhost_windows_renewal import hold_private_input
    require(validate_marker(raw, expected, current_model, Path(marker['source_dir'])) == marker)
    hold_transition(marker, hashes, stack)
    first, prior, generation = anchor(raw, expected)
    old_config_raw = stack.enter_context(hold_private_input(Path(first['config_path'])))
    require(selection.digest(old_config_raw) == first['config_file_sha256'])
    old_config = selection.decode(old_config_raw)
    require(selection.config_digest(old_config) == first['config_sha256']
            and immutable_binding(selection.binding(old_config)) == immutable_binding(expected)
            and marker['minimum_ttl'] == old_config['native']['minimum_ttl'])
    root = Path(marker['attempt_dir'])
    config_path = root/'config.private.json'
    config_raw = stack.enter_context(hold_private_input(config_path))
    config = selection.decode(config_raw)
    require(selection.digest(config_raw) == marker['config_sha256'] and config == successor_configuration(
        effective_config(old_config, current_model), marker['new'], root))
    require(immutable_binding(selection.binding(config)) == immutable_binding(expected))
    activation = root/'activation'
    from selfhost_windows_inputs import _held_private_input
    stack.enter_context(_held_private_input(activation, directory=True))
    paths = [Path(config[key]) for key in ('intent', 'result', 'new_log', 'rollback_log')]
    paths += [Path(path) for step in config['step_receipts'] for path in step.values()]
    require(len(set(paths)) == len(paths) and {item.name for item in activation.iterdir()} == {path.name for path in paths})
    require(all(stack.enter_context(hold_private_input(path)) == b'' for path in paths))
    first = deepcopy(first)
    first.update(sequence=1, parent=None, operation='product-successor', config_path=str(config_path),
        config_file_sha256=selection.digest(config_raw), config_sha256=selection.config_digest(config),
        result_before_sha256=selection.digest(b''))
    selected = deepcopy(prior)
    selected.update(sequence=1, parent=None, intent_sha256=selection.digest(selection.packed(first)),
        decision='product-selected-'+prior['choice'], data_sha256=marker['data_after_sha256'],
        result_sha256=selection.digest(b''), transition_intent_sha256=selection.digest(b''))
    require(selected['selected'] == prior['selected'])
    carry = {'schema': SCHEMA, 'source_dir': marker['source_dir'],
        'intent_sha256': selection.digest(selection.packed(marker)),
        'sequence_offset': generation-1, 'generation_model': model_binding(config),
        'first_intent': first, 'first_selection': selected}
    return {'owner.json': selection.packed({'schema': selection.SCHEMA, 'binding': dict(expected, **marker['new'])}),
            CHECKPOINT: selection.packed(carry), '000001.intent.json': selection.packed(first),
            '000001.selection.json': selection.packed(selected)}


def decision(marker, initial, phases):
    return {'schema': SCHEMA, 'intent_sha256': selection.digest(selection.packed(marker)),
            'target_entries_sha256': {name: selection.digest(body) for name, body in initial.items()},
            'phase_sha256': phases, 'candidate_only': True}


def finish(config_path, marker, phases, *, authority_file):
    """Publish a fully executed forward transition, never replay runtime writes.

    The runtime owner must already have sealed its intent and global guard.
    Missing or empty derived target entries may be completed after interruption;
    nonempty differences, incomplete execution and live drift remain refused.
    Fresh native custody is required even when the decision was already written.
    """
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_model import history
    from selfhost_windows_continuation import hold_ancestry, check_ancestry
    require(isinstance(authority_file, str) and authority_file.startswith('/control/')
            and '..' not in Path(authority_file).parts)
    marker = selection.decode(selection.packed(marker))
    phases = selection.decode(selection.packed(phases))
    journal = Path(marker['source_dir']);target = Path(marker['target_dir'])
    sha = selection.digest(selection.packed(marker));earlier = []
    with ExitStack() as protected:
        # Acquire the project lock before opening any derived output namespace.
        with ExitStack() as receipts:
            with selection._session(config_path, _pending_product_sha256=sha,
                _preserve_history=lambda items: hold_ancestry(items, receipts, protected, earlier)) as (cfg, _body, expected, active, raw, stack):
                require(active == journal)
                _intents, records = selection._parse(raw, expected)
                current_model = history(raw, expected, records)[1]
                require(validate_marker(raw, expected, current_model, active) == marker)
                require(protected.enter_context(renewal.hold_private_input(Path(config_path))) == _body)
                initial = seed(raw, expected, current_model, marker, phases, protected)
                body = decision(marker, initial, phases)
                guard = renewal.product_transition_guard(cfg)
                originals = dict(raw)
                for name, saved in originals.items():
                    require(receipts.enter_context(renewal.hold_private_input(journal/name)) == saved)
                require(receipts.enter_context(renewal.hold_private_input(guard)) == selection.packed(marker))
                for path in (journal.parent, journal):
                    protected.enter_context(renewal.hold_storage_namespace(path))
                if not renewal.namespace_entry_exists(target):target.mkdir()
                protected.enter_context(renewal.hold_storage_namespace(target))
                with _held_private_input(target, directory=True):pass
                require({p.name for p in target.iterdir()} <= set(initial))
                for name, saved in initial.items():
                    path = target/name
                    if not renewal.namespace_entry_exists(path):selection._new_private(path, saved)
                    elif renewal.read_private_bytes(path) == b'':
                        renewal.write_empty_private_file(path, saved.decode())
                    require(receipts.enter_context(renewal.hold_private_input(path)) == saved)
                protected.enter_context(_held_private_input(target, directory=True))
                require({p.name for p in target.iterdir()} == set(initial))
                new_config = selection.decode(receipts.enter_context(renewal.hold_private_input(
                    Path(marker['attempt_dir'])/'config.private.json')))
                values, snapshots = selection._inputs(new_config, protected)
                require(snapshots == selection.decode(initial['000001.intent.json'])['inputs'])
                choice = records[len(records)]['choice']
                require(selection._prove(new_config, choice, values, stack,
                    expected_data=marker['data_after_sha256'], authority_file=authority_file) == marker['data_after_sha256'])
                # Delayed publication must not reuse an earlier compatibility
                # observation after a database/provider change.
                import selfhost_windows_product_probe as probe
                observed = selection._inspect(new_config, choice, values, stack,
                    expected_data=marker['data_after_sha256'])
                profile = probe.LedgerProfile(**selection.decode(renewal.read_private_bytes(
                    Path(marker['attempt_dir'])/'schema-after.json'))['database_roles'])
                owned = [item for item in observed['baseline'] if renewal._project(item) == cfg['project']]
                for category, witness in (
                    ('schema', probe.schema_snapshot(observed['docker'], owned, cfg['project'], profile=profile)),
                    ('provider', probe.provider_snapshot(observed['docker'], owned, cfg['project'], cfg['native']['ca_file']))):
                    require(selection.packed(witness) == renewal.read_private_bytes(
                        Path(marker['attempt_dir'])/(category+'-after.json')))
                observed['context'].check(before_intent=True)
                if DECISION in raw:require(raw[DECISION] == selection.packed(body))
                else:selection._append(journal, raw, DECISION, body, stack)
                require(protected.enter_context(renewal.hold_private_input(journal/DECISION)) == selection.packed(body))
                protected.enter_context(_held_private_input(journal, directory=True))
                names = set(raw)
            require({p.name for p in journal.iterdir()} == names)
            require({p.name for p in target.iterdir()} == set(initial))
        require({p.name for p in journal.iterdir()} == names)
        require({p.name for p in target.iterdir()} == set(initial))
    require({p.name for p in journal.iterdir()} == names)
    require({p.name for p in target.iterdir()} == set(initial))
    require(all(renewal.read_private_bytes(journal/name) == saved for name, saved in originals.items()))
    require(all(renewal.read_private_bytes(target/name) == saved for name, saved in initial.items()))
    require(renewal.read_private_bytes(journal/DECISION) == selection.packed(body))
    require(renewal.read_private_bytes(guard) == selection.packed(marker))
    # File handles release in reverse order. Revalidate the entire retained
    # transition after the outer exits, including directories where a new
    # unknown child could have appeared while existing files stayed held.
    with ExitStack() as final:
        require(seed(raw, expected, current_model, marker, phases, final) == initial)
        require(final.enter_context(renewal.hold_private_input(Path(config_path))) == _body)
        _values, final_snapshots = selection._inputs(new_config, final)
        require(final_snapshots == snapshots)
    # No deferred namespace/stack exits may remain after the last comparison.
    # These are bounded individual reads followed by comparison AFTER closing
    # each read handle, and exact directory inventories on both sides.
    root = Path(marker['attempt_dir'])
    activation_paths = [Path(new_config[key]) for key in ('intent', 'result', 'new_log', 'rollback_log')]
    activation_paths += [Path(path) for step in new_config['step_receipts'] for path in step.values()]
    inventories = {root: set(phases)|{'inputs', 'activation', 'config.private.json'},
                   root/'inputs': ARTIFACTS, root/'activation': {path.name for path in activation_paths},
                   journal: names, target: set(initial)}
    retained = [(root/name, digest, 2*1024*1024) for name, digest in phases.items()]
    retained += [(root/'inputs'/name, digest, 256*1024*1024 if name == 'web-composition.zip' else 4*1024*1024)
                 for name, digest in marker['composition_sha256'].items()]
    retained += [(Path(model['compose_file']), model['compose_sha256'], 2*1024*1024)
                 for model in (marker['old'], marker['new'])]
    first = anchor(raw, expected)[0]
    retained += [(Path(first['config_path']), first['config_file_sha256'], 65536),
                 (Path(config_path), selection.digest(_body), 65536),
                 (root/'config.private.json', marker['config_sha256'], 65536),
                 (guard, sha, 65536)]
    retained += [(path, selection.digest(b''), 65536) for path in activation_paths]
    retained += [(journal/name, selection.digest(saved), 65536) for name, saved in raw.items()]
    retained += [(target/name, selection.digest(saved), 65536) for name, saved in initial.items()]
    for choice in ('old', 'new'):
        snapshot = snapshots[choice];secret_root = Path(snapshot['secrets_dir'])
        inventories[secret_root] = set(values[choice])
        retained.append((Path(snapshot['env_file']), snapshot['env_sha256'], 65536))
        retained += [(secret_root/name, selection.digest(saved), 65536) for name, saved in values[choice].items()]
    require(all({p.name for p in path.iterdir()} == entries for path, entries in inventories.items()))
    for path, digest, maximum in retained:
        with renewal.hold_private_input(path, max_bytes=maximum) as saved:pass
        require(selection.digest(saved) == digest)
    require(all({p.name for p in path.iterdir()} == entries for path, entries in inventories.items()))
    check_ancestry(earlier)
    guard.unlink()
    return {'schema': SCHEMA, 'project': marker['project'], 'result': 'product-selected',
            'journal': str(target), 'generation_sequence': marker['generation_sequence'],
            'credential_rotation': False, 'candidate_only': True}
