"""History-preserving bounded segments of the existing Windows owner journal.

Continuation carries the exact selected inputs; it never mints a credential or
admits expired material. Every later runtime operation retains its native gates.
"""
from copy import deepcopy
from contextlib import ExitStack
from pathlib import Path
import re
import uuid

import selfhost_windows_selection as selection

SCHEMA = 'marty.windows-selection-continuation/v1'
INTENT = 'continuation.intent.json'
DECISION = 'continuation.selection.json'
CHECKPOINT = 'checkpoint.json'
FILES = {INTENT, DECISION, CHECKPOINT}


def require(value):selection.require(value)


def checkpoint(raw):
    """Local seed shape; resolve() independently binds it to the held predecessor."""
    if CHECKPOINT not in raw:return None
    value = selection.decode(raw[CHECKPOINT])
    require(type(value) is dict and set(value) == {'schema', 'source_dir', 'intent_sha256', 'sequence_offset', 'generation_model',
                                                  'first_intent', 'first_selection'})
    from selfhost_windows_product_journal import SCHEMA as product_schema
    require(value['schema'] in {SCHEMA, product_schema} and Path(value['source_dir']).is_absolute()
            and re.fullmatch(r'[0-9a-f]{64}', value['intent_sha256'])
            and type(value['sequence_offset']) is int and value['sequence_offset'] >= 0)
    require(value['first_intent'] == selection.decode(raw['000001.intent.json'])
            and value['first_selection'] == selection.decode(raw['000001.selection.json']))
    return value


def seed(raw, expected, current_model, marker, stack):
    """Derive the only permitted first record from the held previous selection."""
    intents, records = selection._parse(raw, expected)
    require(len(intents) == len(records))
    first = deepcopy(intents[len(records)])
    import selfhost_windows_renewal as renewal
    from selfhost_windows_model import model_binding, immutable_binding
    config_raw = stack.enter_context(renewal.hold_private_input(Path(first['config_path'])))
    config = selection.decode(config_raw)
    require(selection.digest(config_raw) == first['config_file_sha256']
            and selection.config_digest(config) == first['config_sha256']
            and immutable_binding(selection.binding(config)) == immutable_binding(expected))
    first.update(sequence=1, parent=None, operation='continuation')
    selected = deepcopy(records[len(records)])
    selected.update(sequence=1, parent=None, intent_sha256=selection.digest(selection.packed(first)),
                    decision='continued-'+selected['choice'])
    owner = dict(expected, **current_model)
    carry = {'schema': SCHEMA, 'source_dir': marker['source_dir'],
             'intent_sha256': selection.digest(selection.packed(marker)),
             'sequence_offset': (checkpoint(raw)['sequence_offset'] if CHECKPOINT in raw else 0)+len(records)-1,
             'generation_model': model_binding(config),
             'first_intent': first, 'first_selection': selected}
    return {'owner.json': selection.packed({'schema': selection.SCHEMA, 'binding': owner}),
            CHECKPOINT: selection.packed(carry), '000001.intent.json': selection.packed(first),
            '000001.selection.json': selection.packed(selected)}


def validate_marker(raw, expected, root):
    value = selection.decode(raw[INTENT])
    require(type(value) is dict and set(value) == {'schema', 'project', 'engine_id',
                'source_dir', 'target_dir', 'source_sha256', 'candidate_only'})
    require(value['schema'] == SCHEMA and value['candidate_only'] is True
            and value['project'] == expected['project'] and value['engine_id'] == expected['engine_id']
            and value['source_dir'] == str(root))
    target = Path(value['target_dir'])
    require(target.is_absolute() and target.parent == Path(expected['root'])
            and re.fullmatch(re.escape('.'+expected['project']+'.generation-epoch-')+r'[0-9a-f]{32}', target.name))
    require(value['source_sha256'] == {name: selection.digest(body) for name, body in raw.items()
                                      if name not in {INTENT, DECISION}})
    return value


def decision(marker, initial):
    return {'schema': SCHEMA, 'intent_sha256': selection.digest(selection.packed(marker)),
            'target_entries_sha256': {name: selection.digest(body) for name, body in initial.items()},
            'candidate_only': True}


def resolve(config, root, raw, stack, *, pending_model=False, pending_continuation_sha256=None, ancestry=None, discover_pending=False, pending_product_sha256=None):
    """Called under the shared project lock, including activation's existing lock.

    All sealed predecessor records/directories remain held through the caller's
    exit. A dangling/incomplete link never falls back to the earlier segment.
    """
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_model import hold_history, model_binding, owner_binding
    import selfhost_windows_renewal as renewal
    import selfhost_windows_product_journal as product
    accepted = [];visited = set();expected_seed = None
    while True:
        require(root not in visited);visited.add(root)
        if expected_seed is None:require(CHECKPOINT not in raw)
        else:
            require(all(raw.get(name) == body for name, body in expected_seed.items()))
        expected = owner_binding(raw, config)
        if not raw or set(raw) == {'owner.json'}:
            require(expected_seed is None and pending_continuation_sha256 is None and pending_product_sha256 is None)
            return expected, root, raw, [model_binding(expected)]
        has_link = INTENT in raw
        has_product = product.INTENT in raw
        require(not (has_link and has_product) and (product.DECISION not in raw or has_product))
        require(DECISION not in raw or has_link)
        intents, records = selection._parse(raw, expected, allow_pending_model=pending_model and not (has_link or has_product))
        current_model, models = hold_history(raw, expected, records, stack,
                                             allow_pending=pending_model and not (has_link or has_product))
        accepted.extend(models)
        if not has_link and not has_product:
            require(pending_continuation_sha256 is None and pending_product_sha256 is None)
            require(model_binding(config) in accepted)
            return expected, root, raw, accepted
        require(len(intents) == len(records))
        if has_product:
            marker = product.validate_marker(raw, expected, current_model, root)
            if pending_product_sha256 == selection.digest(raw[product.INTENT]):
                require(not pending_model and pending_continuation_sha256 is None and not discover_pending)
                require(model_binding(config) in accepted)
                return expected, root, raw, accepted
            require(product.DECISION in raw)
            selected = selection.decode(raw[product.DECISION])
            require(type(selected) is dict and set(selected) == {'schema', 'intent_sha256',
                    'target_entries_sha256', 'phase_sha256', 'candidate_only'} and selected['candidate_only'] is True)
            initial = product.seed(raw, expected, current_model, marker, selected['phase_sha256'], stack)
            require(selected == product.decision(marker, initial, selected['phase_sha256']))
            if ancestry is not None:ancestry.append((root, dict(raw)))
            stack.enter_context(_held_private_input(root, directory=True))
            root = Path(marker['target_dir'])
            require(root not in visited)
            stack.enter_context(renewal.hold_storage_namespace(root))
            with _held_private_input(root, directory=True):pass
            raw = selection._read(root, stack)
            expected_seed = initial
            continue
        marker = validate_marker(raw, expected, root)
        initial = seed(raw, expected, current_model, marker, stack)
        if DECISION not in raw:
            require(pending_continuation_sha256 == selection.digest(raw[INTENT]) or discover_pending and pending_continuation_sha256 is None)
            require(model_binding(config) in accepted)
            return expected, root, raw, accepted
        require(selection.decode(raw[DECISION]) == decision(marker, initial))
        if pending_continuation_sha256 == selection.digest(raw[INTENT]):
            require(model_binding(config) in accepted)
            return expected, root, raw, accepted
        if ancestry is not None:ancestry.append((root, dict(raw)))
        # This predecessor is sealed. Its handles survive all target writes.
        stack.enter_context(_held_private_input(root, directory=True))
        root = Path(marker['target_dir'])
        require(root not in visited)
        stack.enter_context(renewal.hold_storage_namespace(root))
        with _held_private_input(root, directory=True):pass
        raw = selection._read(root, stack)
        expected_seed = initial


def hold_ancestry(items, receipts, protected, saved):
    """Extend sealed predecessor proofs across a later publication-lock exit."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    for root, raw in items:
        protected.enter_context(renewal.hold_storage_namespace(root))
        protected.enter_context(_held_private_input(root, directory=True))
        for name, body in raw.items():
            require(receipts.enter_context(renewal.hold_private_input(root/name)) == body)
        saved.append((root, raw))


def check_ancestry(saved):
    import selfhost_windows_renewal as renewal
    for root, raw in saved:
        require({p.name for p in root.iterdir()} == set(raw))
        require(all(renewal.read_private_bytes(root/name) == body for name, body in raw.items()))


def result(raw, journal, marker):
    offset = checkpoint(raw)['sequence_offset'] if CHECKPOINT in raw else 0
    sequence = sum(bool(selection.ENTRY.fullmatch(name)) and name.endswith('.selection.json') for name in raw)
    return {'schema': SCHEMA, 'project': marker['project'], 'result': 'journal-continued',
            'previous_journal': str(journal), 'journal': marker['target_dir'],
            'previous_sequence': sequence, 'sequence': 1, 'generation_sequence': offset+sequence,
            'candidate_only': True, 'native_admission': False, 'production_admission': False,
            'automatic_lifecycle': False}


def start(config, choice, values, record, raw, journal, stack):
    """Metadata-only continuation, under the selected lease and project lock."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    from selfhost_windows_model import history
    require(not renewal.recovery_pending(config) and INTENT not in raw and DECISION not in raw)
    expected = selection.decode(raw['owner.json'])['binding']
    _intents, records = selection._parse(raw, expected)
    require(len(_intents) == len(records) and record == records[len(records)])
    require(not selection._initial_current_record(record, records.get(1)))
    current_model = history(raw, expected, records)[1]
    observed = selection._inspect(config, choice, values, stack,
                                  expected_data=record['data_sha256'], require_ready=False)
    target = journal.parent/('.'+config['project']+'.generation-epoch-'+uuid.uuid4().hex)
    require(not renewal.namespace_entry_exists(target))
    marker = {'schema': SCHEMA, 'project': config['project'], 'engine_id': config['engine_id'],
              'source_dir': str(journal), 'target_dir': str(target),
              'source_sha256': {name: selection.digest(body) for name, body in raw.items()},
              'candidate_only': True}
    initial = seed(raw, expected, current_model, marker, stack)
    selection._append(journal, raw, INTENT, marker, stack)
    guard = renewal.continuation_guard(config)
    selection._new_private(guard, selection.packed(marker))
    require(stack.enter_context(renewal.hold_private_input(guard)) == selection.packed(marker))
    target.mkdir()
    stack.enter_context(renewal.hold_storage_namespace(target))
    with _held_private_input(target, directory=True):pass
    for name, body in initial.items():
        selection._new_private(target/name, body)
        require(stack.enter_context(renewal.hold_private_input(target/name)) == body)
    require({p.name for p in target.iterdir()} == set(initial))
    stack.enter_context(_held_private_input(target, directory=True))
    require(renewal.observations(observed['docker'].containers(), config['project'], set())
            == renewal.observations(observed['baseline'], config['project'], set()))
    return {'marker': marker, 'decision': decision(marker, initial), 'initial': initial,
            'result': result(raw, journal, marker)}


def finish(config, config_path, pending):
    """Keep both histories sealed through publication and every held exit."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_inputs import _held_private_input
    marker = pending['marker'];body = pending['decision'];initial = pending['initial']
    journal = Path(marker['source_dir']);target = Path(marker['target_dir'])
    sha = selection.digest(selection.packed(marker));guard = renewal.continuation_guard(config)
    earlier = []
    with ExitStack() as protected:
        for path in (journal.parent, journal, target):
            protected.enter_context(renewal.hold_storage_namespace(path))
        protected.enter_context(_held_private_input(target, directory=True))
        with ExitStack() as receipts:
            with selection._session(config_path, _pending_continuation_sha256=sha,
                _preserve_history=lambda items: hold_ancestry(items, receipts, protected, earlier)) as (cfg, _cfg_raw, expected, active, raw, stack):
                require(active == journal and validate_marker(raw, expected, active) == marker)
                require(not any(renewal.namespace_entry_exists(getter(cfg)) for getter in
                    (renewal.recovery_guard, renewal.recovery_preparation_guard,
                     renewal.renewal_staging_guard, renewal.model_repair_guard)))
                from selfhost_windows_model import history
                _intents, records = selection._parse(raw, expected)
                require(seed(raw, expected, history(raw, expected, records)[1], marker, stack) == initial)
                require(body == decision(marker, initial) and pending['result'] == result(raw, journal, marker))
                originals = dict(raw)
                for name, saved in originals.items():
                    require(receipts.enter_context(renewal.hold_private_input(journal/name)) == saved)
                require(receipts.enter_context(renewal.hold_private_input(guard)) == selection.packed(marker))
                for name, saved in initial.items():
                    require(receipts.enter_context(renewal.hold_private_input(target/name)) == saved)
                require({p.name for p in target.iterdir()} == set(initial))
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
    check_ancestry(earlier)
    guard.unlink()


def reconcile(config_path):
    """Explicit metadata-only reconciliation; no CLI, runtime or mint replay."""
    import selfhost_windows_renewal as renewal
    from selfhost_windows_model import history
    from selfhost_windows_inputs import _held_private_input
    with selection._session(config_path, _discover_continuation=True) as (cfg, _body, expected, journal, raw, stack):
        require(not any(renewal.namespace_entry_exists(getter(cfg)) for getter in
            (renewal.recovery_guard, renewal.recovery_preparation_guard,
             renewal.renewal_staging_guard, renewal.model_repair_guard)))
        marker = validate_marker(raw, expected, journal)
        _intents, records = selection._parse(raw, expected)
        initial = seed(raw, expected, history(raw, expected, records)[1], marker, stack)
        target=Path(marker['target_dir'])
        if not renewal.namespace_entry_exists(target):target.mkdir()
        stack.enter_context(renewal.hold_storage_namespace(target))
        with _held_private_input(target,directory=True):pass
        require({p.name for p in target.iterdir()} <= set(initial))
        for name, body in initial.items():
            path=target/name
            if not renewal.namespace_entry_exists(path):selection._new_private(path,body)
            elif renewal.read_private_bytes(path)==b'':renewal.write_empty_private_file(path,body.decode())
            require(stack.enter_context(renewal.hold_private_input(path))==body)
        stack.enter_context(_held_private_input(target,directory=True))
        pending = {'marker': marker, 'initial': initial, 'decision': decision(marker, initial),
                   'result': result(raw, journal, marker)}
    finish(cfg, config_path, pending)
    return pending['result']
