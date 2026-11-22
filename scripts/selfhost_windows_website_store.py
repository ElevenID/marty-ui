"""Durable phase and tail records for the existing managed Windows owner."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import re

from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website_journal as journal
import selfhost_windows_website_plan as plan_contract


TAIL_SCHEMA = 'marty.windows-website-journal-tail/v1'
PLAN = 'plan.json'
ABORT = 'stage-abort.json'
require = journal.require
renewal = selection.renewal


def namespace_paths(plan):
    plan_contract.validate_envelope(plan)
    owner_root = plan_contract.windows_path(plan['owner']['root'])
    attempt_path = plan_contract.path_under_owner(owner_root, plan['attempt_directory'])
    require(attempt_path.parent == owner_root and re.fullmatch(r'windows-website-[0-9a-f]{32}', attempt_path.name)
            and plan['route_directory'] == str(attempt_path / 'routes'))
    attempt = Path(attempt_path)
    owner = Path(owner_root)
    cycle = attempt.name.removeprefix('windows-website-')
    return attempt / 'journal', owner / ('.' + plan['owner']['project'] + '.website-tail-' + cycle)


@contextmanager
def _directories(plan):
    records, anchors = namespace_paths(plan)
    with ExitStack() as held:
        for path in (records, anchors):
            held.enter_context(renewal.hold_storage_namespace(path))
            held.enter_context(_held_private_input(path, directory=True, mutable_directory=True))
        yield records, anchors, held


def _inventory(path):
    names = set()
    for entry in path.iterdir():
        names.add(entry.name)
        require(len(names) <= journal.MAX_RECORDS + 2)
    return names


def _hold_inventory(path, expected):
    require(_inventory(path) == expected)


def _hold_bytes(path, held):
    return held.enter_context(renewal.hold_private_input(path))


def _tail_value(plan, index, record_name, payload, prior):
    return {'schema': TAIL_SCHEMA, 'sequence': index, 'plan_sha256': plan['plan_sha256'],
            'record_name': record_name, 'record_sha256': selection.digest(payload),
            'prior_anchor_sha256': prior}


def _tail_name(index):
    return f'{index:06}.tail.json'


def initial_anchor_sha256(plan):
    (name, body), = journal.begin(plan).items()
    return selection.digest(selection.packed(_tail_value(plan, 1, name, body, None)))


def _read(plan, records, anchors, held, expected_anchor_sha256, *, verified_next_record_sha256=None):
    pending = verified_next_record_sha256 is not None
    require(not pending or plan_contract.sha(verified_next_record_sha256))
    require(plan_contract.sha(expected_anchor_sha256) or (pending and expected_anchor_sha256 is None))
    names = _inventory(records)
    ordered = sorted(names - {PLAN, ABORT})
    require(PLAN in names and 1 <= len(ordered) <= journal.MAX_RECORDS
            and all(journal.RECORD_NAME.fullmatch(name) for name in ordered))
    expected_count = len(ordered) - int(pending)
    require((expected_count == 0) == (expected_anchor_sha256 is None))
    expected_tails = {_tail_name(index) for index in range(1, len(ordered) + 1)}
    tails = _inventory(anchors)
    require(tails == expected_tails or (pending and tails == expected_tails - {_tail_name(len(ordered))}))
    require(_hold_bytes(records / PLAN, held) == selection.packed(plan))
    receipt = None
    if ABORT in names:
        receipt_raw = _hold_bytes(records / ABORT, held)
        receipt = selection.decode(receipt_raw)
        require(isinstance(receipt, dict) and receipt_raw == selection.packed(receipt))
    entries = {}
    previous_anchor = None
    for index, name in enumerate(ordered, 1):
        entries[name] = _hold_bytes(records / name, held)
        if pending and index == len(ordered):
            require(selection.digest(entries[name]) == verified_next_record_sha256)
        tail_name = _tail_name(index)
        if tail_name in tails:
            raw = _hold_bytes(anchors / tail_name, held)
            require(raw == selection.packed(_tail_value(plan, index, name, entries[name], previous_anchor)))
            previous_anchor = selection.digest(raw)
        if index == expected_count:
            require(previous_anchor == expected_anchor_sha256)
    prepared = receipt is not None and not ordered[-1].endswith('.reconciled-abort.json')
    status = journal.inspect(entries, plan, expected_tail_sha256=selection.digest(entries[ordered[-1]]),
                             held_abort_receipt=None if prepared else receipt)
    if prepared:
        journal.reconciled_abort(entries, plan, expected_tail_sha256=status['tail_sha256'], held_abort_receipt=receipt)
        status['prepared_abort_sha256'] = plan_contract.digest(receipt)
    held.callback(_hold_inventory, anchors, tails)
    held.callback(_hold_inventory, records, names)
    return entries, status, names, tails


def inspect(plan, *, expected_anchor_sha256):
    """Read only the independently pinned prefix and refuse partial publication."""
    with _directories(plan) as (records, anchors, held):
        _entries, status, _names, _tails = _read(plan, records, anchors, held, expected_anchor_sha256)
    return {**status, 'anchor_sha256': expected_anchor_sha256}


def read_evidence(plan, *, expected_anchor_sha256, references, held):
    """Hold private evidence authenticated by an independently pinned journal."""
    with _directories(plan) as (records, anchors, journal_inputs):
        entries, _status, _names, _tails = _read(plan, records, anchors, journal_inputs, expected_anchor_sha256)
        expectations = {}
        for name, (phase, event) in references.items():
            path = records.parent / name
            require(path.name == name and path.parent == records.parent)
            matches = [body for filename, body in entries.items() if filename[7:] == f'{phase}.{event}.json']
            require(len(matches) == 1)
            expectations[name] = selection.decode(matches[0])['evidence_sha256']
        observed = {}
        for name, expected in expectations.items():
            raw = _hold_bytes(records.parent / name, held)
            value = selection.decode(raw)
            require(type(value) is dict and raw == selection.packed(value)
                    and {key: plan_contract.digest(item) for key, item in value.items()} == expected)
            observed[name] = value
        return observed


def hold_terminal_abort(plan, *, expected_anchor_sha256, held):
    """Keep the complete terminal journal and receipt held for an owner decision."""
    records, anchors = namespace_paths(plan)
    for path in (records, anchors):
        held.enter_context(renewal.hold_storage_namespace(path))
        held.enter_context(_held_private_input(path, directory=True))
    _entries, status, _names, _tails = _read(plan, records, anchors, held, expected_anchor_sha256)
    require(status['classification'] == 'abort-evidence-complete')
    receipt = selection.decode(_hold_bytes(records / ABORT, held))
    return status, receipt


def abort_observations_path(attempt, hashes):
    return attempt / ('stage-abort-evidence-' + plan_contract.digest(hashes) + '.json')


def hold_abort_observations(attempt, hashes, held):
    raw = _hold_bytes(abort_observations_path(attempt, hashes), held)
    observed = selection.decode(raw)
    require(type(observed) is dict and raw == selection.packed(observed)
            and {name: plan_contract.digest(value) for name, value in observed.items()} == hashes)
    return observed


def read_prepared_abort(plan, *, expected_anchor_sha256, held):
    """Hold the exact receipt left before a terminal record was written."""
    with _directories(plan) as (records, anchors, journal_inputs):
        _entries, status, _names, _tails = _read(plan, records, anchors, journal_inputs, expected_anchor_sha256)
        require('prepared_abort_sha256' in status)
        receipt = selection.decode(_hold_bytes(records / ABORT, held))
        require(plan_contract.digest(receipt) == status['prepared_abort_sha256'])
    return receipt


def _publish(plan, records, anchors, held, entries, proposed, names, tails, prior, receipt=None):
    require(len(proposed) == len(entries) + 1 and set(entries) < set(proposed))
    name, = set(proposed) - set(entries)
    body = proposed[name]
    tail_name = _tail_name(len(proposed))
    tail_value = _tail_value(plan, len(proposed), name, body, prior)
    _hold_inventory(records, names)
    _hold_inventory(anchors, tails)
    if receipt is not None:
        if ABORT in names:
            require(_hold_bytes(records / ABORT, held) == selection.packed(receipt))
        else:
            selection._append(records, {}, ABORT, receipt, held)
            names.add(ABORT)
    selection._append(records, entries, name, selection.decode(body), held)
    require(entries == proposed)
    names.add(name)
    selection._append(anchors, {}, tail_name, tail_value, held)
    tails.add(tail_name)
    _hold_inventory(records, names)
    _hold_inventory(anchors, tails)
    anchor_sha256 = selection.digest(selection.packed(tail_value))
    return {**journal.inspect(entries, plan, expected_tail_sha256=selection.digest(body),
                              held_abort_receipt=receipt), 'anchor_sha256': anchor_sha256}


def initialize(plan):
    """Publish intent in preallocated empty namespaces under the owner lock."""
    with _directories(plan) as (records, anchors, held):
        _hold_inventory(records, set())
        _hold_inventory(anchors, set())
        initial = journal.begin(plan)
        selection._append(records, {}, PLAN, plan, held)
        names, tails = {PLAN}, set()
        held.callback(_hold_inventory, anchors, tails)
        held.callback(_hold_inventory, records, names)
        result = _publish(plan, records, anchors, held, {}, initial, names, tails, None)
    return result


def append(plan, *, expected_anchor_sha256, phase, event, evidence_sha256):
    """Persist a phase boundary before its owner proceeds to the next action."""
    with _directories(plan) as (records, anchors, held):
        entries, status, names, tails = _read(plan, records, anchors, held, expected_anchor_sha256)
        require('prepared_abort_sha256' not in status)
        proposed = journal.append(entries, plan, expected_tail_sha256=status['tail_sha256'],
                                  phase=phase, event=event, evidence_sha256=evidence_sha256)
        result = _publish(plan, records, anchors, held, entries, proposed, names, tails, expected_anchor_sha256)
    return result


def reconciled_abort(plan, *, expected_anchor_sha256, receipt):
    """Persist the independently established combined-baseline abort receipt."""
    with _directories(plan) as (records, anchors, held):
        entries, status, names, tails = _read(plan, records, anchors, held, expected_anchor_sha256)
        proposed = journal.reconciled_abort(entries, plan, expected_tail_sha256=status['tail_sha256'],
                                            held_abort_receipt=receipt)
        result = _publish(plan, records, anchors, held, entries, proposed, names, tails,
                          expected_anchor_sha256, receipt=receipt)
    return result


def reconcile_publication(plan, *, expected_anchor_sha256, verified_next_record_sha256):
    """Anchor one independently reverified record without replaying its phase.

    The transition owner supplies the digest after reconciling the underlying
    observations. A partial record or unknown runtime outcome needs additional
    evidence. This operation writes only a missing tail, never a phase record.
    A genesis intent uses a null prior pin and requires an exact sole record.
    """
    require(plan_contract.sha(verified_next_record_sha256))
    with _directories(plan) as (records, anchors, held):
        entries, status, _names, tails = _read(plan, records, anchors, held, expected_anchor_sha256,
            verified_next_record_sha256=verified_next_record_sha256)
        name = max(entries)
        tail_name = _tail_name(len(entries))
        tail_value = _tail_value(plan, len(entries), name, entries[name], expected_anchor_sha256)
        if tail_name not in tails:
            selection._append(anchors, {}, tail_name, tail_value, held)
            tails.add(tail_name)
        anchor_sha256 = selection.digest(selection.packed(tail_value))
    return {**status, 'anchor_sha256': anchor_sha256}
