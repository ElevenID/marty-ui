"""A stopped current proof must never be confused with a producer attempt."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from selfhost_windows_selection import _stage_names, packed
from selfhost_windows_staging_recovery import failed_current_receipts


def receipts():
    result = {name: b'' for name in _stage_names() if name != 'intent.json'}
    for name in ('authority.started.json', 'authority.completed.json', 'current.started.json'):
        phase, event, _ = name.split('.')
        result[name] = packed({'phase': phase, 'event': event, 'metadata': {}})
    return result


def test_exact_failed_current_phase_is_bound_without_mutating_receipts():
    raw = receipts()
    before = dict(raw)
    hashes = failed_current_receipts(raw)
    assert raw == before and set(hashes) == set(raw)
    assert all(len(value) == 64 for value in hashes.values())


@pytest.mark.parametrize('name', [name for name in receipts() if not receipts()[name]])
def test_any_later_or_current_completion_receipt_blocks_reconciliation(name):
    raw = receipts()
    raw[name] = b'{}'
    with pytest.raises(ValueError):
        failed_current_receipts(raw)


@pytest.mark.parametrize('change', ['missing', 'extra', 'duplicate', 'metadata', 'uncompleted'])
def test_uncertain_or_altered_evidence_is_refused(change):
    raw = receipts()
    if change == 'missing':
        del raw['tls.started.json']
    elif change == 'extra':
        raw['unknown.json'] = b''
    elif change == 'duplicate':
        raw['current.started.json'] = b'{"phase":"wrong","phase":"current","event":"started","metadata":{}}'
    elif change == 'metadata':
        raw['current.started.json'] = packed({'phase': 'current', 'event': 'started', 'metadata': {'retry': True}})
    else:
        raw['authority.completed.json'] = b''
    with pytest.raises(ValueError):
        failed_current_receipts(raw)
