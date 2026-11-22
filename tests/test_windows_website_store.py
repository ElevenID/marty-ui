"""Managed website journal publication against real private NTFS paths."""
from contextlib import contextmanager
import os
from pathlib import Path

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_selfhost_windows_inputs import private_fixture
from tests.test_windows_website_journal import abort_receipt
from tests.test_windows_website_plan import planned, rehash
import selfhost_windows_selection as selection
import selfhost_windows_website_journal as journal
import selfhost_windows_website_plan as plan_contract
import selfhost_windows_website_store as store


pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows private NTFS journal')


@pytest.fixture
def paths(planned):
    with private_fixture() as (root, _):
        plan = plan_contract.plan(**planned)
        plan['owner']['root'] = str(root)
        cycle = 'a' * 32
        attempt = root / ('windows-website-' + cycle)
        records = attempt / 'journal'
        tails = root / ('.' + plan['owner']['project'] + '.website-tail-' + cycle)
        plan['attempt_directory'] = str(attempt)
        plan['route_directory'] = str(attempt / 'routes')
        rehash(plan)
        records.mkdir(parents=True)
        tails.mkdir()
        lock = root / ('.' + plan['owner']['project'] + '.renewal.lock')
        lock.touch()
        with selection.renewal.hold_private_input(lock, exclusive=True):
            yield plan, records, tails


def publish(plan, prior, phase='stage-candidate', event='started'):
    evidence = journal.START_EVIDENCE if event == 'started' else journal.COMPLETION_EVIDENCE[phase]
    return store.append(plan, expected_anchor_sha256=prior['anchor_sha256'], phase=phase, event=event,
                        evidence_sha256={name: selection.digest(name.encode()) for name in evidence})


def test_phase_publication_preserves_independent_tail_and_backout_boundaries(paths):
    plan, records, tails = paths
    status = store.initialize(plan)
    assert status == store.inspect(plan, expected_anchor_sha256=status['anchor_sha256'])
    assert set(tails.iterdir()) == {tails / '000001.tail.json'}
    with pytest.raises(ValueError):
        store.initialize(plan)
    for phase in ('stage-candidate', 'route-website', *journal.BACKOUT):
        prior = status
        started = publish(plan, status, phase)
        status = store.inspect(plan, expected_anchor_sha256=started['anchor_sha256'])
        assert status['pending_phase'] == phase and not status['automatic_replay_allowed']
        with pytest.raises(ValueError):
            publish(plan, status, phase)
        with pytest.raises(ValueError):
            store.inspect(plan, expected_anchor_sha256=prior['anchor_sha256'])
        status = publish(plan, started, phase, 'completed')
    assert status['classification'] == 'combined-backout-evidence-complete'
    assert not status['activation_supported'] and not status['receipt_contents_verified']
    assert len(list(tails.iterdir())) == len(list(records.iterdir())) - 1 == status['record_count']


@pytest.mark.parametrize('boundary', ['between-record-and-anchor', 'after-anchor-before-proof-exit'])
def test_interrupted_publication_never_reopens_prior_phase(paths, monkeypatch, boundary):
    plan, records, tails = paths
    initial = store.initialize(plan)
    if boundary == 'between-record-and-anchor':
        original = selection._append
        def append(root, raw, name, value, held):
            if root == tails:
                raise RuntimeError('injected interruption before anchoring')
            original(root, raw, name, value, held)
        monkeypatch.setattr(selection, '_append', append)
    else:
        original = store._held_private_input
        @contextmanager
        def late_exit(path, **kwargs):
            with original(path, **kwargs) as raw:
                yield raw
            if path == tails:
                raise RuntimeError('injected interruption after anchoring')
        monkeypatch.setattr(store, '_held_private_input', late_exit)
    with pytest.raises((RuntimeError, ValueError)):
        publish(plan, initial)
    assert (records / '000002.stage-candidate.started.json').is_file()
    assert (tails / '000002.tail.json').is_file() == (boundary == 'after-anchor-before-proof-exit')
    monkeypatch.undo()
    with pytest.raises(ValueError):
        store.inspect(plan, expected_anchor_sha256=initial['anchor_sha256'])
    with pytest.raises(ValueError):
        publish(plan, initial)
    assert not (records / '000003.stage-candidate.completed.json').exists()
    started = records / '000002.stage-candidate.started.json'
    original_bytes = started.read_bytes()
    with pytest.raises(ValueError):
        store.reconcile_publication(plan, expected_anchor_sha256=initial['anchor_sha256'],
                                    verified_next_record_sha256='0'*64)
    reconciled = store.reconcile_publication(plan, expected_anchor_sha256=initial['anchor_sha256'],
        verified_next_record_sha256=selection.digest(original_bytes))
    assert reconciled['classification'] == 'reconciliation-required' and reconciled['pending_phase'] == 'stage-candidate'
    assert started.read_bytes() == original_bytes
    assert store.inspect(plan, expected_anchor_sha256=reconciled['anchor_sha256']) == reconciled


def test_exact_external_pin_refuses_coordinated_suffix_truncation(paths):
    plan, records, tails = paths
    initial = store.initialize(plan)
    started = publish(plan, initial)
    (records / '000002.stage-candidate.started.json').unlink()
    (tails / '000002.tail.json').unlink()
    with pytest.raises(ValueError):
        store.inspect(plan, expected_anchor_sha256=started['anchor_sha256'])


def test_interrupted_genesis_recovers_only_the_exact_retained_intent(paths, monkeypatch):
    plan, records, tails = paths
    original = selection._append
    def append(root, raw, name, value, held):
        if root == tails:
            raise RuntimeError('injected interruption before first anchor')
        original(root, raw, name, value, held)
    monkeypatch.setattr(selection, '_append', append)
    with pytest.raises((RuntimeError, ValueError)):
        store.initialize(plan)
    monkeypatch.undo()
    with pytest.raises(ValueError):
        store.initialize(plan)
    intent = records / '000001.intent.recorded.json'
    saved = intent.read_bytes()
    result = store.reconcile_publication(plan, expected_anchor_sha256=None,
                                         verified_next_record_sha256=selection.digest(saved))
    assert result['classification'] == 'phase-boundary' and result['record_count'] == 1
    assert intent.read_bytes() == saved
    assert store.inspect(plan, expected_anchor_sha256=result['anchor_sha256']) == result


def test_reconciled_abort_requires_original_separate_receipt_on_every_read(paths):
    plan, records, _ = paths
    started = publish(plan, store.initialize(plan))
    entries = {path.name: path.read_bytes() for path in records.iterdir() if path.name != store.PLAN}
    receipt = abort_receipt(plan, entries)
    result = store.reconciled_abort(plan, expected_anchor_sha256=started['anchor_sha256'], receipt=receipt)
    assert result['classification'] == 'abort-evidence-complete' and result['model_state'] == 'combined'
    assert store.inspect(plan, expected_anchor_sha256=result['anchor_sha256']) == result
    assert (records / store.ABORT).read_bytes() == selection.packed(receipt)
    (records / store.ABORT).unlink()
    with pytest.raises(ValueError):
        store.inspect(plan, expected_anchor_sha256=result['anchor_sha256'])


def test_owner_root_confines_journal_before_any_file_creation(paths):
    plan, records, tails = paths
    plan['attempt_directory'] = str(Path(plan['owner']['root']).parent / ('windows-website-' + 'b'*32))
    rehash(plan)
    with pytest.raises(ValueError):
        store.initialize(plan)
    assert list(records.iterdir()) == list(tails.iterdir()) == []
