"""Interrupted website work is never converted into automatic replay authority."""
from copy import deepcopy

import pytest

from tests.test_package_web_composition import candidate as candidate
from tests.test_windows_website_plan import planned, rehash
import selfhost_windows_website_plan as plan_contract
import selfhost_windows_website_journal as journal
import selfhost_windows_selection as selection


def tail(entries):
    return selection.digest(entries[sorted(entries)[-1]])


def record(entries, plan, phase, event):
    evidence = journal.START_EVIDENCE if event == 'started' else journal.COMPLETION_EVIDENCE[phase]
    return journal.append(entries, plan, expected_tail_sha256=tail(entries), phase=phase, event=event,
                          evidence_sha256={name: selection.digest(name.encode()) for name in evidence})


def phase(entries, plan, name):
    return record(record(entries, plan, name, 'started'), plan, name, 'completed')


def status(entries, plan):
    return journal.inspect(entries, plan, expected_tail_sha256=tail(entries))


def test_forward_chain_binds_exact_plan_but_does_not_publish_owner_or_claim_verified_receipts(planned):
    plan = plan_contract.plan(**planned)
    entries = journal.begin(plan)
    assert status(entries, plan)['model_state'] == 'combined'
    for name in journal.FORWARD:
        entries = phase(entries, plan, name)
    result = status(entries, plan)
    assert result['classification'] == 'forward-evidence-complete' and result['record_count'] == 9
    assert result['completed_phases'] == list(journal.FORWARD) and result['model_state'] == 'split'
    assert result['permitted_record_phases'] == []
    assert not any(result[name] for name in ('receipt_contents_verified', 'automatic_replay_allowed',
        'owner_publication_supported', 'activation_supported', 'production_admission'))
    with pytest.raises(ValueError):record(entries, plan, 'restore-combined', 'started')


@pytest.mark.parametrize('through', [1, 2, 3])
def test_first_cutover_backout_restores_then_verifies_combined_before_retiring_candidate(planned, through):
    plan = plan_contract.plan(**planned)
    entries = journal.begin(plan)
    for name in journal.FORWARD[:through]:entries = phase(entries, plan, name)
    for name in journal.BACKOUT:
        entries = phase(entries, plan, name)
    result = status(entries, plan)
    assert result['classification'] == 'combined-backout-evidence-complete'
    assert result['model_state'] == 'combined'
    assert result['completed_phases'][-3:] == list(journal.BACKOUT)
    assert result['permitted_record_phases'] == []
    assert selection.decode(entries[sorted(entries)[-1]])['state'] == plan['states']['combined']


@pytest.mark.parametrize('name', journal.FORWARD+journal.BACKOUT)
def test_started_phase_requires_reconciliation_and_forbids_replay_or_guessing_backout(planned, name):
    plan = plan_contract.plan(**planned)
    entries = journal.begin(plan)
    path = journal.FORWARD[:journal.FORWARD.index(name)] if name in journal.FORWARD else (
        ('stage-candidate', 'route-website') + journal.BACKOUT[:journal.BACKOUT.index(name)])
    for prior in path:entries = phase(entries, plan, prior)
    entries = record(entries, plan, name, 'started')
    result = status(entries, plan)
    assert result['classification'] == 'reconciliation-required' and result['pending_phase'] == name
    assert result['permitted_record_phases'] == [] and result['automatic_replay_allowed'] is False
    for attempted in (name, 'restore-combined', 'retire-candidate'):
        with pytest.raises(ValueError):record(entries, plan, attempted, 'started')


@pytest.mark.parametrize('fault', ['wrong-tail', 'prefix-truncation', 'reordered-phase', 'duplicate-phase',
    'extra-key', 'wrong-parent', 'wrong-plan', 'wrong-state', 'missing-proof', 'unknown-proof',
    'wrong-filename', 'noncanonical', 'boolean-sequence', 'duplicate-json-key'])
def test_journal_rejects_ambiguous_rehashed_or_truncated_history(planned, fault):
    plan = plan_contract.plan(**planned)
    entries = phase(journal.begin(plan), plan, 'stage-candidate')
    expected = tail(entries)
    last = sorted(entries)[-1]
    if fault == 'wrong-tail':expected = 'f'*64
    elif fault == 'prefix-truncation':entries.pop(last)
    elif fault == 'duplicate-phase':
        with pytest.raises(ValueError):record(entries, plan, 'stage-candidate', 'started')
        return
    elif fault == 'wrong-filename':entries['000003.route-website.completed.json'] = entries.pop(last)
    elif fault == 'noncanonical':entries[last] += b' ';expected = tail(entries)
    elif fault == 'duplicate-json-key':
        entries[last] = entries[last].replace(b'{', b'{"phase":"stage-candidate",', 1);expected = tail(entries)
    else:
        value = selection.decode(entries[last])
        if fault == 'reordered-phase':value['phase'] = 'route-website'
        elif fault == 'extra-key':value['execute'] = True
        elif fault == 'wrong-parent':value['parent_sha256'] = 'f'*64
        elif fault == 'wrong-plan':value['plan_sha256'] = 'f'*64
        elif fault == 'wrong-state':value['state'] = deepcopy(plan['states']['split'])
        elif fault == 'missing-proof':value['evidence_sha256'].pop('candidate_health')
        elif fault == 'unknown-proof':value['evidence_sha256']['admission'] = 'f'*64
        elif fault == 'boolean-sequence':value['sequence'] = True
        entries[last] = selection.packed(value);expected = tail(entries)
    with pytest.raises(ValueError):journal.inspect(entries, plan, expected_tail_sha256=expected)


def test_journal_cannot_relabel_a_plan_as_live_admission_or_move_selected_credentials(planned):
    plan = plan_contract.plan(**planned)
    plan['qualification']['owner_lease_held'] = True
    rehash(plan)
    with pytest.raises(ValueError):journal.begin(plan)
    plan = plan_contract.plan(**planned)
    entries = journal.begin(plan)
    plan['owner']['selected_sha256'] = 'f'*64
    plan['backout']['preserved_selected_sha256'] = 'f'*64
    rehash(plan)
    with pytest.raises(ValueError):status(entries, plan)


def abort_receipt(plan, entries, outcome='never-created'):
    names = journal.ABORT_OBSERVATIONS | ({'candidate_compensation'} if outcome == 'created-then-compensated' else set())
    return {'schema': journal.ABORT_SCHEMA, 'plan_sha256': plan['plan_sha256'],
        'started_record_sha256': tail(entries), 'owner_binding_sha256': plan['owner']['binding_sha256'],
        'selected_sha256': plan['owner']['selected_sha256'], 'state': deepcopy(plan['states']['combined']),
        'candidate_outcome': outcome,
        'observations_sha256': {name: selection.digest((outcome+':'+name).encode()) for name in names}}


@pytest.mark.parametrize('outcome', ['never-created', 'created-then-compensated'])
def test_failed_first_stage_can_abort_at_combined_baseline_without_inventing_healthy_stage(planned, outcome):
    plan = plan_contract.plan(**planned)
    entries = record(journal.begin(plan), plan, 'stage-candidate', 'started')
    receipt = abort_receipt(plan, entries, outcome)
    original_entries, original_receipt = deepcopy(entries), deepcopy(receipt)
    assert status(entries, plan)['classification'] == 'reconciliation-required'
    # Merely supplying a receipt cannot rewrite or skip the pending operation.
    with pytest.raises(ValueError):
        journal.inspect(entries, plan, expected_tail_sha256=tail(entries), held_abort_receipt=receipt)
    ended = journal.reconciled_abort(entries, plan, expected_tail_sha256=tail(entries), held_abort_receipt=receipt)
    assert entries == original_entries and receipt == original_receipt
    result = journal.inspect(ended, plan, expected_tail_sha256=tail(ended), held_abort_receipt=receipt)
    assert result['classification'] == 'abort-evidence-complete' and result['record_count'] == 3
    assert result['completed_phases'] == [] and result['aborted_phase'] == 'stage-candidate'
    assert result['pending_phase'] is None and result['model_state'] == 'combined'
    assert result['permitted_record_phases'] == []
    assert not any(result[name] for name in ('receipt_contents_verified', 'automatic_replay_allowed',
        'owner_publication_supported', 'activation_supported', 'production_admission'))
    records = [selection.decode(ended[name]) for name in sorted(ended)]
    assert [item['event'] for item in records] == ['recorded', 'started', 'reconciled-abort']
    assert records[-1]['state'] == plan['states']['combined']
    assert records[-1]['parent_sha256'] == receipt['started_record_sha256']
    assert records[-1]['evidence_sha256'] == {'reconciliation': plan_contract.digest(receipt)}
    with pytest.raises(ValueError):status(ended, plan)
    with pytest.raises(ValueError):
        journal.reconciled_abort(ended, plan, expected_tail_sha256=tail(ended), held_abort_receipt=receipt)
    for following in journal.FORWARD+journal.BACKOUT:
        # Even a correctly rehashed extra record cannot restart or back out an abort.
        extra = deepcopy(records[1])
        extra.update(sequence=4, phase=following, parent_sha256=tail(ended))
        extended = {**ended, journal.filename(extra): selection.packed(extra)}
        with pytest.raises(ValueError):
            journal.inspect(extended, plan, expected_tail_sha256=tail(extended), held_abort_receipt=receipt)


@pytest.mark.parametrize('fault', ['missing-receipt', 'extra-field', 'truncated-receipt', 'schema',
    'stale-plan', 'stale-start', 'stale-owner', 'stale-credentials', 'model-drift', 'data-drift', 'route-drift',
    'absence-missing', 'compensated-absence-missing', 'custody-missing', 'handoff-missing',
    'observation-malformed', 'observation-extra',
    'outcome', 'compensation-missing', 'compensation-unexpected'])
def test_initial_abort_refuses_unbound_or_incomplete_reconciliation(planned, fault):
    plan = plan_contract.plan(**planned)
    entries = record(journal.begin(plan), plan, 'stage-candidate', 'started')
    receipt = abort_receipt(plan, entries)
    if fault == 'missing-receipt':receipt = None
    elif fault == 'extra-field':receipt['clear_guard'] = True
    elif fault == 'truncated-receipt':receipt.pop('state')
    elif fault == 'schema':receipt['schema'] = journal.SCHEMA
    elif fault == 'stale-plan':receipt['plan_sha256'] = 'f'*64
    elif fault == 'stale-start':receipt['started_record_sha256'] = 'f'*64
    elif fault == 'stale-owner':receipt['owner_binding_sha256'] = 'f'*64
    elif fault == 'stale-credentials':receipt['selected_sha256'] = 'f'*64
    elif fault == 'model-drift':receipt['state']['model_sha256'] = plan['states']['staged']['model_sha256']
    elif fault == 'data-drift':receipt['state']['data_sha256'] = plan['states']['staged']['data_sha256']
    elif fault == 'route-drift':receipt['state']['routes_sha256'] = plan['states']['split']['routes_sha256']
    elif fault == 'absence-missing':receipt['observations_sha256'].pop('candidate_absence')
    elif fault == 'compensated-absence-missing':
        receipt = abort_receipt(plan, entries, 'created-then-compensated')
        receipt['observations_sha256'].pop('candidate_absence')
    elif fault == 'custody-missing':receipt['observations_sha256'].pop('native_custody')
    elif fault == 'handoff-missing':receipt['observations_sha256'].pop('application_handoffs')
    elif fault == 'observation-malformed':receipt['observations_sha256']['candidate_absence'] = True
    elif fault == 'observation-extra':receipt['observations_sha256']['guard_cleared'] = 'f'*64
    elif fault == 'outcome':receipt['candidate_outcome'] = 'candidate-still-present'
    elif fault == 'compensation-missing':receipt['candidate_outcome'] = 'created-then-compensated'
    elif fault == 'compensation-unexpected':receipt['observations_sha256']['candidate_compensation'] = 'f'*64
    with pytest.raises(ValueError):
        journal.reconciled_abort(entries, plan, expected_tail_sha256=tail(entries), held_abort_receipt=receipt)


@pytest.mark.parametrize('pending', journal.FORWARD[1:]+journal.BACKOUT+('intent-only', 'stage-completed'))
def test_initial_stage_abort_never_applies_to_other_phase_boundaries(planned, pending):
    plan = plan_contract.plan(**planned)
    entries = journal.begin(plan)
    if pending != 'intent-only':
        path = journal.FORWARD[:journal.FORWARD.index(pending)] if pending in journal.FORWARD else (
            ('stage-candidate',) if pending == 'stage-completed' else
            ('stage-candidate', 'route-website') + journal.BACKOUT[:journal.BACKOUT.index(pending)])
        for prior in path:entries = phase(entries, plan, prior)
        if pending != 'stage-completed':entries = record(entries, plan, pending, 'started')
    receipt = abort_receipt(plan, entries)
    with pytest.raises(ValueError):
        journal.reconciled_abort(entries, plan, expected_tail_sha256=tail(entries), held_abort_receipt=receipt)
    # The parser must refuse a forged terminal even without using its constructor.
    forged = {'schema': journal.SCHEMA, 'sequence': len(entries)+1, 'plan_sha256': plan['plan_sha256'],
        'parent_sha256': tail(entries), 'phase': 'stage-candidate', 'event': 'reconciled-abort',
        'state': deepcopy(plan['states']['combined']),
        'evidence_sha256': {'reconciliation': plan_contract.digest(receipt)}}
    extended = {**entries, journal.filename(forged): selection.packed(forged)}
    with pytest.raises(ValueError):
        journal.inspect(extended, plan, expected_tail_sha256=tail(extended), held_abort_receipt=receipt)


@pytest.mark.parametrize('fault', ['receipt-digest', 'terminal-state', 'terminal-phase', 'tail-truncation'])
def test_abort_parser_requires_exact_held_receipt_baseline_and_current_tail(planned, fault):
    plan = plan_contract.plan(**planned)
    started = record(journal.begin(plan), plan, 'stage-candidate', 'started')
    receipt = abort_receipt(plan, started)
    entries = journal.reconciled_abort(started, plan, expected_tail_sha256=tail(started), held_abort_receipt=receipt)
    expected = tail(entries)
    if fault == 'receipt-digest':receipt['observations_sha256']['runtime_after'] = 'f'*64
    elif fault == 'tail-truncation':entries.pop(sorted(entries)[-1])
    else:
        name = sorted(entries)[-1]
        value = selection.decode(entries.pop(name))
        if fault == 'terminal-state':value['state'] = deepcopy(plan['states']['staged'])
        elif fault == 'terminal-phase':value['phase'] = 'route-website'
        entries[journal.filename(value)] = selection.packed(value)
        expected = tail(entries)
    with pytest.raises(ValueError):
        journal.inspect(entries, plan, expected_tail_sha256=expected, held_abort_receipt=receipt)
