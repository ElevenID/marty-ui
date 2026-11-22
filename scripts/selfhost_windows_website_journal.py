"""Pure record contract for a future managed website transition journal.

No files or guard markers are created and no owner selection is published here.
The future existing-owner writer must hold its lock/ancestry, fsync immutable
records before execution, authenticate referenced evidence and qualify each
runtime boundary. A structurally valid journal never grants those capabilities.
"""
from copy import deepcopy
import re

import selfhost_windows_selection as selection
import selfhost_windows_website_plan as plan_contract


SCHEMA = 'marty.windows-website-transition-journal/v1'
ABORT_SCHEMA = 'marty.windows-website-initial-stage-abort/v1'
ABORT_FIELDS = {'schema', 'plan_sha256', 'started_record_sha256', 'owner_binding_sha256',
                'selected_sha256', 'state', 'candidate_outcome', 'observations_sha256'}
ABORT_OBSERVATIONS = {'owner_lease', 'native_custody', 'foreign_storage', 'runtime_after',
    'normalized_model', 'retained_product', 'mounted_template', 'edge_configuration',
    'public_routes', 'application_handoffs', 'candidate_absence', 'selected_credentials'}
FORWARD = ('stage-candidate', 'route-website', 'verify-website', 'seal-forward')
BACKOUT = ('restore-combined', 'verify-combined', 'retire-candidate')
MAX_RECORDS = 1 + 2*(len(FORWARD)-1+len(BACKOUT))
FIELDS = {'schema', 'sequence', 'plan_sha256', 'parent_sha256', 'phase', 'event', 'state', 'evidence_sha256'}
START_EVIDENCE = {'owner_lease', 'native_custody', 'foreign_storage', 'runtime_before'}
COMPLETION_EVIDENCE = {
    'stage-candidate': {'runtime_after', 'image_metadata', 'candidate_health'},
    'route-website': {'runtime_after', 'mounted_template', 'edge_configuration'},
    'verify-website': {'runtime_after', 'public_routes', 'application_handoffs'},
    'seal-forward': {'runtime_after', 'native_custody', 'foreign_storage', 'successor_candidate'},
    'restore-combined': {'runtime_after', 'mounted_template', 'edge_configuration'},
    'verify-combined': {'runtime_after', 'public_routes', 'application_handoffs'},
    'retire-candidate': {'runtime_after', 'native_custody', 'foreign_storage'},
}
AFTER = {'stage-candidate': 'staged', 'route-website': 'split', 'verify-website': 'split',
         'seal-forward': 'split', 'restore-combined': 'staged', 'verify-combined': 'staged',
         'retire-candidate': 'combined'}


def require(value):
    if not value:
        raise ValueError('Managed website journal contract refused')


def _plan(value):
    """Envelope integrity only; full held-input reconstruction remains mandatory."""
    plan_contract.validate_envelope(value)


def _abort_receipt(value, plan, started_record_sha256):
    """Bind an independently supplied observation receipt, without verifying it."""
    require(type(value) is dict and set(value) == ABORT_FIELDS and value['schema'] == ABORT_SCHEMA
        and value['plan_sha256'] == plan['plan_sha256']
        and value['started_record_sha256'] == started_record_sha256
        and value['owner_binding_sha256'] == plan['owner']['binding_sha256']
        and value['selected_sha256'] == plan['owner']['selected_sha256']
        and value['state'] == plan['states']['combined'])
    outcome = value['candidate_outcome']
    require(isinstance(outcome, str) and outcome in {'never-created', 'created-then-compensated'})
    required = ABORT_OBSERVATIONS | ({'candidate_compensation'} if outcome == 'created-then-compensated' else set())
    observations = value['observations_sha256']
    require(type(observations) is dict and set(observations) == required
            and all(plan_contract.sha(value) for value in observations.values()))


def filename(record):
    return f"{record['sequence']:06}.{record['phase']}.{record['event']}.json"


def _next(completed):
    if not completed:
        return ('stage-candidate',)
    last = completed[-1]
    if last in {'seal-forward', 'retire-candidate'}:
        return ()
    if last in BACKOUT:
        return (BACKOUT[BACKOUT.index(last)+1],)
    return (FORWARD[FORWARD.index(last)+1], 'restore-combined')


def inspect(entries, plan, *, expected_tail_sha256, held_abort_receipt=None):
    """Classify exact canonical records, never replay an uncertain phase.

    The expected tail is a separately held owner input. It prevents a caller
    from presenting an intact shorter prefix as the currently retained journal.
    An initial-stage abort also requires a separate held reconciliation receipt.
    Receipt hashes bind references only; this function does not verify their
    observations or substitute for the live owner/custody/public checks.
    """
    _plan(plan)
    require(type(entries) is dict and 1 <= len(entries) <= MAX_RECORDS
            and all(isinstance(name, str) for name in entries) and plan_contract.sha(expected_tail_sha256))
    ordered = sorted(entries)
    prior = None;pending = None;completed = [];state = 'combined';aborted = False
    for index, name in enumerate(ordered, 1):
        body = entries[name]
        require(not aborted and isinstance(name, str) and re.fullmatch(
            r'[0-9]{6}\.[a-z-]+\.(recorded|started|completed|reconciled-abort)\.json', name)
                and isinstance(body, bytes) and 0 < len(body) <= 16384)
        record = selection.decode(body)
        require(type(record) is dict and set(record) == FIELDS and body == selection.packed(record)
                and record['schema'] == SCHEMA and type(record['sequence']) is int and record['sequence'] == index
                and name == filename(record) and record['plan_sha256'] == plan['plan_sha256']
                and record['parent_sha256'] == prior)
        phase, event, evidence = record['phase'], record['event'], record['evidence_sha256']
        require(isinstance(phase, str) and isinstance(event, str)
                and type(evidence) is dict and all(plan_contract.sha(value) for value in evidence.values()))
        if index == 1:
            require(phase == 'intent' and event == 'recorded' and record['state'] == plan['states']['combined']
                    and evidence == {'plan': plan['plan_sha256']})
        elif event == 'started':
            require(pending is None and phase in _next(completed)
                    and record['state'] == plan['states'][state] and set(evidence) == START_EVIDENCE)
            pending = phase
        elif event == 'completed':
            require(pending == phase and phase in COMPLETION_EVIDENCE
                    and set(evidence) == COMPLETION_EVIDENCE[phase]
                    and record['state'] == plan['states'][AFTER[phase]])
            completed.append(phase);pending = None;state = AFTER[phase]
        elif event == 'reconciled-abort':
            require(index == 3 and phase == pending == 'stage-candidate'
                    and not completed and state == 'combined')
            _abort_receipt(held_abort_receipt, plan, prior)
            require(record['state'] == plan['states']['combined']
                    and evidence == {'reconciliation': plan_contract.digest(held_abort_receipt)})
            pending = None;aborted = True
        else:
            raise ValueError('Managed website journal contract refused')
        prior = selection.digest(body)
    require(prior == expected_tail_sha256 and aborted == (held_abort_receipt is not None))
    terminal = completed[-1] if completed and completed[-1] in {'seal-forward', 'retire-candidate'} else None
    classification = ('abort-evidence-complete' if aborted else 'reconciliation-required' if pending else
        'forward-evidence-complete' if terminal == 'seal-forward' else
        'combined-backout-evidence-complete' if terminal == 'retire-candidate' else 'phase-boundary')
    return {'schema': SCHEMA, 'plan_sha256': plan['plan_sha256'], 'tail_sha256': prior,
        'record_count': len(entries), 'classification': classification, 'pending_phase': pending,
        'completed_phases': completed, 'aborted_phase': 'stage-candidate' if aborted else None, 'model_state': state,
        'permitted_record_phases': [] if pending or terminal or aborted else list(_next(completed)),
        'receipt_contents_verified': False, 'automatic_replay_allowed': False,
        'owner_publication_supported': False, 'activation_supported': False, 'production_admission': False}


def begin(plan):
    """Encode an intent in memory. The existing owner does not consume it yet."""
    _plan(plan)
    record = {'schema': SCHEMA, 'sequence': 1, 'plan_sha256': plan['plan_sha256'],
        'parent_sha256': None, 'phase': 'intent', 'event': 'recorded',
        'state': deepcopy(plan['states']['combined']), 'evidence_sha256': {'plan': plan['plan_sha256']}}
    body = selection.packed(record)
    return {filename(record): body}


def append(entries, plan, *, expected_tail_sha256, phase, event, evidence_sha256):
    """Encode the next record; this performs no durable write or runtime action.

    Completion of a started phase is representable, but after an interruption
    the future runtime owner must reconcile actual evidence before recording it.
    Neither this constructor nor inspect authorizes a retry or recovery action.
    """
    status = inspect(entries, plan, expected_tail_sha256=expected_tail_sha256)
    require(isinstance(phase, str) and isinstance(event, str)
            and phase in COMPLETION_EVIDENCE and event in {'started', 'completed'})
    state = AFTER[phase] if event == 'completed' else status['model_state']
    record = {'schema': SCHEMA, 'sequence': len(entries)+1, 'plan_sha256': plan['plan_sha256'],
        'parent_sha256': expected_tail_sha256, 'phase': phase, 'event': event,
        'state': deepcopy(plan['states'][state]), 'evidence_sha256': deepcopy(evidence_sha256)}
    result = deepcopy(entries);body = selection.packed(record)
    result[filename(record)] = body
    inspect(result, plan, expected_tail_sha256=selection.digest(body))
    return result


def reconciled_abort(entries, plan, *, expected_tail_sha256, held_abort_receipt):
    """Record a failed initial stage only after independent baseline reconciliation.

    A never-created candidate and a created-then-compensated candidate both need
    observed absence and the exact combined baseline. The latter also needs a
    compensation receipt. This constructor performs no cleanup, verifies no live
    observations, and cannot clear an owner guard or publish a selection.
    """
    status = inspect(entries, plan, expected_tail_sha256=expected_tail_sha256)
    require(status['record_count'] == 2 and status['pending_phase'] == 'stage-candidate'
            and not status['completed_phases'] and status['model_state'] == 'combined')
    _abort_receipt(held_abort_receipt, plan, expected_tail_sha256)
    record = {'schema': SCHEMA, 'sequence': 3, 'plan_sha256': plan['plan_sha256'],
        'parent_sha256': expected_tail_sha256, 'phase': 'stage-candidate', 'event': 'reconciled-abort',
        'state': deepcopy(plan['states']['combined']),
        'evidence_sha256': {'reconciliation': plan_contract.digest(held_abort_receipt)}}
    result = deepcopy(entries);body = selection.packed(record)
    result[filename(record)] = body
    inspect(result, plan, expected_tail_sha256=selection.digest(body), held_abort_receipt=held_abort_receipt)
    return result
