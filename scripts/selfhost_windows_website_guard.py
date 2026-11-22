"""The existing selection owner's shared product guard for a website attempt."""
from selfhost_windows_inputs import _held_private_input
import selfhost_windows_selection as selection
import selfhost_windows_website_store as store


SCHEMA = 'marty.windows-website-owner-guard/v1'
require = selection.require
renewal = selection.renewal


def marker(plan):
    store.namespace_paths(plan)
    return {'schema': SCHEMA, 'owner': plan['owner'], 'plan_sha256': plan['plan_sha256'],
            'attempt_directory': plan['attempt_directory'], 'initial_anchor_sha256': store.initial_anchor_sha256(plan)}


def initialize(config, plan, held):
    """Seal normal owner entry points before publishing the initial journal."""
    records, anchors = store.namespace_paths(plan)
    attempt = records.parent
    guard = renewal.product_transition_guard(config)
    require(guard.parent == attempt.parent and plan['owner']['project'] == config['project'])
    require(not renewal.recovery_pending(config))
    require(not renewal.namespace_entry_exists(attempt) and not renewal.namespace_entry_exists(anchors))
    with _held_private_input(guard.parent, directory=True, mutable_directory=True):
        value = marker(plan)
        body = selection.packed(value)
        selection._new_private(guard, body)
        require(held.enter_context(renewal.hold_private_input(guard)) == body)
        attempt.mkdir()
        held.enter_context(_held_private_input(attempt, directory=True, mutable_directory=True))
        records.mkdir()
        anchors.mkdir()
        result = store.initialize(plan)
        require(result['anchor_sha256'] == value['initial_anchor_sha256'])
    return {**result, 'guard_sha256': selection.digest(body)}


def inspect(config, plan, owner, *, guard_sha256, expected_anchor_sha256, held):
    """Under the exact guarded owner lock, inspect a retained website phase."""
    guard = renewal.product_transition_guard(config)
    body = held.enter_context(renewal.hold_private_input(guard))
    require(selection.digest(body) == guard_sha256 and body == selection.packed(marker(plan)))
    require(plan['owner'] == owner)
    return {**store.inspect(plan, expected_anchor_sha256=expected_anchor_sha256), 'guard_sha256': guard_sha256}
