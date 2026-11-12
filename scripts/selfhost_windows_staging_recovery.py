"""Evidence validation for a failed Windows current-generation proof.

This module grants no retry or guard-removal authority. A successful evidence
check does not establish current credential validity or admit activation.
"""
import hashlib

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
