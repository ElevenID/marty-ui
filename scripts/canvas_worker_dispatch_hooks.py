"""Synthetic dispatch shapes selected through the unchanged Python loader.

No database, network, worker registration, clock or application-code changes.
These hooks are a controlled boundary, not an authoritative Canvas provider.
"""


def nonawaitable_result(_repository, _target):
    return {"facts_changed": 1}


async def nonmapping_result(_repository, _target):
    return ["synthetic-not-a-mapping"]


async def valid_mapping(_repository, _target):
    return {
        "facts_changed": 1,
        "no_change": False,
        "synthetic_discarded": "synthetic-operational-result-tripwire",
    }
