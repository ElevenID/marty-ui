"""Typed recovery successors; contracts alone never select a generation."""
from copy import deepcopy
from pathlib import Path
import re

import selfhost_windows_selection as selection

SCHEMA = 'marty.windows-recovery-successor/v1'
INTENT = 'recovery.intent.json'
DECISION = 'recovery.selection.json'
FILES = {INTENT, DECISION}
OPERATOR_FIELDS = {'binary','binary_sha256','source_sha','release_tag'}


def checked_successor_binding(previous, successor, admission):
    """Exactly one freshly admitted operator, preserving all runtime bindings.

    The finishing owner must provide the admission obtained under its held
    signature/API/capability context. A serialized dict is never that authority.
    """
    require=selection.require
    require(type(previous) is dict and type(successor) is dict)
    expected=deepcopy(previous)
    require(set(successor)==set(previous) and type(admission) is dict)
    require(set(admission)=={'schema','source_sha','release_tag','run_id','run_attempt','binary_sha256',
                            'historical_operator_sha256','verifier_sha256'})
    require(admission['schema']=='marty.windows-recovery-operator-admission/v1')
    require(admission['historical_operator_sha256']==previous['native']['binary_sha256'])
    require(re.fullmatch(r'[0-9a-f]{40}',admission['source_sha'])
            and re.fullmatch(r'v\d+\.\d+\.\d+',admission['release_tag'])
            and re.fullmatch(r'[0-9a-f]{64}',admission['binary_sha256']))
    require(all(type(admission[key]) is int and admission[key]>0 for key in ('run_id','run_attempt')))
    verifiers=admission['verifier_sha256']
    require(type(verifiers) is dict and set(verifiers)=={'gh','cosign'}
            and all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) for value in verifiers.values()))
    require(set(successor['native'])==set(previous['native']))
    binary=Path(successor['native']['binary'])
    require(binary.is_absolute() and binary.name=='marty-deploy-linux-amd64'
            and successor['native']['binary']!=previous['native']['binary'])
    for field in OPERATOR_FIELDS:
        expected['native'][field]=successor['native'][field]
    require(expected==successor)
    require(all(successor['native'][field]==admission[field]
                for field in ('binary_sha256','source_sha','release_tag')))
    require(successor['native']['binary_sha256']!=previous['native']['binary_sha256'])
    return deepcopy(successor)
