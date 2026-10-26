"""Exact public-identity key references shared with the native signing API."""
from __future__ import annotations

import json
from pathlib import Path

if __package__:
    from .selfhost_native_operator import operator_bytes
else:
    from selfhost_native_operator import operator_bytes


def managed_reference(org: str, purpose: str, issuer_did: str) -> str:
    if purpose not in {"vc_jwt_issuer", "oid4vp_request_signing"}:
        raise ValueError("unsupported synthetic profile purpose")
    return json.loads(operator_bytes(Path(__file__).resolve().parents[1], "operator", "managed-reference",
                                     input=json.dumps({"org": org, "purpose": purpose,
                                                       "issuer_did": issuer_did}).encode()))
