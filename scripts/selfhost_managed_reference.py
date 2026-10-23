"""Exact tenant-scoped key references seeded by fresh self-host bootstrap."""

from __future__ import annotations

import uuid


def managed_reference(org: str, purpose: str) -> str:
    if purpose not in {"vc_jwt_issuer", "oid4vp_request_signing"}:
        raise ValueError("unsupported synthetic profile purpose")
    # Match signing-keys' tenant_standard_key_reference for the two profiles
    # exercised by the installed journey. The public profile API repairs the
    # bootstrap binding instead of allocating a tuple-derived key.
    tenant = uuid.uuid5(uuid.NAMESPACE_URL, org).hex
    prefix = "cred-issuer-" if purpose == "vc_jwt_issuer" else "oid4vp-verifier-"
    return f"{prefix}{tenant}-marty-es256"
