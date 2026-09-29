"""Sanitize protected Signing Keys issuer resolution for passport evidence.

The caller obtains responses from the private, authenticated
``/internal/compat/resolve-issuer-did`` route. This module never transports or
publishes those responses, which contain KMS key references and DID documents.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


class IssuerProfileEvidenceError(ValueError):
    pass


def _required(value: dict[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item or item.strip() != item:
        raise IssuerProfileEvidenceError(f"Resolved issuer {field} is unavailable")
    return item


def _commit(api_key: str, profile_id: str) -> str:
    return hmac.new(api_key.encode("utf-8"),
                    ("issuer-profile:" + profile_id).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_profiles(
    organization_id: str,
    csca_issuer_did: str,
    dsc_issuer_did: str,
    csca_resolution: dict[str, Any],
    dsc_resolution: dict[str, Any],
    api_key: str,
) -> dict[str, Any]:
    """Verify two live managed profile bindings and return public commitments.

    This proves the selected profile and managed service configuration. The
    protected preliminary producer must also verify the live CSCA/DSC signing
    ceremonies and their certificate chain before claiming KMS custody.
    """
    if not all(isinstance(item, str) and item and item.strip() == item for item in
               (organization_id, csca_issuer_did, dsc_issuer_did, api_key)):
        raise IssuerProfileEvidenceError("Issuer evidence input is incomplete")
    ids: list[str] = []
    references: list[str] = []
    for role, did, resolution, purpose in (
        ("CSCA", csca_issuer_did, csca_resolution, "csca"),
        ("DSC", dsc_issuer_did, dsc_resolution, "x509_doc_signer"),
    ):
        if not isinstance(resolution, dict) or resolution.get("ok") is not True:
            raise IssuerProfileEvidenceError(f"{role} issuer resolution failed")
        profile = resolution.get("issuer_profile")
        service = resolution.get("signing_service")
        resolver = resolution.get("resolver")
        if not all(isinstance(item, dict) for item in (profile, service, resolver)):
            raise IssuerProfileEvidenceError(f"{role} issuer binding is incomplete")
        if (resolution.get("organization_id") != organization_id
                or resolution.get("issuer_did") != did
                or profile.get("organization_id") != organization_id
                or profile.get("issuer_did") != did
                or profile.get("status") != "active"
                or profile.get("issuer_mode") != "org_managed"
                or profile.get("key_purpose") != purpose
                or profile.get("credential_format") != "ICAO_EMRTD"
                or service.get("id") != "managed-openbao-transit"
                or service.get("service_type") != "openbao-transit"
                or service.get("provider") != "openbao"
                or service.get("managed") is not True
                or service.get("status") != "configured"
                or profile.get("signing_service_id") != service.get("id")
                or resolver.get("type") != "organization_issuer_profile"
                or resolver.get("public_fallback_used") is not False):
            raise IssuerProfileEvidenceError(f"{role} issuer is not an active managed KMS profile")
        profile_id = _required(profile, "id")
        reference = _required(profile, "signing_key_reference")
        if reference not in service.get("key_aliases", []):
            raise IssuerProfileEvidenceError(f"{role} managed key is absent from live inventory")
        ids.append(profile_id)
        references.append(reference)

    if len(set(ids)) != 2 or len(set(references)) != 2:
        raise IssuerProfileEvidenceError("CSCA and DSC must select distinct managed profiles and keys")
    return {
        "csca_issuer_profile_commitment": _commit(api_key, ids[0]),
        "dsc_issuer_profile_commitment": _commit(api_key, ids[1]),
        "managed_profile_binding_verified": True,
    }
