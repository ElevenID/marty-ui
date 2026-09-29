"""Private profile evidence must reject unrelated custody and expose only HMACs."""

from __future__ import annotations

import copy
import hashlib
import hmac

import pytest

from scripts.verify_passport_beta_issuer_profiles import (
    IssuerProfileEvidenceError, verify_profiles,
)


def resolution(role: str) -> dict:
    purpose = "csca" if role == "csca" else "x509_doc_signer"
    did = "did:web:beta.example:org:passport"
    reference = f"managed-kms-{role}"
    return {
        "ok": True, "organization_id": "org-a", "issuer_did": did,
        "issuer_profile": {
            "id": f"profile-{role}", "organization_id": "org-a", "issuer_did": did,
            "issuer_mode": "org_managed", "status": "active", "key_purpose": purpose,
            "credential_format": "ICAO_EMRTD", "signing_service_id": "managed-openbao-transit",
            "signing_key_reference": reference,
        },
        "signing_service": {
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "provider": "openbao", "managed": True, "status": "configured",
            "key_aliases": [reference],
        },
        "resolver": {"type": "organization_issuer_profile", "public_fallback_used": False},
        "did_document": {"private_data_for_test": "must not leak"},
    }


def verify(csca: dict, dsc: dict) -> dict:
    return verify_profiles("org-a", csca["issuer_did"], dsc["issuer_did"], csca, dsc, "private-api-key")


def test_distinct_managed_profiles_emit_only_keyed_commitments() -> None:
    result = verify(resolution("csca"), resolution("dsc"))
    expected = hmac.new(b"private-api-key", b"issuer-profile:profile-csca", hashlib.sha256).hexdigest()
    assert result == {
        "csca_issuer_profile_commitment": expected,
        "dsc_issuer_profile_commitment": hmac.new(
            b"private-api-key", b"issuer-profile:profile-dsc", hashlib.sha256).hexdigest(),
        "managed_profile_binding_verified": True,
    }
    assert "profile-csca" not in str(result)
    assert "managed-kms-csca" not in str(result)
    assert "private_data_for_test" not in str(result)


@pytest.mark.parametrize("target,path,value", [
    ("csca", ("issuer_profile", "id"), "profile-dsc"),
    ("csca", ("issuer_profile", "signing_key_reference"), "managed-kms-dsc"),
    ("dsc", ("issuer_profile", "status"), "draft"),
    ("dsc", ("issuer_profile", "key_purpose"), "csca"),
    ("dsc", ("issuer_profile", "credential_format"), "VC_JWT"),
    ("dsc", ("issuer_profile", "organization_id"), "foreign-org"),
    ("dsc", ("issuer_profile", "signing_service_id"), "custom-service"),
    ("dsc", ("signing_service", "managed"), False),
    ("dsc", ("signing_service", "service_type"), "custom-transit-compatible"),
    ("dsc", ("signing_service", "status"), "degraded"),
    ("dsc", ("signing_service", "key_aliases"), []),
    ("dsc", ("resolver", "public_fallback_used"), True),
])
def test_rejects_unproven_managed_binding(target: str, path: tuple[str, str], value: object) -> None:
    csca, dsc = resolution("csca"), resolution("dsc")
    subject = csca if target == "csca" else dsc
    subject[path[0]][path[1]] = value
    with pytest.raises(IssuerProfileEvidenceError):
        verify(csca, dsc)


def test_rejects_same_key_despite_distinct_profiles() -> None:
    csca, dsc = resolution("csca"), resolution("dsc")
    dsc["issuer_profile"]["signing_key_reference"] = csca["issuer_profile"]["signing_key_reference"]
    dsc["signing_service"]["key_aliases"] = copy.copy(csca["signing_service"]["key_aliases"])
    with pytest.raises(IssuerProfileEvidenceError, match="distinct managed"):
        verify(csca, dsc)
