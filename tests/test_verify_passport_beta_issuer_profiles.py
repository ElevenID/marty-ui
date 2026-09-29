"""Private profile evidence must reject unrelated custody and expose only HMACs."""

from __future__ import annotations

import copy
import base64
import hashlib
import hmac

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts import verify_passport_beta_issuer_profiles as profile_evidence
from scripts.verify_passport_beta_issuer_profiles import (
    IssuerProfileEvidenceError, resolve_in_container, verify_profile_certificates,
    verify_profiles,
)
from tests.test_probe_passport_beta_chain import certificates


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


def test_live_profile_certificates_bind_to_governed_chain() -> None:
    csca, dsc = resolution("csca"), resolution("dsc")
    csca_pem, dsc_pem, _ = certificates()
    csca_certificate = x509.load_pem_x509_certificate(csca_pem.encode())
    csca_der = csca_certificate.public_bytes(serialization.Encoding.DER)
    dsc_der = x509.load_pem_x509_certificate(dsc_pem.encode()).public_bytes(serialization.Encoding.DER)
    coordinates = csca_certificate.public_key().public_numbers()
    csca["public_jwk"] = {
        "kty": "EC", "crv": "P-256",
        "x": base64.urlsafe_b64encode(coordinates.x.to_bytes(32, "big")).decode().rstrip("="),
        "y": base64.urlsafe_b64encode(coordinates.y.to_bytes(32, "big")).decode().rstrip("="),
    }
    csca["issuer_x5c"] = []  # CSCA lifecycle storage does not populate this override.
    dsc["issuer_x5c"] = [base64.b64encode(dsc_der).decode("ascii")]
    chain = {
        "csca_http_status": 200, "dsc_http_status": 200,
        "chain_verified_by": "openssl-x509-strict",
        "csca_certificate_sha256": hashlib.sha256(csca_der).hexdigest(),
        "dsc_certificate_sha256": hashlib.sha256(dsc_der).hexdigest(),
    }

    def check() -> dict:
        return verify_profile_certificates("org-a", csca["issuer_did"], dsc["issuer_did"],
                                           csca, dsc, chain, csca_pem, "private-api-key")

    assert check()["managed_kms_custody_verified"] is True
    assert check()["chain_verified"] is True
    dsc["issuer_x5c"] = [base64.b64encode(b"rotated-dsc").decode("ascii")]
    with pytest.raises(IssuerProfileEvidenceError, match="differs from ceremony"):
        check()
    dsc["issuer_x5c"] = []
    with pytest.raises(IssuerProfileEvidenceError, match="unavailable"):
        check()
    dsc["issuer_x5c"] = [base64.b64encode(dsc_der).decode("ascii")]
    csca["public_jwk"]["x"] = "stale-x"
    with pytest.raises(IssuerProfileEvidenceError, match="resolved managed key"):
        check()
    csca["public_jwk"]["x"] = base64.urlsafe_b64encode(
        coordinates.x.to_bytes(32, "big")).decode().rstrip("=")
    chain["dsc_http_status"] = 503
    with pytest.raises(IssuerProfileEvidenceError, match="unverified"):
        check()


def test_private_resolution_keeps_token_inside_selected_container(monkeypatch) -> None:
    calls = []

    def run(command, *, input, capture_output, timeout, check):
        calls.append((command, input, capture_output, timeout, check))
        return type("Result", (), {"stdout": b'{"ok":true}'})()

    monkeypatch.setattr(profile_evidence.subprocess, "run", run)
    result = resolve_in_container("a" * 64, "org-a", "did:web:beta.example:org:passport", "csca")
    assert result == {"ok": True}
    command, body, captured, timeout, check = calls[0]
    assert command[:4] == ["docker", "exec", "-i", "a" * 64]
    assert "127.0.0.1:8017/internal/compat/resolve-issuer-did" in command[-1]
    assert "SIGNING_KEYS_INTERNAL_API_KEY_FILE" in command[-1]
    assert b'"key_purpose":"csca"' in body
    assert captured and check and timeout == 30
    assert "org-a" not in str(command)
    assert "did:web" not in str(command)


def test_private_resolution_rejects_invalid_container_before_docker(monkeypatch) -> None:
    monkeypatch.setattr(profile_evidence.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("docker must not run"))
    with pytest.raises(IssuerProfileEvidenceError, match="input is invalid"):
        resolve_in_container("signing-keys", "org-a", "did:web:beta.example", "csca")
