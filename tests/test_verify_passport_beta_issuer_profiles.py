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
    IssuerProfileEvidenceError, resolve_in_container, sign_in_container,
    verify_live_signatures, verify_profile_certificates, verify_profiles,
)
from tests.test_probe_passport_beta_chain import certificates, public_chain_vectors


def resolution(role: str) -> dict:
    purpose = "csca" if role == "csca" else "x509_doc_signer"
    did = "did:web:beta.example:org:passport"
    reference = f"managed-kms-{role}"
    return {
        "ok": True, "organization_id": "org-a", "issuer_did": did,
        "verification_method_id": f"{did}#{role}",
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

    assert check()["profile_certificate_binding_verified"] is True
    assert "managed_kms_custody_verified" not in check()
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


def test_certificate_material_rejects_trailing_der_or_extra_pem() -> None:
    csca_pem, dsc_pem, _ = certificates()
    dsc_der = x509.load_pem_x509_certificate(dsc_pem.encode()).public_bytes(
        serialization.Encoding.DER)
    with pytest.raises(IssuerProfileEvidenceError, match="trailing DER"):
        profile_evidence._certificate_material(dsc_der + b"JUNK", "DER")
    with pytest.raises(IssuerProfileEvidenceError, match="PEM is invalid"):
        profile_evidence._certificate_material(
            (csca_pem + "JUNK").encode("ascii"), "PEM")


def test_private_resolution_keeps_token_inside_selected_container(monkeypatch) -> None:
    calls = []

    monkeypatch.setenv("DOCKER_HOST", "tcp://foreign.example:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "foreign")
    monkeypatch.setenv("DOCKER_TLS_VERIFY", "1")
    monkeypatch.setenv("DOCKER_CERT_PATH", "/foreign/certs")

    def run(command, *, input, env, capture_output, timeout, check):
        calls.append((command, input, env, capture_output, timeout, check))
        return type("Result", (), {"stdout": b'{"ok":true}'})()

    monkeypatch.setattr(profile_evidence.subprocess, "run", run)
    result = resolve_in_container("a" * 64, "org-a", "did:web:beta.example:org:passport", "csca")
    assert result == {"ok": True}
    command, body, environment, captured, timeout, check = calls[0]
    assert environment["DOCKER_HOST"] == "unix:///var/run/docker.sock"
    assert all(name not in environment for name in (
        "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"))
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


def test_sign_transport_sends_challenge_in_body_only(monkeypatch) -> None:
    captured = []

    def run(command, *, input, env, capture_output, timeout, check):
        captured.append((command, input))
        return type("Result", (), {"stdout": b'{"ok":true}'})()

    monkeypatch.setattr(profile_evidence.subprocess, "run", run)
    challenge = b"z" * 48
    assert sign_in_container("a" * 64, "org-a", "did:web:beta.example", "csca", challenge) == {"ok": True}
    command, body = captured[0]
    assert command[-1].endswith("/internal/compat/issuer-dids/sign")
    assert base64.urlsafe_b64encode(challenge).rstrip(b"=") in body
    assert challenge.decode() not in str(command)


def test_fresh_signing_challenges_reject_replay_and_wrong_key_vectors(monkeypatch) -> None:
    fixture = public_chain_vectors()
    challenges = {
        name: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        for name, value in fixture["challenges"].items()
    }
    order = (
        "csca_positive", "dsc_positive", "csca_replay", "dsc_replay",
        "csca_rotated", "dsc_rotated",
    )
    assert len({challenges[name] for name in order}) == len(order)
    remaining = iter(challenges[name] for name in order)
    def next_challenge(size: int) -> bytes:
        assert size == 48
        return next(remaining)

    monkeypatch.setattr(profile_evidence.secrets, "token_bytes", next_challenge)
    csca, dsc = resolution("csca"), resolution("dsc")
    csca_pem = fixture["csca"]
    csca_cert = x509.load_pem_x509_certificate(csca_pem.encode("ascii"))
    coordinates = csca_cert.public_key().public_numbers()
    csca["public_jwk"] = {
        "kty": "EC", "crv": "P-256",
        "x": base64.urlsafe_b64encode(coordinates.x.to_bytes(32, "big")).decode().rstrip("="),
        "y": base64.urlsafe_b64encode(coordinates.y.to_bytes(32, "big")).decode().rstrip("="),
    }
    dsc_der = x509.load_pem_x509_certificate(fixture["dsc"].encode("ascii")).public_bytes(
        serialization.Encoding.DER
    )
    dsc["issuer_x5c"] = [base64.b64encode(dsc_der).decode()]
    chain = {"csca_http_status": 200, "dsc_http_status": 200,
             "chain_verified_by": "openssl-x509-strict",
             "csca_certificate_sha256": hashlib.sha256(csca_cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
             "dsc_certificate_sha256": hashlib.sha256(dsc_der).hexdigest()}

    def signer(org: str, did: str, purpose: str, challenge: bytes) -> dict:
        assert org == "org-a" and did == csca["issuer_did"] and len(challenge) == 48
        role = "csca" if purpose == "csca" else "dsc"
        label = next(name for name in order if challenges[name] == challenge)
        assert label.startswith(role)
        signature_name = {
            "dsc_replay": "dsc_positive",
            "dsc_rotated": "wrong_dsc_rotated",
        }.get(label, label)
        return {"ok": True, "algorithm": "ES256", "signature_encoding": "der",
                "payload_length": 48, "issuer_did": did,
                "verification_method_id": csca["verification_method_id"] if role == "csca"
                else dsc["verification_method_id"],
                "signature_b64": fixture["signatures"][signature_name]}

    def check(sign):
        return verify_live_signatures("org-a", csca["issuer_did"], dsc["issuer_did"],
                                      csca, dsc, chain, csca_pem, "private-api-key", signer=sign)

    assert check(signer)["managed_kms_custody_verified"] is True
    with pytest.raises(IssuerProfileEvidenceError, match="cannot sign"):
        check(signer)
    with pytest.raises(IssuerProfileEvidenceError, match="cannot sign"):
        check(signer)
    with pytest.raises(StopIteration):
        next(remaining)
