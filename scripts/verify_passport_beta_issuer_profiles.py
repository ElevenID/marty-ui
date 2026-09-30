"""Sanitize protected Signing Keys issuer resolution for passport evidence.

The private resolver is called inside the selected beta Signing Keys container.
This module never publishes its response, which contains KMS key references and
DID documents.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import subprocess
from typing import Any, Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class IssuerProfileEvidenceError(ValueError):
    pass


CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


def _post_in_container(container_id: str, route: str, body: dict[str, Any]) -> dict[str, Any]:
    if (not isinstance(container_id, str) or CONTAINER_ID.fullmatch(container_id) is None
            or route not in ("/internal/compat/resolve-issuer-did",
                             "/internal/compat/issuer-dids/sign")):
        raise IssuerProfileEvidenceError("Private issuer request input is invalid")
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    command = [
        "docker", "exec", "-i", container_id, "sh", "-eu", "-c",
        'key="${SIGNING_KEYS_INTERNAL_API_KEY:-}"; '
        'if [ -z "$key" ] && [ -n "${SIGNING_KEYS_INTERNAL_API_KEY_FILE:-}" ]; '
        'then key="$(cat "$SIGNING_KEYS_INTERNAL_API_KEY_FILE")"; fi; '
        '[ -n "$key" ] || exit 4; '
        'exec curl --fail --silent --show-error --max-time 20 '
        '-H "Content-Type: application/json" -H "x-api-key: $key" '
        f'--data-binary @- http://127.0.0.1:8017{route}',
    ]
    try:
        result = subprocess.run(command, input=payload, capture_output=True,
                                timeout=30, check=True)
        if len(result.stdout) > 256 * 1024:
            raise IssuerProfileEvidenceError("Private issuer response is oversized")
        response = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise IssuerProfileEvidenceError("Private issuer request failed") from exc
    if not isinstance(response, dict):
        raise IssuerProfileEvidenceError("Private issuer response is invalid")
    return response


def resolve_in_container(container_id: str, organization_id: str,
                         issuer_did: str, key_purpose: str) -> dict[str, Any]:
    """Resolve through the private Rust service without exporting its token."""
    if (not isinstance(container_id, str) or CONTAINER_ID.fullmatch(container_id) is None
            or not isinstance(organization_id, str) or not organization_id
            or not isinstance(issuer_did, str) or not issuer_did.startswith("did:")
            or key_purpose not in ("csca", "x509_doc_signer")):
        raise IssuerProfileEvidenceError("Private issuer resolution input is invalid")
    return _post_in_container(container_id, "/internal/compat/resolve-issuer-did", {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "credential_format": "ICAO_EMRTD",
        "key_purpose": key_purpose,
        "algorithm": "ES256",
    })


def sign_in_container(container_id: str, organization_id: str, issuer_did: str,
                      key_purpose: str, challenge: bytes) -> dict[str, Any]:
    if (not isinstance(organization_id, str) or not organization_id
            or not isinstance(issuer_did, str) or not issuer_did.startswith("did:")
            or key_purpose not in ("csca", "x509_doc_signer")
            or not isinstance(challenge, bytes) or len(challenge) != 48):
        raise IssuerProfileEvidenceError("Private issuer signing input is invalid")
    return _post_in_container(container_id, "/internal/compat/issuer-dids/sign", {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "credential_format": "ICAO_EMRTD",
        "key_purpose": key_purpose,
        "algorithm": "ES256",
        "payload_b64": base64.urlsafe_b64encode(challenge).decode("ascii").rstrip("="),
    })


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


def verify_profile_certificates(
    organization_id: str,
    csca_issuer_did: str,
    dsc_issuer_did: str,
    csca_resolution: dict[str, Any],
    dsc_resolution: dict[str, Any],
    chain_evidence: dict[str, Any],
    csca_certificate_pem: str,
    api_key: str,
) -> dict[str, Any]:
    """Bind profile certificates to ceremonies; live key proof is separate."""
    binding = verify_profiles(organization_id, csca_issuer_did, dsc_issuer_did,
                              csca_resolution, dsc_resolution, api_key)
    if (not isinstance(chain_evidence, dict)
            or chain_evidence.get("csca_http_status") != 200
            or chain_evidence.get("dsc_http_status") != 200
            or chain_evidence.get("chain_verified_by") != "openssl-x509-strict"):
        raise IssuerProfileEvidenceError("Governed certificate chain is unverified")
    csca_expected = chain_evidence.get("csca_certificate_sha256")
    dsc_expected = chain_evidence.get("dsc_certificate_sha256")
    if any(not isinstance(digest, str) or len(digest) != 64
           or any(character not in "0123456789abcdef" for character in digest)
           for digest in (csca_expected, dsc_expected)):
        raise IssuerProfileEvidenceError("Governed certificate digests are unavailable")
    try:
        if not isinstance(csca_certificate_pem, str):
            raise ValueError("missing CSCA PEM")
        csca_certificate = x509.load_pem_x509_certificate(csca_certificate_pem.encode("ascii"))
        csca_der = csca_certificate.public_bytes(serialization.Encoding.DER)
    except (ValueError, UnicodeError) as exc:
        raise IssuerProfileEvidenceError("CSCA ceremony certificate is invalid") from exc
    if hashlib.sha256(csca_der).hexdigest() != csca_expected:
        raise IssuerProfileEvidenceError("CSCA certificate differs from ceremony")
    jwk = csca_resolution.get("public_jwk")
    public_key = csca_certificate.public_key()
    if (not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256"
            or not isinstance(public_key, ec.EllipticCurvePublicKey)
            or not isinstance(public_key.curve, ec.SECP256R1)):
        raise IssuerProfileEvidenceError("CSCA certificate does not use the resolved managed key")
    coordinates = public_key.public_numbers()
    if (jwk.get("x") != base64.urlsafe_b64encode(coordinates.x.to_bytes(32, "big")).decode().rstrip("=")
            or jwk.get("y") != base64.urlsafe_b64encode(coordinates.y.to_bytes(32, "big")).decode().rstrip("=")):
        raise IssuerProfileEvidenceError("CSCA certificate does not use the resolved managed key")
    x5c = dsc_resolution.get("issuer_x5c")
    if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
        raise IssuerProfileEvidenceError("DSC profile certificate is unavailable")
    try:
        dsc_der = base64.b64decode(x5c[0], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IssuerProfileEvidenceError("DSC profile certificate is invalid") from exc
    if hashlib.sha256(dsc_der).hexdigest() != dsc_expected:
        raise IssuerProfileEvidenceError("DSC profile certificate differs from ceremony")
    return {
        "csca_issuer_profile_commitment": binding["csca_issuer_profile_commitment"],
        "dsc_issuer_profile_commitment": binding["dsc_issuer_profile_commitment"],
        "profile_certificate_binding_verified": True,
        "chain_verified": True,
    }


def verify_live_signatures(
    organization_id: str,
    csca_issuer_did: str,
    dsc_issuer_did: str,
    csca_resolution: dict[str, Any],
    dsc_resolution: dict[str, Any],
    chain_evidence: dict[str, Any],
    csca_certificate_pem: str,
    api_key: str,
    *,
    signer: Callable[[str, str, str, bytes], dict[str, Any]],
) -> dict[str, Any]:
    """Prove that both current DID-selected KMS keys sign for the selected chain."""
    binding = verify_profile_certificates(
        organization_id, csca_issuer_did, dsc_issuer_did,
        csca_resolution, dsc_resolution, chain_evidence, csca_certificate_pem, api_key,
    )
    csca_certificate = x509.load_pem_x509_certificate(csca_certificate_pem.encode("ascii"))
    dsc_der = base64.b64decode(dsc_resolution["issuer_x5c"][0], validate=True)
    dsc_certificate = x509.load_der_x509_certificate(dsc_der)
    for role, did, resolution, certificate in (
        ("csca", csca_issuer_did, csca_resolution, csca_certificate),
        ("x509_doc_signer", dsc_issuer_did, dsc_resolution, dsc_certificate),
    ):
        challenge = secrets.token_bytes(48)
        signed = signer(organization_id, did, role, challenge)
        if (not isinstance(signed, dict) or signed.get("ok") is not True
                or signed.get("algorithm") != "ES256"
                or signed.get("signature_encoding") != "der"
                or signed.get("payload_length") != len(challenge)
                or signed.get("issuer_did") != did
                or signed.get("verification_method_id") != resolution.get("verification_method_id")
                or not isinstance(signed.get("signature_b64"), str)):
            raise IssuerProfileEvidenceError("Current managed issuer signing proof is incomplete")
        try:
            signature_text = signed["signature_b64"]
            signature = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
            public_key = certificate.public_key()
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise IssuerProfileEvidenceError("Managed issuer certificate key is not ES256")
            public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise IssuerProfileEvidenceError("Current managed key cannot sign for selected certificate") from exc
    return {
        "csca_issuer_profile_commitment": binding["csca_issuer_profile_commitment"],
        "dsc_issuer_profile_commitment": binding["dsc_issuer_profile_commitment"],
        "managed_kms_custody_verified": True,
        "chain_verified": True,
    }
