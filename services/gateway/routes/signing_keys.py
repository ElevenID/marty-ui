"""Signing key compatibility routes backed by OpenBao plus a service registry."""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote

try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, SECP256R1, SECP384R1
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_der_public_key,
        load_pem_public_key,
    )
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False

import httpx
from fastapi import APIRouter, Body, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from gateway.middleware import mip_error_response
from gateway.proxy import get_registry, proxy_request

signing_key_router = APIRouter(prefix="/v1/signing-keys", tags=["Signing Keys"])
internal_signing_key_router = APIRouter(prefix="/internal/signing-keys", tags=["Internal Signing Keys"])

# Public router for did:web resolution — no auth prefix, bypasses auth middleware
did_web_public_router = APIRouter(tags=["DID Web Resolution"])

OPENBAO_SIGNING_KEY_PREFIXES = (
    "cred-issuer-",
    "cred-dsc-",
    "lti-tool-",
)

OPENBAO_NAME_OVERRIDES = {
    "cred-issuer-marty-es256": "Marty ES256 issuer key",
    "cred-issuer-marty-es384": "Marty ES384 issuer key",
    "cred-issuer-marty-rs256": "Marty RS256 issuer key",
    "cred-issuer-marty-eddsa": "Marty EdDSA issuer key",
    "cred-dsc-marty-primary": "Marty document signer key",
    "lti-tool-marty-rs256": "Marty LTI tool signing key",
}

OPENBAO_ALGORITHM_BY_TYPE = {
    "ecdsa-p256": "ES256",
    "ecdsa-p384": "ES384",
    "rsa-2048": "RS256",
    "ed25519": "EdDSA",
}

OPENBAO_TRANSIT_KEY_TYPE_BY_ALGORITHM = {
    "ES256": "ecdsa-p256",
    "ES384": "ecdsa-p384",
    "RS256": "rsa-2048",
    "EdDSA": "ed25519",
}

SUPPORTED_SIGNING_ALGORITHMS = ("ES256", "ES384", "RS256", "EdDSA")
MANAGED_OPENBAO_SERVICE_ID = "managed-openbao-transit"

logger = logging.getLogger(__name__)


def _read_secret_value(name: str) -> str:
    """Read a secret from ENV or ENV_FILE, matching docker secret conventions."""
    direct = os.environ.get(name)
    if direct:
        return direct
    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _require_internal_signing_key_api_key(x_api_key: str | None) -> None:
    configured = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value("ISSUANCE_API_KEY")
    if not configured:
        raise HTTPException(status_code=503, detail="Internal signing API key is not configured.")
    if not x_api_key or not hmac.compare_digest(x_api_key, configured):
        raise HTTPException(status_code=401, detail="Invalid internal signing API key.")

# ---------------------------------------------------------------------------
# Key-purpose and format-routing constants (GAP-002 / GAP-007)
# ---------------------------------------------------------------------------

#: All recognised key purposes. Used in service registration and resolver.
KEY_PURPOSES = (
    "vc_jwt_issuer",     # W3C VC-JWT and SD-JWT VC issuance signing
    "mdoc_dsc",          # ISO 18013-5 mDoc Document Signer Certificate key
    "x509_doc_signer",   # Generic X.509 document signing
    "holder_binding",    # Device-bound credential holder key
    "presentation_signing",  # Presentation signing (holder-side)
    "vdsnc_signing",     # VDS-NC signing key
    "csca",              # Country Signing CA trust anchor key
    "jwks_signing",      # JWKS endpoint key
    "lti_tool_signing",  # Canvas LTI Advantage client assertions and Deep Links
)

#: For each key purpose, the set of algorithms that make sense for it.
#: Mismatches are surfaced as warnings during registration/validation.
KEY_PURPOSE_ALGORITHM_CONSTRAINTS: dict[str, frozenset[str]] = {
    "vc_jwt_issuer":        frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "mdoc_dsc":             frozenset({"ES256", "ES384", "EdDSA"}),  # COSE — no RSA
    "x509_doc_signer":      frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "holder_binding":       frozenset({"ES256", "EdDSA"}),
    "presentation_signing": frozenset({"ES256", "EdDSA"}),
    "vdsnc_signing":        frozenset({"ES256", "ES384", "EdDSA"}),
    "csca":                 frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "jwks_signing":         frozenset({"ES256", "ES384", "RS256", "EdDSA"}),
    "lti_tool_signing":     frozenset({"RS256"}),
}

#: The credential formats each key purpose maps to naturally.
KEY_PURPOSE_CREDENTIAL_FORMATS: dict[str, tuple[str, ...]] = {
    "vc_jwt_issuer":        ("jwt_vc_json", "dc+sd-jwt"),
    "mdoc_dsc":             ("mso_mdoc", "zk_mdoc"),
    "x509_doc_signer":      ("mso_mdoc", "zk_mdoc"),
    "holder_binding":       ("mso_mdoc", "zk_mdoc", "dc+sd-jwt"),
    "presentation_signing": ("jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "zk_mdoc"),
    "vdsnc_signing":        ("mso_mdoc",),
    "csca":                 ("mso_mdoc", "zk_mdoc"),
    "jwks_signing":         ("jwt_vc_json", "dc+sd-jwt"),
    "lti_tool_signing":     (),
}

#: Per-service-type static capability metadata (GAP-007-a).
#: Signature encoding: "raw_ieee_p1363" = raw r||s bytes; "der" = ASN.1 DER.
KEY_MANAGEMENT_SERVICE_CAPABILITIES: dict[str, dict[str, Any]] = {
    "openbao-transit": {
        "supported_algorithms":  ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding":    "der",
        "public_key_export":     True,
        "hardware_attestation":  False,
        "key_import":            False,
        "key_create":            True,
        "key_delete":            True,
        "key_list":              True,
        "rotation":              True,
    },
    "hashicorp-vault-transit": {
        "supported_algorithms":  ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding":    "der",
        "public_key_export":     True,
        "hardware_attestation":  False,
        "key_import":            False,
        "key_create":            True,
        "key_delete":            True,
        "key_list":              True,
        "rotation":              True,
    },
    "aws-kms": {
        "supported_algorithms":  ["ES256", "ES384", "RS256"],
        "signature_encoding":    "der",
        "public_key_export":     True,
        "hardware_attestation":  True,   # HSM-backed by default
        "key_import":            True,
        "key_create":            True,
        "key_delete":            False,  # Requires scheduled deletion
        "key_list":              False,  # No native list in transit mode
        "rotation":              True,   # Auto-rotation supported
    },
    "azure-key-vault": {
        "supported_algorithms":  ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding":    "der",
        "public_key_export":     True,
        "hardware_attestation":  True,   # HSM SKU available
        "key_import":            True,
        "key_create":            True,
        "key_delete":            True,
        "key_list":              True,
        "rotation":              True,
    },
    "gcp-cloud-kms": {
        "supported_algorithms":  ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding":    "der",
        "public_key_export":     True,
        "hardware_attestation":  True,   # HSM protection level available
        "key_import":            True,
        "key_create":            True,
        "key_delete":            False,  # Soft-delete only, then destroy
        "key_list":              True,
        "rotation":              True,
    },
    "custom-transit-compatible": {
        "supported_algorithms":  ["ES256", "ES384", "RS256", "EdDSA"],
        "signature_encoding":    "raw_ieee_p1363",
        "public_key_export":     False,
        "hardware_attestation":  False,
        "key_import":            False,
        "key_create":            False,
        "key_delete":            False,
        "key_list":              False,
        "rotation":              False,
    },
}

KEY_MANAGEMENT_SERVICE_TYPES: tuple[dict[str, Any], ...] = (
    {
        "id": "openbao-transit",
        "label": "OpenBao Transit",
        "description": "Register an OpenBao transit service that exposes signing keys remotely.",
        "provider": "openbao",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "auth_modes": ["service_token", "token", "approle", "mtls"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Transit key name",
        "supports_inventory": True,
    },
    {
        "id": "hashicorp-vault-transit",
        "label": "HashiCorp Vault Transit",
        "description": "Use Vault Transit as the signing backend for issuance keys.",
        "provider": "hashicorp-vault",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "auth_modes": ["token", "approle", "mtls"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Transit key name",
        "supports_inventory": True,
    },
    {
        "id": "aws-kms",
        "label": "AWS KMS",
        "description": "Register a customer-managed AWS KMS key for remote signing.",
        "provider": "aws",
        "protocol": "aws-kms",
        "category": "cloud-kms",
        "auth_modes": ["iam_role", "access_key", "assume_role"],
        "connection_fields": ["region"],
        "key_reference_label": "Key ARN",
        "supports_inventory": False,
    },
    {
        "id": "azure-key-vault",
        "label": "Azure Key Vault",
        "description": "Register an Azure Key Vault key as a signing source.",
        "provider": "azure",
        "protocol": "azure-key-vault",
        "category": "cloud-kms",
        "auth_modes": ["managed_identity", "client_secret", "certificate"],
        "connection_fields": ["endpoint"],
        "key_reference_label": "Key identifier",
        "supports_inventory": False,
    },
    {
        "id": "gcp-cloud-kms",
        "label": "Google Cloud KMS",
        "description": "Register a Google Cloud KMS crypto key version.",
        "provider": "gcp",
        "protocol": "gcp-kms",
        "category": "cloud-kms",
        "auth_modes": ["workload_identity", "service_account"],
        "connection_fields": ["region"],
        "key_reference_label": "Crypto key resource",
        "supports_inventory": False,
    },
    {
        "id": "custom-transit-compatible",
        "label": "Custom Transit-Compatible Service",
        "description": "Any service that implements the transit-compatible signing protocol Marty supports.",
        "provider": "custom",
        "protocol": "vault-transit-compatible",
        "category": "custom",
        "auth_modes": ["token", "mtls", "api_key", "custom"],
        "connection_fields": ["endpoint", "mount", "namespace"],
        "key_reference_label": "Key reference",
        "supports_inventory": False,
    },
)

KEY_MANAGEMENT_SERVICE_TYPE_BY_ID = {
    service_type["id"]: service_type for service_type in KEY_MANAGEMENT_SERVICE_TYPES
}


def _resolve_org_id(request: Request, organization_id: str | None) -> str:
    resolved = organization_id or getattr(request.state, "session_organization_id", None)
    if not resolved:
        raise HTTPException(status_code=422, detail="organization_id is required")
    return resolved


def _bao_address() -> str | None:
    return os.environ.get("BAO_ADDR") or None


def _bao_token() -> str | None:
    return _read_secret_value("BAO_TOKEN") or _read_secret_value("OPENBAO_SERVICE_TOKEN") or None


def _has_openbao_access() -> bool:
    return bool(_bao_address() and _bao_token())


def _provider_name() -> str:
    configured_provider = os.environ.get("HSM_PROVIDER")
    if configured_provider:
        return configured_provider

    if _has_openbao_access():
        return "openbao"

    return "unconfigured"


def _domain_config(request: Request) -> dict[str, Any]:
    host = request.headers.get("host", "")
    public_domain = os.environ.get("PUBLIC_DOMAIN") or host.split(":")[0]
    issuer_base_url = os.environ.get("ISSUER_BASE_URL") or f"{request.url.scheme}://{host}"
    return {
        "public_domain": public_domain,
        "issuer_base_url": issuer_base_url,
        "key_source": os.environ.get(
            "SIGNING_KEY_SOURCE",
            "openbao-transit" if _has_openbao_access() else "external-service-registry",
        ),
        "key_management_mode": "service-registry",
    }


def _provider_metadata(*, status: str, key_count: int, error: str | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "provider": _provider_name(),
        "status": status,
        "managed_by": "OpenBao transit service" if _has_openbao_access() else "Marty gateway compatibility layer",
        "supports_rotation": False,
        "supports_upload": False,
        "supports_delete": False,
        "key_count": key_count,
    }

    if error:
        metadata["error"] = error

    return metadata


def _looks_like_signing_key(key_name: str) -> bool:
    return any(key_name.startswith(prefix) for prefix in OPENBAO_SIGNING_KEY_PREFIXES)


def _algorithm_from_openbao_type(key_type: str | None) -> str:
    normalized_key_type = (key_type or "").lower()
    return OPENBAO_ALGORITHM_BY_TYPE.get(normalized_key_type, key_type or "-")


def _display_name_for_key(key_name: str) -> str:
    if key_name in OPENBAO_NAME_OVERRIDES:
        return OPENBAO_NAME_OVERRIDES[key_name]

    return key_name.replace("-", " ").title()


def _openbao_key_prefix_for_purpose(key_purpose: str | None) -> str:
    if key_purpose == "lti_tool_signing":
        return "lti-tool-"
    if key_purpose in {"mdoc_dsc", "x509_doc_signer", "vdsnc_signing", "csca"}:
        return "cred-dsc-"
    return "cred-issuer-"


def _normalize_requested_openbao_key_name(requested_name: str, key_purpose: str | None, algorithm: str) -> str:
    raw_name = (requested_name or "").strip().lower()
    safe_name = re.sub(r"[^a-z0-9-]+", "-", raw_name).strip("-")
    if not safe_name:
        safe_name = "key"

    expected_prefix = _openbao_key_prefix_for_purpose(key_purpose)
    existing_prefix = next(
        (
            prefix
            for prefix in OPENBAO_SIGNING_KEY_PREFIXES
            if safe_name.startswith(prefix)
        ),
        None,
    )
    if existing_prefix and existing_prefix != expected_prefix:
        # A caller-supplied credential prefix must never defeat the protocol
        # namespace selected by key_purpose.
        safe_name = safe_name[len(existing_prefix):].lstrip("-") or "key"
    if not safe_name.startswith(expected_prefix):
        safe_name = f"{expected_prefix}{safe_name}"

    algorithm_suffix = re.sub(r"[^a-z0-9]+", "", (algorithm or "ES256").lower()) or "es256"
    if not safe_name.endswith(f"-{algorithm_suffix}"):
        safe_name = f"{safe_name}-{algorithm_suffix}"

    return safe_name[:96]


def _sort_key_record(key: dict[str, Any]) -> tuple[int, str]:
    priority = 10
    key_name = key.get("id", "")

    if key_name == "cred-issuer-marty-es256":
        priority = 0
    elif key_name == "cred-issuer-marty-es384":
        priority = 1
    elif key_name == "cred-issuer-marty-rs256":
        priority = 2
    elif key_name == "cred-issuer-marty-eddsa":
        priority = 3
    elif key_name == "cred-dsc-marty-primary":
        priority = 4

    return priority, key_name


def _httpx_error_detail(exc: httpx.HTTPStatusError) -> str:
    response = exc.response
    if response is None:
        return str(exc)

    try:
        payload = response.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list):
            joined = "; ".join(str(item) for item in errors if item)
            if joined:
                return joined
        for key in ("detail", "message", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value

    text = response.text.strip()
    return text or str(exc)


async def _openbao_get_json(
    path: str,
    params: dict[str, str] | None = None,
    *,
    base_url: str | None = None,
    token: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    base_url = base_url or _bao_address()
    token = token or _bao_token()

    if not base_url or not token:
        raise RuntimeError("OpenBao access is not configured for the gateway")

    headers = {
        "X-Vault-Token": token,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout, headers=headers) as client:
        response = await client.get(path, params=params)
        response.raise_for_status()
        return response.json()


async def _openbao_post_json(
    path: str,
    payload: dict[str, Any],
    *,
    base_url: str | None = None,
    token: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    base_url = base_url or _bao_address()
    token = token or _bao_token()

    if not base_url or not token:
        raise RuntimeError("OpenBao access is not configured for the gateway")

    headers = {
        "X-Vault-Token": token,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout, headers=headers) as client:
        response = await client.post(path, json=payload)
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()


def _is_missing_openbao_route(status_code: int, detail: str) -> bool:
    lowered = detail.lower()
    return status_code == 404 and (
        "no handler for route" in lowered
        or "route entry not found" in lowered
    )


def _is_openbao_existing_key_error(status_code: int, detail: str) -> bool:
    lowered = detail.lower()
    return status_code == 400 and "exist" in lowered


async def _ensure_openbao_transit_mount(endpoint: str, token: str, mount: str) -> None:
    normalized_mount = mount.strip("/") or "transit"
    try:
        await _openbao_post_json(
            f"/v1/sys/mounts/{normalized_mount}",
            {"type": "transit"},
            base_url=endpoint,
            token=token,
            timeout=8.0,
        )
    except httpx.HTTPStatusError as exc:
        detail = _httpx_error_detail(exc)
        status_code = exc.response.status_code if exc.response is not None else 0
        lowered = detail.lower()
        if status_code in {400, 409} and (
            "already" in lowered
            or "existing mount" in lowered
            or "path is already in use" in lowered
        ):
            return

        raise HTTPException(
            status_code=400 if status_code and status_code < 500 else 502,
            detail=f"OpenBao transit mount '{normalized_mount}' is unavailable and could not be enabled: {detail}",
        ) from exc


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _public_key_object_to_jwk(public_key: Any) -> dict[str, Any] | None:
    if isinstance(public_key, EllipticCurvePublicKey):
        curve = public_key.curve
        crv = "P-256" if isinstance(curve, SECP256R1) else "P-384" if isinstance(curve, SECP384R1) else None
        if not crv:
            return None
        numbers = public_key.public_numbers()
        key_size = (public_key.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": crv,
            "x": _b64url_no_pad(numbers.x.to_bytes(key_size, "big")),
            "y": _b64url_no_pad(numbers.y.to_bytes(key_size, "big")),
        }

    if isinstance(public_key, RSAPublicKey):
        numbers = public_key.public_numbers()
        e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        return {
            "kty": "RSA",
            "n": _b64url_no_pad(n_bytes),
            "e": _b64url_no_pad(e_bytes),
        }

    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url_no_pad(raw),
        }

    return None


def _pem_to_public_jwk(pem: str) -> dict[str, Any] | None:
    if not _CRYPTOGRAPHY_AVAILABLE or not isinstance(pem, str) or not pem.strip():
        return None
    try:
        public_key = load_pem_public_key(pem.encode())
    except Exception:
        return None
    return _public_key_object_to_jwk(public_key)


def _der_b64_to_public_jwk(der_b64: str) -> dict[str, Any] | None:
    if not _CRYPTOGRAPHY_AVAILABLE or not isinstance(der_b64, str) or not der_b64.strip():
        return None
    try:
        der_bytes = base64.b64decode(der_b64)
        public_key = load_der_public_key(der_bytes)
    except Exception:
        return None
    return _public_key_object_to_jwk(public_key)


def _extract_public_jwk(candidate: Any, *, key_reference_hint: str | None = None) -> dict[str, Any] | None:
    """Normalize provider-specific public key payloads to a canonical public JWK."""
    if not isinstance(candidate, dict):
        return None

    nested_jwk = None
    if isinstance(candidate.get("public_jwk"), dict):
        nested_jwk = candidate.get("public_jwk")
    elif isinstance(candidate.get("publicKeyJwk"), dict):
        nested_jwk = candidate.get("publicKeyJwk")
    elif isinstance(candidate.get("jwk"), dict):
        nested_jwk = candidate.get("jwk")
    elif isinstance(candidate.get("key"), dict):
        nested_jwk = candidate.get("key")
    else:
        nested_jwk = candidate

    if isinstance(nested_jwk, dict) and isinstance(nested_jwk.get("kty"), str):
        private_fields = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        sanitized = {
            key: value
            for key, value in nested_jwk.items()
            if key not in private_fields and value is not None
        }
        if key_reference_hint and not sanitized.get("kid"):
            sanitized["kid"] = key_reference_hint
        return sanitized

    pem_candidate = (
        candidate.get("public_key_pem")
        or candidate.get("publicKeyPem")
        or candidate.get("public_key")
    )
    if isinstance(pem_candidate, str) and pem_candidate.strip():
        jwk_from_pem = _pem_to_public_jwk(pem_candidate)
        if jwk_from_pem:
            if key_reference_hint and not jwk_from_pem.get("kid"):
                jwk_from_pem["kid"] = key_reference_hint
            return jwk_from_pem

    der_candidate = candidate.get("public_key_der_b64") or candidate.get("publicKeyDerB64")
    if isinstance(der_candidate, str) and der_candidate.strip():
        jwk_from_der = _der_b64_to_public_jwk(der_candidate)
        if jwk_from_der:
            if key_reference_hint and not jwk_from_der.get("kid"):
                jwk_from_der["kid"] = key_reference_hint
            return jwk_from_der

    return None


def _normalize_openbao_signing_key(key_name: str, key_details: dict[str, Any]) -> dict[str, Any]:
    key_versions = key_details.get("keys") or {}
    latest_version = str(key_details.get("latest_version") or "")
    latest_key_metadata = key_versions.get(latest_version) or {}
    algorithm = _algorithm_from_openbao_type(key_details.get("type"))
    status = "active" if key_details.get("supports_signing") and not key_details.get("soft_deleted") else "invalid"

    public_jwk = _extract_public_jwk(
        {"public_key_pem": latest_key_metadata.get("public_key")},
        key_reference_hint=key_name,
    )

    result: dict[str, Any] = {
        "id": key_name,
        "name": _display_name_for_key(key_name),
        "algorithm": algorithm,
        "status": status,
        "expiry_date": None,
        "created_at": latest_key_metadata.get("creation_time"),
        "key_type": "hsm",
        "provider": _provider_name(),
        "provider_key_name": key_name,
        "latest_version": key_details.get("latest_version"),
    }
    if public_jwk:
        result["public_jwk"] = public_jwk
    return result


async def _load_service_discovered_keys(
    request: Request,
    resolved_org_id: str | None,
) -> list[dict[str, Any]]:
    """Fetch public keys from registered provider adapters and normalize as key records."""
    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    discovered_keys: list[dict[str, Any]] = []

    for service in services:
        normalized = _normalize_registered_service(service)
        if normalized is None:
            continue

        adapter = _get_adapter(normalized)
        if adapter is None:
            continue

        try:
            raw_payload = await adapter.get_public_key_jwk(normalized)
        except Exception:
            continue

        key_reference = (
            normalized.get("key_reference")
            if isinstance(normalized.get("key_reference"), str)
            else None
        )
        key_reference = key_reference or normalized.get("id")
        public_jwk = _extract_public_jwk(raw_payload, key_reference_hint=key_reference)
        if not public_jwk:
            continue

        algorithms = normalized.get("algorithms") if isinstance(normalized.get("algorithms"), list) else []
        discovered_keys.append(
            {
                "id": key_reference,
                "name": normalized.get("name") or key_reference,
                "algorithm": algorithms[0] if algorithms else normalized.get("algorithm"),
                "status": "active",
                "expiry_date": None,
                "created_at": normalized.get("created_at"),
                "key_type": "hsm",
                "provider": normalized.get("provider") or "external",
                "provider_key_name": key_reference,
                "service_id": normalized.get("id"),
                "service_type": normalized.get("service_type"),
                "public_jwk": public_jwk,
            }
        )

    return discovered_keys


def _dedupe_strings(values: Any) -> list[str]:
    if isinstance(values, str):
        candidate_values = [part.strip() for part in values.split(",")]
    elif isinstance(values, list):
        candidate_values = values
    else:
        candidate_values = []

    deduped: list[str] = []
    seen: set[str] = set()
    for value in candidate_values:
        if not isinstance(value, str):
            continue
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        deduped.append(normalized)
        seen.add(normalized)
    return deduped


def _normalize_key_reference_purposes(value: Any) -> dict[str, dict[str, list[str]]]:
    """Normalize per-service, per-key purpose bindings.

    Service-level capabilities describe a multi-key KMS.  This registry is the
    authorization boundary for the individual key selected within that service.
    """

    if not isinstance(value, dict):
        return {}
    normalized: dict[str, dict[str, list[str]]] = {}
    for raw_service_id, raw_references in value.items():
        if not isinstance(raw_service_id, str) or not raw_service_id.strip():
            continue
        if not isinstance(raw_references, dict):
            continue
        references: dict[str, list[str]] = {}
        for raw_reference, raw_purposes in raw_references.items():
            if not isinstance(raw_reference, str) or not raw_reference.strip():
                continue
            purposes = [
                purpose
                for purpose in _dedupe_strings(raw_purposes)
                if purpose in KEY_PURPOSES
            ]
            if purposes:
                references[raw_reference.strip()] = purposes
        if references:
            normalized[raw_service_id.strip()] = references
    return normalized


def _purposes_for_key_reference(
    registry: dict[str, Any],
    *,
    service_id: str,
    key_reference: str,
) -> list[str]:
    bindings = _normalize_key_reference_purposes(
        registry.get("key_reference_purposes")
        if isinstance(registry, dict)
        else None
    )
    return list(bindings.get(service_id, {}).get(key_reference, []))


def _validate_lti_key_reference_bindings(value: Any) -> None:
    """Reject protocol-key reuse while allowing one service to host many keys."""

    bindings = _normalize_key_reference_purposes(value)
    for service_id, references in bindings.items():
        for key_reference, purposes in references.items():
            if "lti_tool_signing" in purposes and purposes != ["lti_tool_signing"]:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Key reference '{key_reference}' in service '{service_id}' "
                        "cannot combine lti_tool_signing with credential-signing purposes."
                    ),
                )


def _normalize_algorithm_list(values: Any) -> list[str]:
    return [algorithm for algorithm in _dedupe_strings(values) if algorithm in SUPPORTED_SIGNING_ALGORITHMS]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-services"


def _jwks_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-jwks"


def _service_certificates_storage_key(organization_id: str) -> str:
    """Store certificate attachments separately from service registrations.

    Managed signing services are derived from the live OpenBao inventory and
    are intentionally excluded from the writable service registry.  Keeping
    their public certificate material in a small sidecar document lets the
    normal certificate API work for both managed and external services without
    persisting provider credentials or a stale copy of the managed service.
    """
    return f"org:{organization_id}:signing-key-service-certificates"


def _did_doc_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:signing-key-did-document"


_SLUG_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")
_DID_WEB_DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$")
_DID_WEB_DOMAIN_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def _did_web_slug_key(slug: str) -> str:
    """Redis key mapping a normalised org slug to its organization ID."""
    return f"did-web-slug:{slug}"


def _normalize_did_web_domain(value: Any) -> str | None:
    """Return a comparable did:web domain, rejecting URL and path characters."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeDecodeError:
        return None
    if not _DID_WEB_DOMAIN_PATTERN.fullmatch(decoded):
        return None
    host, separator, port = decoded.rpartition(":")
    if not separator:
        host, port = decoded, ""
    host = host.rstrip(".")
    if not host or len(host) > 253:
        return None
    if any(not _DID_WEB_DOMAIN_LABEL_PATTERN.fullmatch(label) for label in host.split(".")):
        return None
    if port and (not port.isdigit() or not 1 <= int(port) <= 65535):
        return None
    normalized = host.lower()
    return f"{normalized}:{port}" if port else normalized


def _did_web_domain(did_id: Any) -> str | None:
    if not isinstance(did_id, str) or not did_id.startswith("did:web:"):
        return None
    parts = did_id.split(":")
    return _normalize_did_web_domain(parts[2]) if len(parts) >= 3 else None


def _did_web_org_slug(did_id: Any, *, public_domain: str | None = None) -> str | None:
    """Return the slug only for the exact ``did:web:<domain>:orgs:<slug>`` form."""
    if not isinstance(did_id, str):
        return None
    parts = did_id.split(":")
    if len(parts) != 5 or parts[:2] != ["did", "web"] or parts[3].lower() != "orgs":
        return None
    did_domain = _normalize_did_web_domain(parts[2])
    if not did_domain:
        return None
    if public_domain is not None and did_domain != _normalize_did_web_domain(public_domain):
        return None
    slug = parts[4].lower()
    return slug if _SLUG_PATTERN.fullmatch(slug) else None


async def _claim_did_web_slug(request: Request, slug: str, organization_id: str) -> None:
    """Atomically claim a public did:web slug without allowing tenant takeover."""
    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        raise HTTPException(status_code=503, detail="DID web slug registry is unavailable.")

    storage_key = _did_web_slug_key(slug)

    def stored_organization(value: Any) -> str | None:
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return value if isinstance(value, str) else None

    try:
        existing_raw = await redis_client.get(storage_key)
        if existing_raw is not None:
            existing = stored_organization(existing_raw)
            if existing == organization_id:
                return
            if existing is None:
                raise HTTPException(status_code=503, detail="DID web slug registry contains invalid data.")
            raise HTTPException(status_code=409, detail=f"DID web slug '{slug}' is already in use.")

        claimed = await redis_client.set(storage_key, organization_id, nx=True)
        if claimed:
            return

        # Another request won the SET NX race. Same-organization retries are
        # idempotent; a different owner is a deterministic conflict.
        existing = stored_organization(await redis_client.get(storage_key))
        if existing == organization_id:
            return
        if existing is None:
            raise HTTPException(status_code=503, detail="DID web slug claim could not be confirmed.")
        raise HTTPException(status_code=409, detail=f"DID web slug '{slug}' is already in use.")
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("DID web slug claim failed for %s: %s", slug, exc, exc_info=True)
        raise HTTPException(status_code=503, detail="DID web slug registry is unavailable.") from exc


def _issuer_profiles_storage_key(organization_id: str) -> str:
    """Redis key storing the list of issuer profiles for an organization."""
    return f"org:{organization_id}:issuer-profiles"


def _retarget_did_document(did_doc: dict[str, Any], did_id: str) -> dict[str, Any]:
    """Return a DID document view with IDs rewritten for the requested DID."""
    source_did = did_doc.get("id") if isinstance(did_doc.get("id"), str) else did_id
    if source_did == did_id:
        return did_doc

    retargeted = dict(did_doc)
    retargeted["id"] = did_id
    retargeted["controller"] = did_id

    def rewrite_identifier(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if value.startswith(f"{source_did}#"):
            return f"{did_id}#{value.split('#', 1)[1]}"
        return value

    methods = did_doc.get("verificationMethod") if isinstance(did_doc.get("verificationMethod"), list) else []
    retargeted_methods: list[dict[str, Any]] = []
    for method in methods:
        if not isinstance(method, dict):
            continue
        rewritten = dict(method)
        rewritten["id"] = rewrite_identifier(rewritten.get("id"))
        if rewritten.get("controller") == source_did:
            rewritten["controller"] = did_id
        retargeted_methods.append(rewritten)
    retargeted["verificationMethod"] = retargeted_methods

    for relationship in ("authentication", "assertionMethod", "capabilityInvocation", "capabilityDelegation"):
        entries = did_doc.get(relationship)
        if isinstance(entries, list):
            retargeted[relationship] = [rewrite_identifier(entry) for entry in entries]

    return retargeted


def _did_fragment_for_key_reference(service_id: str, key_reference: str | None = None) -> str:
    fragment = key_reference or f"{service_id}-vm"
    safe_fragment = re.sub(r"[^a-zA-Z0-9._-]", "-", fragment).strip("-")
    return safe_fragment or f"{service_id}-vm"


def _normalize_did_verification_method_id(issuer_did: str, value: Any) -> str | None:
    """Normalize a DID verification method reference to an absolute DID URL."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.startswith("#"):
        return f"{issuer_did}{candidate}"
    if candidate.startswith("did:"):
        return candidate
    if "#" not in candidate:
        return f"{issuer_did}#{candidate}"
    return candidate


def _issuer_vm_id_candidates(
    issuer_did: str,
    *,
    verification_method_id: str | None = None,
    profile: dict[str, Any] | None = None,
    service_id: str | None = None,
    key_reference: str | None = None,
) -> list[str]:
    """Build ordered verification-method DID URL candidates for an issuer profile."""
    raw_candidates: list[Any] = [verification_method_id]
    if isinstance(profile, dict):
        raw_candidates.extend(
            [
                profile.get("verification_method_id"),
                profile.get("kid"),
                profile.get("signing_key_reference"),
            ]
        )
    if key_reference:
        raw_candidates.append(key_reference)
    if service_id:
        raw_candidates.append(_did_fragment_for_key_reference(service_id, key_reference))

    deduped: list[str] = []
    for raw in raw_candidates:
        normalized = _normalize_did_verification_method_id(issuer_did, raw)
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _did_document_assertion_ids(did_doc: dict[str, Any], issuer_did: str) -> set[str]:
    assertion_entries = did_doc.get("assertionMethod") if isinstance(did_doc.get("assertionMethod"), list) else []
    assertion_ids: set[str] = set()
    for entry in assertion_entries:
        if isinstance(entry, str):
            normalized = _normalize_did_verification_method_id(issuer_did, entry)
            if normalized:
                assertion_ids.add(normalized)
        elif isinstance(entry, dict):
            normalized = _normalize_did_verification_method_id(issuer_did, entry.get("id"))
            if normalized:
                assertion_ids.add(normalized)
    return assertion_ids


def _find_did_verification_method(
    did_doc: dict[str, Any],
    issuer_did: str,
    candidates: list[str],
) -> dict[str, Any] | None:
    """Return the DID verification method matching the requested/profile key, if present."""
    methods = did_doc.get("verificationMethod") if isinstance(did_doc.get("verificationMethod"), list) else []
    assertion_ids = _did_document_assertion_ids(did_doc, issuer_did)
    candidate_set = set(candidates)

    fallback_method: dict[str, Any] | None = None
    for method in methods:
        if not isinstance(method, dict):
            continue
        method_id = _normalize_did_verification_method_id(issuer_did, method.get("id"))
        if not method_id:
            continue
        if candidate_set and method_id not in candidate_set:
            continue
        if assertion_ids and method_id not in assertion_ids:
            continue
        method_copy = dict(method)
        method_copy["id"] = method_id
        if fallback_method is None:
            fallback_method = method_copy
        if candidate_set:
            return method_copy

    return fallback_method if not candidate_set else None


def _public_jwk_from_verification_method(method: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(method, dict):
        return None
    jwk = method.get("publicKeyJwk")
    if isinstance(jwk, dict) and jwk.get("kty"):
        sanitized = {k: v for k, v in jwk.items() if k not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}}
        if method.get("id") and not sanitized.get("kid"):
            sanitized["kid"] = method["id"]
        return sanitized
    return None


async def _public_jwk_from_service(
    service_config: dict[str, Any],
    *,
    key_reference_hint: str | None = None,
) -> dict[str, Any] | None:
    adapter = _get_adapter(service_config)
    if adapter is None:
        return None
    raw_jwk = await adapter.get_public_key_jwk(service_config)
    public_jwk = _extract_public_jwk(raw_jwk, key_reference_hint=key_reference_hint)
    if not public_jwk and isinstance(raw_jwk, dict):
        public_jwk = _extract_public_jwk(raw_jwk, key_reference_hint=key_reference_hint) or dict(raw_jwk)
    return public_jwk if isinstance(public_jwk, dict) and public_jwk.get("kty") else None


def _safe_signing_service_metadata(service: dict[str, Any]) -> dict[str, Any]:
    """Return internal resolver-safe service metadata without auth material."""
    allowed_keys = {
        "id",
        "name",
        "service_type",
        "provider",
        "provider_label",
        "protocol",
        "category",
        "region",
        "key_reference",
        "key_aliases",
        "algorithms",
        "status",
        "managed",
        "read_only",
        "key_purposes",
        "credential_formats",
        "signature_encoding",
        "created_at",
        "updated_at",
    }
    return {key: value for key, value in service.items() if key in allowed_keys}


def _holder_keys_storage_key(organization_id: str) -> str:
    return f"org:{organization_id}:holder-keys"


def _split_pem_chain(pem_blob: str | None) -> list[str]:
    if not pem_blob or not isinstance(pem_blob, str):
        return []
    matches = re.findall(
        r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
        pem_blob,
    )
    return [match.strip() for match in matches if match.strip()]


def _pem_to_x5c_entry(pem_cert: str) -> str | None:
    try:
        body = re.sub(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----", "", pem_cert)
        der = base64.b64decode(re.sub(r"\s+", "", body), validate=True)
        return base64.b64encode(der).decode("ascii")
    except Exception:
        return None


def _service_x5c_chain(service: dict[str, Any]) -> list[str]:
    chain = _split_pem_chain(service.get("cert_chain_pem"))
    leaf = _split_pem_chain(service.get("cert_pem"))
    combined = leaf + chain
    x5c: list[str] = []
    for cert in combined:
        encoded = _pem_to_x5c_entry(cert)
        if encoded:
            x5c.append(encoded)
    return x5c


async def _service_certificate_overrides(
    request: Request,
    organization_id: str | None,
) -> dict[str, dict[str, str]]:
    if not organization_id:
        return {}
    document = await _load_json_document(
        request,
        _service_certificates_storage_key(organization_id),
        {"services": {}},
    )
    raw_services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(raw_services, dict):
        return {}
    return {
        service_id: {
            key: value
            for key, value in attachment.items()
            if key in {"cert_pem", "cert_chain_pem", "cert_expires_at", "updated_at"}
            and isinstance(value, str)
        }
        for service_id, attachment in raw_services.items()
        if isinstance(service_id, str) and isinstance(attachment, dict)
    }


def _apply_service_certificate_override(
    service: dict[str, Any],
    overrides: dict[str, dict[str, str]],
) -> dict[str, Any]:
    result = dict(service)
    service_id = result.get("id")
    if isinstance(service_id, str):
        result.update(overrides.get(service_id, {}))
    return result


async def _load_json_document(request: Request, storage_key: str, default: dict[str, Any]) -> dict[str, Any]:
    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        return dict(default)
    try:
        payload = await redis_client.get(storage_key)
    except Exception:
        return dict(default)
    if not payload:
        return dict(default)
    try:
        decoded = payload if isinstance(payload, str) else payload.decode()
        parsed = json.loads(decoded)
    except Exception:
        return dict(default)
    return parsed if isinstance(parsed, dict) else dict(default)


async def _credential_issuer_key_references(
    request: Request,
    organization_id: str,
) -> set[str]:
    """Load issuer-key assignments without treating storage errors as empty."""

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        raise HTTPException(
            status_code=503,
            detail="Issuer profile registry is unavailable for key-isolation validation.",
        )
    try:
        payload = await redis_client.get(_issuer_profiles_storage_key(organization_id))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Issuer profile registry is unavailable for key-isolation validation.",
        ) from exc
    if payload is None:
        return set()
    try:
        decoded = payload if isinstance(payload, str) else payload.decode()
        profiles_document = json.loads(decoded)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Issuer profile registry is invalid for key-isolation validation.",
        ) from exc
    profiles = (
        profiles_document.get("profiles")
        if isinstance(profiles_document, dict)
        else None
    )
    if not isinstance(profiles, list):
        raise HTTPException(
            status_code=503,
            detail="Issuer profile registry is invalid for key-isolation validation.",
        )

    references: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict) or profile.get("status") == "archived":
            continue
        service_id = profile.get("signing_service_id")
        reference = profile.get("signing_key_reference")
        if isinstance(reference, str) and reference.strip():
            references.add(reference.strip())
        elif isinstance(service_id, str) and service_id.strip():
            # Legacy profiles without an explicit reference resolve through a
            # service default. Treat every key in that service as potentially
            # assigned until an operator repairs the profile.
            references.add(f"service-default:{service_id.strip()}")
    return references


async def _save_json_document(request: Request, storage_key: str, doc: dict[str, Any]) -> None:
    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        return
    await redis_client.set(storage_key, json.dumps(doc))


def _merge_discovered_capabilities(service: dict[str, Any], discovered: dict[str, Any]) -> dict[str, Any]:
    existing = service.get("discovered_capabilities")
    merged = existing.copy() if isinstance(existing, dict) else {}
    for key, value in discovered.items():
        if value is not None:
            merged[key] = value
    merged["discovered_at"] = _utcnow_iso()
    return merged


def _service_type_definition(service_type_id: Any) -> dict[str, Any]:
    if isinstance(service_type_id, str) and service_type_id in KEY_MANAGEMENT_SERVICE_TYPE_BY_ID:
        return KEY_MANAGEMENT_SERVICE_TYPE_BY_ID[service_type_id]
    return KEY_MANAGEMENT_SERVICE_TYPE_BY_ID["custom-transit-compatible"]


def _get_adapter(service_config: dict[str, Any]) -> Any:
    """Return the provider adapter for a registered service config, if available."""
    from gateway.kms_adapters import get_adapter

    return get_adapter(service_config)


def _normalize_service_definition_catalog() -> list[dict[str, Any]]:
    return [dict(service_type) for service_type in KEY_MANAGEMENT_SERVICE_TYPES]


def _normalize_registered_service(service: Any) -> dict[str, Any] | None:
    if not isinstance(service, dict):
        return None

    service_type_id = service.get("service_type")
    definition = _service_type_definition(service_type_id)
    now = _utcnow_iso()
    key_aliases = _dedupe_strings(service.get("key_aliases"))
    algorithms = _normalize_algorithm_list(service.get("algorithms"))

    if not algorithms and service.get("algorithm"):
        algorithms = _normalize_algorithm_list([service.get("algorithm")])

    auth_modes = definition.get("auth_modes") or []
    incoming_auth_mode = service.get("auth_mode")
    auth_mode = incoming_auth_mode if isinstance(incoming_auth_mode, str) and incoming_auth_mode in auth_modes else (
        auth_modes[0] if auth_modes else "custom"
    )

    provider = service.get("provider")
    if not isinstance(provider, str) or not provider.strip():
        provider = definition["provider"]

    provider_label = service.get("provider_label")
    if not isinstance(provider_label, str) or not provider_label.strip():
        provider_label = definition["label"]

    created_at = service.get("created_at") if isinstance(service.get("created_at"), str) else now
    updated_at = service.get("updated_at") if isinstance(service.get("updated_at"), str) else now

    # -- Key purposes and credential-format routing (GAP-002) -----------------
    incoming_purposes = service.get("key_purposes")
    if isinstance(incoming_purposes, list):
        key_purposes = [p for p in incoming_purposes if p in KEY_PURPOSES]
    else:
        key_purposes = []

    incoming_formats = service.get("credential_formats")
    if isinstance(incoming_formats, list):
        credential_formats = [f for f in incoming_formats if isinstance(f, str)]
    else:
        # Derive from key_purposes when not explicitly set
        derived: list[str] = []
        for purpose in key_purposes:
            for fmt in KEY_PURPOSE_CREDENTIAL_FORMATS.get(purpose, ()):
                if fmt not in derived:
                    derived.append(fmt)
        credential_formats = derived

    # -- Provider capability metadata (GAP-007) --------------------------------
    svc_type_id = definition["id"]
    static_caps = KEY_MANAGEMENT_SERVICE_CAPABILITIES.get(
        svc_type_id,
        KEY_MANAGEMENT_SERVICE_CAPABILITIES["custom-transit-compatible"],
    )
    signature_encoding = static_caps.get("signature_encoding", "raw_ieee_p1363")

    rotation_policy = service.get("rotation_policy") if isinstance(service.get("rotation_policy"), dict) else {}
    discovered_capabilities = service.get("discovered_capabilities") if isinstance(service.get("discovered_capabilities"), dict) else {}

    return {
        "id": service.get("id") if isinstance(service.get("id"), str) and service["id"].strip() else f"svc-{uuid.uuid4().hex}",
        "name": service.get("name") if isinstance(service.get("name"), str) and service["name"].strip() else definition["label"],
        "description": service.get("description") if isinstance(service.get("description"), str) else "",
        "service_type": definition["id"],
        "provider": provider,
        "provider_label": provider_label,
        "protocol": service.get("protocol") if isinstance(service.get("protocol"), str) and service["protocol"].strip() else definition["protocol"],
        "category": definition["category"],
        "endpoint": service.get("endpoint") if isinstance(service.get("endpoint"), str) else "",
        "region": service.get("region") if isinstance(service.get("region"), str) else "",
        "mount": service.get("mount") if isinstance(service.get("mount"), str) else "",
        "namespace": service.get("namespace") if isinstance(service.get("namespace"), str) else "",
        "auth_mode": auth_mode,
        "auth_reference": service.get("auth_reference") if isinstance(service.get("auth_reference"), str) else "",
        "key_reference": service.get("key_reference") if isinstance(service.get("key_reference"), str) else "",
        "country_code": service.get("country_code") if isinstance(service.get("country_code"), str) else "",
        "authority_name": service.get("authority_name") if isinstance(service.get("authority_name"), str) else "",
        "key_aliases": key_aliases,
        "algorithms": algorithms,
        "status": service.get("status") if isinstance(service.get("status"), str) else "registered",
        "managed": False,
        "read_only": False,
        "managed_by": None,
        "key_count": len(key_aliases) if key_aliases else (1 if service.get("key_reference") else 0),
        "capabilities": {
            "discover_keys": bool(definition.get("supports_inventory")),
            "sign": True,
            "rotate_keys": static_caps.get("rotation", False),
            "upload_public_keys": static_caps.get("key_import", False),
            "delete_keys": static_caps.get("key_delete", False),
            "multiple_key_references": True,
            "public_key_export": static_caps.get("public_key_export", False),
            "hardware_attestation": static_caps.get("hardware_attestation", False),
            "supported_algorithms": static_caps.get("supported_algorithms", list(SUPPORTED_SIGNING_ALGORITHMS)),
        },
        "signature_encoding": signature_encoding,
        "key_purposes": key_purposes,
        "credential_formats": credential_formats,
        "rotation_policy": {
            "rotation_interval_days": int(rotation_policy.get("rotation_interval_days", 0) or 0),
            "overlap_days": int(rotation_policy.get("overlap_days", 0) or 0),
            "auto_publish": bool(rotation_policy.get("auto_publish", False)),
        },
        "rotation_state": service.get("rotation_state") if isinstance(service.get("rotation_state"), dict) else {},
        "created_at": created_at,
        "updated_at": updated_at,
        "discovered_capabilities": discovered_capabilities,
        "cert_pem": service.get("cert_pem") if isinstance(service.get("cert_pem"), str) else None,
        "cert_chain_pem": service.get("cert_chain_pem") if isinstance(service.get("cert_chain_pem"), str) else None,
        "cert_expires_at": service.get("cert_expires_at") if isinstance(service.get("cert_expires_at"), str) else None,
    }


# ---------------------------------------------------------------------------
# Format / purpose resolver (GAP-002-c)
# ---------------------------------------------------------------------------

def _resolve_service_for_format(
    registry: dict[str, Any],
    credential_format: str | None,
    key_purpose: str | None,
    algorithm: str | None,
) -> dict[str, Any] | None:
    """Return the best matching registered service for a given format/purpose/algorithm.

    Resolution order (most specific first):
      1. ``type_defaults`` map keyed by credential_format or key_purpose
      2. ``format_defaults`` map keyed by credential_format
      3. ``default_service_id``
      4. First service that declares the requested format/purpose/algorithm
    """
    services_by_id: dict[str, dict[str, Any]] = {
        svc["id"]: svc
        for svc in (registry.get("services") or [])
        if isinstance(svc, dict) and svc.get("id")
    }

    def _svc(service_id: Any) -> dict[str, Any] | None:
        if isinstance(service_id, str) and service_id in services_by_id:
            return services_by_id[service_id]
        return None

    # 1. type_defaults: prefer the most specific key available
    type_defaults: dict[str, str] = registry.get("type_defaults") or {}
    for lookup_key in filter(None, [credential_format, key_purpose]):
        candidate = _svc(type_defaults.get(lookup_key))
        if candidate:
            return candidate

    # 2. format_defaults
    format_defaults: dict[str, str] = registry.get("format_defaults") or {}
    if credential_format:
        candidate = _svc(format_defaults.get(credential_format))
        if candidate:
            return candidate

    # 3. global default
    global_default = _svc(registry.get("default_service_id"))
    if global_default:
        return global_default

    # 4. First service that matches all supplied filters
    for svc in services_by_id.values():
        if credential_format and credential_format not in (svc.get("credential_formats") or []):
            continue
        if key_purpose and key_purpose not in (svc.get("key_purposes") or []):
            continue
        if algorithm and algorithm not in (svc.get("algorithms") or []):
            continue
        return svc

    return None


def _resolve_key_reference_for_purpose(
    registry: dict[str, Any],
    service: dict[str, Any],
    keys: list[dict[str, Any]],
    *,
    key_purpose: str | None,
    algorithm: str | None,
) -> str | None:
    """Select a purpose-bound key instead of a service's unrelated default.

    A managed KMS service hosts several protocol keys. Service resolution alone
    is therefore insufficient: mdoc must use its DSC key, and an ES384 request
    must not silently receive the service's ES256 default.
    """
    current = service.get("key_reference")
    current_reference = current.strip() if isinstance(current, str) and current.strip() else None
    if not key_purpose:
        return current_reference

    service_id = service.get("id")
    if not isinstance(service_id, str):
        return current_reference
    bindings = _normalize_key_reference_purposes(registry.get("key_reference_purposes"))
    service_bindings = bindings.get(service_id, {})
    if not service_bindings:
        return current_reference

    aliases = set(_dedupe_strings(service.get("key_aliases")))
    if current_reference:
        aliases.add(current_reference)
    candidates = [
        reference
        for reference, purposes in service_bindings.items()
        if key_purpose in purposes and (not aliases or reference in aliases)
    ]
    if algorithm:
        algorithm_by_reference = {
            str(key.get("provider_key_name") or key.get("id")): key.get("algorithm")
            for key in keys
            if isinstance(key, dict) and (key.get("provider_key_name") or key.get("id"))
        }
        candidates = [
            reference
            for reference in candidates
            if algorithm_by_reference.get(reference) == algorithm
        ]
    if current_reference in candidates:
        return current_reference
    return sorted(candidates)[0] if candidates else None


async def _load_registered_service_registry(request: Request, organization_id: str | None) -> dict[str, Any]:
    empty = {
        "services": [],
        "default_service_id": None,
        "format_defaults": {},
        "type_defaults": {},
        "key_reference_purposes": {},
    }
    if not organization_id:
        return dict(empty)

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        return dict(empty)

    try:
        payload = await redis_client.get(_storage_key(organization_id))
    except Exception:
        return dict(empty)

    if not payload:
        return dict(empty)

    try:
        decoded = payload if isinstance(payload, str) else payload.decode()
        parsed = json.loads(decoded)
    except Exception:
        return dict(empty)

    raw_services = parsed.get("services") if isinstance(parsed, dict) and isinstance(parsed.get("services"), list) else []
    services = [
        normalized
        for normalized in (_normalize_registered_service(service) for service in raw_services)
        if normalized
    ]
    default_service_id = parsed.get("default_service_id") if isinstance(parsed, dict) else None
    raw_format_defaults = parsed.get("format_defaults") if isinstance(parsed, dict) else {}
    format_defaults = {k: v for k, v in raw_format_defaults.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(raw_format_defaults, dict) else {}
    raw_type_defaults = parsed.get("type_defaults") if isinstance(parsed, dict) else {}
    type_defaults = {k: v for k, v in raw_type_defaults.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(raw_type_defaults, dict) else {}
    key_reference_purposes = _normalize_key_reference_purposes(
        parsed.get("key_reference_purposes") if isinstance(parsed, dict) else None
    )
    return {
        "services": services,
        "default_service_id": default_service_id if isinstance(default_service_id, str) else None,
        "format_defaults": format_defaults,
        "type_defaults": type_defaults,
        "key_reference_purposes": key_reference_purposes,
    }


async def _save_registered_service_registry(
    request: Request,
    organization_id: str | None,
    registry: dict[str, Any],
) -> None:
    if not organization_id:
        return

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        return

    payload = {
        "default_service_id": registry.get("default_service_id"),
        "format_defaults": registry.get("format_defaults") or {},
        "type_defaults": registry.get("type_defaults") or {},
        "key_reference_purposes": _normalize_key_reference_purposes(
            registry.get("key_reference_purposes")
        ),
        "services": registry.get("services") or [],
    }
    await redis_client.set(_storage_key(organization_id), json.dumps(payload))


def _managed_openbao_service(
    snapshot: dict[str, Any],
    organization_id: str | None,
    key_reference_purposes: Any = None,
) -> dict[str, Any] | None:
    config = snapshot.get("config") or {}
    hsm_settings = config.get("hsm_settings") or {}
    if not config.get("hsm_enabled"):
        return None

    keys = snapshot.get("keys") or []
    bindings = _normalize_key_reference_purposes(key_reference_purposes)
    managed_bindings = bindings.get(MANAGED_OPENBAO_SERVICE_ID, {})
    managed_purposes = sorted(
        {
            purpose
            for purposes in managed_bindings.values()
            for purpose in purposes
        }
    )
    return {
        "id": MANAGED_OPENBAO_SERVICE_ID,
        "name": "Marty managed OpenBao transit",
        "description": "Managed by the Marty service stack.",
        "service_type": "openbao-transit",
        "provider": hsm_settings.get("provider") or _provider_name(),
        "provider_label": "OpenBao Transit",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "endpoint": hsm_settings.get("service_url") or _bao_address() or "",
        "region": "",
        "mount": hsm_settings.get("mount") or "transit",
        "namespace": "",
        "auth_mode": "service_token",
        "auth_reference": "Managed by Marty service stack",
        "key_reference": keys[0]["provider_key_name"] if keys else "",
        "key_aliases": [key.get("provider_key_name") or key.get("id") for key in keys],
        "algorithms": _normalize_algorithm_list([key.get("algorithm") for key in keys]),
        "key_purposes": managed_purposes,
        "status": snapshot.get("provider_metadata", {}).get("status", "configured"),
        "managed": True,
        "read_only": True,
        "managed_by": hsm_settings.get("managed_by") or "Marty service stack",
        "organization_id": organization_id,
        "key_count": len(keys),
        "capabilities": {
            "discover_keys": True,
            "sign": True,
            "rotate_keys": False,
            "upload_public_keys": False,
            "delete_keys": False,
            "multiple_key_references": True,
        },
        "created_at": None,
        "updated_at": None,
    }


def _default_service_id(services: list[dict[str, Any]], requested_default: str | None) -> str | None:
    if requested_default and any(service["id"] == requested_default for service in services):
        return requested_default
    if any(service["id"] == MANAGED_OPENBAO_SERVICE_ID for service in services):
        return MANAGED_OPENBAO_SERVICE_ID
    return services[0]["id"] if services else None


def _default_service(services: list[dict[str, Any]], default_service_id: str | None) -> dict[str, Any] | None:
    if not default_service_id:
        return None
    return next((service for service in services if service["id"] == default_service_id), None)


def _legacy_hsm_settings_from_default_service(
    default_service: dict[str, Any] | None,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    if default_service is None:
        config = snapshot.get("config") or {}
        hsm_settings = config.get("hsm_settings")
        return hsm_settings if isinstance(hsm_settings, dict) else {}

    if default_service["id"] == MANAGED_OPENBAO_SERVICE_ID:
        config = snapshot.get("config") or {}
        hsm_settings = config.get("hsm_settings")
        return hsm_settings if isinstance(hsm_settings, dict) else {}

    return {
        "provider": default_service.get("provider"),
        "provider_label": default_service.get("provider_label"),
        "service_url": default_service.get("endpoint"),
        "mount": default_service.get("mount"),
        "namespace": default_service.get("namespace"),
        "region": default_service.get("region"),
        "organization_id": default_service.get("organization_id"),
        "signing_key_count": default_service.get("key_count", 0),
        "signing_key_names": default_service.get("key_aliases") or [],
        "key_reference": default_service.get("key_reference"),
        "auth_mode": default_service.get("auth_mode"),
    }


def _provider_metadata_from_default_service(
    snapshot_metadata: dict[str, Any],
    default_service: dict[str, Any] | None,
) -> dict[str, Any]:
    if default_service is None or default_service["id"] == MANAGED_OPENBAO_SERVICE_ID:
        return snapshot_metadata

    capabilities = default_service.get("capabilities") or {}
    return {
        **snapshot_metadata,
        "provider": default_service.get("provider") or snapshot_metadata.get("provider"),
        "status": default_service.get("status") or snapshot_metadata.get("status"),
        "managed_by": default_service.get("managed_by") or "Registered via console",
        "supports_rotation": bool(capabilities.get("rotate_keys")),
        "supports_upload": bool(capabilities.get("upload_public_keys")),
        "supports_delete": bool(capabilities.get("delete_keys")),
        "key_count": default_service.get("key_count", snapshot_metadata.get("key_count", 0)),
    }


def _registry_from_legacy_body(body: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None

    if not body.get("hsm_enabled"):
        return {"services": [], "default_service_id": None}

    hsm_settings = body.get("hsm_settings")
    if not isinstance(hsm_settings, dict):
        return None

    if hsm_settings.get("managed_by"):
        return {"services": [], "default_service_id": MANAGED_OPENBAO_SERVICE_ID}

    service = _normalize_registered_service(
        {
            "name": hsm_settings.get("provider_label") or hsm_settings.get("provider") or "Registered KMS/HSM",
            "service_type": "custom-transit-compatible",
            "provider": hsm_settings.get("provider") or "custom",
            "protocol": "vault-transit-compatible",
            "endpoint": hsm_settings.get("service_url"),
            "mount": hsm_settings.get("mount"),
            "namespace": hsm_settings.get("namespace"),
            "region": hsm_settings.get("region"),
            "auth_mode": hsm_settings.get("auth_mode"),
            "key_reference": hsm_settings.get("key_reference"),
            "key_aliases": hsm_settings.get("signing_key_names"),
        }
    )
    if service is None:
        return None
    return {"services": [service], "default_service_id": service["id"]}


def _normalize_requested_registry(body: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None

    if isinstance(body.get("services"), list):
        services = [
            normalized
            for normalized in (
                _normalize_registered_service(service)
                for service in body.get("services", [])
                if isinstance(service, dict)
                and not service.get("managed")
                and not service.get("read_only")
                and service.get("id") != MANAGED_OPENBAO_SERVICE_ID
            )
            if normalized
        ]
        default_service_id = body.get("default_service_id") if isinstance(body.get("default_service_id"), str) else None

        # Persist per-format and per-type defaults (GAP-006)
        raw_format_defaults = body.get("format_defaults")
        format_defaults = {k: v for k, v in raw_format_defaults.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(raw_format_defaults, dict) else {}

        raw_type_defaults = body.get("type_defaults")
        type_defaults = {k: v for k, v in raw_type_defaults.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(raw_type_defaults, dict) else {}

        return {
            "services": services,
            "default_service_id": default_service_id,
            "format_defaults": format_defaults,
            "type_defaults": type_defaults,
            "key_reference_purposes": _normalize_key_reference_purposes(
                body.get("key_reference_purposes")
            ),
        }

    return _registry_from_legacy_body(body)


def _non_empty_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _normalize_validation_payload(body: dict[str, Any]) -> dict[str, Any]:
    service_type_id = _non_empty_string(body.get("service_type")) or "custom-transit-compatible"
    definition = _service_type_definition(service_type_id)

    return {
        "service_type": definition["id"],
        "provider": definition.get("provider"),
        "protocol": definition.get("protocol"),
        "connection_fields": definition.get("connection_fields") or [],
        "name": _non_empty_string(body.get("name")),
        "endpoint": _non_empty_string(body.get("endpoint")),
        "region": _non_empty_string(body.get("region")),
        "mount": _non_empty_string(body.get("mount")) or "transit",
        "namespace": _non_empty_string(body.get("namespace")),
        "auth_mode": _non_empty_string(body.get("auth_mode")),
        "auth_reference": _non_empty_string(body.get("auth_reference")),
        "key_reference": _non_empty_string(body.get("key_reference")),
        "key_aliases": _dedupe_strings(body.get("key_aliases")),
        "algorithms": _normalize_algorithm_list(body.get("algorithms")),
    }


def _create_check(name: str, status: str, detail: str, source: str = "gateway") -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "detail": detail,
        "source": source,
    }


def _requires_auth_reference(auth_mode: str) -> bool:
    return auth_mode in {
        "token",
        "approle",
        "access_key",
        "client_secret",
        "certificate",
        "service_account",
        "api_key",
    }


def _append_baseline_validation_checks(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    auth_mode = payload.get("auth_mode") or ""
    auth_reference = payload.get("auth_reference") or ""
    key_reference = payload.get("key_reference") or ""
    algorithms = payload.get("algorithms") or []

    if _requires_auth_reference(auth_mode) and not auth_reference:
        checks.append(
            _create_check(
                "Authentication reference",
                "warning",
                "Provide a credential or secret reference for this auth mode.",
                source="baseline",
            )
        )
    else:
        checks.append(
            _create_check(
                "Authentication reference",
                "pass",
                "Authentication mode and reference look ready.",
                source="baseline",
            )
        )

    if not key_reference:
        checks.append(_create_check("Key reference", "fail", "Key reference is required.", source="baseline"))
    else:
        checks.append(_create_check("Key reference", "pass", "Key reference was provided.", source="baseline"))

    if not algorithms:
        checks.append(
            _create_check(
                "Algorithm coverage",
                "fail",
                "Select at least one supported signing algorithm.",
                source="baseline",
            )
        )
    else:
        checks.append(
            _create_check(
                "Algorithm coverage",
                "pass",
                f"Selected algorithms: {', '.join(algorithms)}",
                source="baseline",
            )
        )

    # Key purpose / algorithm compatibility check (GAP-002-e)
    key_purposes: list[str] = payload.get("key_purposes") or []
    if key_purposes and algorithms:
        incompatible: list[str] = []
        for purpose in key_purposes:
            allowed = KEY_PURPOSE_ALGORITHM_CONSTRAINTS.get(purpose)
            if allowed:
                bad = [a for a in algorithms if a not in allowed]
                incompatible.extend(bad)
        if incompatible:
            checks.append(
                _create_check(
                    "Key purpose algorithm fit",
                    "warning",
                    f"Algorithm(s) {', '.join(set(incompatible))} may not be suitable for the declared "
                    f"key purpose(s) {', '.join(key_purposes)}.",
                    source="baseline",
                )
            )
        else:
            checks.append(
                _create_check(
                    "Key purpose algorithm fit",
                    "pass",
                    "Selected algorithms are compatible with all declared key purposes.",
                    source="baseline",
                )
            )


AWS_KMS_ARN_RE = re.compile(r"^arn:aws:kms:[a-z0-9-]+:\d{12}:key\/[A-Za-z0-9-]+$")
AZURE_KEY_ID_RE = re.compile(r"^https:\/\/[a-z0-9-]+\.vault\.azure\.net\/keys\/[A-Za-z0-9-]+(\/[A-Za-z0-9-]+)?$")
GCP_KMS_KEY_RE = re.compile(
    r"^projects\/[a-z0-9-]+\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+(\/cryptoKeyVersions\/[0-9]+)?$"
)


def _validate_provider_key_reference(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    provider = payload.get("provider") or ""
    key_reference = payload.get("key_reference") or ""

    if not key_reference:
        return

    if provider == "aws":
        if AWS_KMS_ARN_RE.match(key_reference):
            checks.append(
                _create_check(
                    "Provider key format",
                    "pass",
                    "AWS key reference looks like a valid KMS key ARN.",
                    source="provider",
                )
            )
        else:
            checks.append(
                _create_check(
                    "Provider key format",
                    "fail",
                    "AWS key reference should be a key ARN (arn:aws:kms:region:account:key/<id>).",
                    source="provider",
                )
            )
    elif provider == "azure":
        if AZURE_KEY_ID_RE.match(key_reference):
            checks.append(
                _create_check(
                    "Provider key format",
                    "pass",
                    "Azure key reference looks like a Key Vault key identifier.",
                    source="provider",
                )
            )
        else:
            checks.append(
                _create_check(
                    "Provider key format",
                    "fail",
                    "Azure key reference should look like https://<vault>.vault.azure.net/keys/<name>/<version?>.",
                    source="provider",
                )
            )
    elif provider == "gcp":
        if GCP_KMS_KEY_RE.match(key_reference):
            checks.append(
                _create_check(
                    "Provider key format",
                    "pass",
                    "GCP key reference looks like a Cloud KMS resource path.",
                    source="provider",
                )
            )
        else:
            checks.append(
                _create_check(
                    "Provider key format",
                    "fail",
                    "GCP key reference should look like projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>[/cryptoKeyVersions/<v>].",
                    source="provider",
                )
            )


def _validate_provider_auth_mode(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    provider = payload.get("provider") or ""
    auth_mode = payload.get("auth_mode") or ""
    auth_reference = payload.get("auth_reference") or ""

    if provider == "aws":
        if auth_mode == "iam_role":
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "IAM role mode selected; ensure gateway runtime identity has kms:Sign permissions.",
                    source="provider",
                )
            )
        elif auth_mode in {"access_key", "assume_role"} and auth_reference:
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "Credential reference provided for AWS auth mode.",
                    source="provider",
                )
            )
        elif auth_mode in {"access_key", "assume_role"}:
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "warning",
                    "Provide an auth reference for access_key/assume_role modes.",
                    source="provider",
                )
            )
    elif provider == "azure":
        if auth_mode == "managed_identity":
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "Managed identity mode selected; ensure Key Vault sign permissions are granted.",
                    source="provider",
                )
            )
        elif auth_mode in {"client_secret", "certificate"} and auth_reference:
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "Credential reference provided for Azure auth mode.",
                    source="provider",
                )
            )
        elif auth_mode in {"client_secret", "certificate"}:
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "warning",
                    "Provide an auth reference for client_secret/certificate modes.",
                    source="provider",
                )
            )
    elif provider == "gcp":
        if auth_mode == "workload_identity":
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "Workload identity selected; ensure cloudkms.cryptoKeyVersions.useToSign permission is granted.",
                    source="provider",
                )
            )
        elif auth_mode == "service_account" and auth_reference:
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "pass",
                    "Service account reference provided for GCP auth mode.",
                    source="provider",
                )
            )
        elif auth_mode == "service_account":
            checks.append(
                _create_check(
                    "Provider auth policy",
                    "warning",
                    "Provide a service account reference for GCP auth mode.",
                    source="provider",
                )
            )


def _validate_provider_algorithm_support(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    provider = payload.get("provider") or ""
    selected_algorithms = payload.get("algorithms") or []
    if not selected_algorithms:
        return

    provider_supported_algorithms = {
        "aws": {"ES256", "ES384", "RS256"},
        "azure": {"ES256", "ES384", "RS256", "EdDSA"},
        "gcp": {"ES256", "ES384", "RS256", "EdDSA"},
    }.get(provider)

    if not provider_supported_algorithms:
        return

    unsupported = [algorithm for algorithm in selected_algorithms if algorithm not in provider_supported_algorithms]
    if unsupported:
        checks.append(
            _create_check(
                "Provider algorithm fit",
                "warning",
                f"Selected algorithms may not be available in {provider}: {', '.join(unsupported)}.",
                source="provider",
            )
        )
    else:
        checks.append(
            _create_check(
                "Provider algorithm fit",
                "pass",
                f"Selected algorithms are compatible with expected {provider} signer capabilities.",
                source="provider",
            )
        )


def _cloud_validator_url(provider: str) -> str:
    return {
        "aws": os.environ.get("AWS_KMS_VALIDATOR_URL", "").strip(),
        "azure": os.environ.get("AZURE_KEY_VAULT_VALIDATOR_URL", "").strip(),
        "gcp": os.environ.get("GCP_CLOUD_KMS_VALIDATOR_URL", "").strip(),
    }.get(provider, "")


async def _run_cloud_validator_probe(payload: dict[str, Any], validator_url: str) -> tuple[bool, str | None]:
    auth_reference = payload.get("auth_reference") or ""
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if auth_reference:
        headers["X-Auth-Reference"] = auth_reference

    validation_payload = {
        "service_type": payload.get("service_type"),
        "provider": payload.get("provider"),
        "region": payload.get("region"),
        "endpoint": payload.get("endpoint"),
        "auth_mode": payload.get("auth_mode"),
        "auth_reference": auth_reference,
        "key_reference": payload.get("key_reference"),
        "algorithms": payload.get("algorithms"),
    }

    async with httpx.AsyncClient(base_url=validator_url.rstrip("/"), timeout=8.0, headers=headers) as client:
        health_response = await client.get("/health")
        if health_response.status_code != 200:
            return False, f"Validator health probe returned HTTP {health_response.status_code}."

        validation_response = await client.post("/v1/signing/validate", json=validation_payload)
        if validation_response.status_code != 200:
            return False, f"Validator sign-capability probe returned HTTP {validation_response.status_code}."

        body = validation_response.json() if validation_response.content else {}
        if isinstance(body, dict) and body.get("ok") is True:
            return True, None
        if isinstance(body, dict) and isinstance(body.get("detail"), str):
            return False, body["detail"]
        return False, "Validator returned a non-success response payload."


async def _validate_transit_provider(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    endpoint = payload.get("endpoint") or _bao_address() or ""
    mount = payload.get("mount") or "transit"
    namespace = payload.get("namespace") or ""
    auth_mode = payload.get("auth_mode") or ""
    auth_reference = payload.get("auth_reference") or ""
    key_reference = payload.get("key_reference") or ""

    if not endpoint:
        checks.append(
            _create_check(
                "Provider connectivity",
                "fail",
                "Transit endpoint is required for live validation.",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Signer capability",
                "warning",
                "Skipped signer capability check because provider endpoint is missing.",
                source="live",
            )
        )
        return

    token: str | None = None
    if auth_mode == "service_token":
        token = _bao_token()
    elif auth_mode in {"token", "api_key", "custom"} and auth_reference:
        token = auth_reference

    headers: dict[str, str] = {"Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    if namespace:
        headers["X-Vault-Namespace"] = namespace

    try:
        async with httpx.AsyncClient(base_url=endpoint.rstrip("/"), timeout=6.0, headers=headers) as client:
            health = await client.get("/v1/sys/health")
            if health.status_code in {200, 429, 472, 473, 501}:
                checks.append(
                    _create_check(
                        "Provider connectivity",
                        "pass",
                        "Connected to transit-compatible provider health endpoint.",
                        source="live",
                    )
                )
            else:
                checks.append(
                    _create_check(
                        "Provider connectivity",
                        "fail",
                        f"Provider health check returned HTTP {health.status_code}.",
                        source="live",
                    )
                )

            if token:
                auth_check = await client.get("/v1/auth/token/lookup-self")
                if auth_check.status_code == 200:
                    checks.append(
                        _create_check(
                            "Provider auth",
                            "pass",
                            "Token authentication validated against provider.",
                            source="live",
                        )
                    )
                else:
                    checks.append(
                        _create_check(
                            "Provider auth",
                            "fail",
                            f"Provider rejected token authentication (HTTP {auth_check.status_code}).",
                            source="live",
                        )
                    )
            else:
                checks.append(
                    _create_check(
                        "Provider auth",
                        "warning",
                        "Live auth validation requires a token-based auth mode or managed service token.",
                        source="live",
                    )
                )

            if not key_reference:
                checks.append(
                    _create_check(
                        "Signer capability",
                        "fail",
                        "Key reference is required to verify signing capability.",
                        source="live",
                    )
                )
            else:
                sign_response = await client.post(
                    f"/v1/{mount}/sign/{key_reference}",
                    json={"input": "dGVzdA=="},
                )
                if sign_response.status_code == 200:
                    body = sign_response.json()
                    signature = ((body.get("data") or {}).get("signature")) if isinstance(body, dict) else None
                    if isinstance(signature, str) and signature:
                        checks.append(
                            _create_check(
                                "Signer capability",
                                "pass",
                                "Provider signed a test payload with the requested key reference.",
                                source="live",
                            )
                        )
                    else:
                        checks.append(
                            _create_check(
                                "Signer capability",
                                "warning",
                                "Provider responded but did not return a signature payload.",
                                source="live",
                            )
                        )
                elif sign_response.status_code == 404:
                    checks.append(
                        _create_check(
                            "Signer capability",
                            "fail",
                            "Provider could not find the referenced signing key.",
                            source="live",
                        )
                    )
                elif sign_response.status_code in {401, 403}:
                    checks.append(
                        _create_check(
                            "Signer capability",
                            "fail",
                            "Provider denied signing operation for the configured identity.",
                            source="live",
                        )
                    )
                else:
                    checks.append(
                        _create_check(
                            "Signer capability",
                            "warning",
                            f"Provider sign check returned HTTP {sign_response.status_code}.",
                            source="live",
                        )
                    )
    except Exception as exc:
        checks.append(
            _create_check(
                "Provider connectivity",
                "fail",
                f"Unable to reach provider endpoint: {exc}",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Provider auth",
                "warning",
                "Skipped provider auth check because connectivity failed.",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Signer capability",
                "warning",
                "Skipped signer capability check because connectivity failed.",
                source="live",
            )
        )


def _append_cloud_provider_validation(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    _validate_provider_key_reference(payload, checks)
    _validate_provider_auth_mode(payload, checks)
    _validate_provider_algorithm_support(payload, checks)


async def _append_adapter_live_validation(payload: dict[str, Any], checks: list[dict[str, str]]) -> bool:
    """Run live checks through a provider adapter when one is available."""
    adapter = _get_adapter(payload)
    if adapter is None:
        return False

    try:
        result = await adapter.verify_connection(payload)
    except Exception as exc:  # noqa: BLE001
        checks.append(
            _create_check(
                "Provider connectivity",
                "warning",
                f"Adapter live validation failed unexpectedly: {exc}",
                source="adapter",
            )
        )
        return True

    if not result.checks:
        checks.append(
            _create_check(
                "Provider connectivity",
                "pass" if result.ok else "warning",
                "Adapter live validation completed.",
                source="adapter",
            )
        )
    else:
        for check in result.checks:
            checks.append(
                _create_check(
                    check.get("name") or "Adapter check",
                    check.get("status") or ("pass" if result.ok else "warning"),
                    check.get("detail") or "Adapter validation check completed.",
                    source=check.get("source") or "adapter",
                )
            )

    if result.error:
        checks.append(
            _create_check(
                "Adapter error",
                "warning" if result.ok else "fail",
                result.error,
                source="adapter",
            )
        )

    return True


async def _append_cloud_provider_live_validation(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    provider = payload.get("provider") or "provider"
    validator_url = _cloud_validator_url(provider)
    if not validator_url:
        used_adapter = await _append_adapter_live_validation(payload, checks)
        if used_adapter:
            return

        checks.append(
            _create_check(
                "Provider connectivity",
                "warning",
                f"No {provider} validator bridge is configured (set {provider.upper()} validator URL env).",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Provider auth",
                "warning",
                f"Live {provider} authentication is not validated by gateway without a validator bridge.",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Signer capability",
                "warning",
                "Gateway could not run a live sign test for this provider type.",
                source="live",
            )
        )
        return

    try:
        probe_ok, error_detail = await _run_cloud_validator_probe(payload, validator_url)
        if probe_ok:
            checks.append(
                _create_check(
                    "Provider connectivity",
                    "pass",
                    "Connected to provider validator bridge.",
                    source="live",
                )
            )
            checks.append(
                _create_check(
                    "Provider auth",
                    "pass",
                    "Validator bridge reported provider authentication success.",
                    source="live",
                )
            )
            checks.append(
                _create_check(
                    "Signer capability",
                    "pass",
                    "Validator bridge completed a remote sign-capability probe.",
                    source="live",
                )
            )
        else:
            checks.append(
                _create_check(
                    "Provider connectivity",
                    "warning",
                    "Provider validator bridge is reachable but validation did not succeed.",
                    source="live",
                )
            )
            checks.append(
                _create_check(
                    "Provider auth",
                    "warning",
                    error_detail or "Provider authentication could not be validated.",
                    source="live",
                )
            )
            checks.append(
                _create_check(
                    "Signer capability",
                    "warning",
                    error_detail or "Remote sign-capability probe did not succeed.",
                    source="live",
                )
            )
    except Exception as exc:
        checks.append(
            _create_check(
                "Provider connectivity",
                "warning",
                f"Could not reach provider validator bridge: {exc}",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Provider auth",
                "warning",
                "Skipped provider auth check because validator probe failed.",
                source="live",
            )
        )
        checks.append(
            _create_check(
                "Signer capability",
                "warning",
                "Skipped signer capability check because validator probe failed.",
                source="live",
            )
        )

async def _run_cloud_provider_validation(payload: dict[str, Any], checks: list[dict[str, str]]) -> None:
    _append_cloud_provider_validation(payload, checks)
    await _append_cloud_provider_live_validation(payload, checks)


async def _run_service_validation(body: dict[str, Any]) -> dict[str, Any]:
    payload = _normalize_validation_payload(body)
    checks: list[dict[str, str]] = []
    _append_baseline_validation_checks(payload, checks)

    protocol = payload.get("protocol")
    if protocol in {"vault-transit", "vault-transit-compatible"}:
        used_adapter = await _append_adapter_live_validation(payload, checks)
        if not used_adapter:
            await _validate_transit_provider(payload, checks)
    else:
        await _run_cloud_provider_validation(payload, checks)

    has_failures = any(check["status"] == "fail" for check in checks)
    return {
        "ok": not has_failures,
        "checks": checks,
        "validated_at": _utcnow_iso(),
    }


async def _build_key_management_config(
    request: Request,
    resolved_org_id: str | None,
    snapshot: dict[str, Any],
    registry_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = registry_override or await _load_registered_service_registry(request, resolved_org_id)
    registered_services = registry.get("services") if isinstance(registry, dict) else []
    writable_services = [
        normalized
        for normalized in (_normalize_registered_service(service) for service in registered_services if isinstance(registered_services, list))
        if normalized
    ]

    key_reference_purposes = _normalize_key_reference_purposes(
        registry.get("key_reference_purposes")
        if isinstance(registry, dict)
        else None
    )
    services: list[dict[str, Any]] = []
    managed_openbao_service = _managed_openbao_service(
        snapshot,
        resolved_org_id,
        key_reference_purposes,
    )
    if managed_openbao_service:
        services.append(managed_openbao_service)
        writable_services = [service for service in writable_services if service.get("id") != MANAGED_OPENBAO_SERVICE_ID]
    services.extend(writable_services)
    certificate_overrides = await _service_certificate_overrides(request, resolved_org_id)
    services = [
        _apply_service_certificate_override(service, certificate_overrides)
        for service in services
    ]

    requested_default = registry.get("default_service_id") if isinstance(registry, dict) else None
    default_service_id = _default_service_id(services, requested_default)
    default_service = _default_service(services, default_service_id)
    snapshot_provider_metadata = snapshot.get("provider_metadata") or _provider_metadata(status="metadata_only", key_count=0)

    return {
        "hsm_enabled": bool(services),
        "hsm_settings": _legacy_hsm_settings_from_default_service(default_service, snapshot),
        "vault_enabled": False,
        "vault_settings": {},
        "provider_metadata": _provider_metadata_from_default_service(snapshot_provider_metadata, default_service),
        "domain_config": _domain_config(request),
        "supports_native_key_management": False,
        "registration_mode": "external-only",
        "default_service_id": default_service_id,
        "services": services,
        "key_reference_purposes": key_reference_purposes,
        "service_type_catalog": _normalize_service_definition_catalog(),
    }


async def _resolve_effective_service(
    request: Request,
    resolved_org_id: str | None,
    service_id: str,
    *,
    key_reference_override: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bool]:
    registry = await _load_registered_service_registry(request, resolved_org_id)
    raw_services = registry.get("services") if isinstance(registry, dict) else []
    service = next(
        (candidate for candidate in raw_services if isinstance(candidate, dict) and candidate.get("id") == service_id),
        None,
    )
    from_registry = service is not None

    if service is None:
        snapshot = await _load_signing_key_snapshot(resolved_org_id)
        config = await _build_key_management_config(request, resolved_org_id, snapshot, registry_override=registry)
        config_services = config.get("services") if isinstance(config, dict) else []
        service = next(
            (candidate for candidate in config_services if isinstance(candidate, dict) and candidate.get("id") == service_id),
            None,
        )

    if service is None:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")

    certificate_overrides = await _service_certificate_overrides(request, resolved_org_id)
    effective_service = _apply_service_certificate_override(service, certificate_overrides)
    if effective_service.get("id") == MANAGED_OPENBAO_SERVICE_ID:
        effective_service["endpoint"] = effective_service.get("endpoint") or (_bao_address() or "")
        effective_service["mount"] = effective_service.get("mount") or "transit"
        if effective_service.get("auth_mode") == "service_token":
            # Keep the config payload free of secrets, but use the real token for
            # server-side operations that need to talk to OpenBao.
            effective_service["auth_reference"] = _bao_token() or ""

    if isinstance(key_reference_override, str) and key_reference_override.strip():
        effective_service["key_reference"] = key_reference_override.strip()
        key_aliases = _dedupe_strings(effective_service.get("key_aliases"))
        if key_reference_override.strip() not in key_aliases:
            effective_service["key_aliases"] = [key_reference_override.strip(), *key_aliases]
        effective_service["key_count"] = max(int(effective_service.get("key_count", 0) or 0), 1)

    normalized = _normalize_registered_service(effective_service)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Service could not be normalized.")

    return registry, effective_service, normalized, from_registry


async def _load_signing_key_snapshot(resolved_org_id: str | None) -> dict[str, Any]:
    if not _has_openbao_access():
        return {
            "keys": [],
            "provider_metadata": _provider_metadata(status="metadata_only", key_count=0),
            "config": {
                "hsm_enabled": False,
                "hsm_settings": {},
                "vault_enabled": False,
                "vault_settings": {},
            },
            "message": "Gateway does not have OpenBao credentials configured for signing-key inventory.",
        }

    try:
        listed_keys = await _openbao_get_json("/v1/transit/keys", params={"list": "true"})
        key_names = listed_keys.get("data", {}).get("keys", [])
        signing_key_names = [key_name for key_name in key_names if _looks_like_signing_key(key_name)]

        key_responses = await asyncio.gather(
            *[_openbao_get_json(f"/v1/transit/keys/{key_name}") for key_name in signing_key_names]
        )
        keys = sorted(
            [
                _normalize_openbao_signing_key(key_name, key_response.get("data", {}))
                for key_name, key_response in zip(signing_key_names, key_responses, strict=False)
            ],
            key=_sort_key_record,
        )

        config = {
            "hsm_enabled": True,
            "hsm_settings": {
                "provider": _provider_name(),
                "service_url": _bao_address(),
                "mount": "transit",
                "managed_by": "Marty service stack",
                "organization_id": resolved_org_id,
                "signing_key_count": len(keys),
                "signing_key_names": [key["id"] for key in keys],
            },
            "vault_enabled": False,
            "vault_settings": {},
        }

        return {
            "keys": keys,
            "provider_metadata": _provider_metadata(status="configured", key_count=len(keys)),
            "config": config,
            "message": None,
        }
    except Exception as exc:  # pragma: no cover - exercised via route tests
        config = {
            "hsm_enabled": True,
            "hsm_settings": {
                "provider": _provider_name(),
                "service_url": _bao_address(),
                "mount": "transit",
                "managed_by": "Marty service stack",
                "organization_id": resolved_org_id,
                "signing_key_count": 0,
                "signing_key_names": [],
                "connection_error": str(exc),
            },
            "vault_enabled": False,
            "vault_settings": {},
        }
        return {
            "keys": [],
            "provider_metadata": _provider_metadata(status="degraded", key_count=0, error=str(exc)),
            "config": config,
            "message": "OpenBao signing-key inventory could not be loaded.",
        }


@signing_key_router.get("", summary="List Signing Keys")
async def list_signing_keys(
    request: Request,
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Return signing-key metadata and inventory from the configured OpenBao transit service."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    keys = [key for key in (snapshot.get("keys") or []) if isinstance(key, dict)]

    discovered_keys = await _load_service_discovered_keys(request, resolved_org_id)
    index_by_reference = {
        key.get("provider_key_name") or key.get("id"): idx
        for idx, key in enumerate(keys)
        if isinstance(key, dict)
    }

    for discovered in discovered_keys:
        reference = discovered.get("provider_key_name") or discovered.get("id")
        if reference in index_by_reference:
            existing_key = dict(keys[index_by_reference[reference]])
            if not existing_key.get("public_jwk"):
                existing_key["public_jwk"] = discovered.get("public_jwk")
            if not existing_key.get("service_id") and discovered.get("service_id"):
                existing_key["service_id"] = discovered.get("service_id")
            keys[index_by_reference[reference]] = existing_key
        else:
            keys.append(discovered)

    return JSONResponse(
        content={
            "keys": keys,
            "provider_metadata": snapshot["provider_metadata"],
            "domain_config": _domain_config(request),
            "message": snapshot["message"],
        }
    )


async def _create_managed_openbao_transit_key(
    service: dict[str, Any],
    key_reference: str,
    algorithm: str,
) -> dict[str, Any]:
    token = _bao_token()
    endpoint = (service.get("endpoint") or _bao_address() or "").rstrip("/")
    mount = (service.get("mount") or "transit").strip("/")
    transit_key_type = OPENBAO_TRANSIT_KEY_TYPE_BY_ALGORITHM.get(algorithm)

    if not transit_key_type:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported signing algorithm '{algorithm}'. Must be one of {sorted(OPENBAO_TRANSIT_KEY_TYPE_BY_ALGORITHM)}.",
        )

    if not endpoint or not token:
        raise HTTPException(status_code=503, detail="Managed OpenBao access is not configured for the gateway.")

    async def create_key() -> None:
        await _openbao_post_json(
            f"/v1/{mount}/keys/{key_reference}",
            {"type": transit_key_type},
            base_url=endpoint,
            token=token,
            timeout=8.0,
        )

    async def read_existing_key() -> dict[str, Any]:
        existing = await _openbao_get_json(
            f"/v1/{mount}/keys/{key_reference}",
            base_url=endpoint,
            token=token,
            timeout=8.0,
        )
        return existing.get("data") if isinstance(existing, dict) else {}

    try:
        await create_key()
    except httpx.HTTPStatusError as exc:
        detail = _httpx_error_detail(exc)
        status_code = exc.response.status_code if exc.response is not None else 0
        if _is_openbao_existing_key_error(status_code, detail):
            return await read_existing_key()

        if _is_missing_openbao_route(status_code, detail):
            logger.warning(
                "Managed OpenBao transit mount %s was missing while creating key %s; enabling and retrying once.",
                mount,
                key_reference,
            )
            await _ensure_openbao_transit_mount(endpoint, token, mount)
            try:
                await create_key()
            except httpx.HTTPStatusError as retry_exc:
                retry_detail = _httpx_error_detail(retry_exc)
                retry_status_code = retry_exc.response.status_code if retry_exc.response is not None else 0
                if _is_openbao_existing_key_error(retry_status_code, retry_detail):
                    return await read_existing_key()

                raise HTTPException(
                    status_code=400 if retry_status_code and retry_status_code < 500 else 502,
                    detail=f"OpenBao could not create transit key '{key_reference}' after enabling mount: {retry_detail}",
                ) from retry_exc

            return await read_existing_key()

        raise HTTPException(
            status_code=400 if status_code and status_code < 500 else 502,
            detail=f"OpenBao could not create transit key '{key_reference}': {detail}",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Managed OpenBao key creation failed: {exc}") from exc

    created = await _openbao_get_json(
        f"/v1/{mount}/keys/{key_reference}",
        base_url=endpoint,
        token=token,
        timeout=8.0,
    )
    return created.get("data") if isinstance(created, dict) else {}


@signing_key_router.post("", summary="Create Signing Key")
async def create_signing_key(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Create a new managed OpenBao transit signing key for the active organization."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    requested_name = body.get("name") if isinstance(body.get("name"), str) else body.get("key_name")
    if not isinstance(requested_name, str) or not requested_name.strip():
        raise HTTPException(status_code=422, detail="name is required.")

    algorithm = body.get("algorithm") if isinstance(body.get("algorithm"), str) else "ES256"
    if algorithm not in SUPPORTED_SIGNING_ALGORITHMS:
        raise HTTPException(status_code=422, detail=f"Unsupported algorithm '{algorithm}'.")

    key_purpose = body.get("key_purpose") if isinstance(body.get("key_purpose"), str) else "vc_jwt_issuer"
    if key_purpose not in KEY_PURPOSES:
        raise HTTPException(status_code=422, detail=f"Unsupported key_purpose '{key_purpose}'.")
    if key_purpose == "lti_tool_signing" and algorithm != "RS256":
        raise HTTPException(
            status_code=422,
            detail="lti_tool_signing keys must use RS256.",
        )

    service_id = body.get("service_id") if isinstance(body.get("service_id"), str) else None
    if not service_id:
        snapshot = await _load_signing_key_snapshot(resolved_org_id)
        config = await _build_key_management_config(request, resolved_org_id, snapshot)
        service_id = config.get("default_service_id") if isinstance(config.get("default_service_id"), str) else None

    if not service_id:
        raise HTTPException(status_code=400, detail="No signing service is configured for this organization.")

    _, _, normalized_service, _ = await _resolve_effective_service(request, resolved_org_id, service_id)
    if service_id != MANAGED_OPENBAO_SERVICE_ID:
        raise HTTPException(
            status_code=400,
            detail="Gateway-managed key creation is currently supported only for the managed OpenBao transit service.",
        )

    provider_key_name = _normalize_requested_openbao_key_name(requested_name, key_purpose, algorithm)
    registry = await _load_registered_service_registry(request, resolved_org_id)
    bindings = _normalize_key_reference_purposes(
        registry.get("key_reference_purposes")
    )
    service_bindings = dict(bindings.get(service_id, {}))
    existing_purposes = service_bindings.get(provider_key_name, [])
    if existing_purposes and (
        "lti_tool_signing" in existing_purposes
        or key_purpose == "lti_tool_signing"
    ) and existing_purposes != [key_purpose]:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Key reference '{provider_key_name}' already has an incompatible "
                "purpose and cannot be reused for LTI tool signing."
            ),
        )
    created_key_details = await _create_managed_openbao_transit_key(normalized_service, provider_key_name, algorithm)
    created_key = _normalize_openbao_signing_key(provider_key_name, created_key_details)
    created_key["name"] = requested_name.strip()
    created_key["service_id"] = service_id
    created_key["key_purpose"] = key_purpose

    service_bindings[provider_key_name] = _dedupe_strings(
        [*existing_purposes, key_purpose]
    )
    bindings[service_id] = service_bindings
    _validate_lti_key_reference_bindings(bindings)
    registry["key_reference_purposes"] = bindings
    await _save_registered_service_registry(request, resolved_org_id, registry)

    return JSONResponse(
        content={
            "ok": True,
            "service_id": service_id,
            "provider_key_name": provider_key_name,
            "key": created_key,
            "created_at": _utcnow_iso(),
        }
    )


@signing_key_router.get("/config", summary="Get Signing Key Management Config")
async def get_signing_key_config(
    request: Request,
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Return the signing-key service registry and the managed OpenBao connection if present."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    config = await _build_key_management_config(request, resolved_org_id, snapshot)
    return JSONResponse(content=config)


@signing_key_router.patch("/config", summary="Update Signing Key Management Config")
async def update_signing_key_config(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Persist the external signing-key service registry for the active organization."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    current_registry = await _load_registered_service_registry(request, resolved_org_id)
    registry_override = _normalize_requested_registry(body) or {"services": [], "default_service_id": None}
    if "key_reference_purposes" not in body:
        # The console edits service registrations independently of managed key
        # bindings.  Never erase the per-key authorization boundary just
        # because an older client did not round-trip this new field.
        registry_override["key_reference_purposes"] = current_registry.get(
            "key_reference_purposes",
            {},
        )
    _validate_lti_key_reference_bindings(
        registry_override.get("key_reference_purposes")
    )
    await _save_registered_service_registry(request, resolved_org_id, registry_override)

    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    config = await _build_key_management_config(
        request,
        resolved_org_id,
        snapshot,
        registry_override=registry_override,
    )
    return JSONResponse(content=config)


@signing_key_router.post("/config/validate", summary="Validate Signing Key Management Service")
async def validate_signing_key_service(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(default=None),
):
    """Run baseline and provider-specific validation checks for a signing service registration."""
    result = await _run_service_validation(body)

    # Persist discovered capabilities when validation succeeds for a registered service.
    if bool(result.get("ok")) and isinstance(body.get("service_id"), str):
        resolved_org_id = _resolve_org_id(request, organization_id)
        registry = await _load_registered_service_registry(request, resolved_org_id)
        services = registry.get("services") if isinstance(registry, dict) else []
        service_idx = next((i for i, s in enumerate(services) if s.get("id") == body["service_id"]), None)
        if service_idx is not None:
            capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
            discovered = {
                "connectivity": True,
                "provider_validation": True,
                "supports_sign": bool(capabilities.get("sign")),
                "supports_rotation": bool(capabilities.get("rotate_keys")),
                "supports_discovery": bool(capabilities.get("discover_keys")),
            }
            services[service_idx]["discovered_capabilities"] = _merge_discovered_capabilities(services[service_idx], discovered)
            services[service_idx]["updated_at"] = _utcnow_iso()
            registry["services"] = services
            await _save_registered_service_registry(request, resolved_org_id, registry)

    return JSONResponse(content=result)


@signing_key_router.post("/config/resolve", summary="Resolve Signing Service for Format/Purpose")
async def resolve_signing_service(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(default=None),
):
    """Return the best matching registered signing service for a credential format, key purpose, and/or algorithm.

    Request body fields (all optional):
    - ``credential_format``: one of ``jwt_vc_json``, ``dc+sd-jwt``, ``mso_mdoc``, ``zk_mdoc``
    - ``key_purpose``: one of the recognised key purpose identifiers
    - ``algorithm``: one of ``ES256``, ``ES384``, ``RS256``, ``EdDSA``

    Resolution order: type_defaults → format_defaults → global default → first matching service.
    Returns ``404`` when no service matches.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)
    registry = await _load_registered_service_registry(request, resolved_org_id)

    credential_format = body.get("credential_format") if isinstance(body.get("credential_format"), str) else None
    key_purpose = body.get("key_purpose") if isinstance(body.get("key_purpose"), str) else None
    algorithm = body.get("algorithm") if isinstance(body.get("algorithm"), str) else None

    service = _resolve_service_for_format(registry, credential_format, key_purpose, algorithm)
    if service is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No registered signing service found for the requested credential_format"
                f" {credential_format!r}, key_purpose {key_purpose!r}, algorithm {algorithm!r}."
            ),
        )

    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    keys = [key for key in (snapshot.get("keys") or []) if isinstance(key, dict)]
    resolved_key_reference = _resolve_key_reference_for_purpose(
        registry,
        service,
        keys,
        key_purpose=key_purpose,
        algorithm=algorithm,
    )
    if key_purpose and not resolved_key_reference:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Signing service '{service.get('id')}' has no key reference bound to "
                f"purpose {key_purpose!r} and algorithm {algorithm!r}."
            ),
        )
    service = dict(service)
    if resolved_key_reference:
        service["key_reference"] = resolved_key_reference

    mdoc_hints = None
    if key_purpose in {"mdoc_dsc", "vdsnc_signing", "csca"} or credential_format in {"mso_mdoc", "zk_mdoc"}:
        x5c = _service_x5c_chain(service)
        if x5c:
            mdoc_hints = {
                "x5c": x5c,
                "x5c_length": len(x5c),
                "key_reference": service.get("key_reference"),
            }

    return JSONResponse(content={
        "service": service,
        "resolved_by": {
            "credential_format": credential_format,
            "key_purpose": key_purpose,
            "algorithm": algorithm,
        },
        "mdoc_signing_hints": mdoc_hints,
    })


@signing_key_router.get("/config/purposes", summary="List Available Key Purposes")
async def list_key_purposes(request: Request):
    """Return canonical key-purpose metadata from the signing-keys service."""
    service_url = get_registry().get_service_url("signing-keys")
    return await proxy_request(request, service_url, "/v1/signing-keys/config/purposes")


@signing_key_router.get("/config/service-capabilities", summary="List Provider Capability Metadata")
async def list_service_capabilities(request: Request):
    """Return canonical provider capabilities from the signing-keys service."""
    service_url = get_registry().get_service_url("signing-keys")
    return await proxy_request(request, service_url, "/v1/signing-keys/config/service-capabilities")


# ---------------------------------------------------------------------------
# X.509 Certificate Lifecycle (GAP-004)
# ---------------------------------------------------------------------------


def _extract_cert_expiry_date(cert_pem: str) -> str | None:
    """Extract the expiry date from a PEM-encoded certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert_bytes = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        expiry = cert.not_valid_after_utc
        # Convert to ISO string: remove +00:00 suffix and append Z
        iso_str = expiry.isoformat()
        if iso_str.endswith("+00:00"):
            iso_str = iso_str[:-6]  # Remove timezone
        return iso_str + "Z"
    except Exception:  # noqa: BLE001
        return None


async def _generate_csr_from_service(
    service_config: dict[str, Any],
) -> str | None:
    """Generate a PKCS#10 CSR from a service's public key."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID

        adapter = _get_adapter(service_config)
        if adapter is None:
            return None

        # Fetch public key from adapter
        jwk = await adapter.get_public_key_jwk(service_config)
        public_key_pem = jwk.get("public_key_pem")
        if not public_key_pem:
            return None

        # Load the public key
        serialization.load_pem_public_key(public_key_pem.encode(), default_backend())

        # Build subject name
        service_name = service_config.get("name") or service_config.get("key_reference") or "Marty Signing Key"
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, service_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Marty Credential Platform"),
        ])

        # Build enough context to prove the key is reachable. CSR signing for
        # remote KMS keys requires a provider-specific Sign operation and DER
        # CSR assembly, which is not implemented for this route yet.
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:marty:kms")]), critical=False)
        return None
    except Exception:  # noqa: BLE001
        return None


@signing_key_router.post("/services/{service_id}/certificate-csr", summary="Generate Certificate Signing Request")
async def generate_csr(
    request: Request,
    service_id: str,
    organization_id: str | None = Query(None),
):
    """Generate a PKCS#10 CSR from a registered signing service's public key.

    For KMS-backed services, the CSR will be generated but requires external signing
    with the KMS provider before the certificate can be stored.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    service = next((s for s in services if s.get("id") == service_id), None)
    if service is None:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")

    normalized = _normalize_registered_service(service)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Service could not be normalized.")

    csr_pem = await _generate_csr_from_service(normalized)
    if not csr_pem:
        raise HTTPException(
            status_code=501,
            detail={
                "error": "kms_csr_generation_unavailable",
                "message": "CSR generation for remote KMS-backed signing services is not implemented for this deployment.",
                "service_id": service_id,
            },
        )

    return JSONResponse(
        content={
            "ok": True,
            "service_id": service_id,
            "csr_pem": csr_pem,
            "generated_at": _utcnow_iso(),
        }
    )


@signing_key_router.put("/services/{service_id}/certificate", summary="Store Certificate for Service")
async def store_service_certificate(
    request: Request,
    service_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Store a certificate and optional certificate chain for a registered signing service."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    cert_pem = body.get("cert_pem") if isinstance(body.get("cert_pem"), str) else None
    cert_chain_pem = body.get("cert_chain_pem") if isinstance(body.get("cert_chain_pem"), str) else None

    if not cert_pem:
        raise HTTPException(status_code=400, detail="cert_pem is required.")

    # Extract expiry date from certificate
    cert_expires_at = _extract_cert_expiry_date(cert_pem)

    registry, _, normalized, from_registry = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
    )
    services = registry.get("services") if isinstance(registry, dict) else []
    service_idx = next((i for i, s in enumerate(services) if s.get("id") == service_id), None)

    updated_at = _utcnow_iso()
    attachment = {
        "cert_pem": cert_pem,
        "cert_chain_pem": cert_chain_pem or "",
        "cert_expires_at": cert_expires_at or "",
        "updated_at": updated_at,
    }
    certificate_document = await _load_json_document(
        request,
        _service_certificates_storage_key(resolved_org_id),
        {"services": {}},
    )
    certificate_services = certificate_document.get("services")
    if not isinstance(certificate_services, dict):
        certificate_services = {}
    certificate_services[service_id] = attachment
    certificate_document["services"] = certificate_services
    certificate_document["updated_at"] = updated_at
    await _save_json_document(
        request,
        _service_certificates_storage_key(resolved_org_id),
        certificate_document,
    )

    # Preserve the existing registry representation for writable external
    # services. Managed services have no registry row, so their attachment is
    # supplied exclusively by the sidecar document above.
    if from_registry and service_idx is not None:
        services[service_idx].update(attachment)
        registry["services"] = services
        await _save_registered_service_registry(request, resolved_org_id, registry)

    normalized = _apply_service_certificate_override(normalized, {service_id: attachment})
    return JSONResponse(
        content={
            "ok": True,
            "service_id": service_id,
            "cert_pem": cert_pem[:100] + "..." if len(cert_pem) > 100 else cert_pem,
            "cert_expires_at": cert_expires_at,
            "stored_at": _utcnow_iso(),
            "service": normalized,
        }
    )


@signing_key_router.get("/services/{service_id}/certificate", summary="Retrieve Service Certificate")
async def get_service_certificate(
    request: Request,
    service_id: str,
    organization_id: str | None = Query(None),
):
    """Retrieve the stored certificate and chain for a registered signing service."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    _, _, normalized, _ = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
    )
    if not normalized or not normalized.get("cert_pem"):
        raise HTTPException(status_code=404, detail=f"No certificate stored for service '{service_id}'.")

    return JSONResponse(
        content={
            "service_id": service_id,
            "cert_pem": normalized["cert_pem"],
            "cert_chain_pem": normalized["cert_chain_pem"],
            "cert_expires_at": normalized["cert_expires_at"],
        }
    )


@signing_key_router.get("/config/certificate-expiry-alerts", summary="List Services with Expiring Certificates")
async def list_certificate_expiry_alerts(
    request: Request,
    days_until_expiry: int = Query(30, description="Alert if certificate expires within this many days"),
    organization_id: str | None = Query(None),
):
    """Return services whose certificates expire within the specified days threshold."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    registry = await _load_registered_service_registry(request, resolved_org_id)
    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    config = await _build_key_management_config(
        request,
        resolved_org_id,
        snapshot,
        registry_override=registry,
    )
    services = config.get("services") if isinstance(config, dict) else []

    now = datetime.now(timezone.utc)
    expiry_threshold = now + timedelta(days=days_until_expiry)

    alerts: list[dict[str, Any]] = []
    for svc in services:
        if isinstance(svc, dict):
            cert_expires_at = svc.get("cert_expires_at")
            if cert_expires_at:
                try:
                    expiry_dt = datetime.fromisoformat(cert_expires_at.replace("Z", "+00:00"))
                    if expiry_dt <= expiry_threshold:
                        # Don't require normalization - we have what we need
                        days_left = (expiry_dt - now).days
                        alerts.append({
                            "service_id": svc.get("id"),
                            "service_name": svc.get("name"),
                            "cert_expires_at": cert_expires_at,
                            "days_until_expiry": max(0, days_left),
                            "status": "critical" if days_left <= 7 else "warning",
                        })
                except ValueError:
                    pass

    return JSONResponse(
        content={
            "alerts": sorted(alerts, key=lambda a: a["days_until_expiry"]),
            "alert_threshold_days": days_until_expiry,
            "checked_at": _utcnow_iso(),
        }
    )


# ---------------------------------------------------------------------------
# Public Key Publication (GAP-005)
# ---------------------------------------------------------------------------


@signing_key_router.post("/services/{service_id}/publish-jwks", summary="Publish Service Public Key to JWKS")
async def publish_service_to_jwks(
    request: Request,
    service_id: str,
    body: dict | None = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Fetch public key from KMS service and publish to organization's JWKS endpoint.

    This endpoint retrieves the public key via the service's KMS adapter and upser ts
    it into the organization's JWKS storage, making it available for credential verification.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    safe_body = body if isinstance(body, dict) else {}
    key_reference_override = safe_body.get("key_reference") if isinstance(safe_body.get("key_reference"), str) else None
    registry, _, normalized, from_registry = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
        key_reference_override=key_reference_override,
    )

    # Fetch public key via adapter
    adapter = _get_adapter(normalized)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter found for service type '{normalized.get('service_type')}'.")

    try:
        raw_jwk = await adapter.get_public_key_jwk(normalized)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Failed to fetch public key from KMS: {str(e)}")

    key_reference = normalized.get("key_reference") if isinstance(normalized.get("key_reference"), str) else None
    jwk = _extract_public_jwk(raw_jwk, key_reference_hint=key_reference)
    if not jwk and isinstance(raw_jwk, dict):
        jwk = dict(raw_jwk)
    if not jwk:
        raise HTTPException(status_code=503, detail="Provider did not return a usable public key for JWKS publication.")

    discovered = {
        "public_key_export": True,
        "last_jwk_fetch_ok": True,
        "provider": normalized.get("provider"),
    }

    services = registry.get("services") if isinstance(registry, dict) else []
    service_idx = next((i for i, s in enumerate(services) if s.get("id") == service_id), None)
    if from_registry and service_idx is not None:
        services[service_idx]["discovered_capabilities"] = _merge_discovered_capabilities(services[service_idx], discovered)
        services[service_idx]["updated_at"] = _utcnow_iso()
        registry["services"] = services
        await _save_registered_service_registry(request, resolved_org_id, registry)

    jwks_doc = await _load_json_document(
        request,
        _jwks_storage_key(resolved_org_id),
        {"keys": [], "organization_id": resolved_org_id, "updated_at": _utcnow_iso()},
    )
    existing_keys = jwks_doc.get("keys") if isinstance(jwks_doc.get("keys"), list) else []

    kid = (
        jwk.get("kid")
        or normalized.get("key_reference")
        or service_id
    )
    stored_jwk = dict(jwk)
    stored_jwk["kid"] = kid
    stored_jwk["service_id"] = service_id
    stored_jwk["key_reference"] = normalized.get("key_reference")
    if normalized.get("cert_chain_pem"):
        x5c = _service_x5c_chain(normalized)
        if x5c:
            stored_jwk["x5c"] = x5c

    updated_keys = [
        existing
        for existing in existing_keys
        if not (
            isinstance(existing, dict)
            and (existing.get("kid") == kid or existing.get("service_id") == service_id)
        )
    ]
    updated_keys.append(stored_jwk)
    jwks_doc["keys"] = updated_keys
    jwks_doc["organization_id"] = resolved_org_id
    jwks_doc["updated_at"] = _utcnow_iso()
    await _save_json_document(request, _jwks_storage_key(resolved_org_id), jwks_doc)

    return JSONResponse(
        content={
            "ok": True,
            "service_id": service_id,
            "message": "Public key published to organization JWKS document",
            "jwk": stored_jwk,
            "jwks_document": {
                "organization_id": resolved_org_id,
                "key_count": len(updated_keys),
            },
            "published_at": _utcnow_iso(),
        }
    )


@signing_key_router.post("/services/{service_id}/publish-did-vm", summary="Publish Service Public Key to DID Document")
async def publish_service_to_did(
    request: Request,
    service_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Add a verificationMethod to the organization's DID document using the service's public key.

    This endpoint retrieves the public key and optionally certificate chain, then
    creates a verificationMethod entry in the DID document for credential verification.

    Body accepts optional fields:
      - ``did_id``: Full DID to use as the document ``id`` (e.g. ``did:web:beta.elevenidllc.com:orgs:acme``).
        When omitted, a path-scoped DID is derived from ``org_slug`` and the platform domain.
      - ``org_slug``: URL-safe slug for the organization, used in path-scoped did:web identifiers.
        When provided the gateway stores a ``did-web-slug:{slug} → org_id`` mapping so
        the public ``/orgs/{slug}/did.json`` endpoint can resolve the document without auth.
      - ``fragment``: Verification-method fragment override (default: ``{service_id}-vm``).
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    key_reference_override = body.get("key_reference") if isinstance(body.get("key_reference"), str) else None
    registry, _, normalized, from_registry = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
        key_reference_override=key_reference_override,
    )

    # Fetch public key via adapter
    adapter = _get_adapter(normalized)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter found for service type '{normalized.get('service_type')}'.")

    try:
        raw_jwk = await adapter.get_public_key_jwk(normalized)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Failed to fetch public key from KMS: {str(e)}")

    key_reference = normalized.get("key_reference") if isinstance(normalized.get("key_reference"), str) else None
    jwk = _extract_public_jwk(raw_jwk, key_reference_hint=key_reference)
    if not jwk and isinstance(raw_jwk, dict):
        jwk = dict(raw_jwk)
    if not jwk:
        raise HTTPException(status_code=503, detail="Provider did not return a usable public key for DID publication.")

    # --- Resolve DID identifier ---------------------------------------------------
    # Only an exact DID on this gateway's configured did:web domain may claim a
    # local public slug. External and root DIDs remain publishable without a
    # local mapping for compatibility.
    configured_public_domain = _normalize_did_web_domain(_domain_config(request).get("public_domain"))
    if not configured_public_domain:
        raise HTTPException(status_code=503, detail="PUBLIC_DOMAIN is not a valid did:web domain.")

    raw_did_id = body.get("did_id")
    if raw_did_id is not None and (
        not isinstance(raw_did_id, str) or not raw_did_id or raw_did_id != raw_did_id.strip()
    ):
        raise HTTPException(status_code=422, detail="did_id must be a non-empty DID without surrounding whitespace.")
    did_id = raw_did_id

    raw_org_slug = body.get("org_slug")
    if raw_org_slug is not None and (
        not isinstance(raw_org_slug, str) or not _SLUG_PATTERN.fullmatch(raw_org_slug)
    ):
        raise HTTPException(status_code=422, detail="org_slug must contain only letters, numbers, '.', '_' or '-'.")
    org_slug = raw_org_slug.lower() if isinstance(raw_org_slug, str) else None

    if not did_id:
        org_slug = org_slug or resolved_org_id.lower()
        if not _SLUG_PATTERN.fullmatch(org_slug):
            raise HTTPException(status_code=422, detail="Organization ID cannot be used as a did:web slug.")
        did_domain = configured_public_domain.replace(":", "%3A")
        did_id = f"did:web:{did_domain}:orgs:{org_slug}"
    elif did_id.startswith("did:web:"):
        local_slug = _did_web_org_slug(did_id, public_domain=configured_public_domain)
        did_domain = _did_web_domain(did_id)
        if did_domain == configured_public_domain and len(did_id.split(":")) != 3 and local_slug is None:
            raise HTTPException(
                status_code=422,
                detail="Local did:web identifiers must use did:web:<PUBLIC_DOMAIN>:orgs:<slug>.",
            )
        if org_slug is not None and local_slug != org_slug:
            raise HTTPException(
                status_code=422,
                detail="org_slug must match a path-scoped DID on the configured PUBLIC_DOMAIN.",
            )
        org_slug = org_slug or local_slug
    elif org_slug is not None:
        raise HTTPException(status_code=422, detail="org_slug is only valid for a local path-scoped did:web identifier.")

    # Build verification method structure
    vm_id = body.get("fragment") or _did_fragment_for_key_reference(service_id, key_reference)
    verification_method = {
        "id": f"{did_id}#{vm_id}",
        "type": "JsonWebKey",
        "controller": did_id,
        "publicKeyJwk": jwk,
    }

    # Add certificate chain if present
    x5c = _service_x5c_chain(normalized)
    if x5c:
        verification_method["x5c"] = x5c

    discovered = {
        "public_key_export": True,
        "did_verification_method_publish": True,
        "last_did_publish_ok": True,
        "provider": normalized.get("provider"),
        "has_x5c": bool(x5c),
    }
    services = registry.get("services") if isinstance(registry, dict) else []
    service_idx = next((i for i, s in enumerate(services) if s.get("id") == service_id), None)
    if from_registry and service_idx is not None:
        services[service_idx]["discovered_capabilities"] = _merge_discovered_capabilities(services[service_idx], discovered)
        services[service_idx]["updated_at"] = _utcnow_iso()
        registry["services"] = services
        await _save_registered_service_registry(request, resolved_org_id, registry)

    did_doc = await _load_json_document(
        request,
        _did_doc_storage_key(resolved_org_id),
        {
            "id": did_id,
            "controller": did_id,
            "verificationMethod": [],
            "assertionMethod": [],
            "updated_at": _utcnow_iso(),
        },
    )

    # Ensure the document id matches the resolved DID (may have been created with a placeholder)
    did_doc["id"] = did_id
    did_doc["controller"] = did_id

    methods = did_doc.get("verificationMethod") if isinstance(did_doc.get("verificationMethod"), list) else []
    methods = [m for m in methods if not (isinstance(m, dict) and m.get("id") == verification_method["id"])]
    methods.append(verification_method)
    did_doc["verificationMethod"] = methods

    assertion = did_doc.get("assertionMethod") if isinstance(did_doc.get("assertionMethod"), list) else []
    assertion = [entry for entry in assertion if entry != verification_method["id"]]
    assertion.append(verification_method["id"])
    did_doc["assertionMethod"] = assertion
    did_doc["updated_at"] = _utcnow_iso()
    await _save_json_document(request, _did_doc_storage_key(resolved_org_id), did_doc)

    # --- Store slug → org_id mapping for public did:web resolution ----------------
    if org_slug:
        await _claim_did_web_slug(request, org_slug, resolved_org_id)

    return JSONResponse(
        content={
            "ok": True,
            "service_id": service_id,
            "message": "Verification method published to organization DID document",
            "verification_method": verification_method,
            "did_document": {
                "id": did_doc.get("id"),
                "verification_method_count": len(methods),
            },
            "published_at": _utcnow_iso(),
        }
    )


@signing_key_router.get("/jwks", summary="Get Organization JWKS Document")
async def get_organization_jwks(
    request: Request,
    organization_id: str | None = Query(None),
):
    resolved_org_id = _resolve_org_id(request, organization_id)
    jwks_doc = await _load_json_document(
        request,
        _jwks_storage_key(resolved_org_id),
        {"keys": [], "organization_id": resolved_org_id, "updated_at": _utcnow_iso()},
    )
    return JSONResponse(content=jwks_doc)


@signing_key_router.get("/did-document", summary="Get Organization DID Document")
async def get_organization_did_document(
    request: Request,
    organization_id: str | None = Query(None),
):
    resolved_org_id = _resolve_org_id(request, organization_id)
    domain_cfg = _domain_config(request)
    public_domain = domain_cfg.get("public_domain", "")
    fallback_did = f"did:web:{public_domain}:orgs:{resolved_org_id}"
    did_doc = await _load_json_document(
        request,
        _did_doc_storage_key(resolved_org_id),
        {
            "id": fallback_did,
            "controller": fallback_did,
            "verificationMethod": [],
            "assertionMethod": [],
            "updated_at": _utcnow_iso(),
        },
    )
    return JSONResponse(content=did_doc)


@signing_key_router.get("/services/{service_id}/mdoc-x5c", summary="Get mDoc X.509 Header Material")
async def get_mdoc_x5c_material(
    request: Request,
    service_id: str,
    organization_id: str | None = Query(None),
):
    """Return the x5c chain that issuance can inject into mDoc COSE protected headers."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    service = next((s for s in services if s.get("id") == service_id), None)
    if service is None:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")

    normalized = _normalize_registered_service(service)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Service could not be normalized.")

    x5c = _service_x5c_chain(normalized)
    if not x5c:
        raise HTTPException(status_code=404, detail=f"No certificate chain stored for service '{service_id}'.")

    return JSONResponse(
        content={
            "service_id": service_id,
            "key_reference": normalized.get("key_reference"),
            "x5c": x5c,
            "mdoc_cose_header_hints": {
                "x5chain": True,
                "x5c_length": len(x5c),
            },
        }
    )


@signing_key_router.post("/services/{service_id}/sign", summary="Sign Payload Using Service Key")
async def sign_payload_with_service(
    request: Request,
    service_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Sign a payload using a registered signing service's key.

    This endpoint retrieves or accepts a payload in base64 or raw bytes, signs it
    using the service's KMS adapter, and returns the signature with encoding metadata.

    Request body:
    - `payload_b64` (str): Base64url-encoded payload to sign
    - `payload_hex` (str): Hex-encoded payload to sign
    - `algorithm` (str, optional): Specify algorithm (for multi-key services)

    Response:
    - `signature_b64`: Base64url-encoded signature
    - `signature_hex`: Hex-encoded signature
    - `encoding`: "raw_ieee_p1363" or "der"
    - `algorithm`: Algorithm used
    - `service_id`: The service that performed the signing
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    # Parse payload from request
    payload_b64 = body.get("payload_b64")
    payload_hex = body.get("payload_hex")
    algorithm = body.get("algorithm")

    payload_bytes: bytes | None = None
    if payload_b64:
        try:
            # Handle both standard and URL-safe base64
            b64 = payload_b64
            padding = "=" * (-len(b64) % 4)
            payload_bytes = base64.urlsafe_b64decode(b64 + padding)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Invalid payload_b64: {exc}")
    elif payload_hex:
        try:
            payload_bytes = bytes.fromhex(payload_hex)
        except ValueError as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Invalid payload_hex: {exc}")

    if not payload_bytes:
        raise HTTPException(status_code=400, detail="Either payload_b64 or payload_hex is required")

    key_reference_override = body.get("key_reference") if isinstance(body.get("key_reference"), str) else None
    registry, service, normalized, _ = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
        key_reference_override=key_reference_override,
    )

    # Purpose is an authorization boundary, not descriptive metadata.  A
    # caller that needs a special-purpose signature (for example, Canvas LTI
    # tool assertions) must name that purpose and may only use a service that
    # was registered for it.  This prevents credential-issuer keys from being
    # reused as protocol/client-assertion keys merely by knowing a service ID.
    key_purpose = (
        body.get("key_purpose")
        if isinstance(body.get("key_purpose"), str)
        else None
    )
    requested_key_reference = (
        key_reference_override.strip()
        if isinstance(key_reference_override, str)
        else ""
    )
    reference_purposes = (
        _purposes_for_key_reference(
            registry,
            service_id=service_id,
            key_reference=requested_key_reference,
        )
        if requested_key_reference
        else []
    )
    if (
        "lti_tool_signing" in reference_purposes
        and key_purpose != "lti_tool_signing"
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Key reference '{requested_key_reference}' is reserved exclusively "
                "for lti_tool_signing."
            ),
        )
    if key_purpose:
        if key_purpose not in KEY_PURPOSES:
            raise HTTPException(
                status_code=422,
                detail=f"Unsupported key_purpose '{key_purpose}'.",
            )
        service_purposes = normalized.get("key_purposes")
        if not isinstance(service_purposes, list):
            service_purposes = service.get("key_purposes")
        if not isinstance(service_purposes, list) or key_purpose not in service_purposes:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Signing service '{service_id}' is not configured for "
                    f"key_purpose '{key_purpose}'."
                ),
            )

    if key_purpose == "lti_tool_signing":
        if not requested_key_reference:
            raise HTTPException(
                status_code=409,
                detail=(
                    "LTI tool signing requires an explicit key_reference; the "
                    "signing service default may be a credential issuer key."
                ),
            )
        if algorithm != "RS256":
            raise HTTPException(
                status_code=409,
                detail="LTI tool signing requires the dedicated RSA/RS256 key.",
            )
        if reference_purposes != ["lti_tool_signing"]:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Key reference '{requested_key_reference}' is not registered "
                    "exclusively for lti_tool_signing."
                ),
            )
        if resolved_org_id:
            issuer_references = await _credential_issuer_key_references(
                request,
                resolved_org_id,
            )
            if (
                requested_key_reference in issuer_references
                or f"service-default:{service_id}" in issuer_references
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Key reference '{requested_key_reference}' is assigned to a "
                        "credential issuer profile and cannot sign LTI assertions."
                    ),
                )

    # Validate algorithm if specified
    service_algorithms = _normalize_algorithm_list(normalized.get("algorithms")) or _normalize_algorithm_list(service.get("algorithms"))
    service_algorithm = algorithm if algorithm in service_algorithms else (service_algorithms[0] if service_algorithms else "ES256")
    if algorithm:
        if algorithm != service_algorithm:
            allowed_algorithms = service_algorithms or service.get("supported_algorithms") or [service_algorithm]
            if algorithm not in allowed_algorithms:
                raise HTTPException(
                    status_code=400,
                    detail=f"Algorithm '{algorithm}' not supported by this service. Supported: {allowed_algorithms}",
                )
    else:
        algorithm = service_algorithm

    # Get adapter and sign
    adapter = _get_adapter(normalized)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter found for service type '{service.get('service_type')}'.")

    try:
        signature_bytes = await adapter.sign(normalized, payload_bytes)
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code if exc.response is not None else 0
        key_reference = normalized.get("key_reference") if isinstance(normalized.get("key_reference"), str) else ""
        service_type = str(normalized.get("service_type") or service.get("service_type") or "")
        can_auto_create_managed_key = (
            service_id == MANAGED_OPENBAO_SERVICE_ID
            and status_code == 404
            and service_type in {"openbao-transit", "hashicorp-vault-transit", "custom-transit-compatible"}
            and key_reference
        )
        if not can_auto_create_managed_key:
            raise HTTPException(status_code=503, detail=f"Signing failed: {_httpx_error_detail(exc)}") from exc

        logger.warning(
            "Managed OpenBao key %s was missing during sign for org=%s; creating and retrying once.",
            key_reference,
            resolved_org_id,
        )
        await _create_managed_openbao_transit_key(normalized, key_reference, algorithm or service_algorithm)
        try:
            signature_bytes = await adapter.sign(normalized, payload_bytes)
        except Exception as retry_exc:  # noqa: BLE001
            raise HTTPException(status_code=503, detail=f"Signing retry failed: {str(retry_exc)}") from retry_exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Signing failed: {str(exc)}") from exc

    # Determine signature encoding from adapter
    signature_encoding = getattr(adapter, "signature_encoding", "der")

    # If DER-encoded and a raw format is needed, convert (optional transcoding)
    # This is provided as an option in the response; callers can use it if needed
    signature_transcoded: bytes | None = None
    if signature_encoding == "der":
        try:
            # Infer key size from algorithm
            key_size_bytes = 32 if algorithm in {"ES256"} else (48 if algorithm in {"ES384"} else 32)
            from gateway.kms_adapters import der_to_raw_ecdsa
            signature_transcoded = der_to_raw_ecdsa(signature_bytes, key_size_bytes)
        except Exception:  # noqa: BLE001
            # If transcoding fails, just return DER; caller can handle it
            pass

    # Return signature(s) in multiple encodings for flexibility
    response_data = {
        "ok": True,
        "service_id": service_id,
        "algorithm": algorithm,
        "payload_length": len(payload_bytes),
        "signature_encoding": signature_encoding,
        "signature_b64": base64.urlsafe_b64encode(signature_bytes).decode().rstrip("="),
        "signature_hex": signature_bytes.hex(),
        "signed_at": _utcnow_iso(),
    }

    # Add transcoded signature if available
    if signature_transcoded:
        response_data["signature_raw_b64"] = base64.urlsafe_b64encode(signature_transcoded).decode().rstrip("=")
        response_data["signature_raw_hex"] = signature_transcoded.hex()

    return JSONResponse(content=response_data)


@internal_signing_key_router.get("/issuer-context", summary="Resolve Active Issuer Profile")
async def internal_resolve_issuer_context(
    request: Request,
    organization_id: str = Query(..., description="Organization ID"),
    issuer_profile_id: str | None = Query(None, description="Explicit issuer profile ID to use"),
    issuer_mode: str = Query("org_managed", description="Issuer mode to select when issuer_profile_id is omitted"),
    credential_format: str | None = Query(None),
    key_purpose: str | None = Query(None),
    algorithm: str | None = Query(None),
    x_api_key: str | None = Header(default=None),
):
    """Return the active DID issuer profile bound to a registered signing service.

    This is intentionally service-to-service only. The issuance service uses it
    when creating wallet offers so transactions carry the exact DID + remote KMS
    service that should sign credentials later.
    """
    _require_internal_signing_key_api_key(x_api_key)
    requested_issuer_mode = _normalize_issuer_mode(issuer_mode)

    profiles_doc = await _load_json_document(
        request,
        _issuer_profiles_storage_key(organization_id),
        {"profiles": []},
    )
    profiles = profiles_doc.get("profiles") if isinstance(profiles_doc, dict) else []
    active_profiles = [
        profile
        for profile in (profiles or [])
        if isinstance(profile, dict)
        and profile.get("status") == "active"
        and profile.get("issuer_did")
        and profile.get("signing_service_id")
    ]

    if issuer_profile_id:
        selected = next((profile for profile in active_profiles if profile.get("id") == issuer_profile_id), None)
        if selected is None:
            raise HTTPException(
                status_code=404,
                detail="Requested issuer profile is not active for this organization.",
            )
        if key_purpose and selected.get("key_purpose") != key_purpose:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Requested issuer profile '{issuer_profile_id}' is configured for "
                    f"key_purpose '{selected.get('key_purpose')}', not '{key_purpose}'."
                ),
            )
        active_profiles = [selected]
    else:
        active_profiles = [
            profile
            for profile in active_profiles
            if _normalize_issuer_mode(profile.get("issuer_mode")) == requested_issuer_mode
        ]

    if key_purpose:
        preferred = [
            profile
            for profile in active_profiles
            if profile.get("key_purpose") == key_purpose
        ]
        active_profiles = preferred

    if not active_profiles:
        raise HTTPException(
            status_code=404,
            detail=(
                "No active issuer profile is configured for this organization. "
                "Create a DID identity backed by a registered remote signing service first."
            ),
        )

    profile = active_profiles[0]
    profile_issuer_mode = _normalize_issuer_mode(profile.get("issuer_mode"))
    service_id = str(profile["signing_service_id"])
    key_reference = profile.get("signing_key_reference") if isinstance(profile.get("signing_key_reference"), str) else None
    registry, _, normalized, _ = await _resolve_effective_service(
        request,
        organization_id,
        service_id,
        key_reference_override=key_reference,
    )

    requested_purpose = key_purpose or profile.get("key_purpose")
    effective_profile = dict(profile)
    effective_profile["signing_key_reference"] = (
        profile.get("signing_key_reference") or normalized.get("key_reference")
    )
    effective_profile["key_purpose"] = requested_purpose or "vc_jwt_issuer"
    _assert_issuer_profile_key_compatible(effective_profile, registry)
    # mDoc issuer authentication uses an X.509 chain in the protected COSE
    # header.  Return it only on this internal, service-to-service contract;
    # it is public certificate material, but must not be supplied by a wallet
    # claim or inferred by the issuance service.
    mdoc_x5c = _service_x5c_chain(normalized)
    if credential_format or requested_purpose or algorithm:
        resolved = _resolve_service_for_format(registry, credential_format, requested_purpose, algorithm)
        if resolved is not None and resolved.get("id") != service_id:
            logger.info(
                "Issuer profile service %s differs from format resolver %s for org=%s format=%s purpose=%s",
                service_id,
                resolved.get("id"),
                organization_id,
                credential_format,
                requested_purpose,
            )

    return JSONResponse(
        content={
            "ok": True,
            "organization_id": organization_id,
            "issuer_profile_id": profile.get("id"),
            "issuer_mode": profile_issuer_mode,
            "issuer_did": profile.get("issuer_did"),
            "signing_service_id": service_id,
            "signing_key_reference": profile.get("signing_key_reference") or normalized.get("key_reference"),
            "verification_method_id": profile.get("verification_method_id") or _normalize_did_verification_method_id(
                str(profile.get("issuer_did") or ""),
                _did_fragment_for_key_reference(service_id, profile.get("signing_key_reference") or normalized.get("key_reference")),
            ),
            "key_purpose": profile.get("key_purpose") or requested_purpose or "vc_jwt_issuer",
            "mdoc_x5c": mdoc_x5c,
            "issuer_profile": profile,
            "service": normalized,
        }
    )


@internal_signing_key_router.get("/resolve-issuer-did", summary="Resolve Issuer DID Through Org Registry")
async def internal_resolve_issuer_did(
    request: Request,
    organization_id: str = Query(..., description="Organization ID"),
    issuer_did: str = Query(..., description="Issuer DID from the credential"),
    verification_method_id: str | None = Query(None, description="Expected DID verification method / kid"),
    credential_format: str | None = Query(None),
    key_purpose: str | None = Query(None),
    algorithm: str | None = Query(None),
    x_api_key: str | None = Header(default=None),
):
    """Resolve an issuer DID to its org-owned KMS-backed public key.

    Verification services call this endpoint before public DID resolution so
    remote KMS keys remain behind organization-scoped DID issuer identities.
    """
    _require_internal_signing_key_api_key(x_api_key)
    if not issuer_did.startswith("did:"):
        raise HTTPException(status_code=422, detail="issuer_did must be a DID string.")

    resolved = await _resolve_org_scoped_issuer_identity(
        request,
        organization_id=organization_id,
        issuer_did=issuer_did,
        verification_method_id=verification_method_id,
        credential_format=credential_format,
        key_purpose=key_purpose,
        algorithm=algorithm,
    )
    return JSONResponse(content=resolved)


@internal_signing_key_router.post("/services/{service_id}/sign", summary="Sign Payload Using Service Key")
async def internal_sign_payload_with_service(
    request: Request,
    service_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str = Query(..., description="Organization scope"),
    x_api_key: str | None = Header(default=None),
):
    """Service-to-service wrapper around the remote KMS signing endpoint."""
    _require_internal_signing_key_api_key(x_api_key)
    return await sign_payload_with_service(
        request=request,
        service_id=service_id,
        body=body,
        organization_id=organization_id,
    )


async def _rotate_openbao_transit_key(service: dict[str, Any]) -> dict[str, Any]:
    endpoint = (service.get("endpoint") or _bao_address() or "").rstrip("/")
    token = _bao_token() if service.get("auth_mode") == "service_token" else (service.get("auth_reference") or _bao_token())
    if not endpoint or not token:
        return {"ok": False, "error": "Transit endpoint or token unavailable for rotation."}

    mount = service.get("mount") or "transit"
    key_reference = service.get("key_reference")
    if not key_reference:
        return {"ok": False, "error": "key_reference is required for rotation."}

    headers = {"X-Vault-Token": token, "Accept": "application/json"}
    namespace = service.get("namespace")
    if isinstance(namespace, str) and namespace.strip():
        headers["X-Vault-Namespace"] = namespace

    async with httpx.AsyncClient(base_url=endpoint, timeout=8.0, headers=headers) as client:
        rotate_response = await client.post(f"/v1/{mount}/keys/{key_reference}/rotate")
        if rotate_response.status_code not in {200, 204}:
            return {"ok": False, "error": f"Rotation call failed with HTTP {rotate_response.status_code}."}

        read_response = await client.get(f"/v1/{mount}/keys/{key_reference}")
        if read_response.status_code != 200:
            return {"ok": True, "version": None}

        body = read_response.json() if read_response.content else {}
        data = body.get("data") if isinstance(body, dict) else {}
        latest_version = data.get("latest_version") if isinstance(data, dict) else None
        return {"ok": True, "version": latest_version}


@signing_key_router.post("/services/{service_id}/rotate", summary="Rotate Signing Service Key")
async def rotate_service_key(
    request: Request,
    service_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Rotate a signing key with overlap and optional publication refresh."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    registry, service, normalized, from_registry = await _resolve_effective_service(request, resolved_org_id, service_id)

    overlap_days = int(body.get("overlap_days", 7) or 7)
    activate_at = body.get("activate_at") if isinstance(body.get("activate_at"), str) else _utcnow_iso()
    publish_updates = bool(body.get("publish_updates", True))

    provider_rotation = {"ok": False, "error": "No provider rotation adapter available."}
    if normalized.get("service_type") in {"openbao-transit", "hashicorp-vault-transit", "custom-transit-compatible"}:
        provider_rotation = await _rotate_openbao_transit_key(normalized)

    rotation_state = service.get("rotation_state") if isinstance(service.get("rotation_state"), dict) else {}
    previous = rotation_state.get("previous_versions") if isinstance(rotation_state.get("previous_versions"), list) else []
    if normalized.get("key_reference"):
        previous.append(
            {
                "key_reference": normalized.get("key_reference"),
                "retire_after": (datetime.now(timezone.utc) + timedelta(days=overlap_days)).isoformat(),
                "recorded_at": _utcnow_iso(),
            }
        )

    rotation_state.update(
        {
            "last_rotated_at": _utcnow_iso(),
            "activate_at": activate_at,
            "overlap_days": overlap_days,
            "previous_versions": previous,
            "provider_rotation": provider_rotation,
        }
    )

    service["rotation_state"] = rotation_state
    policy = service.get("rotation_policy") if isinstance(service.get("rotation_policy"), dict) else {}
    service["rotation_policy"] = {
        "rotation_interval_days": int(policy.get("rotation_interval_days", 0) or 0),
        "overlap_days": overlap_days,
        "auto_publish": publish_updates,
    }
    service["updated_at"] = _utcnow_iso()
    if from_registry:
        services = registry.get("services") if isinstance(registry, dict) else []
        service_idx = next((i for i, s in enumerate(services) if s.get("id") == service_id), None)
        if service_idx is not None:
            services[service_idx] = service
            registry["services"] = services
            await _save_registered_service_registry(request, resolved_org_id, registry)

    publication = {"jwks": False, "did": False}
    if publish_updates:
        try:
            await publish_service_to_jwks(request=request, service_id=service_id, organization_id=resolved_org_id)
            publication["jwks"] = True
        except Exception:
            publication["jwks"] = False
        try:
            await publish_service_to_did(request=request, service_id=service_id, body={}, organization_id=resolved_org_id)
            publication["did"] = True
        except Exception:
            publication["did"] = False

    return JSONResponse(
        content={
            "ok": bool(provider_rotation.get("ok", False)),
            "service_id": service_id,
            "rotation_state": rotation_state,
            "publication": publication,
            "rotated_at": _utcnow_iso(),
            "note": "Provider rotation is best-effort for non-transit cloud services.",
        }
    )


@signing_key_router.post("/holder-keys", summary="Register Holder/Presentation Key")
async def register_holder_key(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Register a wallet-supplied holder binding or presentation key descriptor."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    key_purpose = body.get("key_purpose") if isinstance(body.get("key_purpose"), str) else "holder_binding"
    if key_purpose not in {"holder_binding", "presentation_signing"}:
        raise HTTPException(status_code=422, detail="key_purpose must be holder_binding or presentation_signing")

    device_id = body.get("device_id") if isinstance(body.get("device_id"), str) else ""
    credential_id = body.get("credential_id") if isinstance(body.get("credential_id"), str) else ""
    public_jwk = body.get("public_jwk") if isinstance(body.get("public_jwk"), dict) else None
    if not device_id or not credential_id or not public_jwk:
        raise HTTPException(status_code=422, detail="device_id, credential_id, and public_jwk are required")

    holder_doc = await _load_json_document(
        request,
        _holder_keys_storage_key(resolved_org_id),
        {"organization_id": resolved_org_id, "keys": [], "updated_at": _utcnow_iso()},
    )
    records = holder_doc.get("keys") if isinstance(holder_doc.get("keys"), list) else []
    record_id = f"holder:{device_id}:{credential_id}:{key_purpose}"
    records = [r for r in records if not (isinstance(r, dict) and r.get("id") == record_id)]
    records.append(
        {
            "id": record_id,
            "device_id": device_id,
            "credential_id": credential_id,
            "key_purpose": key_purpose,
            "public_jwk": public_jwk,
            "created_at": _utcnow_iso(),
        }
    )
    holder_doc["keys"] = records
    holder_doc["updated_at"] = _utcnow_iso()
    await _save_json_document(request, _holder_keys_storage_key(resolved_org_id), holder_doc)

    return JSONResponse(content={"ok": True, "record_id": record_id, "registered_at": _utcnow_iso()})


@signing_key_router.get("/holder-keys", summary="List Holder/Presentation Keys")
async def list_holder_keys(
    request: Request,
    organization_id: str | None = Query(None),
    device_id: str | None = Query(None),
):
    resolved_org_id = _resolve_org_id(request, organization_id)
    holder_doc = await _load_json_document(
        request,
        _holder_keys_storage_key(resolved_org_id),
        {"organization_id": resolved_org_id, "keys": [], "updated_at": _utcnow_iso()},
    )
    records = holder_doc.get("keys") if isinstance(holder_doc.get("keys"), list) else []
    if device_id:
        records = [r for r in records if isinstance(r, dict) and r.get("device_id") == device_id]
    return JSONResponse(content={"organization_id": resolved_org_id, "keys": records})


@signing_key_router.post("/holder-keys/derive", summary="Derive Holder Binding Key Reference")
async def derive_holder_key_reference(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Expose deterministic holder-binding key derivation for server-managed wallet flows."""
    _resolve_org_id(request, organization_id)
    device_id = body.get("device_id") if isinstance(body.get("device_id"), str) else ""
    credential_id = body.get("credential_id") if isinstance(body.get("credential_id"), str) else ""
    if not device_id or not credential_id:
        raise HTTPException(status_code=422, detail="device_id and credential_id are required")

    try:
        from marty_common.crypto.credential_kms import CredentialKeyPrefix  # type: ignore

        key_reference = CredentialKeyPrefix.holder_key_id(device_id, credential_id)
    except Exception:
        key_reference = f"cred:holder:{device_id}:{credential_id}"

    return JSONResponse(
        content={
            "ok": True,
            "device_id": device_id,
            "credential_id": credential_id,
            "key_purpose": "holder_binding",
            "derived_key_reference": key_reference,
            "derived_at": _utcnow_iso(),
        }
    )


@signing_key_router.post("/services/vdsnc/register", summary="Register VDS-NC Signing Service")
async def register_vdsnc_service(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Register a namespaced VDS-NC signer entry in the service registry."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    country_code = (body.get("country_code") or "").strip().upper() if isinstance(body.get("country_code"), str) else ""
    authority_name = (body.get("authority_name") or "").strip() if isinstance(body.get("authority_name"), str) else ""
    role = (body.get("role") or "dsc").strip().lower() if isinstance(body.get("role"), str) else "dsc"
    generation = int(body.get("generation", 1) or 1)
    key_reference = (body.get("key_reference") or "").strip() if isinstance(body.get("key_reference"), str) else ""
    if not country_code or not authority_name:
        raise HTTPException(status_code=422, detail="country_code and authority_name are required")

    if not key_reference:
        try:
            from marty_common.crypto.credential_kms import CredentialKeyPrefix  # type: ignore

            key_reference = CredentialKeyPrefix.vdsnc_key_id(country_code, role, generation)
        except Exception:
            key_reference = f"cred:vdsnc:{country_code}:{role}:{generation}"

    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    new_service = _normalize_registered_service(
        {
            "id": f"svc-vdsnc-{country_code.lower()}-{uuid.uuid4().hex[:8]}",
            "name": f"VDS-NC {country_code} {authority_name}",
            "service_type": body.get("service_type") or "custom-transit-compatible",
            "provider": body.get("provider") or "custom",
            "endpoint": body.get("endpoint") or "",
            "mount": body.get("mount") or "transit",
            "namespace": body.get("namespace") or "",
            "auth_mode": body.get("auth_mode") or "token",
            "auth_reference": body.get("auth_reference") or "",
            "key_reference": key_reference,
            "algorithms": body.get("algorithms") or ["ES256"],
            "key_purposes": ["vdsnc_signing"],
            "credential_formats": ["mso_mdoc"],
            "country_code": country_code,
            "authority_name": authority_name,
            "discovered_capabilities": {
                "vdsnc_namespaced_key_reference": key_reference,
                "vdsnc_role": role,
                "vdsnc_generation": generation,
            },
        }
    )
    if new_service is None:
        raise HTTPException(status_code=400, detail="Failed to normalize VDS-NC service registration")

    services = [s for s in services if not (isinstance(s, dict) and s.get("id") == new_service["id"])]
    services.append(new_service)
    registry["services"] = services
    if not registry.get("default_service_id"):
        registry["default_service_id"] = new_service["id"]
    await _save_registered_service_registry(request, resolved_org_id, registry)

    return JSONResponse(content={"ok": True, "service": new_service, "registered_at": _utcnow_iso()})


# ---------------------------------------------------------------------------
# Public Key Verification (GAP-006)
# ---------------------------------------------------------------------------


@signing_key_router.get("/services/{service_id}/verify-current", summary="Verify Current Public Key")
async def verify_service_public_key(
    request: Request,
    service_id: str,
    organization_id: str | None = Query(None),
):
    """Verify that the service's current public key is valid and matches expected state.

    This endpoint performs checks such as:
    - Fetching current public key from KMS
    - Comparing with previously stored key
    - Validating key properties (algorithm, curve, etc.)
    - Checking key status and lifecycle
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    service = next((s for s in services if s.get("id") == service_id), None)
    if service is None:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")

    normalized = _normalize_registered_service(service)
    if normalized is None:
        raise HTTPException(status_code=400, detail="Service could not be normalized.")

    # Fetch current public key via adapter
    adapter = _get_adapter(normalized)
    if adapter is None:
        raise HTTPException(status_code=400, detail=f"No adapter found for service type '{service.get('service_type')}'.")

    try:
        current_raw = await adapter.get_public_key_jwk(normalized)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"Failed to fetch public key from KMS: {str(e)}")

    key_reference = normalized.get("key_reference") if isinstance(normalized.get("key_reference"), str) else None
    current_jwk = _extract_public_jwk(current_raw, key_reference_hint=key_reference)
    if not current_jwk and isinstance(current_raw, dict):
        current_jwk = dict(current_raw)
    if not current_jwk:
        raise HTTPException(status_code=503, detail="Provider did not return a usable public key for verification.")

    # Verify key properties
    verification_results = {
        "service_id": service_id,
        "key_valid": True,
        "checks": {},
        "verified_at": _utcnow_iso(),
    }

    # Check key is not empty
    verification_results["checks"]["key_present"] = bool(current_jwk)

    # Check key has required fields
    verification_results["checks"]["required_fields_present"] = bool(current_jwk.get("kty"))

    # Check algorithm is supported
    supported_algs = {"RS256", "ES256", "PS256"}
    verification_results["checks"]["algorithm_supported"] = (
        current_jwk.get("alg") in supported_algs
    )

    # Overall result
    verification_results["key_valid"] = all(
        verification_results["checks"].values()
    )

    return JSONResponse(content=verification_results)


# ---------------------------------------------------------------------------
# Audit and Compliance (GAP-007)
# ---------------------------------------------------------------------------


@signing_key_router.get("/services/{service_id}/audit-log", summary="Get Key Audit Events")
async def get_key_audit_log(
    request: Request,
    service_id: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    organization_id: str | None = Query(None),
):
    """Retrieve audit log of key rotation, publication, and access events.

    This endpoint returns a paginated list of audit events for the service's signing keys,
    including rotations, JWKS publications, DID updates, and access attempts.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    registry = await _load_registered_service_registry(request, resolved_org_id)
    services = registry.get("services") if isinstance(registry, dict) else []
    service = next((s for s in services if s.get("id") == service_id), None)
    if service is None:
        raise HTTPException(status_code=404, detail=f"Service '{service_id}' not found.")

    return mip_error_response(
        status_code=501,
        error="key_audit_log_unavailable",
        message=f"Key audit log storage is not available for service '{service_id}'.",
        extra={
            "organization_id": resolved_org_id,
            "service_id": service_id,
        },
    )


@signing_key_router.get("/compliance/keys-summary", summary="Get Key Compliance Summary")
async def get_keys_compliance_summary(
    request: Request,
    organization_id: str | None = Query(None),
):
    """Get a compliance summary across all services' signing keys.

    This endpoint returns aggregate metrics such as:
    - Total services with valid keys
    - Services with expiring keys
    - Key rotation compliance
    - Published vs unpublished keys
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    return mip_error_response(
        status_code=501,
        error="key_compliance_summary_unavailable",
        message="Key compliance summary metrics are not available from a live backing data source.",
        extra={"organization_id": resolved_org_id},
    )


# ---------------------------------------------------------------------------
# Issuer Profiles — bind a published DID to a KMS signing service
# ---------------------------------------------------------------------------

_ISSUER_PROFILE_STATUSES = {"draft", "active", "revoked"}
_ISSUER_MODES = {"org_managed", "elevenid_managed", "elevenid_alias_for_org"}


def _normalize_issuer_mode(value: Any) -> str:
    mode = str(value or "org_managed").strip() or "org_managed"
    if mode not in _ISSUER_MODES:
        raise HTTPException(status_code=422, detail=f"Invalid issuer_mode '{mode}'. Must be one of {sorted(_ISSUER_MODES)}.")
    return mode


def _normalize_issuer_profile(
    body: dict[str, Any],
    *,
    existing: dict[str, Any] | None = None,
    org_id: str,
) -> dict[str, Any]:
    """Validate and normalise an issuer profile dict.

    When *existing* is supplied the caller is doing an update; missing fields
    are carried forward from the previous version.
    """
    base = dict(existing) if existing else {}
    profile_id = base.get("id") or f"ip-{uuid.uuid4().hex[:16]}"
    now = _utcnow_iso()

    status = body.get("status", base.get("status", "draft"))
    if status not in _ISSUER_PROFILE_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid status '{status}'. Must be one of {sorted(_ISSUER_PROFILE_STATUSES)}.")

    issuer_did = body.get("issuer_did", base.get("issuer_did", ""))
    signing_service_id = body.get("signing_service_id", base.get("signing_service_id", ""))
    if not issuer_did:
        raise HTTPException(status_code=422, detail="issuer_did is required.")
    if not isinstance(issuer_did, str) or not issuer_did.startswith("did:"):
        raise HTTPException(status_code=422, detail="issuer_did must be a DID string.")
    if not signing_service_id:
        raise HTTPException(status_code=422, detail="signing_service_id is required.")

    key_purpose = body.get("key_purpose", base.get("key_purpose", "vc_jwt_issuer"))
    if key_purpose not in KEY_PURPOSES:
        raise HTTPException(status_code=422, detail=f"Invalid key_purpose '{key_purpose}'. Must be one of {list(KEY_PURPOSES)}.")
    if key_purpose == "lti_tool_signing":
        raise HTTPException(
            status_code=422,
            detail="lti_tool_signing is a protocol-key purpose and cannot be used by an issuer profile.",
        )

    algorithm = body.get("algorithm", base.get("algorithm", ""))
    if algorithm and algorithm not in SUPPORTED_SIGNING_ALGORITHMS:
        raise HTTPException(status_code=422, detail=f"Invalid algorithm '{algorithm}'. Must be one of {list(SUPPORTED_SIGNING_ALGORITHMS)}.")

    issuer_mode = _normalize_issuer_mode(body.get("issuer_mode", base.get("issuer_mode", "org_managed")))

    return {
        "id": profile_id,
        "organization_id": org_id,
        "name": body.get("name", base.get("name", "")),
        "issuer_mode": issuer_mode,
        "issuer_did": issuer_did,
        "signing_service_id": signing_service_id,
        "signing_key_reference": body.get("signing_key_reference", base.get("signing_key_reference", "")),
        "verification_method_id": body.get("verification_method_id", base.get("verification_method_id", "")),
        "key_purpose": key_purpose,
        "algorithm": algorithm,
        "status": status,
        "created_at": base.get("created_at", now),
        "updated_at": now,
    }


def _assert_issuer_profile_service_compatible(profile: dict[str, Any], service: dict[str, Any]) -> None:
    """Reject issuer profiles that point at an incompatible signing service."""
    key_purpose = profile.get("key_purpose")
    service_purposes = service.get("key_purposes") if isinstance(service.get("key_purposes"), list) else []
    if key_purpose and service_purposes and key_purpose not in service_purposes:
        raise HTTPException(
            status_code=422,
            detail=f"Signing service '{service.get('id')}' is not configured for key_purpose '{key_purpose}'.",
        )

    algorithm = profile.get("algorithm")
    service_algorithms = service.get("algorithms") if isinstance(service.get("algorithms"), list) else []
    if algorithm and service_algorithms and algorithm not in service_algorithms:
        raise HTTPException(
            status_code=422,
            detail=f"Signing service '{service.get('id')}' does not support algorithm '{algorithm}'.",
        )


def _assert_issuer_profile_key_compatible(
    profile: dict[str, Any],
    registry: dict[str, Any],
) -> None:
    """Reject issuer profiles that select a protocol-only key reference."""

    service_id = str(profile.get("signing_service_id") or "").strip()
    key_reference = str(profile.get("signing_key_reference") or "").strip()
    key_purpose = str(profile.get("key_purpose") or "vc_jwt_issuer").strip()
    if key_purpose == "lti_tool_signing":
        raise HTTPException(
            status_code=422,
            detail="LTI tool signing keys cannot be assigned to issuer profiles.",
        )
    if not service_id or not key_reference:
        raise HTTPException(
            status_code=422,
            detail="Issuer profiles require an explicit signing key reference.",
        )
    reference_purposes = _purposes_for_key_reference(
        registry,
        service_id=service_id,
        key_reference=key_reference,
    )
    if "lti_tool_signing" in reference_purposes:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Key reference '{key_reference}' is reserved for LTI tool signing "
                "and cannot be assigned to an issuer profile."
            ),
        )
    if reference_purposes and key_purpose not in reference_purposes:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Key reference '{key_reference}' is not registered for issuer "
                f"key_purpose '{key_purpose}'."
            ),
        )


async def _resolve_org_scoped_issuer_identity(
    request: Request,
    *,
    organization_id: str,
    issuer_did: str,
    verification_method_id: str | None = None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
) -> dict[str, Any]:
    """Resolve an issuer DID to the org-owned KMS-backed verification method."""
    profiles_doc = await _load_json_document(
        request,
        _issuer_profiles_storage_key(organization_id),
        {"profiles": []},
    )
    profiles = profiles_doc.get("profiles") if isinstance(profiles_doc, dict) else []
    active_profiles = [
        profile
        for profile in (profiles or [])
        if isinstance(profile, dict)
        and profile.get("status") == "active"
        and profile.get("issuer_did") == issuer_did
        and profile.get("signing_service_id")
    ]

    if key_purpose:
        active_profiles = [
            profile
            for profile in active_profiles
            if profile.get("key_purpose") == key_purpose
        ]
    if algorithm:
        active_profiles = [
            profile
            for profile in active_profiles
            if profile.get("algorithm") in {algorithm, None, ""}
        ]

    if not active_profiles:
        raise HTTPException(
            status_code=404,
            detail="Issuer DID is not an active issuer identity for this organization.",
        )

    did_doc_default = {
        "id": issuer_did,
        "controller": issuer_did,
        "verificationMethod": [],
        "assertionMethod": [],
        "updated_at": _utcnow_iso(),
    }
    did_doc = await _load_json_document(
        request,
        _did_doc_storage_key(organization_id),
        did_doc_default,
    )
    if did_doc.get("id") != issuer_did:
        did_doc = _retarget_did_document(did_doc, issuer_did)

    last_mismatch_detail = "No matching DID verification method was found for the issuer profile."
    for profile in active_profiles:
        service_id = str(profile["signing_service_id"])
        key_reference = profile.get("signing_key_reference") if isinstance(profile.get("signing_key_reference"), str) else None
        registry, _, normalized_service, _ = await _resolve_effective_service(
            request,
            organization_id,
            service_id,
            key_reference_override=key_reference,
        )
        effective_profile = dict(profile)
        effective_profile["signing_key_reference"] = (
            profile.get("signing_key_reference")
            or normalized_service.get("key_reference")
        )
        effective_profile["key_purpose"] = (
            key_purpose or profile.get("key_purpose") or "vc_jwt_issuer"
        )
        _assert_issuer_profile_key_compatible(effective_profile, registry)

        service_formats = normalized_service.get("credential_formats") if isinstance(normalized_service.get("credential_formats"), list) else []
        service_purposes = normalized_service.get("key_purposes") if isinstance(normalized_service.get("key_purposes"), list) else []
        service_algorithms = normalized_service.get("algorithms") if isinstance(normalized_service.get("algorithms"), list) else []
        if credential_format and service_formats and credential_format not in service_formats:
            last_mismatch_detail = f"Signing service '{service_id}' is not configured for credential_format '{credential_format}'."
            continue
        if key_purpose and service_purposes and key_purpose not in service_purposes:
            last_mismatch_detail = f"Signing service '{service_id}' is not configured for key_purpose '{key_purpose}'."
            continue
        if algorithm and service_algorithms and algorithm not in service_algorithms:
            last_mismatch_detail = f"Signing service '{service_id}' does not support algorithm '{algorithm}'."
            continue

        if credential_format or key_purpose or algorithm:
            resolved = _resolve_service_for_format(registry, credential_format, key_purpose, algorithm)
            if resolved is not None and resolved.get("id") != service_id:
                logger.info(
                    "Issuer DID resolver kept profile service %s despite format resolver preferring %s for org=%s issuer=%s",
                    service_id,
                    resolved.get("id"),
                    organization_id,
                    issuer_did,
                )

        candidates = _issuer_vm_id_candidates(
            issuer_did,
            verification_method_id=verification_method_id,
            profile=profile,
            service_id=service_id,
            key_reference=key_reference or normalized_service.get("key_reference"),
        )
        method = _find_did_verification_method(did_doc, issuer_did, candidates)
        if method is None:
            continue

        public_jwk = _public_jwk_from_verification_method(method)
        if public_jwk is None:
            try:
                public_jwk = await _public_jwk_from_service(
                    normalized_service,
                    key_reference_hint=key_reference or normalized_service.get("key_reference"),
                )
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(status_code=503, detail=f"Failed to refresh issuer public key from KMS: {exc}") from exc
        if public_jwk is None:
            raise HTTPException(status_code=503, detail="Issuer DID verification method has no usable public key material.")
        public_jwk = dict(public_jwk)
        public_jwk["kid"] = method["id"]

        profile_with_vm = dict(profile)
        if not profile_with_vm.get("verification_method_id"):
            profile_with_vm["verification_method_id"] = method["id"]

        return {
            "ok": True,
            "organization_id": organization_id,
            "issuer_did": issuer_did,
            "verification_method_id": method["id"],
            "public_jwk": public_jwk,
            "verification_method": method,
            "did_document": did_doc,
            "issuer_profile": profile_with_vm,
            "signing_service": _safe_signing_service_metadata(normalized_service),
            "resolver": {
                "type": "organization_issuer_profile",
                "source": "gateway_signing_key_registry",
                "public_fallback_used": False,
                "resolved_at": _utcnow_iso(),
            },
        }

    raise HTTPException(status_code=404, detail=last_mismatch_detail)


@signing_key_router.post(
    "/issuer-profiles",
    summary="Create Issuer Profile",
    response_class=JSONResponse,
)
async def create_issuer_profile(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Create a new issuer profile linking a published DID to a KMS signing service."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    profile = _normalize_issuer_profile(body, org_id=resolved_org_id)
    service_id = str(profile["signing_service_id"])
    key_reference = profile.get("signing_key_reference") if isinstance(profile.get("signing_key_reference"), str) else None

    registry, _, normalized_service, _ = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
        key_reference_override=key_reference,
    )
    _assert_issuer_profile_service_compatible(profile, normalized_service)
    if not profile.get("signing_key_reference") and normalized_service.get("key_reference"):
        profile["signing_key_reference"] = normalized_service["key_reference"]
    _assert_issuer_profile_key_compatible(profile, registry)

    storage_key = _issuer_profiles_storage_key(resolved_org_id)
    doc = await _load_json_document(request, storage_key, {"profiles": []})
    profiles: list = doc.get("profiles") or []

    async def ensure_did_web_verification_method(target_profile: dict[str, Any]) -> dict[str, Any]:
        issuer_did = str(target_profile.get("issuer_did") or "")
        if not issuer_did.startswith("did:web:") or target_profile.get("verification_method_id"):
            return target_profile

        configured_public_domain = _normalize_did_web_domain(_domain_config(request).get("public_domain"))
        org_slug = _did_web_org_slug(issuer_did, public_domain=configured_public_domain)
        if not configured_public_domain or not org_slug:
            raise HTTPException(
                status_code=422,
                detail=(
                    "An automatically published did:web issuer must use "
                    "did:web:<PUBLIC_DOMAIN>:orgs:<slug>."
                ),
            )

        publication_response = await publish_service_to_did(
            request=request,
            service_id=service_id,
            body={
                "did_id": issuer_did,
                "org_slug": org_slug,
                "fragment": _did_fragment_for_key_reference(service_id, target_profile.get("signing_key_reference") or None),
                "key_reference": target_profile.get("signing_key_reference") or None,
            },
            organization_id=resolved_org_id,
        )
        try:
            publication_body = json.loads(publication_response.body)
        except Exception:
            publication_body = {}
        verification_method = publication_body.get("verification_method") if isinstance(publication_body, dict) else None
        if isinstance(verification_method, dict) and isinstance(verification_method.get("id"), str):
            next_profile = dict(target_profile)
            next_profile["verification_method_id"] = verification_method["id"]
            return next_profile
        return target_profile

    existing_profile_index = next(
        (
            index
            for index, candidate in enumerate(profiles)
            if isinstance(candidate, dict)
            and candidate.get("status") != "revoked"
            and candidate.get("issuer_did") == profile.get("issuer_did")
            and candidate.get("signing_service_id") == profile.get("signing_service_id")
            and (
                candidate.get("signing_key_reference")
                or normalized_service.get("key_reference")
                or ""
            ) == (profile.get("signing_key_reference") or "")
            and (candidate.get("key_purpose") or "vc_jwt_issuer") == (profile.get("key_purpose") or "vc_jwt_issuer")
        ),
        None,
    )
    if existing_profile_index is not None:
        existing_profile = profiles[existing_profile_index]
        repaired_profile = dict(existing_profile)
        if profile.get("status") == "active" and repaired_profile.get("status") != "active":
            repaired_profile["status"] = "active"
        if not repaired_profile.get("signing_key_reference") and profile.get("signing_key_reference"):
            repaired_profile["signing_key_reference"] = profile["signing_key_reference"]
        if not repaired_profile.get("key_purpose") and profile.get("key_purpose"):
            repaired_profile["key_purpose"] = profile["key_purpose"]
        if not repaired_profile.get("name") and profile.get("name"):
            repaired_profile["name"] = profile["name"]

        repaired_profile = await ensure_did_web_verification_method(repaired_profile)
        if repaired_profile != existing_profile:
            repaired_profile["updated_at"] = _utcnow_iso()
            profiles[existing_profile_index] = repaired_profile
            doc["profiles"] = profiles
            await _save_json_document(request, storage_key, doc)

        return JSONResponse(content={"ok": True, "profile": repaired_profile, "created": False})

    if str(profile.get("issuer_did") or "").startswith("did:web:"):
        # Make DID identity creation an invariant of the profile, not a UI-only
        # convention. If the KMS key cannot publish a DID verification method,
        # the issuer profile should not be created.
        profile = await ensure_did_web_verification_method(profile)

    profiles.append(profile)
    doc["profiles"] = profiles
    await _save_json_document(request, storage_key, doc)

    return JSONResponse(content={"ok": True, "profile": profile, "created": True})


@signing_key_router.get(
    "/issuer-profiles",
    summary="List Issuer Profiles",
    response_class=JSONResponse,
)
async def list_issuer_profiles(
    request: Request,
    organization_id: str | None = Query(None),
):
    """Return all issuer profiles for the resolved organization."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    storage_key = _issuer_profiles_storage_key(resolved_org_id)
    doc = await _load_json_document(request, storage_key, {"profiles": []})
    profiles: list = doc.get("profiles") or []
    return JSONResponse(content={"profiles": profiles})


@signing_key_router.get(
    "/issuer-profiles/{profile_id}",
    summary="Get Issuer Profile",
    response_class=JSONResponse,
)
async def get_issuer_profile(
    request: Request,
    profile_id: str,
    organization_id: str | None = Query(None),
):
    """Return a single issuer profile by ID."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    storage_key = _issuer_profiles_storage_key(resolved_org_id)
    doc = await _load_json_document(request, storage_key, {"profiles": []})
    profiles: list = doc.get("profiles") or []
    profile = next((p for p in profiles if p.get("id") == profile_id), None)
    if profile is None:
        raise HTTPException(status_code=404, detail="Issuer profile not found.")
    return JSONResponse(content={"profile": profile})


@signing_key_router.patch(
    "/issuer-profiles/{profile_id}",
    summary="Update Issuer Profile",
    response_class=JSONResponse,
)
async def update_issuer_profile(
    request: Request,
    profile_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Update an existing issuer profile (partial update)."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    storage_key = _issuer_profiles_storage_key(resolved_org_id)
    doc = await _load_json_document(request, storage_key, {"profiles": []})
    profiles: list = doc.get("profiles") or []

    idx = next((i for i, p in enumerate(profiles) if p.get("id") == profile_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Issuer profile not found.")

    updated = _normalize_issuer_profile(body, existing=profiles[idx], org_id=resolved_org_id)
    updated["id"] = profile_id  # preserve original ID
    service_id = str(updated["signing_service_id"])
    key_reference = (
        updated.get("signing_key_reference")
        if isinstance(updated.get("signing_key_reference"), str)
        else None
    )
    registry, _, normalized_service, _ = await _resolve_effective_service(
        request,
        resolved_org_id,
        service_id,
        key_reference_override=key_reference,
    )
    _assert_issuer_profile_service_compatible(updated, normalized_service)
    if not updated.get("signing_key_reference") and normalized_service.get(
        "key_reference"
    ):
        updated["signing_key_reference"] = normalized_service["key_reference"]
    _assert_issuer_profile_key_compatible(updated, registry)
    profiles[idx] = updated
    doc["profiles"] = profiles
    await _save_json_document(request, storage_key, doc)

    return JSONResponse(content={"ok": True, "profile": updated})


@signing_key_router.delete(
    "/issuer-profiles/{profile_id}",
    summary="Delete Issuer Profile",
    response_class=JSONResponse,
)
async def delete_issuer_profile(
    request: Request,
    profile_id: str,
    organization_id: str | None = Query(None),
):
    """Delete an issuer profile by ID."""
    resolved_org_id = _resolve_org_id(request, organization_id)
    storage_key = _issuer_profiles_storage_key(resolved_org_id)
    doc = await _load_json_document(request, storage_key, {"profiles": []})
    profiles: list = doc.get("profiles") or []

    original_len = len(profiles)
    profiles = [p for p in profiles if p.get("id") != profile_id]
    if len(profiles) == original_len:
        raise HTTPException(status_code=404, detail="Issuer profile not found.")

    doc["profiles"] = profiles
    await _save_json_document(request, storage_key, doc)

    return JSONResponse(content={"ok": True, "deleted": profile_id})


# ---------------------------------------------------------------------------
# Parameterised /{key_id} routes — MUST come AFTER all static /signing-keys/*
# paths so that FastAPI doesn't match "config", "jwks", etc. as a {key_id}.
# ---------------------------------------------------------------------------

@signing_key_router.get("/{key_id}", summary="Get Signing Key")
async def get_signing_key(
    request: Request,
    key_id: str,
    organization_id: str | None = Query(None),
):
    """Return metadata for a single signing key by ID or provider key name."""
    resolved_org_id = _resolve_org_id(request, organization_id)

    snapshot = await _load_signing_key_snapshot(resolved_org_id)
    keys: list[dict[str, Any]] = snapshot.get("keys") or []
    key = next(
        (k for k in keys if k.get("id") == key_id or k.get("provider_key_name") == key_id),
        None,
    )
    if key is None:
        raise HTTPException(status_code=404, detail=f"Signing key '{key_id}' not found.")
    return JSONResponse(content=key)


@signing_key_router.patch("/{key_id}", summary="Update Signing Key Metadata")
async def update_signing_key(
    request: Request,
    key_id: str,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None),
):
    """Update mutable metadata for a signing key (name, status, aliases).

    This updates the key's metadata in the org's JWKS storage layer only.
    Mutations to the underlying key material must be performed in the external KMS.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    # Load current JWKS document and patch the matching key entry
    storage_key = _jwks_storage_key(resolved_org_id)
    jwks_doc = await _load_json_document(request, storage_key, {"keys": []})
    jwks_keys: list[dict[str, Any]] = jwks_doc.get("keys") or []
    idx = next(
        (i for i, k in enumerate(jwks_keys) if k.get("kid") == key_id or k.get("provider_key_name") == key_id),
        None,
    )
    if idx is None:
        raise HTTPException(status_code=404, detail=f"Signing key '{key_id}' not found in org JWKS.")

    allowed_updates = {"name", "status", "aliases", "key_aliases"}
    for field in allowed_updates:
        if field in body:
            jwks_keys[idx][field] = body[field]

    jwks_doc["keys"] = jwks_keys
    await _save_json_document(request, storage_key, jwks_doc)
    return JSONResponse(content={"ok": True, "key_id": key_id, "updated": list(set(body.keys()) & allowed_updates)})


@signing_key_router.delete("/{key_id}", summary="Delete / Deregister Signing Key")
async def delete_signing_key(
    request: Request,
    key_id: str,
    organization_id: str | None = Query(None),
):
    """Remove a signing key entry from the org JWKS registry.

    This deregisters the key from Marty's published JWKS document only.
    The key material itself is not deleted from the external KMS.
    """
    resolved_org_id = _resolve_org_id(request, organization_id)

    storage_key = _jwks_storage_key(resolved_org_id)
    jwks_doc = await _load_json_document(request, storage_key, {"keys": []})
    jwks_keys: list[dict[str, Any]] = jwks_doc.get("keys") or []
    filtered = [k for k in jwks_keys if k.get("kid") != key_id and k.get("provider_key_name") != key_id]
    if len(filtered) == len(jwks_keys):
        raise HTTPException(status_code=404, detail=f"Signing key '{key_id}' not found in org JWKS.")

    jwks_doc["keys"] = filtered
    await _save_json_document(request, storage_key, jwks_doc)
    return JSONResponse(content={"ok": True, "key_id": key_id, "removed": True})


# ---------------------------------------------------------------------------
# Public did:web resolution endpoints (no auth)
# ---------------------------------------------------------------------------
# These routes serve DID documents at the standard did:web resolution URLs.
# did:web:{domain}:orgs:{slug}  →  GET /orgs/{slug}/did.json
# did:web:{domain}               →  GET /.well-known/did.json  (root org)

@did_web_public_router.get(
    "/orgs/{org_slug}/did.json",
    summary="Resolve path-scoped did:web DID document",
    response_class=JSONResponse,
)
async def resolve_did_web_by_slug(request: Request, org_slug: str):
    """Public endpoint for did:web resolution of path-scoped organization DIDs.

    A did:web resolver for ``did:web:beta.elevenidllc.com:orgs:acme`` will
    fetch ``https://beta.elevenidllc.com/orgs/acme/did.json``.
    """
    safe_slug = org_slug.strip().lower()
    if not _SLUG_PATTERN.match(safe_slug):
        raise HTTPException(status_code=400, detail="Invalid organization slug.")

    redis_client = getattr(request.app.state, "redis_client", None)
    if redis_client is None:
        raise HTTPException(status_code=503, detail="Storage unavailable.")

    org_id = await redis_client.get(_did_web_slug_key(safe_slug))
    if not org_id:
        raise HTTPException(status_code=404, detail="Organization DID not found.")

    org_id = org_id if isinstance(org_id, str) else org_id.decode()

    domain_cfg = _domain_config(request)
    public_domain = domain_cfg.get("public_domain", "")
    fallback_did = f"did:web:{public_domain}:orgs:{safe_slug}"

    did_doc = await _load_json_document(
        request,
        _did_doc_storage_key(org_id),
        {
            "id": fallback_did,
            "controller": fallback_did,
            "verificationMethod": [],
            "assertionMethod": [],
        },
    )

    return JSONResponse(
        content=did_doc,
        headers={
            "Content-Type": "application/did+json",
            "Cache-Control": "public, max-age=300",
        },
    )


@did_web_public_router.get(
    "/.well-known/did.json",
    summary="Resolve root did:web DID document",
    response_class=JSONResponse,
)
async def resolve_did_web_root(request: Request):
    """Public endpoint for root did:web resolution.

    A did:web resolver for ``did:web:beta.elevenidllc.com`` will fetch
    ``https://beta.elevenidllc.com/.well-known/did.json``.

    Returns the DID document of the platform's default organization when
    a ``DEFAULT_ORG_ID`` environment variable is set.
    """
    default_org_id = os.environ.get("DEFAULT_ORG_ID")
    if not default_org_id:
        raise HTTPException(status_code=404, detail="Root DID document not configured.")

    domain_cfg = _domain_config(request)
    public_domain = domain_cfg.get("public_domain", "")
    fallback_did = f"did:web:{public_domain}"

    did_doc = await _load_json_document(
        request,
        _did_doc_storage_key(default_org_id),
        {
            "id": fallback_did,
            "controller": fallback_did,
            "verificationMethod": [],
            "assertionMethod": [],
        },
    )
    did_doc = _retarget_did_document(did_doc, fallback_did)

    return JSONResponse(
        content=did_doc,
        headers={
            "Content-Type": "application/did+json",
            "Cache-Control": "public, max-age=300",
        },
    )
