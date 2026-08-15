"""Thin compatibility adapter for the canonical Rust signing-key service."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from gateway.proxy import get_http_client, get_registry

_PROVIDER_NAMES = {
    "openbao-transit": "openbao",
    "hashicorp-vault-transit": "openbao",
    "aws-kms": "aws",
    "azure-key-vault": "azure",
    "gcp-cloud-kms": "gcp",
}


def _internal_api_key() -> str:
    direct = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY")
    if direct:
        return direct
    path = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            pass
    raise RuntimeError("Internal signing API key is not configured")


def _decode_base64url(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"Rust signing-key service omitted {field}")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise RuntimeError(
            f"Rust signing-key service returned invalid {field}"
        ) from exc


@dataclass(frozen=True)
class NativeCapabilityResult:
    ok: bool
    checks: list[dict[str, str]]
    error: str | None = None


def _service_url() -> str:
    service_url = get_registry().get_service_url("signing-keys")
    if not service_url:
        raise RuntimeError("Rust signing-key service is not configured")
    return service_url


async def _post_native(path: str, payload: dict[str, Any]) -> Any:
    response = await get_http_client().post(
        f"{_service_url()}{path}",
        json=payload,
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


async def _put_native(path: str, payload: dict[str, Any]) -> Any:
    response = await get_http_client().put(
        f"{_service_url()}{path}",
        json=payload,
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


async def _get_native(path: str) -> Any:
    response = await get_http_client().get(
        f"{_service_url()}{path}",
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


async def _patch_native(path: str, payload: dict[str, Any]) -> Any:
    response = await get_http_client().patch(
        f"{_service_url()}{path}",
        json=payload,
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


async def _delete_native(path: str) -> Any:
    response = await get_http_client().delete(
        f"{_service_url()}{path}",
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()


async def normalize_native_signing_service(
    service: Any,
) -> dict[str, Any] | None:
    body = await _post_native(
        "/internal/registry/normalize-service", {"service": service}
    )
    if not isinstance(body, dict) or set(body) != {"service"}:
        raise RuntimeError(
            "Rust signing-key service returned an invalid normalized service"
        )
    normalized = body["service"]
    if normalized is not None and not isinstance(normalized, dict):
        raise RuntimeError(
            "Rust signing-key service returned an invalid normalized service"
        )
    return normalized


async def normalize_native_signing_registry(
    registry: Any, *, mode: str
) -> dict[str, Any]:
    if mode not in {"requested", "stored"}:
        raise ValueError("mode must be 'requested' or 'stored'")
    body = await _post_native(
        "/internal/registry/normalize", {"registry": registry, "mode": mode}
    )
    if (
        not isinstance(body, dict)
        or set(body) != {"registry"}
        or not isinstance(body["registry"], dict)
    ):
        raise RuntimeError("Rust signing-key service returned an invalid registry")
    return body["registry"]


async def resolve_native_signing_registry(
    registry: dict[str, Any],
    *,
    service: dict[str, Any] | None = None,
    keys: list[dict[str, Any]] | None = None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    body = await _post_native(
        "/internal/registry/resolve",
        {
            "registry": registry,
            "service": service,
            "keys": keys or [],
            "credential_format": credential_format,
            "key_purpose": key_purpose,
            "algorithm": algorithm,
        },
    )
    if not isinstance(body, dict) or set(body) != {"service", "key_reference"}:
        raise RuntimeError("Rust signing-key service returned an invalid resolution")
    service = body["service"]
    key_reference = body["key_reference"]
    if service is not None and not isinstance(service, dict):
        raise RuntimeError(
            "Rust signing-key service returned an invalid resolved service"
        )
    if key_reference is not None and not isinstance(key_reference, str):
        raise RuntimeError("Rust signing-key service returned an invalid key reference")
    return service, key_reference


async def get_native_signing_service_catalog() -> list[dict[str, Any]]:
    response = await get_http_client().get(
        f"{_service_url()}/internal/registry/catalog",
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    body = response.json()
    if (
        not isinstance(body, dict)
        or set(body) != {"service_types"}
        or not isinstance(body["service_types"], list)
        or any(not isinstance(item, dict) for item in body["service_types"])
    ):
        raise RuntimeError(
            "Rust signing-key service returned an invalid service catalog"
        )
    return body["service_types"]


async def load_native_signing_registry(organization_id: str) -> dict[str, Any]:
    response = await get_http_client().get(
        f"{_service_url()}/internal/registry/{quote(organization_id, safe='')}",
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("services"), list):
        raise RuntimeError(
            "Rust signing-key service returned an invalid stored registry"
        )
    return body


async def save_native_signing_registry(
    organization_id: str, registry: dict[str, Any]
) -> dict[str, Any]:
    response = await get_http_client().put(
        f"{_service_url()}/internal/registry/{quote(organization_id, safe='')}",
        json={"registry": registry},
        headers={"X-API-Key": _internal_api_key()},
        timeout=30.0,
    )
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict) or not isinstance(body.get("services"), list):
        raise RuntimeError(
            "Rust signing-key service returned an invalid stored registry"
        )
    return body


async def inspect_native_signing_certificate(
    cert_pem: str,
    *,
    cert_chain_pem: str | None = None,
    expected_public_jwk: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = await _post_native(
        "/internal/documents/certificate/inspect",
        {
            "cert_pem": cert_pem,
            "cert_chain_pem": cert_chain_pem,
            "expected_public_jwk": expected_public_jwk,
        },
    )
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("expires_at"), str)
        or not isinstance(body.get("public_jwk"), dict)
        or not isinstance(body.get("x5c"), list)
    ):
        raise RuntimeError(
            "Rust signing-key service returned invalid certificate metadata"
        )
    return body


async def calculate_native_certificate_alerts(
    services: list[dict[str, Any]], days_until_expiry: int
) -> dict[str, Any]:
    body = await _post_native(
        "/internal/documents/certificate-alerts",
        {"services": services, "days_until_expiry": days_until_expiry},
    )
    if not isinstance(body, dict) or not isinstance(body.get("alerts"), list):
        raise RuntimeError(
            "Rust signing-key service returned invalid certificate alerts"
        )
    return body


async def get_native_certificate_overrides(organization_id: str) -> dict[str, Any]:
    body = await _get_native(
        f"/internal/documents/{quote(organization_id, safe='')}/certificates"
    )
    if not isinstance(body, dict) or not isinstance(body.get("services"), dict):
        raise RuntimeError(
            "Rust signing-key service returned invalid certificate storage"
        )
    return body


async def store_native_signing_certificate(
    organization_id: str,
    service_id: str,
    *,
    cert_pem: str,
    cert_chain_pem: str | None = None,
) -> dict[str, Any]:
    body = await _put_native(
        f"/internal/documents/{quote(organization_id, safe='')}/certificates/{quote(service_id, safe='')}",
        {"cert_pem": cert_pem, "cert_chain_pem": cert_chain_pem},
    )
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("cert_pem"), str)
        or not isinstance(body.get("cert_expires_at"), str)
    ):
        raise RuntimeError(
            "Rust signing-key service returned invalid certificate storage"
        )
    return body


async def get_native_signing_jwks(organization_id: str) -> dict[str, Any]:
    body = await _get_native(
        f"/internal/documents/{quote(organization_id, safe='')}/jwks"
    )
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise RuntimeError("Rust signing-key service returned an invalid JWKS document")
    return body


async def publish_native_signing_jwk(
    organization_id: str,
    service_id: str,
    *,
    jwk: dict[str, Any],
    key_reference: str | None = None,
    cert_pem: str | None = None,
    cert_chain_pem: str | None = None,
) -> dict[str, Any]:
    body = await _put_native(
        f"/internal/documents/{quote(organization_id, safe='')}/jwks/{quote(service_id, safe='')}",
        {
            "jwk": jwk,
            "key_reference": key_reference,
            "cert_pem": cert_pem,
            "cert_chain_pem": cert_chain_pem,
        },
    )
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("jwk"), dict)
        or not isinstance(body.get("document"), dict)
        or not isinstance(body.get("key_count"), int)
    ):
        raise RuntimeError("Rust signing-key service returned invalid JWKS publication")
    return body


async def update_native_signing_jwk(
    organization_id: str, key_id: str, updates: dict[str, Any]
) -> list[str]:
    body = await _patch_native(
        f"/internal/documents/{quote(organization_id, safe='')}/jwks/{quote(key_id, safe='')}",
        {"updates": updates},
    )
    if not isinstance(body, dict) or not isinstance(body.get("updated"), list):
        raise RuntimeError("Rust signing-key service returned invalid JWKS metadata")
    return body["updated"]


async def delete_native_signing_jwk(organization_id: str, key_id: str) -> bool:
    body = await _delete_native(
        f"/internal/documents/{quote(organization_id, safe='')}/jwks/{quote(key_id, safe='')}"
    )
    if not isinstance(body, dict) or not isinstance(body.get("removed"), bool):
        raise RuntimeError("Rust signing-key service returned invalid JWKS deletion")
    return body["removed"]


async def load_native_signing_did_document(
    organization_id: str,
    *,
    did_id: str | None = None,
    fallback_did: str | None = None,
) -> tuple[dict[str, Any], bool]:
    body = await _post_native(
        f"/internal/documents/{quote(organization_id, safe='')}/did/load",
        {"did_id": did_id, "fallback_did": fallback_did},
    )
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("document"), dict)
        or not isinstance(body.get("found"), bool)
        or not isinstance(body["document"].get("id"), str)
    ):
        raise RuntimeError("Rust signing-key service returned an invalid DID document")
    return body["document"], body["found"]


async def publish_native_signing_did(
    organization_id: str,
    service_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    body = await _put_native(
        f"/internal/documents/{quote(organization_id, safe='')}/did/{quote(service_id, safe='')}",
        payload,
    )
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("verification_method"), dict)
        or not isinstance(body.get("document"), dict)
        or not isinstance(body.get("did_id"), str)
    ):
        raise RuntimeError("Rust signing-key service returned invalid DID publication")
    return body


async def resolve_native_did_web_slug(slug: str) -> str | None:
    body = await _get_native(f"/internal/documents/did-web/{quote(slug, safe='')}")
    if not isinstance(body, dict) or set(body) != {"organization_id"}:
        raise RuntimeError(
            "Rust signing-key service returned an invalid DID slug result"
        )
    organization_id = body["organization_id"]
    if organization_id is not None and not isinstance(organization_id, str):
        raise RuntimeError(
            "Rust signing-key service returned an invalid DID slug result"
        )
    return organization_id


async def normalize_native_issuer_profile(
    organization_id: str,
    body: dict[str, Any],
    *,
    existing: dict[str, Any] | None = None,
    profile_id: str | None = None,
) -> dict[str, Any]:
    response = await _post_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/normalize",
        {"body": body, "existing": existing, "profile_id": profile_id},
    )
    if not isinstance(response, dict) or not isinstance(response.get("profile"), dict):
        raise RuntimeError(
            "Rust signing-key service returned an invalid issuer profile"
        )
    return response["profile"]


async def validate_native_issuer_profile_binding(
    organization_id: str,
    *,
    profile: dict[str, Any],
    service: dict[str, Any],
    registry: dict[str, Any],
) -> None:
    response = await _post_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/validate-binding",
        {"profile": profile, "service": service, "registry": registry},
    )
    if response != {"ok": True}:
        raise RuntimeError(
            "Rust signing-key service returned invalid profile validation"
        )


async def resolve_native_profile_custody_format(
    organization_id: str,
    credential_format: str,
    key_purpose: str,
) -> str:
    response = await _post_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/custody-format",
        {"credential_format": credential_format, "key_purpose": key_purpose},
    )
    wire_format = response.get("wire_format") if isinstance(response, dict) else None
    if not isinstance(wire_format, str) or not wire_format:
        raise RuntimeError("Rust signing-key service returned invalid custody format")
    return wire_format


async def list_native_issuer_profiles(organization_id: str) -> list[dict[str, Any]]:
    response = await _get_native(
        f"/internal/profiles/{quote(organization_id, safe='')}"
    )
    if not isinstance(response, dict) or not isinstance(response.get("profiles"), list):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile storage"
        )
    if any(not isinstance(profile, dict) for profile in response["profiles"]):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile storage"
        )
    return response["profiles"]


async def get_native_issuer_profile(
    organization_id: str, profile_id: str
) -> dict[str, Any]:
    response = await _get_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/{quote(profile_id, safe='')}"
    )
    if not isinstance(response, dict) or not isinstance(response.get("profile"), dict):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile storage"
        )
    return response["profile"]


async def save_native_issuer_profile(
    organization_id: str, profile: dict[str, Any]
) -> dict[str, Any]:
    profile_id = profile.get("id")
    if not isinstance(profile_id, str) or not profile_id:
        raise RuntimeError("Issuer profile has no stable ID")
    response = await _put_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/{quote(profile_id, safe='')}",
        profile,
    )
    if not isinstance(response, dict) or not isinstance(response.get("profile"), dict):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile storage"
        )
    return response["profile"]


async def delete_native_issuer_profile(organization_id: str, profile_id: str) -> str:
    response = await _delete_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/{quote(profile_id, safe='')}"
    )
    if not isinstance(response, dict) or response.get("deleted") != profile_id:
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile deletion"
        )
    return profile_id


async def find_native_issuer_profiles(
    organization_id: str, selectors: dict[str, Any]
) -> list[dict[str, Any]]:
    response = await _post_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/find", selectors
    )
    if not isinstance(response, dict) or not isinstance(response.get("profiles"), list):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile selection"
        )
    if any(not isinstance(profile, dict) for profile in response["profiles"]):
        raise RuntimeError(
            "Rust signing-key service returned invalid issuer profile selection"
        )
    return response["profiles"]


async def find_native_duplicate_issuer_profile(
    organization_id: str,
    profile: dict[str, Any],
    *,
    service_key_reference: str | None = None,
) -> tuple[dict[str, Any] | None, bool]:
    response = await _post_native(
        f"/internal/profiles/{quote(organization_id, safe='')}/find-duplicate",
        {"profile": profile, "service_key_reference": service_key_reference},
    )
    if (
        not isinstance(response, dict)
        or not isinstance(response.get("found"), bool)
        or (
            response.get("profile") is not None
            and not isinstance(response["profile"], dict)
        )
    ):
        raise RuntimeError(
            "Rust signing-key service returned invalid duplicate profile result"
        )
    return response.get("profile"), response["found"]


async def bind_native_issuer_profile_registry(
    organization_id: str, profile: dict[str, Any]
) -> dict[str, Any]:
    response = await _post_native(
        f"/internal/registry/{quote(organization_id, safe='')}/bind-profile",
        {"profile": profile},
    )
    if (
        not isinstance(response, dict)
        or not isinstance(response.get("services"), list)
        or not isinstance(response.get("key_reference_purposes"), dict)
    ):
        raise RuntimeError(
            "Rust signing-key service returned invalid profile registry binding"
        )
    return response


async def validate_native_signing_service(
    service_config: dict[str, Any],
) -> dict[str, Any]:
    """Run the canonical Rust registration-validation decision."""
    body = await _post_native("/internal/config/validate", service_config)
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("ok"), bool)
        or not isinstance(body.get("checks"), list)
        or any(not isinstance(check, dict) for check in body["checks"])
        or not isinstance(body.get("validated_at"), str)
    ):
        raise RuntimeError(
            "Rust signing-key service returned an invalid validation result"
        )
    return body


class NativeKmsAdapter:
    """Provider adapter whose implementation lives entirely in Rust."""

    signature_encoding = "der"
    transcoded_signature: bytes | None = None

    def __init__(self, provider: str):
        self.provider = provider
        self.signature_encoding = "der"
        self.transcoded_signature = None

    async def _post(self, path: str, service_config: dict[str, Any]) -> Any:
        service_url = get_registry().get_service_url("signing-keys")
        if not service_url:
            raise RuntimeError("Rust signing-key service is not configured")
        response = await get_http_client().post(
            f"{service_url}{path}",
            json={"service_config": service_config},
            headers={"X-API-Key": _internal_api_key()},
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        service_url = get_registry().get_service_url("signing-keys")
        if not service_url:
            raise RuntimeError("Rust signing-key service is not configured")
        response = await get_http_client().post(
            f"{service_url}/internal/kms/sign",
            json={
                "service_config": service_config,
                "payload_b64": base64.urlsafe_b64encode(payload).decode().rstrip("="),
            },
            headers={"X-API-Key": _internal_api_key()},
            timeout=30.0,
        )
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("Rust signing-key service returned an invalid response")
        encoding = body.get("signature_encoding")
        if encoding not in {"der", "raw", "raw_ieee_p1363"}:
            raise RuntimeError(
                "Rust signing-key service returned an invalid signature_encoding"
            )
        self.signature_encoding = encoding
        transcoded = body.get("transcoded_signature_b64")
        self.transcoded_signature = (
            _decode_base64url(transcoded, "transcoded_signature_b64")
            if transcoded is not None
            else None
        )
        return _decode_base64url(body.get("signature_b64"), "signature_b64")

    async def get_public_key_jwk(
        self, service_config: dict[str, Any]
    ) -> dict[str, Any]:
        body = await self._post("/internal/kms/public-key", service_config)
        if not isinstance(body, dict):
            raise RuntimeError(
                "Rust signing-key service returned an invalid public key"
            )
        return body

    async def verify_connection(
        self, service_config: dict[str, Any]
    ) -> NativeCapabilityResult:
        body = await self._post("/internal/kms/verify", service_config)
        if not isinstance(body, dict) or not isinstance(body.get("ok"), bool):
            raise RuntimeError(
                "Rust signing-key service returned an invalid capability result"
            )
        checks = body.get("checks")
        if not isinstance(checks, list) or any(
            not isinstance(check, dict) for check in checks
        ):
            raise RuntimeError(
                "Rust signing-key service returned invalid capability checks"
            )
        return NativeCapabilityResult(
            ok=body["ok"],
            checks=checks,
            error=body.get("error") if isinstance(body.get("error"), str) else None,
        )


def get_native_kms_adapter(
    service_config: dict[str, Any],
) -> NativeKmsAdapter | None:
    provider = _PROVIDER_NAMES.get(str(service_config.get("service_type") or ""))
    return NativeKmsAdapter(provider) if provider else None
