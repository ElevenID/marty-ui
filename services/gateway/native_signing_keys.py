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


async def normalize_native_signing_service(
    service: Any,
) -> dict[str, Any] | None:
    body = await _post_native(
        "/internal/registry/normalize-service", {"service": service}
    )
    if not isinstance(body, dict) or set(body) != {"service"}:
        raise RuntimeError("Rust signing-key service returned an invalid normalized service")
    normalized = body["service"]
    if normalized is not None and not isinstance(normalized, dict):
        raise RuntimeError("Rust signing-key service returned an invalid normalized service")
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
        raise RuntimeError("Rust signing-key service returned an invalid resolved service")
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
        raise RuntimeError("Rust signing-key service returned an invalid service catalog")
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
        raise RuntimeError("Rust signing-key service returned an invalid stored registry")
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
        raise RuntimeError("Rust signing-key service returned an invalid stored registry")
    return body


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
        raise RuntimeError("Rust signing-key service returned an invalid validation result")
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
            raise RuntimeError("Rust signing-key service returned an invalid public key")
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
