"""KMS provider adapters for remote signing (GAP-003).

Each adapter implements the :class:`KmsAdapter` protocol, providing:

- :meth:`sign` — sign raw bytes and return the bytes as they come from the provider
- :meth:`get_public_key_jwk` — return the current public key as a JWK dict
- :meth:`verify_connection` — probe the provider and return a :class:`CapabilityResult`

Signature encoding notes
------------------------
AWS KMS, Azure Key Vault, and GCP Cloud KMS all return ECDSA signatures in
DER/ASN.1 encoding rather than the raw IEEE P1363 ``r || s`` form expected by
JWT/COSE assemblers.  Use :func:`der_to_raw_ecdsa` to transcode before passing
to format-specific assemblers.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def der_to_raw_ecdsa(der_bytes: bytes, key_size_bytes: int = 32) -> bytes:
    """Convert a DER-encoded ECDSA signature to raw ``r || s`` (IEEE P1363).

    Args:
        der_bytes: DER-encoded ``SEQUENCE { INTEGER r, INTEGER s }``.
        key_size_bytes: Byte length of each component (32 for P-256/ES256,
            48 for P-384/ES384, 66 for P-521).

    Returns:
        ``key_size_bytes * 2`` raw bytes in big-endian ``r || s`` form.

    Raises:
        ValueError: When the DER structure is malformed.
    """
    if not der_bytes or der_bytes[0] != 0x30:
        raise ValueError("Expected DER SEQUENCE (0x30) at start of signature bytes")

    offset = 2  # skip 0x30 <total-len>

    def _read_int(pos: int) -> tuple[bytes, int]:
        if pos >= len(der_bytes) or der_bytes[pos] != 0x02:
            raise ValueError(f"Expected DER INTEGER (0x02) at offset {pos}")
        length = der_bytes[pos + 1]
        raw = der_bytes[pos + 2 : pos + 2 + length]
        # Strip leading zero padding
        raw = raw.lstrip(b"\x00")
        return raw, pos + 2 + length

    r_raw, offset = _read_int(offset)
    s_raw, _ = _read_int(offset)

    # Zero-pad to key_size_bytes
    r_padded = r_raw.rjust(key_size_bytes, b"\x00")
    s_padded = s_raw.rjust(key_size_bytes, b"\x00")
    return r_padded + s_padded


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


# ---------------------------------------------------------------------------
# Capability result
# ---------------------------------------------------------------------------


@dataclass
class CapabilityResult:
    """Result of a provider connectivity / capability probe."""

    ok: bool
    checks: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None

    def add_check(self, name: str, status: str, detail: str, source: str = "adapter") -> None:
        self.checks.append({"name": name, "status": status, "detail": detail, "source": source})


# ---------------------------------------------------------------------------
# Adapter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class KmsAdapter(Protocol):
    """Protocol that every KMS provider adapter must satisfy."""

    #: Human-readable provider name (e.g. ``"aws"``, ``"azure"``, ``"gcp"``).
    provider: str

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        """Sign ``payload`` and return the raw provider response bytes.

        The caller is responsible for transcoding DER→raw if needed
        (check :attr:`signature_encoding`).
        """
        ...

    async def get_public_key_jwk(self, service_config: dict[str, Any]) -> dict[str, Any]:
        """Return the current signing public key as a JWK dict."""
        ...

    async def verify_connection(self, service_config: dict[str, Any]) -> CapabilityResult:
        """Probe the provider and return a structured capability report."""
        ...

    @property
    def signature_encoding(self) -> str:
        """``"raw_ieee_p1363"`` or ``"der"``."""
        ...


# ---------------------------------------------------------------------------
# OpenBao / Vault Transit adapter
# ---------------------------------------------------------------------------


class OpenBaoTransitAdapter:
    """KMS adapter for OpenBao / HashiCorp Vault transit secrets engine.

    Signs payloads using the ``/transit/sign/{key}`` endpoint and returns
    provider-native signatures. Vault/OpenBao Transit returns ECDSA signatures
    as ASN.1 DER by default; the signing route transcodes those to raw
    IEEE P1363 ``r || s`` bytes for JOSE/JWS consumers.
    """

    provider = "openbao"
    signature_encoding = "der"

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        import hashlib
        import httpx

        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        mount = (service_config.get("mount") or "transit").strip("/")
        key_reference = service_config.get("key_reference") or ""
        auth_reference = service_config.get("auth_reference") or ""

        if not endpoint or not key_reference:
            raise ValueError("OpenBao adapter requires 'endpoint' and 'key_reference' in service_config")

        # Vault Transit sign endpoint expects base64url-encoded input hash
        digest = base64.b64encode(hashlib.sha256(payload).digest()).decode()
        url = f"{endpoint}/v1/{mount}/sign/{key_reference}"
        headers = {"X-Vault-Token": auth_reference, "Content-Type": "application/json"}
        body = {"input": digest, "prehashed": True}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        # Vault returns "vault:v1:<base64url-sig>"
        sig_raw = data["data"]["signature"]
        sig_b64 = sig_raw.split(":")[-1]
        return base64.b64decode(sig_b64 + "==")

    async def get_public_key_jwk(self, service_config: dict[str, Any]) -> dict[str, Any]:
        import httpx

        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        mount = (service_config.get("mount") or "transit").strip("/")
        key_reference = service_config.get("key_reference") or ""
        auth_reference = service_config.get("auth_reference") or ""

        if not endpoint or not key_reference:
            raise ValueError("OpenBao adapter requires 'endpoint' and 'key_reference' in service_config")

        url = f"{endpoint}/v1/{mount}/keys/{key_reference}"
        headers = {"X-Vault-Token": auth_reference}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        keys = data.get("data", {}).get("keys") or {}
        latest = str(data.get("data", {}).get("latest_version", "1"))
        key_meta = keys.get(latest) or {}
        public_key_pem = key_meta.get("public_key") or ""
        # Return minimal JWK identifying fields; full JWK conversion requires
        # parsing the PEM — callers can use cryptography.hazmat.primitives.
        return {"provider": self.provider, "key_reference": key_reference, "public_key_pem": public_key_pem}

    async def verify_connection(self, service_config: dict[str, Any]) -> CapabilityResult:
        import httpx

        result = CapabilityResult(ok=True)
        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        mount = (service_config.get("mount") or "transit").strip("/")
        key_reference = service_config.get("key_reference") or ""
        auth_reference = service_config.get("auth_reference") or ""

        if not endpoint:
            result.ok = False
            result.add_check("Endpoint", "fail", "endpoint is required")
            return result

        try:
            url = f"{endpoint}/v1/{mount}/keys/{key_reference}"
            headers = {"X-Vault-Token": auth_reference}
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                supports_signing = data.get("supports_signing", False)
                result.add_check(
                    "Key exists",
                    "pass" if supports_signing else "warning",
                    f"Key '{key_reference}' found; supports_signing={supports_signing}.",
                )
            elif resp.status_code == 403:
                result.ok = False
                result.add_check("Authentication", "fail", "Token is invalid or lacks read permissions.")
            elif resp.status_code == 404:
                result.ok = False
                result.add_check("Key exists", "fail", f"Key '{key_reference}' was not found in mount '{mount}'.")
            else:
                result.ok = False
                result.add_check("Connectivity", "fail", f"Unexpected HTTP {resp.status_code} from transit endpoint.")
        except httpx.ConnectError as exc:
            result.ok = False
            result.add_check("Connectivity", "fail", f"Cannot reach endpoint: {exc}")
        except Exception as exc:  # noqa: BLE001
            result.ok = False
            result.add_check("Connectivity", "fail", f"Unexpected error: {exc}")

        return result


class AwsKmsAdapter:
    """KMS adapter for AWS KMS using boto3 client calls."""

    provider = "aws"
    signature_encoding = "der"

    def _build_client(self, service_config: dict[str, Any]) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - depends on deployment extras
            raise RuntimeError("boto3 is required for aws-kms adapter") from exc

        region = service_config.get("region") or "us-east-1"
        endpoint = service_config.get("endpoint")
        session_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint:
            session_kwargs["endpoint_url"] = endpoint
        return boto3.client("kms", **session_kwargs)

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        import asyncio

        key_id = service_config.get("key_reference") or ""
        if not key_id:
            raise ValueError("aws-kms adapter requires 'key_reference' in service_config")

        algorithm = service_config.get("aws_signing_algorithm") or "ECDSA_SHA_256"
        client = self._build_client(service_config)
        response = await asyncio.to_thread(
            client.sign,
            KeyId=key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm=algorithm,
        )
        signature = response.get("Signature")
        if not isinstance(signature, (bytes, bytearray)):
            raise RuntimeError("AWS KMS sign response did not include binary Signature")
        return bytes(signature)

    async def get_public_key_jwk(self, service_config: dict[str, Any]) -> dict[str, Any]:
        import asyncio

        key_id = service_config.get("key_reference") or ""
        if not key_id:
            raise ValueError("aws-kms adapter requires 'key_reference' in service_config")

        client = self._build_client(service_config)
        response = await asyncio.to_thread(client.get_public_key, KeyId=key_id)
        return {
            "provider": self.provider,
            "key_reference": key_id,
            "public_key_der_b64": base64.b64encode(response.get("PublicKey") or b"").decode(),
            "signing_algorithms": response.get("SigningAlgorithms") or [],
            "key_spec": response.get("KeySpec"),
            "key_usage": response.get("KeyUsage"),
        }

    async def verify_connection(self, service_config: dict[str, Any]) -> CapabilityResult:
        import asyncio

        result = CapabilityResult(ok=True)
        key_id = service_config.get("key_reference") or ""
        if not key_id:
            result.ok = False
            result.add_check("Key reference", "fail", "key_reference is required")
            return result

        try:
            client = self._build_client(service_config)
            await asyncio.to_thread(client.describe_key, KeyId=key_id)
            result.add_check("Key exists", "pass", f"AWS KMS key '{key_id}' is reachable.")
        except Exception as exc:  # noqa: BLE001
            result.ok = False
            result.add_check("Connectivity", "fail", f"AWS KMS verification failed: {exc}")
        return result


class AzureKeyVaultAdapter:
    """KMS adapter for Azure Key Vault Keys REST APIs."""

    provider = "azure"
    signature_encoding = "der"

    def _base_headers(self, service_config: dict[str, Any]) -> dict[str, str]:
        token = service_config.get("auth_reference") or ""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        import hashlib
        import httpx

        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        key_reference = service_config.get("key_reference") or ""
        key_version = service_config.get("key_version")
        if not endpoint or not key_reference:
            raise ValueError("azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config")

        key_path = f"{key_reference}/{key_version}" if key_version else key_reference
        url = f"{endpoint}/keys/{key_path}/sign?api-version=7.4"
        digest = hashlib.sha256(payload).digest()
        body = {"alg": service_config.get("azure_signing_algorithm") or "ES256", "value": _b64url_encode(digest)}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=body, headers=self._base_headers(service_config))
            resp.raise_for_status()
            data = resp.json()

        value = data.get("value")
        if not isinstance(value, str) or not value:
            raise RuntimeError("Azure Key Vault sign response did not include signature value")
        return _b64url_decode(value)

    async def get_public_key_jwk(self, service_config: dict[str, Any]) -> dict[str, Any]:
        import httpx

        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        key_reference = service_config.get("key_reference") or ""
        key_version = service_config.get("key_version")
        if not endpoint or not key_reference:
            raise ValueError("azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config")

        key_path = f"{key_reference}/{key_version}" if key_version else key_reference
        url = f"{endpoint}/keys/{key_path}?api-version=7.4"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=self._base_headers(service_config))
            resp.raise_for_status()
            data = resp.json()

        jwk = data.get("key") if isinstance(data.get("key"), dict) else {}
        return {"provider": self.provider, "key_reference": key_reference, **jwk}

    async def verify_connection(self, service_config: dict[str, Any]) -> CapabilityResult:
        import httpx

        result = CapabilityResult(ok=True)
        endpoint = (service_config.get("endpoint") or "").rstrip("/")
        if not endpoint:
            result.ok = False
            result.add_check("Endpoint", "fail", "endpoint is required")
            return result

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{endpoint}/keys?api-version=7.4", headers=self._base_headers(service_config))
            if resp.status_code == 200:
                result.add_check("Connectivity", "pass", "Azure Key Vault endpoint is reachable.")
            elif resp.status_code in {401, 403}:
                result.ok = False
                result.add_check("Authentication", "fail", "Azure token is invalid or unauthorized.")
            else:
                result.ok = False
                result.add_check("Connectivity", "fail", f"Azure returned HTTP {resp.status_code}.")
        except Exception as exc:  # noqa: BLE001
            result.ok = False
            result.add_check("Connectivity", "fail", f"Azure Key Vault verification failed: {exc}")
        return result


class GcpCloudKmsAdapter:
    """KMS adapter for GCP Cloud KMS REST APIs."""

    provider = "gcp"
    signature_encoding = "der"

    def _base_headers(self, service_config: dict[str, Any]) -> dict[str, str]:
        token = service_config.get("auth_reference") or ""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def sign(self, service_config: dict[str, Any], payload: bytes) -> bytes:
        import hashlib
        import httpx

        endpoint = (service_config.get("endpoint") or "https://cloudkms.googleapis.com").rstrip("/")
        key_reference = service_config.get("key_reference") or ""
        if not key_reference:
            raise ValueError("gcp-cloud-kms adapter requires 'key_reference' in service_config")

        digest = hashlib.sha256(payload).digest()
        url = f"{endpoint}/v1/{key_reference}:asymmetricSign"
        body = {"digest": {"sha256": base64.b64encode(digest).decode()}}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=body, headers=self._base_headers(service_config))
            resp.raise_for_status()
            data = resp.json()

        signature = data.get("signature")
        if not isinstance(signature, str) or not signature:
            raise RuntimeError("GCP Cloud KMS sign response did not include signature")
        return base64.b64decode(signature)

    async def get_public_key_jwk(self, service_config: dict[str, Any]) -> dict[str, Any]:
        import httpx

        endpoint = (service_config.get("endpoint") or "https://cloudkms.googleapis.com").rstrip("/")
        key_reference = service_config.get("key_reference") or ""
        if not key_reference:
            raise ValueError("gcp-cloud-kms adapter requires 'key_reference' in service_config")

        url = f"{endpoint}/v1/{key_reference}/publicKey"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=self._base_headers(service_config))
            resp.raise_for_status()
            data = resp.json()

        return {
            "provider": self.provider,
            "key_reference": key_reference,
            "public_key_pem": data.get("pem"),
            "algorithm": data.get("algorithm"),
            "protection_level": data.get("protectionLevel"),
        }

    async def verify_connection(self, service_config: dict[str, Any]) -> CapabilityResult:
        import httpx

        result = CapabilityResult(ok=True)
        endpoint = (service_config.get("endpoint") or "https://cloudkms.googleapis.com").rstrip("/")
        key_reference = service_config.get("key_reference") or ""
        if not key_reference:
            result.ok = False
            result.add_check("Key reference", "fail", "key_reference is required")
            return result

        try:
            url = f"{endpoint}/v1/{key_reference}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=self._base_headers(service_config))
            if resp.status_code == 200:
                result.add_check("Key exists", "pass", f"GCP KMS key '{key_reference}' is reachable.")
            elif resp.status_code in {401, 403}:
                result.ok = False
                result.add_check("Authentication", "fail", "GCP token is invalid or unauthorized.")
            elif resp.status_code == 404:
                result.ok = False
                result.add_check("Key exists", "fail", "Configured GCP key reference was not found.")
            else:
                result.ok = False
                result.add_check("Connectivity", "fail", f"GCP returned HTTP {resp.status_code}.")
        except Exception as exc:  # noqa: BLE001
            result.ok = False
            result.add_check("Connectivity", "fail", f"GCP Cloud KMS verification failed: {exc}")
        return result


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

_ADAPTER_MAP: dict[str, KmsAdapter] = {
    "openbao-transit": OpenBaoTransitAdapter(),
    "hashicorp-vault-transit": OpenBaoTransitAdapter(),  # same protocol
    "aws-kms": AwsKmsAdapter(),
    "azure-key-vault": AzureKeyVaultAdapter(),
    "gcp-cloud-kms": GcpCloudKmsAdapter(),
}


def get_adapter(service_config: dict[str, Any]) -> KmsAdapter | None:
    """Return the :class:`KmsAdapter` for a registered service config, or ``None``.

    Matches on ``service_type`` first.
    """
    service_type = service_config.get("service_type") or ""
    return _ADAPTER_MAP.get(service_type)
