"""OpenBao Transit envelope protection for registered webhook secrets.

The ciphertext contains a versioned, tenant- and webhook-bound document.  The
binding is authenticated by Transit and is checked again after decryption so a
row cannot borrow another endpoint's signing key.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from notification.webhook_security import valid_webhook_signing_secret


WEBHOOK_SECRET_ENVELOPE_KEY_ID = "notification-webhook-envelope-marty-aes256"
WEBHOOK_SECRET_ENVELOPE_SCHEMA = "marty.notification-webhook-secret/v1"
WEBHOOK_SECRET_ENVELOPE_PURPOSE = "webhook_hmac_signing"


class WebhookSecretEnvelopeError(RuntimeError):
    """Base class for safe, non-secret-bearing envelope failures."""


class WebhookSecretEnvelopeUnavailable(WebhookSecretEnvelopeError):
    """The KMS operation could not be completed and may be retried."""


class InvalidWebhookSecretEnvelope(WebhookSecretEnvelopeError):
    """The envelope or its authenticated endpoint binding is invalid."""


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name, "").strip()
    if direct:
        return direct
    file_name = os.environ.get(f"{name}_FILE", "").strip()
    if not file_name:
        return ""
    try:
        return Path(file_name).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise WebhookSecretEnvelopeUnavailable(
            "OpenBao service token file is unavailable"
        ) from exc


def _bound_document(
    *, organization_id: str, webhook_id: str, secret: str
) -> dict[str, str]:
    return {
        "schema": WEBHOOK_SECRET_ENVELOPE_SCHEMA,
        "organization_id": organization_id,
        "webhook_id": webhook_id,
        "purpose": WEBHOOK_SECRET_ENVELOPE_PURPOSE,
        "secret": secret,
    }


def encode_bound_webhook_secret(
    *, organization_id: str, webhook_id: str, secret: str
) -> str:
    """Return Transit-ready base64 without placing secrets in logs or URLs."""
    if not organization_id or not webhook_id:
        raise InvalidWebhookSecretEnvelope("Webhook secret binding is incomplete")
    if not valid_webhook_signing_secret(secret):
        raise InvalidWebhookSecretEnvelope("Webhook signing secret is invalid")
    document = _bound_document(
        organization_id=organization_id, webhook_id=webhook_id, secret=secret
    )
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(canonical).decode("ascii")


def decode_bound_webhook_secret(
    plaintext: str, *, organization_id: str, webhook_id: str
) -> str:
    try:
        decoded = base64.b64decode(plaintext, validate=True)
        document = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidWebhookSecretEnvelope(
            "Webhook secret envelope plaintext is malformed"
        ) from exc
    if not isinstance(document, dict):
        raise InvalidWebhookSecretEnvelope(
            "Webhook secret envelope plaintext is malformed"
        )
    expected = {
        "schema": WEBHOOK_SECRET_ENVELOPE_SCHEMA,
        "organization_id": organization_id,
        "webhook_id": webhook_id,
        "purpose": WEBHOOK_SECRET_ENVELOPE_PURPOSE,
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise InvalidWebhookSecretEnvelope("Webhook secret envelope binding mismatch")
    secret = document.get("secret")
    if not isinstance(secret, str) or not valid_webhook_signing_secret(secret):
        raise InvalidWebhookSecretEnvelope(
            "Webhook secret envelope contains an invalid signing secret"
        )
    if set(document) != {*expected, "secret"}:
        raise InvalidWebhookSecretEnvelope(
            "Webhook secret envelope contains unexpected fields"
        )
    return secret


@dataclass(frozen=True)
class WebhookSecretEnvelope:
    bao_addr: str
    bao_token: str
    key_id: str = WEBHOOK_SECRET_ENVELOPE_KEY_ID
    timeout_seconds: float = 8.0

    @classmethod
    def from_environment(cls) -> "WebhookSecretEnvelope":
        bao_addr = os.environ.get("BAO_ADDR", "").strip()
        dedicated_token = _read_secret_value("NOTIFICATION_OPENBAO_TOKEN")
        environment = os.environ.get("ENVIRONMENT", "development").strip().lower()
        if environment in {"production", "prod"} and not dedicated_token:
            raise WebhookSecretEnvelopeUnavailable(
                "Dedicated Notification OpenBao identity is not configured"
            )
        token = dedicated_token or _read_secret_value(
            "OPENBAO_SERVICE_TOKEN"
        ) or _read_secret_value("BAO_TOKEN")
        if not bao_addr or not token:
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret protection is not configured"
            )
        if not bao_addr.startswith(("https://", "http://")):
            raise WebhookSecretEnvelopeUnavailable("OpenBao address is invalid")
        return cls(bao_addr=bao_addr.rstrip("/"), bao_token=token)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        invalid_ciphertext_status: bool = False,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.request(
                    method,
                    f"{self.bao_addr}/v1/{path.lstrip('/')}",
                    headers={"X-Vault-Token": self.bao_token},
                    json=json_body,
                )
        except httpx.RequestError as exc:
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret operation is unavailable"
            ) from exc
        if invalid_ciphertext_status and response.status_code == 400:
            raise InvalidWebhookSecretEnvelope(
                "Webhook secret ciphertext was rejected"
            )
        if response.status_code >= 400:
            raise WebhookSecretEnvelopeUnavailable(
                f"OpenBao webhook secret operation failed with HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret response is invalid"
            ) from exc
        if not isinstance(payload, dict):
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret response is invalid"
            )
        return payload

    async def check_ready(self) -> None:
        payload = await self._request("GET", f"transit/keys/{self.key_id}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret key metadata is invalid"
            )
        if data.get("type") != "aes256-gcm96" or data.get("exportable") is not False:
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao webhook secret key has unsafe attributes"
            )

    async def wrap(
        self, *, organization_id: str, webhook_id: str, secret: str
    ) -> str:
        plaintext = encode_bound_webhook_secret(
            organization_id=organization_id, webhook_id=webhook_id, secret=secret
        )
        payload = await self._request(
            "POST",
            f"transit/encrypt/{self.key_id}",
            json_body={"plaintext": plaintext},
        )
        data = payload.get("data")
        ciphertext = data.get("ciphertext") if isinstance(data, dict) else None
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao did not return a webhook secret ciphertext"
            )
        return ciphertext

    async def unwrap(
        self, *, organization_id: str, webhook_id: str, ciphertext: str
    ) -> str:
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise InvalidWebhookSecretEnvelope("Webhook secret ciphertext is invalid")
        payload = await self._request(
            "POST",
            f"transit/decrypt/{self.key_id}",
            json_body={"ciphertext": ciphertext},
            invalid_ciphertext_status=True,
        )
        data = payload.get("data")
        plaintext = data.get("plaintext") if isinstance(data, dict) else None
        if not isinstance(plaintext, str):
            raise WebhookSecretEnvelopeUnavailable(
                "OpenBao did not return webhook secret plaintext"
            )
        return decode_bound_webhook_secret(
            plaintext, organization_id=organization_id, webhook_id=webhook_id
        )
