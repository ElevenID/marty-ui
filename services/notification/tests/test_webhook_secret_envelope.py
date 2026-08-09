"""Marty-owned tests for registered webhook secret protection."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import HTTPException

from notification.infrastructure.adapters.postgres_adapter import (
    PostgresNotificationRepository,
)
from services.notification import main as notification
from notification.main import WebhookEndpoint
from notification.webhook_secret_envelope import (
    InvalidWebhookSecretEnvelope,
    WebhookSecretEnvelope,
    WebhookSecretEnvelopeUnavailable,
    decode_bound_webhook_secret,
    encode_bound_webhook_secret,
)


def test_bound_secret_rejects_cross_tenant_and_cross_webhook_replay() -> None:
    encoded = encode_bound_webhook_secret(
        organization_id="org-a", webhook_id="hook-a", secret="s" * 32
    )

    assert (
        decode_bound_webhook_secret(
            encoded, organization_id="org-a", webhook_id="hook-a"
        )
        == "s" * 32
    )
    with pytest.raises(InvalidWebhookSecretEnvelope, match="binding mismatch"):
        decode_bound_webhook_secret(
            encoded, organization_id="org-b", webhook_id="hook-a"
        )
    with pytest.raises(InvalidWebhookSecretEnvelope, match="binding mismatch"):
        decode_bound_webhook_secret(
            encoded, organization_id="org-a", webhook_id="hook-b"
        )


def test_bound_secret_rejects_schema_or_purpose_substitution() -> None:
    document = {
        "schema": "marty.flow-key-envelope/v1",
        "organization_id": "org-a",
        "webhook_id": "hook-a",
        "purpose": "oid4vp_response_decryption",
        "secret": "s" * 32,
    }
    encoded = base64.b64encode(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).decode()

    with pytest.raises(InvalidWebhookSecretEnvelope, match="binding mismatch"):
        decode_bound_webhook_secret(
            encoded, organization_id="org-a", webhook_id="hook-a"
        )


def test_production_rejects_shared_openbao_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BAO_ADDR", "https://bao.example")
    monkeypatch.setenv("OPENBAO_SERVICE_TOKEN", "shared-token")
    monkeypatch.delenv("NOTIFICATION_OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("NOTIFICATION_OPENBAO_TOKEN_FILE", raising=False)

    with pytest.raises(
        WebhookSecretEnvelopeUnavailable,
        match="Dedicated Notification OpenBao identity",
    ):
        WebhookSecretEnvelope.from_environment()


def test_production_loads_only_the_dedicated_notification_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    token_file = tmp_path / "notification_openbao_token"
    token_file.write_text("notification-token", encoding="utf-8")
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BAO_ADDR", "https://bao.example")
    monkeypatch.setenv("OPENBAO_SERVICE_TOKEN", "shared-token")
    monkeypatch.delenv("NOTIFICATION_OPENBAO_TOKEN", raising=False)
    monkeypatch.setenv("NOTIFICATION_OPENBAO_TOKEN_FILE", str(token_file))

    envelope = WebhookSecretEnvelope.from_environment()

    assert envelope.bao_token == "notification-token"


@pytest.mark.asyncio
async def test_transit_wrap_and_unwrap_preserve_only_ciphertext_between_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext_seen = ""

    async def fake_request(
        self,
        method: str,
        path: str,
        *,
        json_body=None,
        invalid_ciphertext_status: bool = False,
    ):
        nonlocal plaintext_seen
        assert method == "POST"
        if "/encrypt/" in path:
            plaintext_seen = json_body["plaintext"]
            return {"data": {"ciphertext": "vault:v1:opaque"}}
        assert json_body == {"ciphertext": "vault:v1:opaque"}
        return {"data": {"plaintext": plaintext_seen}}

    monkeypatch.setattr(WebhookSecretEnvelope, "_request", fake_request)
    envelope = WebhookSecretEnvelope("https://bao.example", "service-token")

    ciphertext = await envelope.wrap(
        organization_id="org-a", webhook_id="hook-a", secret="k" * 48
    )
    assert ciphertext == "vault:v1:opaque"
    assert "k" * 48 not in ciphertext
    assert (
        await envelope.unwrap(
            organization_id="org-a",
            webhook_id="hook-a",
            ciphertext=ciphertext,
        )
        == "k" * 48
    )


@pytest.mark.asyncio
async def test_postgres_adapter_never_persists_or_loads_plaintext_secret() -> None:
    repo = PostgresNotificationRepository(None)  # type: ignore[arg-type]
    captured: dict[str, object] = {}

    async def capture_upsert(table, identity_column: str, payload: dict) -> None:
        captured.update(payload)

    repo._upsert = capture_upsert  # type: ignore[method-assign]
    webhook = WebhookEndpoint(
        id="hook-a",
        organization_id="org-a",
        secret="p" * 32,
        secret_envelope="vault:v1:opaque",
        secret_hint="pppp",
    )

    await repo.save_webhook(webhook)
    assert "secret" not in captured
    assert captured["secret_envelope"] == "vault:v1:opaque"
    assert captured["secret_hint"] == "pppp"

    loaded = repo._to_webhook(captured)
    assert loaded.secret == ""
    assert loaded.secret_envelope == "vault:v1:opaque"
    assert loaded.secret_hint == "pppp"


@pytest.mark.asyncio
async def test_postgres_adapter_rejects_plaintext_only_webhook() -> None:
    repo = PostgresNotificationRepository(None)  # type: ignore[arg-type]
    webhook = WebhookEndpoint(
        id="hook-a", organization_id="org-a", secret="p" * 32
    )

    with pytest.raises(ValueError, match="encrypted signing secret"):
        await repo.save_webhook(webhook)


@pytest.mark.asyncio
async def test_create_returns_secret_once_but_persists_only_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = PostgresNotificationRepository(None)  # type: ignore[arg-type]
    captured: dict[str, object] = {}

    async def capture_upsert(table, identity_column: str, payload: dict) -> None:
        captured.update(payload)

    class Envelope:
        async def wrap(self, **kwargs: str) -> str:
            assert kwargs["organization_id"] == "org-a"
            assert kwargs["secret"] == "c" * 32
            return "vault:v1:created"

    repo._upsert = capture_upsert  # type: ignore[method-assign]
    monkeypatch.setattr(notification, "_webhook_secret_envelope", Envelope())
    monkeypatch.setattr(notification, "_validate_webhook_url", lambda _url: None)

    response = await notification.create_webhook(
        notification.CreateWebhookRequest(
            organization_id="org-a",
            name="Created hook",
            url="https://hooks.example/events",
            secret="c" * 32,
        ),
        repo,
    )

    assert response.signing_secret == "c" * 32
    assert response.signing_secret_masked == "cccc..."
    assert "secret" not in captured
    assert captured["secret_envelope"] == "vault:v1:created"
    loaded = repo._to_webhook(captured)
    ordinary_response = notification._webhook_to_response(loaded)
    assert ordinary_response.signing_secret is None
    assert ordinary_response.signing_secret_masked == "cccc..."


@pytest.mark.asyncio
async def test_rotation_rewraps_before_persistence_and_returns_new_secret_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = PostgresNotificationRepository(None)  # type: ignore[arg-type]
    stored = WebhookEndpoint(
        id="hook-a",
        organization_id="org-a",
        name="Hook",
        url="https://hooks.example/events",
        secret="",
        secret_envelope="vault:v1:old",
        secret_hint="oooo",
    )
    captured: dict[str, object] = {}

    async def get_webhook(_webhook_id: str) -> WebhookEndpoint:
        return stored

    async def capture_upsert(table, identity_column: str, payload: dict) -> None:
        captured.update(payload)

    class Envelope:
        async def wrap(self, **kwargs: str) -> str:
            assert kwargs == {
                "organization_id": "org-a",
                "webhook_id": "hook-a",
                "secret": "r" * 48,
            }
            return "vault:v2:rotated"

    repo.get_webhook = get_webhook  # type: ignore[method-assign]
    repo._upsert = capture_upsert  # type: ignore[method-assign]
    monkeypatch.setattr(notification, "_webhook_secret_envelope", Envelope())

    response = await notification.update_webhook(
        "hook-a",
        notification.UpdateWebhookRequest(secret="r" * 48),
        "org-a",
        repo,
    )

    assert response.signing_secret == "r" * 48
    assert response.signing_secret_masked == "rrrr..."
    assert "secret" not in captured
    assert captured["secret_envelope"] == "vault:v2:rotated"
    assert captured["secret_hint"] == "rrrr"


@pytest.mark.asyncio
async def test_create_fails_without_persistence_when_kms_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = PostgresNotificationRepository(None)  # type: ignore[arg-type]
    persisted = False

    async def capture_upsert(table, identity_column: str, payload: dict) -> None:
        nonlocal persisted
        persisted = True

    class Envelope:
        async def wrap(self, **_kwargs: str) -> str:
            raise WebhookSecretEnvelopeUnavailable("unavailable")

    repo._upsert = capture_upsert  # type: ignore[method-assign]
    monkeypatch.setattr(notification, "_webhook_secret_envelope", Envelope())
    monkeypatch.setattr(notification, "_validate_webhook_url", lambda _url: None)

    with pytest.raises(HTTPException) as caught:
        await notification.create_webhook(
            notification.CreateWebhookRequest(
                organization_id="org-a",
                name="Unavailable hook",
                url="https://hooks.example/events",
                secret="c" * 32,
            ),
            repo,
        )

    assert caught.value.status_code == 503
    assert persisted is False
