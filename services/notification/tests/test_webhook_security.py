"""Marty-owned regression tests for notification webhook trust boundaries."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from notification import webhook_security
from services.notification import main as notification


PUBLIC_ADDRESS = "93.184.216.34"


def _address_info(*addresses: str) -> list[tuple[Any, ...]]:
    return [
        (
            webhook_security.socket.AF_INET,
            webhook_security.socket.SOCK_STREAM,
            6,
            "",
            (address, 443),
        )
        for address in addresses
    ]


class _ResponseContext:
    def __init__(self, status_code: int) -> None:
        self.response = SimpleNamespace(status_code=status_code)

    async def __aenter__(self) -> SimpleNamespace:
        return self.response

    async def __aexit__(self, *_args: object) -> None:
        return None


class _FakeClient:
    def __init__(
        self,
        statuses: list[int],
        calls: list[dict[str, Any]],
    ) -> None:
        self._statuses = statuses
        self._calls = calls

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def stream(self, method: str, url: str, **kwargs: Any) -> _ResponseContext:
        self._calls.append({"method": method, "url": url, **kwargs})
        return _ResponseContext(self._statuses.pop(0))


def _client_factory(
    statuses: list[int], calls: list[dict[str, Any]]
) -> Callable[..., _FakeClient]:
    return lambda **_kwargs: _FakeClient(statuses, calls)


@pytest.mark.asyncio
async def test_destination_is_pinned_to_the_validated_public_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        webhook_security.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _address_info(PUBLIC_ADDRESS),
    )

    destination = await webhook_security.resolve_webhook_destination(
        "https://hooks.example.com:8443/events?tenant=one"
    )

    assert destination.url == f"https://{PUBLIC_ADDRESS}:8443/events?tenant=one"
    assert destination.host_header == "hooks.example.com:8443"
    assert destination.extensions == {"sni_hostname": "hooks.example.com"}


@pytest.mark.asyncio
async def test_destination_rejects_any_non_public_dns_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        webhook_security.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: _address_info(PUBLIC_ADDRESS, "127.0.0.1"),
    )

    with pytest.raises(
        webhook_security.WebhookDestinationError,
        match="WEBHOOK_DESTINATION_REJECTED",
    ):
        await webhook_security.resolve_webhook_destination(
            "https://hooks.example.com/events"
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@hooks.example.com/events",
        "https://hooks.example.com/events#fragment",
        "https://127.0.0.1/events",
    ],
)
def test_destination_rejects_ambiguous_or_non_public_url_forms(url: str) -> None:
    with pytest.raises(webhook_security.WebhookDestinationError):
        webhook_security.validate_webhook_url_structure(url)


def test_direct_signing_secret_loads_from_a_dedicated_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret_file = tmp_path / "notification_webhook_secret"
    secret_file.write_text("f" * 48, encoding="utf-8")
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET_FILE", str(secret_file))

    assert webhook_security.load_direct_webhook_signing_secret() == "f" * 48


def test_direct_signing_secret_rejects_ambiguous_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret_file = tmp_path / "notification_webhook_secret"
    secret_file.write_text("f" * 48, encoding="utf-8")
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "e" * 48)
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET_FILE", str(secret_file))

    assert webhook_security.load_direct_webhook_signing_secret() is None


def test_webhook_signing_secret_matches_the_persisted_32_to_128_contract() -> None:
    assert webhook_security.valid_webhook_signing_secret("s" * 32) is True
    assert webhook_security.valid_webhook_signing_secret("s" * 128) is True
    assert webhook_security.valid_webhook_signing_secret("s" * 31) is False
    assert webhook_security.valid_webhook_signing_secret("s" * 129) is False
    with pytest.raises(ValueError):
        notification.CreateWebhookRequest(
            organization_id="org-1",
            name="Too-long key",
            url="https://hooks.example.com/events",
            secret="s" * 129,
        )


@pytest.mark.parametrize(
    "retry_policy",
    [
        {"max_attempts": 0},
        {"max_attempts": 11},
        {"initial_backoff_seconds": -1},
        {"max_backoff_seconds": 301},
        {"initial_backoff_seconds": 31, "max_backoff_seconds": 30},
    ],
)
@pytest.mark.parametrize(
    "policy_type",
    [notification.RetryPolicy, notification.RetryPolicyModel],
)
def test_retry_policy_is_bounded(
    retry_policy: dict[str, int], policy_type: type
) -> None:
    with pytest.raises(ValueError):
        policy_type(**retry_policy)


@pytest.mark.asyncio
async def test_direct_webhook_fails_before_network_without_signing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_SECRET_FILE", raising=False)

    async def unexpected_resolution(_url: str) -> None:
        raise AssertionError("an unsigned webhook must not resolve or connect")

    monkeypatch.setattr(
        notification, "resolve_webhook_destination", unexpected_resolution
    )
    result = await notification._deliver_direct_webhook(
        notification.Notification(), "https://hooks.example.com/events"
    )

    assert result.success is False
    assert result.error_code == "WEBHOOK_SIGNING_UNAVAILABLE"
    assert result.should_retry is False


@pytest.mark.asyncio
async def test_direct_webhook_revalidates_each_retry_and_rejects_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_SECRET", "s" * 32)
    monkeypatch.delenv("NOTIFICATION_WEBHOOK_SECRET_FILE", raising=False)
    monkeypatch.setenv("DIRECT_WEBHOOK_MAX_RETRIES", "3")
    destinations = [
        webhook_security.PinnedWebhookDestination(
            url=f"https://{PUBLIC_ADDRESS}/events",
            host_header="hooks.example.com",
            extensions={"sni_hostname": "hooks.example.com"},
        ),
        webhook_security.PinnedWebhookDestination(
            url="https://93.184.216.35/events",
            host_header="hooks.example.com",
            extensions={"sni_hostname": "hooks.example.com"},
        ),
    ]
    resolutions: list[str] = []

    async def resolve(url: str) -> webhook_security.PinnedWebhookDestination:
        resolutions.append(url)
        return destinations.pop(0)

    calls: list[dict[str, Any]] = []
    statuses = [503, 302]
    monkeypatch.setattr(notification, "resolve_webhook_destination", resolve)
    monkeypatch.setattr(
        notification.httpx,
        "AsyncClient",
        _client_factory(statuses, calls),
    )

    async def no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(notification.asyncio, "sleep", no_wait)
    result = await notification._deliver_direct_webhook(
        notification.Notification(event_type="credential.issued"),
        "https://hooks.example.com/events",
    )

    assert result.success is False
    assert result.error_code == "WEBHOOK_REDIRECT_REJECTED"
    assert resolutions == [
        "https://hooks.example.com/events",
        "https://hooks.example.com/events",
    ]
    assert len(calls) == 2
    assert calls[0]["url"] == f"https://{PUBLIC_ADDRESS}/events"
    assert calls[1]["url"] == "https://93.184.216.35/events"
    assert calls[0]["headers"]["Host"] == "hooks.example.com"
    assert calls[0]["headers"]["X-MIP-Signature"].startswith("sha256=")
    assert calls[0]["follow_redirects"] is False


@pytest.mark.asyncio
async def test_registered_delivery_does_not_retain_receiver_response_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = notification.InMemoryNotificationRepository()
    subscription = notification.Subscription(
        organization_id="org-1",
        retry_policy=notification.RetryPolicy(max_attempts=1),
    )
    webhook = notification.WebhookEndpoint(
        organization_id="org-1",
        url="https://hooks.example.com/events",
    )
    destination = webhook_security.PinnedWebhookDestination(
        url=f"https://{PUBLIC_ADDRESS}/events",
        host_header="hooks.example.com",
        extensions={"sni_hostname": "hooks.example.com"},
    )

    async def resolve(_url: str) -> webhook_security.PinnedWebhookDestination:
        return destination

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(notification, "resolve_webhook_destination", resolve)
    monkeypatch.setattr(
        notification.httpx,
        "AsyncClient",
        _client_factory([500], calls),
    )
    delivery = await notification._deliver_to_webhook(
        {
            "id": "event-1",
            "type": "credential.issued",
            "timestamp": "2026-08-08T00:00:00+00:00",
        },
        subscription,
        webhook,
        repo,
    )

    assert delivery.success is False
    assert delivery.response_status_code == 500
    assert delivery.response_body is None
    assert delivery.error_message == "HTTP_500"
    assert calls[0]["follow_redirects"] is False
    assert calls[0]["headers"]["X-MIP-Delivery-Id"] == delivery.id
    assert calls[0]["headers"]["X-MIP-Delivery-Attempt"] == "1"


@pytest.mark.asyncio
async def test_dispatch_rechecks_webhook_tenant_before_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = notification.InMemoryNotificationRepository()
    webhook = notification.WebhookEndpoint(organization_id="org-b", enabled=True)
    subscription = notification.Subscription(
        organization_id="org-a",
        event_types=["credential.issued"],
        delivery_target_id=webhook.id,
    )
    await repo.save_webhook(webhook)
    await repo.save_subscription(subscription)

    async def unexpected_delivery(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a cross-tenant webhook must never be delivered")

    monkeypatch.setattr(notification, "_deliver_to_webhook", unexpected_delivery)
    result = await notification._dispatch_event_to_subscriptions(
        notification.EventIngestRequest(
            event_id="event-1",
            event_type="credential.issued",
            aggregate_id="credential-1",
            aggregate_type="credential",
            organization_id="org-a",
        ),
        repo,
    )

    assert result == {
        "matched_subscriptions": 1,
        "deliveries": 0,
        "failures": 1,
    }
