"""Tests for EventPublisher gRPC integration."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from common.events import (
    DomainEvent,
    EventPublisher,
    EventType,
    get_event_publisher,
)


def _make_event(event_type=EventType.APPLICATION_APPROVED, **overrides):
    defaults = dict(
        event_type=event_type,
        aggregate_id="app-1",
        aggregate_type="Application",
        organization_id="org-1",
        data={"applicant_id": "a-1", "credential_type": "MemberCredential"},
        timestamp=datetime(2026, 3, 14, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return DomainEvent(**defaults)


# ── APPLICATION_APPROVED → gRPC ──────────────────────────────────────


class TestApplicationApprovedGrpc:
    async def test_routes_to_grpc_not_http(self):
        """APPLICATION_APPROVED events are routed to _publish_to_flow_grpc, not HTTP."""
        publisher = EventPublisher()
        # Add an HTTP subscriber that should NOT be called
        publisher.subscribers[EventType.APPLICATION_APPROVED] = [
            "http://should-not-call.example.com/events",
        ]
        event = _make_event()

        with patch.object(publisher, "_publish_to_flow_grpc", new_callable=AsyncMock) as mock_grpc:
            await publisher.publish(event)
            mock_grpc.assert_awaited_once_with(event)

    async def test_other_events_not_routed_to_grpc(self):
        """Non-APPLICATION_APPROVED events should NOT go through _publish_to_flow_grpc."""
        publisher = EventPublisher()
        event = _make_event(event_type=EventType.CREDENTIAL_ISSUED)

        with patch.object(publisher, "_publish_to_flow_grpc", new_callable=AsyncMock) as mock_grpc:
            await publisher.publish(event)
            mock_grpc.assert_not_awaited()

        with patch.object(
            publisher,
            "_publish_to_flow_grpc",
            new_callable=AsyncMock,
            side_effect=Exception("connection refused"),
        ):
            # _publish_to_flow_grpc is called from publish() which catches exceptions
            # The patch replaces _publish_to_flow_grpc itself, so the exception propagates
            # from publish() since publish() calls _publish_to_flow_grpc directly.
            # Actually, publish() doesn't catch — the real _publish_to_flow_grpc does.
            # Since we replaced the whole method, the exception goes up. Let's test
            # the real path instead by verifying the internal error handling.
            pass

    async def test_grpc_error_handled_internally(self):
        """The real _publish_to_flow_grpc catches exceptions and logs them."""
        publisher = EventPublisher()
        event = _make_event()

        mock_channel = MagicMock()
        mock_stub = MagicMock()
        mock_stub.ApplicationApproved = AsyncMock(side_effect=Exception("connection refused"))

        mock_pb2_grpc = MagicMock()
        mock_pb2_grpc.FlowServiceStub.return_value = mock_stub
        mock_pb2 = MagicMock()
        mock_pb2.ApplicationApprovedEvent.return_value = MagicMock()

        with patch.dict("sys.modules", {
            "marty_proto.v1.flow_service_pb2_grpc": mock_pb2_grpc,
            "marty_proto.v1.flow_service_pb2": mock_pb2,
        }), patch.object(publisher, "_get_flow_grpc_channel", return_value=mock_channel):
            # Should not raise — errors are logged internally
            await publisher.publish(event)


# ── Other events → HTTP webhooks ─────────────────────────────────────


class TestHttpWebhookPublish:
    async def test_no_subscribers_is_noop(self):
        publisher = EventPublisher()
        event = _make_event(event_type=EventType.CREDENTIAL_ISSUED)

        # No subscribers configured → silent no-op
        await publisher.publish(event)

    async def test_delivers_to_http_subscribers(self):
        publisher = EventPublisher()
        publisher.subscribers[EventType.CREDENTIAL_ISSUED] = [
            "http://hook1.example.com/events",
        ]
        event = _make_event(event_type=EventType.CREDENTIAL_ISSUED)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("common.events.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await publisher.publish(event)

            client_instance.post.assert_awaited_once()
            call_kwargs = client_instance.post.call_args
            assert call_kwargs[0][0] == "http://hook1.example.com/events"


# ── Lazy gRPC channel ───────────────────────────────────────────────


class TestLazyGrpcChannel:
    def test_channel_created_once(self):
        publisher = EventPublisher()
        with patch("common.grpc_factory.create_grpc_channel", return_value=MagicMock()) as mock_create:
            ch1 = publisher._get_flow_grpc_channel()
            ch2 = publisher._get_flow_grpc_channel()

            assert ch1 is ch2
            mock_create.assert_called_once()


# ── Singleton ────────────────────────────────────────────────────────


class TestGetEventPublisher:
    def test_returns_same_instance(self):
        import common.events as mod

        mod._publisher = None
        p1 = get_event_publisher()
        p2 = get_event_publisher()
        assert p1 is p2
        mod._publisher = None  # cleanup
