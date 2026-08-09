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
from common.grpc_event_bus import GrpcEventStreamPublisher


@pytest.fixture(autouse=True)
def event_stream_publish(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    publish = AsyncMock(return_value=0)
    monkeypatch.setattr(GrpcEventStreamPublisher, "publish_fields", publish)
    return publish


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
    async def test_all_events_are_published_to_central_stream(
        self, event_stream_publish: AsyncMock
    ):
        publisher = EventPublisher()
        event = _make_event(event_type=EventType.CREDENTIAL_ISSUED)

        await publisher.publish(event)

        event_stream_publish.assert_awaited_once_with(
            event_type="credential.issued",
            aggregate_id="app-1",
            aggregate_type="Application",
            organization_id="org-1",
            data={
                "applicant_id": "a-1",
                "credential_type": "MemberCredential",
            },
            event_id=event.event_id,
            timestamp="2026-03-14T00:00:00+00:00",
        )

    async def test_routes_to_grpc_not_http(self):
        """APPLICATION_APPROVED events are routed to the Flow RPC."""
        publisher = EventPublisher()
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


# ── External fan-out governance ──────────────────────────────────────


class TestExternalFanoutGovernance:
    async def test_retired_environment_subscriber_cannot_trigger_direct_http(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv(
            "CREDENTIAL_ISSUED_SUBSCRIBERS",
            "https://legacy.example/events",
        )
        publisher = EventPublisher()
        publisher._publish_to_notification_service = AsyncMock()
        event = _make_event(event_type=EventType.CREDENTIAL_ISSUED)

        with patch("common.events.httpx.AsyncClient") as direct_client:
            await publisher.publish(event)

        direct_client.assert_not_called()
        publisher._publish_to_notification_service.assert_awaited_once_with(event)
        assert "Ignoring retired direct subscriber variables" in caplog.text


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
