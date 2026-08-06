from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from common.grpc_event_bus import GrpcEventStreamPublisher


async def test_publish_fields_calls_central_service_with_tenant_scope() -> None:
    publisher = GrpcEventStreamPublisher(target="events.internal:9015")
    response = MagicMock(success=True, subscribers_notified=2)
    stub = MagicMock()
    stub.Publish = AsyncMock(return_value=response)

    with (
        patch(
            "marty_proto.v1.event_stream_service_pb2_grpc.EventStreamServiceStub",
            return_value=stub,
        ),
        patch.object(publisher, "_get_channel", return_value=MagicMock()),
    ):
        notified = await publisher.publish_fields(
            event_type="application.approved",
            aggregate_id="application-1",
            aggregate_type="application",
            organization_id="org-a",
            data={"approved": True, "claims": {"given_name": "Ada"}},
            event_id="event-1",
            timestamp="2026-08-06T12:00:00+00:00",
            correlation_id="correlation-1",
        )

    assert notified == 2
    request = stub.Publish.await_args.args[0]
    assert request.event.event_id == "event-1"
    assert request.event.event_type == "application.approved"
    assert request.event.aggregate_id == "application-1"
    assert request.event.aggregate_type == "application"
    assert request.event.organization_id == "org-a"
    assert request.event.data == {
        "approved": "true",
        "claims": '{"given_name":"Ada"}',
    }
    assert request.event.timestamp == "2026-08-06T12:00:00+00:00"
    assert request.event.correlation_id == "correlation-1"
    assert stub.Publish.await_args.kwargs == {"timeout": 5.0}


async def test_domain_event_normalization_reads_scope_from_event_data() -> None:
    publisher = GrpcEventStreamPublisher()
    publisher.publish_fields = AsyncMock(return_value=1)

    class OrganizationEvent:
        source_service = "organization"

        @staticmethod
        def to_dict() -> dict:
            return {
                "event_id": "event-2",
                "event_type": "organization.updated",
                "timestamp": "2026-08-06T12:01:00+00:00",
                "correlation_id": "correlation-2",
                "data": {
                    "organization_id": "org-b",
                    "updated_fields": ["name"],
                },
            }

    await publisher.publish(OrganizationEvent())

    publisher.publish_fields.assert_awaited_once_with(
        event_type="organization.updated",
        aggregate_id="org-b",
        aggregate_type="organization",
        organization_id="org-b",
        data={"organization_id": "org-b", "updated_fields": ["name"]},
        event_id="event-2",
        timestamp="2026-08-06T12:01:00+00:00",
        correlation_id="correlation-2",
    )


async def test_unscoped_event_is_not_sent() -> None:
    publisher = GrpcEventStreamPublisher()
    publisher._get_channel = MagicMock()

    notified = await publisher.publish_fields(
        event_type="unsafe.unscoped",
        aggregate_id="resource-1",
        aggregate_type="resource",
        organization_id="",
        data={},
    )

    assert notified == 0
    publisher._get_channel.assert_not_called()


def test_channel_is_created_once_for_configured_target() -> None:
    publisher = GrpcEventStreamPublisher(target="events.internal:9015")
    channel = MagicMock()

    with patch(
        "common.grpc_factory.create_grpc_channel", return_value=channel
    ) as create:
        assert publisher._get_channel() is channel
        assert publisher._get_channel() is channel

    create.assert_called_once_with("events.internal:9015")
