"""
Event Stream Service gRPC Adapter (Inbound)

Implements the EventStreamService gRPC servicer, providing a centralized
event bus that replaces RabbitMQ pub/sub with gRPC server streaming.
"""

from __future__ import annotations

import logging

import grpc

from common.grpc_event_bus import get_event_bus
from marty_proto.v1 import (
    event_stream_service_pb2 as es_pb2,
    event_stream_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


class EventStreamServiceGrpc(
    event_stream_service_pb2_grpc.EventStreamServiceServicer,
):
    """gRPC inbound adapter for the centralized event stream."""

    async def Subscribe(self, request, context):
        """Server-streaming: push matching events to the subscriber."""
        event_bus = get_event_bus()
        event_types = set(request.event_types) if request.event_types else None

        sub_id, stream = await event_bus.subscribe(
            event_types=event_types,
            organization_id=request.organization_id,
            aggregate_type=request.aggregate_type,
            subscriber_id=request.subscriber_id,
        )
        logger.info("EventStream.Subscribe: sub_id=%s", sub_id)

        try:
            async for event in stream:
                if context.cancelled():
                    break
                yield es_pb2.DomainEvent(
                    event_id=event["event_id"],
                    event_type=event["event_type"],
                    aggregate_id=event["aggregate_id"],
                    aggregate_type=event["aggregate_type"],
                    organization_id=event["organization_id"],
                    data=event["data"],
                    timestamp=event["timestamp"],
                    correlation_id=event.get("correlation_id", ""),
                )
        finally:
            await event_bus.unsubscribe(sub_id)

    async def Publish(self, request, context):
        """Publish a domain event to all active subscribers."""
        event_bus = get_event_bus()
        ev = request.event
        notified = await event_bus.publish(
            event_type=ev.event_type,
            aggregate_id=ev.aggregate_id,
            aggregate_type=ev.aggregate_type,
            organization_id=ev.organization_id,
            data=dict(ev.data),
            correlation_id=ev.correlation_id,
        )
        return es_pb2.PublishEventResponse(
            success=True,
            subscribers_notified=notified,
        )

    async def HealthCheck(self, request, context):
        return es_pb2.HealthCheckResponse(status="serving")
