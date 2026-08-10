"""
Event Publisher Adapter

Implements EventPublisherPort using the central gRPC event stream.
"""

from __future__ import annotations

from typing import Any

from ...application.ports import EventPublisherPort

class EventStreamPublisherAdapter(EventPublisherPort):
    """
    Central gRPC event-stream publisher adapter.

    Publishes domain events to the central event-stream service.
    """

    def __init__(self) -> None:
        from common.grpc_event_bus import GrpcEventStreamPublisher

        self._publisher = GrpcEventStreamPublisher()

    async def publish(self, event: Any) -> None:
        """Publish a domain event via the central gRPC service."""
        await self._publisher.publish(event)
