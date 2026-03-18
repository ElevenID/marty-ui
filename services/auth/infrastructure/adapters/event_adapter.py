"""
Event Publisher Adapter

Implements EventPublisherPort using the gRPC event bus.
"""

from __future__ import annotations

import logging
from typing import Any

from ...application.ports import EventPublisherPort

logger = logging.getLogger(__name__)


class GrpcEventBusPublisher(EventPublisherPort):
    """
    gRPC event bus publisher adapter.

    Publishes domain events to the in-process GrpcEventBus, which fans
    them out to active streaming subscribers.
    """

    async def publish(self, event: Any) -> None:
        """Publish a domain event via the gRPC event bus."""
        try:
            from common.grpc_event_bus import get_event_bus

            event_dict = event.to_dict() if hasattr(event, "to_dict") else {}
            event_type = event_dict.get("event_type", type(event).__name__)
            await get_event_bus().publish(
                event_type=event_type,
                aggregate_id=event_dict.get("aggregate_id", ""),
                aggregate_type=event_dict.get("aggregate_type", ""),
                organization_id=event_dict.get("organization_id", ""),
                data={k: str(v) for k, v in event_dict.items()},
            )
            logger.debug("Published event %s via gRPC event bus", event_type)
        except Exception as exc:
            logger.error("Failed to publish event via gRPC event bus: %s", exc)
    
    def clear(self) -> None:
        """Clear stored events."""
        self.events.clear()
    
    def get_events_of_type(self, event_type: type) -> list[Any]:
        """Get all events of a specific type."""
        return [e for e in self.events if isinstance(e, event_type)]
