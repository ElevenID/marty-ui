"""
gRPC Event Bus

In-process event fan-out that replaces RabbitMQ topic exchange with
gRPC server streaming.  Publishers push domain events; each active
streaming subscriber receives matching events through an asyncio queue.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator

logger = logging.getLogger(__name__)


@dataclass
class Subscriber:
    """An active streaming subscriber with a filter and asyncio queue."""

    subscriber_id: str
    event_types: set[str]
    organization_id: str
    aggregate_type: str
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=256))
    active: bool = True

    def matches(self, event_type: str, organization_id: str, aggregate_type: str) -> bool:
        if self.event_types and event_type not in self.event_types:
            return False
        if self.organization_id and organization_id != self.organization_id:
            return False
        if self.aggregate_type and aggregate_type != self.aggregate_type:
            return False
        return True


class GrpcEventBus:
    """
    In-process event bus backed by asyncio queues.

    Thread-safe for concurrent publish/subscribe from multiple gRPC
    handlers.  Each ``subscribe()`` call returns an async iterator that
    yields events matching the caller's filter criteria.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, Subscriber] = {}
        self._lock = asyncio.Lock()

    async def publish(
        self,
        event_type: str,
        aggregate_id: str,
        aggregate_type: str,
        organization_id: str,
        data: dict[str, str],
        correlation_id: str = "",
    ) -> int:
        """Publish an event to all matching subscribers.  Returns the
        number of subscribers that received the event."""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "aggregate_id": aggregate_id,
            "aggregate_type": aggregate_type,
            "organization_id": organization_id,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": correlation_id,
        }
        notified = 0
        async with self._lock:
            stale: list[str] = []
            for sub_id, sub in self._subscribers.items():
                if not sub.active:
                    stale.append(sub_id)
                    continue
                if sub.matches(event_type, organization_id, aggregate_type):
                    try:
                        sub.queue.put_nowait(event)
                        notified += 1
                    except asyncio.QueueFull:
                        logger.warning(
                            "Dropping event %s for slow subscriber %s",
                            event_type,
                            sub_id,
                        )
            for sid in stale:
                del self._subscribers[sid]
        return notified

    async def subscribe(
        self,
        event_types: set[str] | None = None,
        organization_id: str = "",
        aggregate_type: str = "",
        subscriber_id: str = "",
    ) -> tuple[str, AsyncIterator[dict]]:
        """Register a subscriber and return ``(sub_id, async_iterator)``.

        The caller should iterate over the returned async iterator to
        receive events.  Call ``unsubscribe(sub_id)`` when done.
        """
        sub_id = subscriber_id or str(uuid.uuid4())
        sub = Subscriber(
            subscriber_id=sub_id,
            event_types=event_types or set(),
            organization_id=organization_id,
            aggregate_type=aggregate_type,
        )
        async with self._lock:
            self._subscribers[sub_id] = sub
        logger.info("Subscriber %s registered (types=%s)", sub_id, event_types or "all")

        async def _stream():
            try:
                while sub.active:
                    try:
                        event = await asyncio.wait_for(sub.queue.get(), timeout=30.0)
                        yield event
                    except asyncio.TimeoutError:
                        # Send keepalive — caller can ignore empty yields
                        continue
            finally:
                await self.unsubscribe(sub_id)

        return sub_id, _stream()

    async def unsubscribe(self, subscriber_id: str) -> None:
        async with self._lock:
            sub = self._subscribers.pop(subscriber_id, None)
            if sub:
                sub.active = False
                logger.info("Subscriber %s removed", subscriber_id)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Module-level singleton — shared across the process.
_event_bus: GrpcEventBus | None = None


def get_event_bus() -> GrpcEventBus:
    """Return the global event bus singleton."""
    global _event_bus
    if _event_bus is None:
        _event_bus = GrpcEventBus()
    return _event_bus


class GrpcEventBusPublisher:
    """Publishes domain events to the gRPC event bus.

    Shared adapter used by services that don't need a custom port interface.
    """

    async def publish(self, event) -> None:
        try:
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
            logger.warning("Failed to publish event via gRPC event bus: %s", exc)
