"""
gRPC Event Bus

In-process event fan-out that replaces RabbitMQ topic exchange with
gRPC server streaming.  Publishers push domain events; each active
streaming subscriber receives matching events through an asyncio queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
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
        event_id: str = "",
        timestamp: str = "",
    ) -> int:
        """Publish an event to all matching subscribers.  Returns the
        number of subscribers that received the event."""
        event = {
            "event_id": event_id or str(uuid.uuid4()),
            "event_type": event_type,
            "aggregate_id": aggregate_id,
            "aggregate_type": aggregate_type,
            "organization_id": organization_id,
            "data": data,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
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


def _stringify_event_value(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None or isinstance(value, (bool, int, float, list, dict)):
        return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return str(value)


class GrpcEventStreamPublisher:
    """Publish events to the central event-stream service over gRPC.

    Producers run in separate containers from the event-stream service. They
    must therefore call its Publish RPC; writing to this module's in-process
    queue would only notify subscribers in the producer's own process.
    """

    def __init__(self, target: str | None = None) -> None:
        self._target = target
        self._channel = None

    def _get_channel(self):
        if self._channel is None:
            from common.grpc_factory import create_grpc_channel

            target = self._target or os.environ.get(
                "ES_GRPC_TARGET", "event-stream:9015"
            )
            self._channel = create_grpc_channel(target)
        return self._channel

    async def publish_fields(
        self,
        *,
        event_type: str,
        aggregate_id: str,
        aggregate_type: str,
        organization_id: str,
        data: dict[str, object],
        event_id: str = "",
        timestamp: str = "",
        correlation_id: str = "",
    ) -> int:
        """Publish normalized fields and return the subscriber count."""
        if not organization_id:
            logger.warning(
                "Refusing to publish unscoped event %s to the event stream",
                event_type,
            )
            return 0

        try:
            from marty_proto.v1 import (
                event_stream_service_pb2 as es_pb2,
                event_stream_service_pb2_grpc,
            )

            stub = event_stream_service_pb2_grpc.EventStreamServiceStub(
                self._get_channel()
            )
            response = await stub.Publish(
                es_pb2.PublishEventRequest(
                    event=es_pb2.DomainEvent(
                        event_id=event_id or str(uuid.uuid4()),
                        event_type=event_type,
                        aggregate_id=aggregate_id,
                        aggregate_type=aggregate_type,
                        organization_id=organization_id,
                        data={
                            key: _stringify_event_value(value)
                            for key, value in data.items()
                        },
                        timestamp=timestamp
                        or datetime.now(timezone.utc).isoformat(),
                        correlation_id=correlation_id,
                    )
                ),
                timeout=float(os.environ.get("ES_GRPC_TIMEOUT_SECONDS", "5")),
            )
            if not response.success:
                logger.warning("Event-stream service rejected event %s", event_type)
                return 0
            return int(response.subscribers_notified)
        except Exception as exc:
            # Domain writes remain available during a transient notification
            # outage; event delivery is observable through this warning.
            logger.warning("Failed to publish event via event-stream gRPC: %s", exc)
            return 0

    async def publish(self, event) -> None:
        """Normalize a marty-common domain event and publish it remotely."""
        event_dict = event.to_dict() if hasattr(event, "to_dict") else {}
        raw_data = event_dict.get("data")
        data = dict(raw_data) if isinstance(raw_data, dict) else {}
        organization_id = str(
            event_dict.get("organization_id")
            or data.get("organization_id")
            or ""
        )
        aggregate_id = str(
            event_dict.get("aggregate_id")
            or data.get("aggregate_id")
            or data.get("application_id")
            or data.get("applicant_id")
            or data.get("member_id")
            or data.get("user_id")
            or organization_id
        )
        aggregate_type = str(
            event_dict.get("aggregate_type")
            or data.get("aggregate_type")
            or getattr(event, "source_service", "domain")
            or "domain"
        )
        await self.publish_fields(
            event_type=str(
                event_dict.get("event_type") or type(event).__name__
            ),
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            organization_id=organization_id,
            data=data,
            event_id=str(event_dict.get("event_id") or ""),
            timestamp=str(event_dict.get("timestamp") or ""),
            correlation_id=str(event_dict.get("correlation_id") or ""),
        )
