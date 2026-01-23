"""Domain event publisher using MMF messaging infrastructure.

This module provides a publisher that converts domain events to MMF Messages
and publishes them through the configured messaging backend.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, Protocol

from .domain_events import DomainEvent, DomainEventType, MessagePriority

logger = logging.getLogger(__name__)


class IMessageProducer(Protocol):
    """Protocol matching MMF IMessageProducer interface."""

    async def publish(self, message: Any) -> bool:
        """Publish a message."""
        ...

    async def publish_batch(self, messages: list[Any]) -> dict[str, bool]:
        """Publish multiple messages."""
        ...


@dataclass
class PublishResult:
    """Result of a publish operation."""

    success: bool
    event_id: str
    published_at: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None


@dataclass
class BatchPublishResult:
    """Result of a batch publish operation."""

    total: int
    successful: int
    failed: int
    results: dict[str, PublishResult] = field(default_factory=dict)


class DomainEventPublisher:
    """Publisher for domain events using MMF messaging.

    This class wraps the MMF messaging infrastructure to provide a typed
    interface for publishing domain events. It handles conversion from
    DomainEvent to MMF Message format and provides hooks for middleware.

    Example:
        publisher = DomainEventPublisher(producer)

        event = CredentialRevokedEvent(
            tenant_id="org-123",
            credential_id="cred-456",
            credential_type="mDoc",
            reason="DSC revoked",
            revoked_by="system",
            status_list_format="token_status_list",
        )

        result = await publisher.publish(event)
    """

    def __init__(
        self,
        producer: IMessageProducer,
        default_priority: MessagePriority = MessagePriority.NORMAL,
        on_publish: Optional[Callable[[DomainEvent], None]] = None,
        on_error: Optional[Callable[[DomainEvent, Exception], None]] = None,
    ):
        """Initialize the publisher.

        Args:
            producer: The MMF message producer to use
            default_priority: Default priority for published events
            on_publish: Callback invoked after successful publish
            on_error: Callback invoked on publish error
        """
        self._producer = producer
        self._default_priority = default_priority
        self._on_publish = on_publish
        self._on_error = on_error
        self._event_count = 0

    async def publish(
        self,
        event: DomainEvent,
        priority: Optional[MessagePriority] = None,
    ) -> PublishResult:
        """Publish a single domain event.

        Args:
            event: The domain event to publish
            priority: Optional priority override

        Returns:
            PublishResult indicating success/failure
        """
        effective_priority = priority or self._default_priority

        try:
            message_dict = event.to_message_dict(effective_priority)

            # Create MMF-compatible message structure
            message = self._create_message(message_dict)

            success = await self._producer.publish(message)

            if success:
                self._event_count += 1
                logger.info(
                    "Published domain event",
                    extra={
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "tenant_id": event.tenant_id,
                        "aggregate_id": event.aggregate_id,
                    },
                )
                if self._on_publish:
                    self._on_publish(event)

                return PublishResult(
                    success=True,
                    event_id=event.event_id,
                )
            else:
                error_msg = "Producer returned False"
                logger.error(
                    "Failed to publish domain event",
                    extra={
                        "event_id": event.event_id,
                        "event_type": event.event_type.value,
                        "error": error_msg,
                    },
                )
                return PublishResult(
                    success=False,
                    event_id=event.event_id,
                    error=error_msg,
                )

        except Exception as e:
            logger.exception(
                "Error publishing domain event",
                extra={
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                },
            )
            if self._on_error:
                self._on_error(event, e)

            return PublishResult(
                success=False,
                event_id=event.event_id,
                error=str(e),
            )

    async def publish_batch(
        self,
        events: list[DomainEvent],
        priority: Optional[MessagePriority] = None,
    ) -> BatchPublishResult:
        """Publish multiple domain events as a batch.

        Args:
            events: List of domain events to publish
            priority: Optional priority override for all events

        Returns:
            BatchPublishResult with per-event results
        """
        effective_priority = priority or self._default_priority

        messages = []
        event_map: dict[str, DomainEvent] = {}

        for event in events:
            message_dict = event.to_message_dict(effective_priority)
            message = self._create_message(message_dict)
            messages.append(message)
            event_map[event.event_id] = event

        try:
            results = await self._producer.publish_batch(messages)

            publish_results: dict[str, PublishResult] = {}
            successful = 0
            failed = 0

            for event_id, success in results.items():
                if success:
                    successful += 1
                    self._event_count += 1
                    if self._on_publish and event_id in event_map:
                        self._on_publish(event_map[event_id])
                else:
                    failed += 1

                publish_results[event_id] = PublishResult(
                    success=success,
                    event_id=event_id,
                    error=None if success else "Batch publish failed for this event",
                )

            logger.info(
                "Batch published domain events",
                extra={
                    "total": len(events),
                    "successful": successful,
                    "failed": failed,
                },
            )

            return BatchPublishResult(
                total=len(events),
                successful=successful,
                failed=failed,
                results=publish_results,
            )

        except Exception as e:
            logger.exception("Error in batch publish")

            # Mark all as failed
            publish_results = {}
            for event in events:
                publish_results[event.event_id] = PublishResult(
                    success=False,
                    event_id=event.event_id,
                    error=str(e),
                )
                if self._on_error:
                    self._on_error(event, e)

            return BatchPublishResult(
                total=len(events),
                successful=0,
                failed=len(events),
                results=publish_results,
            )

    async def publish_with_retry(
        self,
        event: DomainEvent,
        max_retries: int = 3,
        priority: Optional[MessagePriority] = None,
    ) -> PublishResult:
        """Publish with automatic retry on failure.

        Args:
            event: The domain event to publish
            max_retries: Maximum retry attempts
            priority: Optional priority override

        Returns:
            PublishResult from final attempt
        """
        import asyncio

        last_result: Optional[PublishResult] = None

        for attempt in range(max_retries + 1):
            result = await self.publish(event, priority)
            last_result = result

            if result.success:
                return result

            if attempt < max_retries:
                # Exponential backoff: 0.1s, 0.2s, 0.4s, ...
                delay = 0.1 * (2**attempt)
                logger.warning(
                    f"Retry attempt {attempt + 1}/{max_retries} for event {event.event_id}",
                    extra={"delay": delay},
                )
                await asyncio.sleep(delay)

        return last_result or PublishResult(
            success=False,
            event_id=event.event_id,
            error="Max retries exceeded",
        )

    def _create_message(self, message_dict: dict[str, Any]) -> Any:
        """Create an MMF-compatible message from dictionary.

        This creates a simple object that matches the expected structure.
        When MMF is available, this can create actual Message instances.
        """

        class MessageWrapper:
            """Wrapper to match MMF Message interface."""

            def __init__(self, data: dict[str, Any]):
                self.id = data["id"]
                self.body = data["body"]
                self.headers = data["headers"]
                self.priority = data["priority"]
                self.routing_key = data["routing_key"]

        return MessageWrapper(message_dict)

    @property
    def event_count(self) -> int:
        """Total number of successfully published events."""
        return self._event_count


class InMemoryEventStore:
    """Simple in-memory event store for testing and development.

    This can be used when MMF messaging is not available, such as
    in unit tests or local development without a message broker.
    """

    def __init__(self):
        self._events: list[DomainEvent] = []
        self._subscribers: dict[DomainEventType, list[Callable[[DomainEvent], None]]] = {}

    async def publish(self, message: Any) -> bool:
        """Store the event and notify subscribers."""
        # Extract event from message
        if hasattr(message, "body"):
            event_type = DomainEventType(message.body.get("event_type"))

            # Notify subscribers
            if event_type in self._subscribers:
                for handler in self._subscribers[event_type]:
                    try:
                        handler(message)
                    except Exception as e:
                        logger.error(f"Subscriber error: {e}")

        return True

    async def publish_batch(self, messages: list[Any]) -> dict[str, bool]:
        """Store multiple events."""
        results = {}
        for message in messages:
            success = await self.publish(message)
            if hasattr(message, "id"):
                results[message.id] = success
        return results

    def subscribe(
        self,
        event_type: DomainEventType,
        handler: Callable[[DomainEvent], None],
    ) -> None:
        """Subscribe to events of a specific type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def get_events(
        self,
        event_type: Optional[DomainEventType] = None,
        tenant_id: Optional[str] = None,
    ) -> list[DomainEvent]:
        """Query stored events."""
        events = self._events

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]

        return events

    def clear(self) -> None:
        """Clear all stored events."""
        self._events.clear()
