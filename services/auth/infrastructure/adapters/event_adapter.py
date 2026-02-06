"""
Event Publisher Adapter

Implements EventPublisherPort using RabbitMQ via MMF messaging.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ...application.ports import EventPublisherPort

logger = logging.getLogger(__name__)


class RabbitMQEventPublisher(EventPublisherPort):
    """
    RabbitMQ event publisher adapter.
    
    Publishes domain events to RabbitMQ using the MMF event bus.
    """
    
    def __init__(
        self,
        connection_url: str = "amqp://guest:guest@localhost:5672/",
        exchange_name: str = "marty.events",
    ):
        self.connection_url = connection_url
        self.exchange_name = exchange_name
        self._connection = None
        self._channel = None
    
    async def _ensure_connection(self) -> None:
        """Ensure RabbitMQ connection is established."""
        if self._connection is None or self._connection.is_closed:
            import aio_pika
            self._connection = await aio_pika.connect_robust(self.connection_url)
            self._channel = await self._connection.channel()
            
            # Declare exchange
            await self._channel.declare_exchange(
                self.exchange_name,
                aio_pika.ExchangeType.TOPIC,
                durable=True,
            )
    
    async def publish(self, event: Any) -> None:
        """Publish a domain event to RabbitMQ."""
        try:
            await self._ensure_connection()
            
            import aio_pika
            
            # Get event data
            event_dict = event.to_dict() if hasattr(event, "to_dict") else event
            event_type = event_dict.get("event_type", "unknown")
            
            # Create message
            message = aio_pika.Message(
                body=json.dumps(event_dict).encode(),
                content_type="application/json",
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            )
            
            # Publish to exchange with event type as routing key
            exchange = await self._channel.get_exchange(self.exchange_name)
            await exchange.publish(message, routing_key=event_type)
            
            logger.debug(f"Published event {event_type}")
            
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            # Don't raise - event publishing should not break the main flow


class InMemoryEventPublisher(EventPublisherPort):
    """
    In-memory event publisher for testing.
    
    Stores events in memory for verification in tests.
    """
    
    def __init__(self):
        self.events: list[Any] = []
    
    async def publish(self, event: Any) -> None:
        """Store event in memory."""
        self.events.append(event)
        logger.debug(f"Published event to memory: {type(event).__name__}")
    
    def clear(self) -> None:
        """Clear stored events."""
        self.events.clear()
    
    def get_events_of_type(self, event_type: type) -> list[Any]:
        """Get all events of a specific type."""
        return [e for e in self.events if isinstance(e, event_type)]
