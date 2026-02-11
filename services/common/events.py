"""
Event Publishing Utilities

Simple event bus for inter-service communication.
Uses HTTP callbacks for event delivery.
"""

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Types of domain events."""
    APPLICATION_APPROVED = "application.approved"
    APPLICATION_REJECTED = "application.rejected"
    IDENTITY_VERIFIED = "identity.verified"
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_REVOKED = "credential.revoked"
    QR_CODE_SCANNED = "qr_code.scanned"
    FLOW_COMPLETED = "flow.completed"


@dataclass
class DomainEvent:
    """
    Domain event.
    
    Represents something that happened in the system.
    """
    event_type: EventType
    aggregate_id: str
    aggregate_type: str
    organization_id: str
    data: dict[str, Any]
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class EventPublisher:
    """
    Simple event publisher using HTTP callbacks.
    
    In production, use a message broker like RabbitMQ, Kafka, or Redis Pub/Sub.
    """
    
    def __init__(self):
        self.subscribers: dict[EventType, list[str]] = {}
        self._load_subscriptions()
    
    def _load_subscriptions(self):
        """Load event subscriptions from environment variables."""
        # Format: EVENT_TYPE_SUBSCRIBERS=http://service1:port/webhook,http://service2:port/webhook
        
        # Flow service subscribes to application approval events
        flow_service_url = os.environ.get("FLOW_SERVICE_URL", "http://flow-service:8011")
        self.subscribers[EventType.APPLICATION_APPROVED] = [
            f"{flow_service_url}/v1/flows/webhooks/application-approved"
        ]
        
        # Can add more subscriptions from environment
        for event_type in EventType:
            env_key = f"{event_type.name}_SUBSCRIBERS"
            urls = os.environ.get(env_key, "")
            if urls:
                if event_type not in self.subscribers:
                    self.subscribers[event_type] = []
                self.subscribers[event_type].extend([u.strip() for u in urls.split(",") if u.strip()])
    
    async def publish(self, event: DomainEvent) -> None:
        """
        Publish an event to all subscribers.
        
        Uses fire-and-forget pattern for now. In production, add retry logic
        and dead letter queue handling.
        """
        subscribers = self.subscribers.get(event.event_type, [])
        if not subscribers:
            logger.debug(f"No subscribers for event type: {event.event_type}")
            return
        
        payload = {
            "event_type": event.event_type.value,
            "aggregate_id": event.aggregate_id,
            "aggregate_type": event.aggregate_type,
            "organization_id": event.organization_id,
            "data": event.data,
            "timestamp": event.timestamp.isoformat(),
        }
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            for subscriber_url in subscribers:
                try:
                    logger.info(f"Publishing {event.event_type} to {subscriber_url}")
                    response = await client.post(
                        subscriber_url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    
                    if response.status_code >= 400:
                        logger.warning(
                            f"Event delivery failed to {subscriber_url}: "
                            f"status={response.status_code}"
                        )
                    else:
                        logger.info(f"Event delivered successfully to {subscriber_url}")
                
                except httpx.TimeoutException:
                    logger.warning(f"Timeout publishing event to {subscriber_url}")
                except Exception as e:
                    logger.error(f"Error publishing event to {subscriber_url}: {e}")


# Global event publisher instance
_publisher: EventPublisher | None = None


def get_event_publisher() -> EventPublisher:
    """Get the global event publisher instance."""
    global _publisher
    if _publisher is None:
        _publisher = EventPublisher()
    return _publisher
