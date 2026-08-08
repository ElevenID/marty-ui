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

from common.notification_event_auth import (
    NotificationEventAuthConfigurationError,
    notification_event_ingest_headers,
)

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
    Event publisher using gRPC for known services and HTTP for generic
    webhooks. All streaming events go through the central event-stream RPC.
    """

    def __init__(self):
        self.subscribers: dict[EventType, list[str]] = {}
        self._flow_grpc_channel = None
        from common.grpc_event_bus import GrpcEventStreamPublisher

        self._event_stream_publisher = GrpcEventStreamPublisher()
        self._load_subscriptions()

    def _load_subscriptions(self):
        """Load event subscriptions from environment variables."""
        # Can add webhook subscriptions from environment
        for event_type in EventType:
            env_key = f"{event_type.name}_SUBSCRIBERS"
            urls = os.environ.get(env_key, "")
            if urls:
                if event_type not in self.subscribers:
                    self.subscribers[event_type] = []
                self.subscribers[event_type].extend(
                    [u.strip() for u in urls.split(",") if u.strip()]
                )

    def _get_flow_grpc_channel(self):
        """Lazy-create gRPC channel to flow service."""
        if self._flow_grpc_channel is None:
            from common.grpc_factory import create_grpc_channel

            flow_grpc_target = os.environ.get("FLOW_GRPC_TARGET", "flow:9011")
            self._flow_grpc_channel = create_grpc_channel(flow_grpc_target)
        return self._flow_grpc_channel

    def _get_notification_ingest_url(self) -> str | None:
        explicit = os.environ.get("NOTIFICATION_EVENT_INGEST_URL")
        if explicit:
            return explicit
        base = os.environ.get("NOTIFICATION_SERVICE_URL")
        if not base:
            return None
        return f"{base.rstrip('/')}/internal/events"

    async def publish(self, event: DomainEvent) -> None:
        """Publish an event through central gRPC and configured subscribers."""
        await self._event_stream_publisher.publish_fields(
            event_type=event.event_type.value,
            aggregate_id=event.aggregate_id,
            aggregate_type=event.aggregate_type,
            organization_id=event.organization_id,
            data=event.data,
            timestamp=event.timestamp.isoformat(),
        )

        # APPLICATION_APPROVED goes directly to flow service via gRPC
        if event.event_type == EventType.APPLICATION_APPROVED:
            await self._publish_to_flow_grpc(event)

        await self._publish_to_notification_service(event)

        # Other events use HTTP webhooks
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

    async def _publish_to_notification_service(self, event: DomainEvent) -> None:
        """Deliver events to the notification service for dynamic subscription fan-out."""
        ingest_url = self._get_notification_ingest_url()
        if not ingest_url:
            return

        payload = {
            "event_type": event.event_type.value,
            "aggregate_id": event.aggregate_id,
            "aggregate_type": event.aggregate_type,
            "organization_id": event.organization_id,
            "data": event.data,
            "timestamp": event.timestamp.isoformat(),
        }
        try:
            auth_headers = notification_event_ingest_headers()
        except NotificationEventAuthConfigurationError:
            logger.error(
                "Notification ingest skipped: service authentication is unavailable"
            )
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    ingest_url,
                    json=payload,
                    headers={"Content-Type": "application/json", **auth_headers},
                )
            if response.status_code >= 400:
                logger.warning(
                    "Notification ingest failed: status=%s",
                    response.status_code,
                )
        except httpx.HTTPError:
            logger.warning("Notification ingest unavailable: request failed")

    async def _publish_to_flow_grpc(self, event: DomainEvent) -> None:
        """Deliver APPLICATION_APPROVED event to the flow service via gRPC."""
        try:
            from marty_proto.v1 import flow_service_pb2, flow_service_pb2_grpc

            channel = self._get_flow_grpc_channel()
            stub = flow_service_pb2_grpc.FlowServiceStub(channel)
            resp = await stub.ApplicationApproved(
                flow_service_pb2.ApplicationApprovedEvent(
                    event_type=event.event_type.value,
                    aggregate_id=event.aggregate_id,
                    aggregate_type=event.aggregate_type,
                    organization_id=event.organization_id,
                    data={k: str(v) for k, v in event.data.items()},
                    timestamp=event.timestamp.isoformat(),
                )
            )
            logger.info(
                f"APPLICATION_APPROVED delivered via gRPC: "
                f"success={resp.success}, flows_triggered={resp.flows_triggered}"
            )
        except Exception as exc:
            logger.error(f"Failed to deliver APPLICATION_APPROVED via gRPC: {exc}")


# Global event publisher instance
_publisher: EventPublisher | None = None


def get_event_publisher() -> EventPublisher:
    """Get the global event publisher instance."""
    global _publisher
    if _publisher is None:
        _publisher = EventPublisher()
    return _publisher
