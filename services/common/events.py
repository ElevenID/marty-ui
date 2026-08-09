"""
Event Publishing Utilities

Publishes to the central event stream, the authenticated Notification ingest
boundary, and the application-approved Flow RPC.
"""

import logging
import os
import uuid
from dataclasses import dataclass, field
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
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class EventPublisher:
    """
    Event publisher using governed internal service boundaries.

    External webhook fan-out belongs to Notification, where destinations are
    tenant-bound, signed, minimized, and durably retried.
    """

    def __init__(self):
        self._flow_grpc_channel = None
        from common.grpc_event_bus import GrpcEventStreamPublisher

        self._event_stream_publisher = GrpcEventStreamPublisher()
        self._warn_about_retired_subscriber_configuration()

    @staticmethod
    def _warn_about_retired_subscriber_configuration() -> None:
        retired = [
            f"{event_type.name}_SUBSCRIBERS"
            for event_type in EventType
            if os.environ.get(f"{event_type.name}_SUBSCRIBERS", "").strip()
        ]
        if retired:
            logger.error(
                "Ignoring retired direct subscriber variables %s; register "
                "tenant-owned webhooks and subscriptions through Notification",
                ", ".join(retired),
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
        """Publish through the central stream and governed service boundaries."""
        await self._event_stream_publisher.publish_fields(
            event_type=event.event_type.value,
            aggregate_id=event.aggregate_id,
            aggregate_type=event.aggregate_type,
            organization_id=event.organization_id,
            data=event.data,
            event_id=event.event_id,
            timestamp=event.timestamp.isoformat(),
        )

        # APPLICATION_APPROVED goes directly to flow service via gRPC
        if event.event_type == EventType.APPLICATION_APPROVED:
            await self._publish_to_flow_grpc(event)

        await self._publish_to_notification_service(event)

    async def _publish_to_notification_service(self, event: DomainEvent) -> None:
        """Deliver events to the notification service for dynamic subscription fan-out."""
        ingest_url = self._get_notification_ingest_url()
        if not ingest_url:
            return

        payload = {
            "event_id": event.event_id,
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
                "Notification ingest skipped: producer authentication is unavailable"
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
