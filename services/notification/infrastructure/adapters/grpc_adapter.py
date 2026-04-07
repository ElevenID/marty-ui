"""
Notification Service gRPC Adapter (Inbound)

Implements the NotificationService gRPC servicer, delegating to the same
in-memory repository that backs the REST endpoints.  Includes server
streaming for real-time notification delivery.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import grpc

from marty_proto.v1 import (
    notification_service_pb2 as notif_pb2,
    notification_service_pb2_grpc,
)

logger = logging.getLogger(__name__)


def _notification_to_pb(n: Any) -> notif_pb2.NotificationResponse:
    """Map domain Notification → protobuf."""
    return notif_pb2.NotificationResponse(
        id=n.id,
        notification_type=n.notification_type.value,
        status=n.status.value,
        read=n.is_read,
        title=n.subject,
        message=n.body,
        severity=n.severity or "info",
        link=n.link or "",
        recipient_email=n.recipient_email or "",
        subject=n.subject,
        created_at=n.created_at.isoformat(),
        delivered_at=n.delivered_at.isoformat() if n.delivered_at else "",
    )


class NotificationServiceGrpc(
    notification_service_pb2_grpc.NotificationServiceServicer,
):
    """gRPC inbound adapter for the notification service."""

    def __init__(self, get_repo_fn: Any) -> None:
        self._get_repo = get_repo_fn
        # Active streaming subscribers: subscriber_id → {queue, org_id, recipient_id, types}
        self._stream_queues: dict[str, dict] = {}

    # ------------------------------------------------------------------ #
    # Send
    # ------------------------------------------------------------------ #

    async def SendNotification(self, request, context):
        from notification.main import (
            Notification,
            NotificationPriority,
            NotificationTarget,
            NotificationType,
        )

        repo = self._get_repo()

        subject = request.subject or ""
        body = request.body or ""

        if request.template_id:
            template = await repo.get_template(request.template_id)
            if template:
                subject = template.subject_template
                body = template.body_template
                for key, value in request.data.items():
                    subject = subject.replace(f"{{{{{key}}}}}", str(value))
                    body = body.replace(f"{{{{{key}}}}}", str(value))

        notification = Notification(
            organization_id=request.organization_id or None,
            recipient_id=request.recipient_id or None,
            recipient_email=request.recipient_email or None,
            notification_type=NotificationType(request.notification_type) if request.notification_type else NotificationType.EMAIL,
            template_id=request.template_id or None,
            subject=subject,
            body=body,
            severity=request.severity or "info",
            link=request.link or None,
            data=dict(request.data),
            correlation_id=getattr(request, "correlation_id", None) or None,
            priority=NotificationPriority(request.priority) if request.priority else NotificationPriority.NORMAL,
            target=NotificationTarget(
                organization_id=request.organization_id or None,
                recipient_id=request.recipient_id or None,
            ),
        )

        notification.mark_sent()

        # Deliver via configured channels (FCM, email, webhook, etc.)
        from notification.main import _deliver_notification, _apply_delivery_results
        results = await _deliver_notification(notification)
        _apply_delivery_results(notification, results)

        await repo.save_notification(notification)
        logger.info("gRPC SendNotification: %s → %s", notification.id, request.recipient_email)

        # Push to active stream subscribers
        await self._notify_streams("created", notification)

        return _notification_to_pb(notification)

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    async def GetNotification(self, request, context):
        repo = self._get_repo()
        notification = await repo.get_notification(request.notification_id)
        if not notification:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Notification {request.notification_id} not found")
            return notif_pb2.NotificationResponse()
        return _notification_to_pb(notification)

    async def ListNotifications(self, request, context):
        from notification.main import NotificationStatus

        repo = self._get_repo()
        status_filter = NotificationStatus(request.status) if request.status else None
        notifications = await repo.list_notifications(
            request.organization_id or None,
            request.recipient_id or None,
            status_filter,
        )
        if request.unread_only:
            notifications = [n for n in notifications if not n.is_read]
        return notif_pb2.ListNotificationsResponse(
            notifications=[_notification_to_pb(n) for n in notifications],
            total=len(notifications),
        )

    async def GetUnreadCount(self, request, context):
        repo = self._get_repo()
        notifications = await repo.list_notifications(
            None, request.recipient_id or None,
        )
        count = sum(1 for n in notifications if not n.is_read)
        return notif_pb2.GetUnreadCountResponse(count=count)

    # ------------------------------------------------------------------ #
    # Status updates
    # ------------------------------------------------------------------ #

    async def MarkAsRead(self, request, context):
        repo = self._get_repo()
        notification = await repo.get_notification(request.notification_id)
        if not notification:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Notification not found")
            return notif_pb2.NotificationResponse()
        notification.mark_read()
        await repo.save_notification(notification)
        return _notification_to_pb(notification)

    async def MarkAllAsRead(self, request, context):
        repo = self._get_repo()
        notifications = await repo.list_notifications(
            request.organization_id or None,
            request.recipient_id or None,
        )
        count = 0
        for n in notifications:
            if not n.is_read:
                n.mark_read()
                await repo.save_notification(n)
                count += 1
        return notif_pb2.MarkAllAsReadResponse(updated_count=count)

    # ------------------------------------------------------------------ #
    # Delete
    # ------------------------------------------------------------------ #

    async def DeleteNotification(self, request, context):
        repo = self._get_repo()
        deleted = await repo.delete_notification(request.notification_id)
        if not deleted:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Notification not found")
            return notif_pb2.DeleteNotificationResponse(success=False)
        return notif_pb2.DeleteNotificationResponse(success=True)

    # ------------------------------------------------------------------ #
    # Streaming
    # ------------------------------------------------------------------ #

    async def _notify_streams(self, event_type: str, notification: Any) -> None:
        """Push a notification event to matching stream subscribers."""
        stale: list[str] = []
        for sub_id, sub in self._stream_queues.items():
            # Apply per-subscriber filters before queuing
            if sub["org_id"] and notification.organization_id != sub["org_id"]:
                continue
            if sub["recipient_id"] and notification.recipient_id != sub["recipient_id"]:
                continue
            if sub["types"] and notification.notification_type.value not in sub["types"]:
                continue

            event = notif_pb2.NotificationEvent(
                event_type=event_type,
                notification=_notification_to_pb(notification),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            try:
                sub["queue"].put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Dropping notification event for slow subscriber %s", sub_id)
            except Exception:
                logger.warning("Failed to enqueue notification for subscriber %s — marking stale", sub_id, exc_info=True)
                stale.append(sub_id)
        for sid in stale:
            self._stream_queues.pop(sid, None)

    async def StreamNotifications(self, request, context):
        """Server-streaming: push new notifications to the caller."""
        import uuid

        sub_id = str(uuid.uuid4())
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._stream_queues[sub_id] = {
            "queue": q,
            "org_id": request.organization_id or None,
            "recipient_id": request.recipient_id or None,
            "types": list(request.notification_types) if request.notification_types else [],
        }
        logger.info(
            "StreamNotifications: subscriber %s connected (org=%s, recipient=%s)",
            sub_id, request.organization_id or "*", request.recipient_id or "*",
        )

        try:
            while not context.cancelled():
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            self._stream_queues.pop(sub_id, None)
            logger.info("StreamNotifications: subscriber %s disconnected", sub_id)

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    async def HealthCheck(self, request, context):
        return notif_pb2.HealthCheckResponse(status="serving")
