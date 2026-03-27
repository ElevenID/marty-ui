"""PostgreSQL adapter for notification service."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from notification.infrastructure.models import (
    notification_templates,
    notifications,
    subscriptions,
    webhook_deliveries,
    webhook_endpoints,
)

if TYPE_CHECKING:
    from notification.main import (
        Notification,
        NotificationTemplate,
        Subscription,
        WebhookDelivery,
        WebhookEndpoint,
    )


class PostgresNotificationRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory

    @staticmethod
    def _split_notification_data(payload: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
        raw_payload = dict(payload or {})
        metadata = raw_payload.pop("__mip", {}) or {}
        return raw_payload, metadata

    @staticmethod
    def _compose_notification_data(notification: "Notification") -> dict[str, Any]:
        return {
            **notification.data,
            "__mip": {
                "event_type": notification.event_type,
                "ttl_seconds": notification.ttl_seconds,
                "collapse_key": notification.collapse_key,
                "correlation_id": notification.correlation_id,
                "target": {
                    "organization_id": notification.target.organization_id,
                    "user_id": notification.target.user_id,
                    "device_tokens": notification.target.device_tokens,
                    "webhook_endpoints": notification.target.webhook_endpoints,
                    "email_addresses": notification.target.email_addresses,
                    "channels": [channel.value for channel in notification.target.channels],
                }
                if notification.target
                else None,
                "delivery_results": [
                    {
                        "notification_id": result.notification_id,
                        "channel": result.channel.value,
                        "success": result.success,
                        "attempted_at": result.attempted_at.isoformat(),
                        "delivered_at": result.delivered_at.isoformat() if result.delivered_at else None,
                        "error_code": result.error_code,
                        "should_retry": result.should_retry,
                        "retry_after": result.retry_after,
                    }
                    for result in notification.delivery_results
                ],
            },
        }

    @staticmethod
    def _to_notification(row: dict[str, Any]) -> "Notification":
        from datetime import datetime

        from notification.main import (
            ChannelType,
            DeliveryResult,
            Notification,
            NotificationPriority,
            NotificationStatus,
            NotificationTarget,
            NotificationType,
            _parse_priority,
        )

        data, metadata = PostgresNotificationRepository._split_notification_data(row["data"])
        target_metadata = metadata.get("target") or {}
        delivery_results = [
            DeliveryResult(
                notification_id=result["notification_id"],
                channel=ChannelType(result["channel"]),
                success=result["success"],
                attempted_at=datetime.fromisoformat(result["attempted_at"]),
                delivered_at=datetime.fromisoformat(result["delivered_at"]) if result.get("delivered_at") else None,
                error_code=result.get("error_code"),
                should_retry=result.get("should_retry"),
                retry_after=result.get("retry_after"),
            )
            for result in metadata.get("delivery_results", [])
        ]

        return Notification(
            id=row["id"],
            organization_id=row["organization_id"],
            recipient_id=row["recipient_id"],
            recipient_email=row["recipient_email"],
            recipient_phone=row["recipient_phone"],
            notification_type=NotificationType(row["notification_type"]),
            template_id=row["template_id"],
            subject=row["subject"],
            body=row["body"],
            severity=row["severity"],
            link=row["link"],
            data=data,
            status=NotificationStatus(row["status"]),
            priority=_parse_priority(row["priority"]),
            event_type=metadata.get("event_type", "custom"),
            ttl_seconds=metadata.get("ttl_seconds", 86400),
            collapse_key=metadata.get("collapse_key"),
            correlation_id=metadata.get("correlation_id"),
            target=(
                NotificationTarget(
                    organization_id=target_metadata.get("organization_id"),
                    user_id=target_metadata.get("user_id"),
                    device_tokens=target_metadata.get("device_tokens") or [],
                    webhook_endpoints=target_metadata.get("webhook_endpoints") or [],
                    email_addresses=target_metadata.get("email_addresses") or [],
                    channels=[ChannelType(channel) for channel in target_metadata.get("channels") or []],
                )
                if target_metadata
                else None
            ),
            delivery_results=delivery_results,
            attempts=row["attempts"],
            last_attempt_at=row["last_attempt_at"],
            delivered_at=row["delivered_at"],
            error_message=row["error_message"],
            created_at=row["created_at"],
            scheduled_at=row["scheduled_at"],
            read_at=row["read_at"],
        )

    @staticmethod
    def _to_template(row: dict[str, Any]) -> "NotificationTemplate":
        from notification.main import NotificationTemplate, NotificationType

        return NotificationTemplate(
            id=row["id"],
            organization_id=row["organization_id"],
            name=row["name"],
            notification_type=NotificationType(row["notification_type"]),
            subject_template=row["subject_template"],
            body_template=row["body_template"],
            active=row["active"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _to_subscription(row: dict[str, Any]) -> "Subscription":
        from notification.main import DeliveryChannel, RetryPolicy, Subscription

        return Subscription(
            id=row["id"],
            organization_id=row["organization_id"],
            name=row["name"],
            description=row["description"],
            event_types=row["event_types"] or [],
            delivery_channel=DeliveryChannel(row["delivery_channel"]),
            filter_config=row["filter_config"] or {},
            retry_policy=RetryPolicy(**(row["retry_policy"] or {})),
            delivery_target_id=row["delivery_target_id"],
            enabled=row["enabled"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _to_webhook(row: dict[str, Any]) -> "WebhookEndpoint":
        from notification.main import WebhookEndpoint

        return WebhookEndpoint(
            id=row["id"],
            organization_id=row["organization_id"],
            name=row["name"],
            url=row["url"],
            secret=row["secret"],
            description=row["description"],
            event_types=row["event_types"] or [],
            enabled=row["enabled"],
            failure_count=row["failure_count"],
            last_failure_at=row["last_failure_at"],
            last_triggered_at=row["last_triggered_at"],
            circuit_breaker_open_until=row["circuit_breaker_open_until"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _to_webhook_delivery(row: dict[str, Any]) -> "WebhookDelivery":
        from notification.main import WebhookDelivery

        return WebhookDelivery(
            id=row["id"],
            organization_id=row["organization_id"],
            webhook_id=row["webhook_id"],
            subscription_id=row["subscription_id"],
            event_id=row["event_id"],
            event_type=row["event_type"],
            success=row["success"],
            response_status_code=row["response_status_code"],
            response_body=row["response_body"],
            error_message=row["error_message"],
            retry_count=row["retry_count"],
            response_time_ms=row["response_time_ms"],
            created_at=row["created_at"],
        )

    async def _upsert(self, table, identity_column: str, payload: dict[str, Any]) -> None:
        async with self._session_factory() as session:
            result = await session.execute(select(table).where(getattr(table.c, identity_column) == payload[identity_column]))
            existing = result.mappings().first()
            if existing:
                stmt = table.update().where(getattr(table.c, identity_column) == payload[identity_column]).values(**payload)
            else:
                stmt = table.insert().values(**payload)
            await session.execute(stmt)
            await session.commit()

    async def _delete_by_identity(self, table, identity_column: str, identity_value: str) -> bool:
        async with self._session_factory() as session:
            result = await session.execute(delete(table).where(getattr(table.c, identity_column) == identity_value))
            await session.commit()
            return bool(result.rowcount)

    async def save_notification(self, notification: "Notification") -> None:
        await self._upsert(
            notifications,
            "id",
            {
                "id": notification.id,
                "organization_id": notification.organization_id,
                "recipient_id": notification.recipient_id,
                "recipient_email": notification.recipient_email,
                "recipient_phone": notification.recipient_phone,
                "notification_type": notification.notification_type.value,
                "template_id": notification.template_id,
                "subject": notification.subject,
                "body": notification.body,
                "severity": notification.severity,
                "link": notification.link,
                "data": self._compose_notification_data(notification),
                "status": notification.status.value,
                "priority": notification.priority.value,
                "attempts": notification.attempts,
                "last_attempt_at": notification.last_attempt_at,
                "delivered_at": notification.delivered_at,
                "error_message": notification.error_message,
                "created_at": notification.created_at,
                "scheduled_at": notification.scheduled_at,
                "read_at": notification.read_at,
            },
        )

    async def get_notification(self, notif_id: str) -> "Notification | None":
        async with self._session_factory() as session:
            result = await session.execute(select(notifications).where(notifications.c.id == notif_id))
            row = result.mappings().first()
            return self._to_notification(row) if row else None

    async def delete_notification(self, notif_id: str) -> bool:
        return await self._delete_by_identity(notifications, "id", notif_id)

    async def list_notifications(self, org_id: str | None = None, recipient_id: str | None = None, status=None) -> list["Notification"]:
        async with self._session_factory() as session:
            stmt = select(notifications)
            if org_id:
                stmt = stmt.where(notifications.c.organization_id == org_id)
            if recipient_id:
                stmt = stmt.where(notifications.c.recipient_id == recipient_id)
            if status:
                stmt = stmt.where(notifications.c.status == status.value)
            stmt = stmt.order_by(notifications.c.created_at.desc())
            result = await session.execute(stmt)
            return [self._to_notification(row) for row in result.mappings().all()]

    async def save_template(self, template: "NotificationTemplate") -> None:
        await self._upsert(
            notification_templates,
            "id",
            {
                "id": template.id,
                "organization_id": template.organization_id,
                "name": template.name,
                "notification_type": template.notification_type.value,
                "subject_template": template.subject_template,
                "body_template": template.body_template,
                "active": template.active,
                "created_at": template.created_at,
                "updated_at": template.updated_at,
            },
        )

    async def get_template(self, template_id: str) -> "NotificationTemplate | None":
        async with self._session_factory() as session:
            result = await session.execute(select(notification_templates).where(notification_templates.c.id == template_id))
            row = result.mappings().first()
            return self._to_template(row) if row else None

    async def list_templates(self, org_id: str | None = None) -> list["NotificationTemplate"]:
        async with self._session_factory() as session:
            stmt = select(notification_templates)
            if org_id:
                stmt = stmt.where(or_(notification_templates.c.organization_id == org_id, notification_templates.c.organization_id.is_(None)))
            stmt = stmt.order_by(notification_templates.c.name.asc())
            result = await session.execute(stmt)
            return [self._to_template(row) for row in result.mappings().all()]

    async def save_subscription(self, subscription: "Subscription") -> None:
        await self._upsert(
            subscriptions,
            "id",
            {
                "id": subscription.id,
                "organization_id": subscription.organization_id,
                "name": subscription.name,
                "description": subscription.description,
                "event_types": subscription.event_types,
                "delivery_channel": subscription.delivery_channel.value,
                "filter_config": subscription.filter_config,
                "retry_policy": subscription.retry_policy.model_dump(),
                "delivery_target_id": subscription.delivery_target_id,
                "enabled": subscription.enabled,
                "created_at": subscription.created_at,
                "updated_at": subscription.updated_at,
            },
        )

    async def get_subscription(self, subscription_id: str) -> "Subscription | None":
        async with self._session_factory() as session:
            result = await session.execute(select(subscriptions).where(subscriptions.c.id == subscription_id))
            row = result.mappings().first()
            return self._to_subscription(row) if row else None

    async def list_subscriptions(self, organization_id: str | None = None) -> list["Subscription"]:
        async with self._session_factory() as session:
            stmt = select(subscriptions)
            if organization_id:
                stmt = stmt.where(subscriptions.c.organization_id == organization_id)
            stmt = stmt.order_by(subscriptions.c.created_at.desc())
            result = await session.execute(stmt)
            return [self._to_subscription(row) for row in result.mappings().all()]

    async def delete_subscription(self, subscription_id: str) -> bool:
        return await self._delete_by_identity(subscriptions, "id", subscription_id)

    async def save_webhook(self, webhook: "WebhookEndpoint") -> None:
        await self._upsert(
            webhook_endpoints,
            "id",
            {
                "id": webhook.id,
                "organization_id": webhook.organization_id,
                "name": webhook.name,
                "url": webhook.url,
                "secret": webhook.secret,
                "description": webhook.description,
                "event_types": webhook.event_types,
                "enabled": webhook.enabled,
                "failure_count": webhook.failure_count,
                "last_failure_at": webhook.last_failure_at,
                "last_triggered_at": webhook.last_triggered_at,
                "circuit_breaker_open_until": webhook.circuit_breaker_open_until,
                "created_at": webhook.created_at,
                "updated_at": webhook.updated_at,
            },
        )

    async def get_webhook(self, webhook_id: str) -> "WebhookEndpoint | None":
        async with self._session_factory() as session:
            result = await session.execute(select(webhook_endpoints).where(webhook_endpoints.c.id == webhook_id))
            row = result.mappings().first()
            return self._to_webhook(row) if row else None

    async def list_webhooks(self, organization_id: str | None = None) -> list["WebhookEndpoint"]:
        async with self._session_factory() as session:
            stmt = select(webhook_endpoints)
            if organization_id:
                stmt = stmt.where(webhook_endpoints.c.organization_id == organization_id)
            stmt = stmt.order_by(webhook_endpoints.c.created_at.desc())
            result = await session.execute(stmt)
            return [self._to_webhook(row) for row in result.mappings().all()]

    async def delete_webhook(self, webhook_id: str) -> bool:
        return await self._delete_by_identity(webhook_endpoints, "id", webhook_id)

    async def save_webhook_delivery(self, delivery: "WebhookDelivery") -> None:
        await self._upsert(
            webhook_deliveries,
            "id",
            {
                "id": delivery.id,
                "organization_id": delivery.organization_id,
                "webhook_id": delivery.webhook_id,
                "subscription_id": delivery.subscription_id,
                "event_id": delivery.event_id,
                "event_type": delivery.event_type,
                "success": delivery.success,
                "response_status_code": delivery.response_status_code,
                "response_body": delivery.response_body,
                "error_message": delivery.error_message,
                "retry_count": delivery.retry_count,
                "response_time_ms": delivery.response_time_ms,
                "created_at": delivery.created_at,
            },
        )

    async def list_webhook_deliveries(self, webhook_id: str) -> list["WebhookDelivery"]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(webhook_deliveries)
                .where(webhook_deliveries.c.webhook_id == webhook_id)
                .order_by(webhook_deliveries.c.created_at.desc())
            )
            return [self._to_webhook_delivery(row) for row in result.mappings().all()]
