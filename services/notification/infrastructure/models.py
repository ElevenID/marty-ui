"""SQLAlchemy models for notification service."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Table, Text
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.orm import registry

mapper_registry = registry()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


notification_templates = Table(
    "notification_templates",
    mapper_registry.metadata,
    Column("id", String(64), primary_key=True),
    Column("organization_id", String(36), nullable=True),
    Column("name", String(255), nullable=False),
    Column("notification_type", String(32), nullable=False),
    Column("subject_template", Text, nullable=False, default=""),
    Column("body_template", Text, nullable=False, default=""),
    Column("active", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    schema="notification_service",
)


notifications = Table(
    "notifications",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=True),
    Column("recipient_id", String(255), nullable=True),
    Column("recipient_email", String(255), nullable=True),
    Column("recipient_phone", String(64), nullable=True),
    Column("notification_type", String(32), nullable=False),
    Column("template_id", String(64), nullable=True),
    Column("subject", Text, nullable=False, default=""),
    Column("body", Text, nullable=False, default=""),
    Column("severity", String(32), nullable=False, default="info"),
    Column("link", Text, nullable=True),
    Column("data", JSON, nullable=False, default=dict),
    Column("status", String(32), nullable=False),
    Column("priority", String(32), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("last_attempt_at", DateTime(timezone=True), nullable=True),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    Column("error_message", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("scheduled_at", DateTime(timezone=True), nullable=True),
    Column("read_at", DateTime(timezone=True), nullable=True),
    schema="notification_service",
)


subscriptions = Table(
    "subscriptions",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("name", String(255), nullable=False),
    Column("description", Text, nullable=True),
    Column("event_types", JSON, nullable=False, default=list),
    Column("delivery_channel", String(32), nullable=False),
    Column("filter_config", JSON, nullable=False, default=dict),
    Column("retry_policy", JSON, nullable=False, default=dict),
    Column("delivery_target_id", String(36), nullable=True),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    schema="notification_service",
)


webhook_endpoints = Table(
    "webhook_endpoints",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("name", String(255), nullable=False),
    Column("url", Text, nullable=False),
    Column("secret", String(128), nullable=False),
    Column("description", Text, nullable=True),
    Column("event_types", JSON, nullable=False, default=list),
    Column("enabled", Boolean, nullable=False, default=True),
    Column("failure_count", Integer, nullable=False, default=0),
    Column("last_failure_at", DateTime(timezone=True), nullable=True),
    Column("last_triggered_at", DateTime(timezone=True), nullable=True),
    Column("circuit_breaker_open_until", DateTime(timezone=True), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow),
    schema="notification_service",
)


webhook_deliveries = Table(
    "webhook_deliveries",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("webhook_id", String(36), nullable=False),
    Column("subscription_id", String(36), nullable=True),
    Column("event_id", String(64), nullable=False),
    Column("event_type", String(255), nullable=False),
    Column("success", Boolean, nullable=False),
    Column("response_status_code", Integer, nullable=True),
    Column("response_body", Text, nullable=True),
    Column("error_message", Text, nullable=True),
    Column("retry_count", Integer, nullable=False, default=0),
    Column("response_time_ms", Integer, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    schema="notification_service",
)


Index("ix_notification_templates_org", notification_templates.c.organization_id)
Index("ix_notifications_org", notifications.c.organization_id)
Index("ix_notifications_recipient", notifications.c.recipient_id)
Index("ix_notifications_status", notifications.c.status)
Index("ix_subscriptions_org", subscriptions.c.organization_id)
Index("ix_subscriptions_target", subscriptions.c.delivery_target_id)
Index("ix_webhook_endpoints_org", webhook_endpoints.c.organization_id)
Index("ix_webhook_deliveries_webhook", webhook_deliveries.c.webhook_id)
Index("ix_webhook_deliveries_event", webhook_deliveries.c.event_id)
