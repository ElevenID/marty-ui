"""Adopt the Notification schema and remove retained receiver bodies.

Revision ID: 20260808_0001
Revises: None
Create Date: 2026-08-08 22:20:00+00:00

This first owned revision is safe for both clean databases and installations
whose tables were previously created by SQLAlchemy ``create_all``. Its table
definitions are intentionally local to this immutable migration.
"""

from __future__ import annotations

from alembic import context, op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260808_0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA = "notification_service"


def _owned_metadata() -> sa.MetaData:
    metadata = sa.MetaData()
    sa.Table(
        "notification_templates",
        metadata,
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("organization_id", sa.String(36)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("notification_type", sa.String(32), nullable=False),
        sa.Column("subject_template", sa.Text(), nullable=False),
        sa.Column("body_template", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=SCHEMA,
    )
    sa.Table(
        "notifications",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36)),
        sa.Column("recipient_id", sa.String(255)),
        sa.Column("recipient_email", sa.String(255)),
        sa.Column("recipient_phone", sa.String(64)),
        sa.Column("notification_type", sa.String(32), nullable=False),
        sa.Column("template_id", sa.String(64)),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("link", sa.Text()),
        sa.Column("data", postgresql.JSON(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("priority", sa.String(32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("error_message", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scheduled_at", sa.DateTime(timezone=True)),
        sa.Column("read_at", sa.DateTime(timezone=True)),
        schema=SCHEMA,
    )
    sa.Table(
        "subscriptions",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("event_types", postgresql.JSON(), nullable=False),
        sa.Column("delivery_channel", sa.String(32), nullable=False),
        sa.Column("filter_config", postgresql.JSON(), nullable=False),
        sa.Column("retry_policy", postgresql.JSON(), nullable=False),
        sa.Column("delivery_target_id", sa.String(36)),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=SCHEMA,
    )
    sa.Table(
        "webhook_endpoints",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret", sa.String(128), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("event_types", postgresql.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("last_failure_at", sa.DateTime(timezone=True)),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True)),
        sa.Column("circuit_breaker_open_until", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        schema=SCHEMA,
    )
    sa.Table(
        "webhook_deliveries",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("webhook_id", sa.String(36), nullable=False),
        sa.Column("subscription_id", sa.String(36)),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(255), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("response_status_code", sa.Integer()),
        sa.Column("error_message", sa.Text()),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("response_time_ms", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        schema=SCHEMA,
    )
    sa.Table(
        "webhook_outbox",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), nullable=False),
        sa.Column("webhook_id", sa.String(36), nullable=False),
        sa.Column("subscription_id", sa.String(36), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(255), nullable=False),
        sa.Column("payload", postgresql.JSON(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("initial_backoff_seconds", sa.Integer(), nullable=False),
        sa.Column("max_backoff_seconds", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(128)),
        sa.Column("response_status_code", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'retry', 'delivering', 'delivered', "
            "'dead_letter', 'expired')",
            name="ck_webhook_outbox_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0", name="ck_webhook_outbox_attempt_count"
        ),
        sa.CheckConstraint("max_attempts >= 1", name="ck_webhook_outbox_max_attempts"),
        sa.CheckConstraint(
            "initial_backoff_seconds >= 0 AND max_backoff_seconds >= 1 "
            "AND initial_backoff_seconds <= max_backoff_seconds",
            name="ck_webhook_outbox_backoff",
        ),
        schema=SCHEMA,
    )

    indexes = (
        ("ix_notification_templates_org", "notification_templates", "organization_id"),
        ("ix_notifications_org", "notifications", "organization_id"),
        ("ix_notifications_recipient", "notifications", "recipient_id"),
        ("ix_notifications_status", "notifications", "status"),
        ("ix_subscriptions_org", "subscriptions", "organization_id"),
        ("ix_subscriptions_target", "subscriptions", "delivery_target_id"),
        ("ix_webhook_endpoints_org", "webhook_endpoints", "organization_id"),
        ("ix_webhook_deliveries_webhook", "webhook_deliveries", "webhook_id"),
        ("ix_webhook_deliveries_event", "webhook_deliveries", "event_id"),
        ("ix_webhook_outbox_expires", "webhook_outbox", "expires_at"),
    )
    for name, table_name, column_name in indexes:
        table = metadata.tables[f"{SCHEMA}.{table_name}"]
        sa.Index(name, table.c[column_name])
    outbox = metadata.tables[f"{SCHEMA}.webhook_outbox"]
    sa.Index("ix_webhook_outbox_due", outbox.c.status, outbox.c.next_attempt_at)
    sa.Index(
        "ux_webhook_outbox_logical_delivery",
        outbox.c.event_id,
        outbox.c.subscription_id,
        outbox.c.webhook_id,
        unique=True,
    )
    return metadata


def upgrade() -> None:
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
    metadata = _owned_metadata()
    bind = op.get_bind()
    metadata.create_all(bind=bind, checkfirst=True)
    index_statements = (
        "CREATE INDEX IF NOT EXISTS ix_notification_templates_org "
        "ON notification_service.notification_templates (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_notifications_org "
        "ON notification_service.notifications (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_notifications_recipient "
        "ON notification_service.notifications (recipient_id)",
        "CREATE INDEX IF NOT EXISTS ix_notifications_status "
        "ON notification_service.notifications (status)",
        "CREATE INDEX IF NOT EXISTS ix_subscriptions_org "
        "ON notification_service.subscriptions (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_subscriptions_target "
        "ON notification_service.subscriptions (delivery_target_id)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_endpoints_org "
        "ON notification_service.webhook_endpoints (organization_id)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_webhook "
        "ON notification_service.webhook_deliveries (webhook_id)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_event "
        "ON notification_service.webhook_deliveries (event_id)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_outbox_due "
        "ON notification_service.webhook_outbox (status, next_attempt_at)",
        "CREATE INDEX IF NOT EXISTS ix_webhook_outbox_expires "
        "ON notification_service.webhook_outbox (expires_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_webhook_outbox_logical_delivery "
        "ON notification_service.webhook_outbox "
        "(event_id, subscription_id, webhook_id)",
    )
    for statement in index_statements:
        op.execute(sa.text(statement))
    # This value was receiver-controlled and could contain secrets or PII. The
    # deletion is deliberately irreversible and also removes future storage.
    op.execute(
        sa.text(
            f"ALTER TABLE {SCHEMA}.webhook_deliveries "
            "DROP COLUMN IF EXISTS response_body"
        )
    )
    if context.is_offline_mode():
        return
    inspector = sa.inspect(bind)
    for table in metadata.sorted_tables:
        actual = {
            column["name"]
            for column in inspector.get_columns(table.name, schema=SCHEMA)
        }
        expected = set(table.c.keys())
        if actual != expected:
            raise RuntimeError(
                f"cannot adopt {SCHEMA}.{table.name}: "
                f"missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
    outbox_checks = {
        check["name"]
        for check in inspector.get_check_constraints("webhook_outbox", schema=SCHEMA)
    }
    expected_checks = {
        "ck_webhook_outbox_status",
        "ck_webhook_outbox_attempt_count",
        "ck_webhook_outbox_max_attempts",
        "ck_webhook_outbox_backoff",
    }
    if not expected_checks.issubset(outbox_checks):
        raise RuntimeError(
            "cannot adopt notification_service.webhook_outbox: "
            f"missing checks={sorted(expected_checks - outbox_checks)}"
        )


def downgrade() -> None:
    raise RuntimeError(
        "notification schema adoption and receiver-body deletion are irreversible"
    )
