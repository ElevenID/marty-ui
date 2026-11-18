CREATE SCHEMA IF NOT EXISTS notification_service;

CREATE TABLE IF NOT EXISTS notification_service.notification_templates (
    id varchar(64) PRIMARY KEY,
    organization_id varchar(36),
    name varchar(255) NOT NULL,
    notification_type varchar(32) NOT NULL,
    subject_template text NOT NULL DEFAULT '',
    body_template text NOT NULL DEFAULT '',
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_service.notifications (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36),
    recipient_id varchar(255),
    recipient_email varchar(255),
    recipient_phone varchar(64),
    notification_type varchar(32) NOT NULL,
    template_id varchar(64),
    subject text NOT NULL DEFAULT '',
    body text NOT NULL DEFAULT '',
    severity varchar(32) NOT NULL DEFAULT 'info',
    link text,
    data json NOT NULL DEFAULT '{}',
    status varchar(32) NOT NULL,
    priority varchar(32) NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    delivered_at timestamptz,
    error_message text,
    created_at timestamptz NOT NULL,
    scheduled_at timestamptz,
    read_at timestamptz
);

CREATE TABLE IF NOT EXISTS notification_service.subscriptions (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36) NOT NULL,
    name varchar(255) NOT NULL,
    description text,
    event_types json NOT NULL DEFAULT '[]',
    delivery_channel varchar(32) NOT NULL DEFAULT 'WEBHOOK',
    filter_config json NOT NULL DEFAULT '{}',
    retry_policy json NOT NULL DEFAULT '{}',
    delivery_target_id varchar(36),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_service.webhook_endpoints (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36) NOT NULL,
    name varchar(255) NOT NULL,
    url text NOT NULL,
    secret_envelope text NOT NULL,
    secret_hint varchar(8) NOT NULL,
    description text,
    event_types json NOT NULL DEFAULT '[]',
    enabled boolean NOT NULL DEFAULT true,
    failure_count integer NOT NULL DEFAULT 0,
    last_failure_at timestamptz,
    last_triggered_at timestamptz,
    circuit_breaker_open_until timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_webhook_endpoints_secret_envelope CHECK (secret_envelope LIKE 'vault:%'),
    CONSTRAINT ck_webhook_endpoints_secret_hint CHECK (char_length(secret_hint) = 4)
);

CREATE TABLE IF NOT EXISTS notification_service.webhook_deliveries (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36) NOT NULL,
    webhook_id varchar(36) NOT NULL,
    subscription_id varchar(36),
    event_id varchar(64) NOT NULL,
    event_type varchar(255) NOT NULL,
    success boolean NOT NULL,
    response_status_code integer,
    error_message text,
    retry_count integer NOT NULL DEFAULT 0,
    response_time_ms integer,
    created_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_service.webhook_outbox (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36) NOT NULL,
    webhook_id varchar(36) NOT NULL,
    subscription_id varchar(36) NOT NULL,
    event_id varchar(64) NOT NULL,
    event_type varchar(255) NOT NULL,
    payload json NOT NULL DEFAULT '{}',
    max_attempts integer NOT NULL,
    initial_backoff_seconds integer NOT NULL,
    max_backoff_seconds integer NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    lease_token varchar(36),
    lease_expires_at timestamptz,
    delivered_at timestamptz,
    last_error_code varchar(128),
    response_status_code integer,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CONSTRAINT ck_webhook_outbox_status CHECK (status IN ('pending','retry','delivering','delivered','dead_letter','expired')),
    CONSTRAINT ck_webhook_outbox_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT ck_webhook_outbox_max_attempts CHECK (max_attempts >= 1),
    CONSTRAINT ck_webhook_outbox_backoff CHECK (initial_backoff_seconds >= 0 AND max_backoff_seconds >= 1 AND initial_backoff_seconds <= max_backoff_seconds)
);

CREATE TABLE IF NOT EXISTS notification_service.alembic_version (
    version_num varchar(32) PRIMARY KEY
);

CREATE INDEX IF NOT EXISTS ix_notification_templates_org ON notification_service.notification_templates (organization_id);
CREATE INDEX IF NOT EXISTS ix_notifications_org ON notification_service.notifications (organization_id);
CREATE INDEX IF NOT EXISTS ix_notifications_recipient ON notification_service.notifications (recipient_id);
CREATE INDEX IF NOT EXISTS ix_notifications_status ON notification_service.notifications (status);
CREATE INDEX IF NOT EXISTS ix_subscriptions_org ON notification_service.subscriptions (organization_id);
CREATE INDEX IF NOT EXISTS ix_subscriptions_target ON notification_service.subscriptions (delivery_target_id);
CREATE INDEX IF NOT EXISTS ix_webhook_endpoints_org ON notification_service.webhook_endpoints (organization_id);
CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_webhook ON notification_service.webhook_deliveries (webhook_id);
CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_event ON notification_service.webhook_deliveries (event_id);
CREATE INDEX IF NOT EXISTS ix_webhook_outbox_due ON notification_service.webhook_outbox (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_webhook_outbox_expires ON notification_service.webhook_outbox (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS ux_webhook_outbox_logical_delivery ON notification_service.webhook_outbox (event_id, subscription_id, webhook_id);

ALTER TABLE notification_service.webhook_deliveries DROP COLUMN IF EXISTS response_body;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_webhook_endpoints_secret_envelope' AND conrelid = 'notification_service.webhook_endpoints'::regclass) THEN
        ALTER TABLE notification_service.webhook_endpoints ADD CONSTRAINT ck_webhook_endpoints_secret_envelope CHECK (secret_envelope LIKE 'vault:%');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_webhook_endpoints_secret_hint' AND conrelid = 'notification_service.webhook_endpoints'::regclass) THEN
        ALTER TABLE notification_service.webhook_endpoints ADD CONSTRAINT ck_webhook_endpoints_secret_hint CHECK (char_length(secret_hint) = 4);
    END IF;
END $$;
DELETE FROM notification_service.alembic_version;
INSERT INTO notification_service.alembic_version(version_num) VALUES ('20260808_0002');
