ALTER TABLE notification_service.webhook_deliveries
    ADD COLUMN IF NOT EXISTS correlation_id varchar(64);

CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_correlation
    ON notification_service.webhook_deliveries (correlation_id);
