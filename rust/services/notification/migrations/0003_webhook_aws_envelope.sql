-- Keep existing Vault records while admitting the bounded AWS ciphertext tag.
-- Application admission uses the shared canonical AWS codec; this constraint
-- excludes plaintext, unknown providers/versions and oversized AWS records.
ALTER TABLE notification_service.webhook_endpoints
    DROP CONSTRAINT IF EXISTS ck_webhook_endpoints_secret_envelope;

ALTER TABLE notification_service.webhook_endpoints
    ADD CONSTRAINT ck_webhook_endpoints_secret_envelope CHECK (
        secret_envelope LIKE 'vault:%'
        OR (
            secret_envelope LIKE 'aws-kms:v1:%'
            AND octet_length(secret_envelope) BETWEEN 15 AND 8203
        )
    );

DELETE FROM notification_service.alembic_version;
INSERT INTO notification_service.alembic_version(version_num) VALUES ('20261031_0003');
