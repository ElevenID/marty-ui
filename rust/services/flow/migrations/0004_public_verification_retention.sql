-- Minimal public-launch receipts survive deletion of visitor session payloads.
-- No visitor IP, capability, claims, token, selection, result or provider data.
CREATE TABLE IF NOT EXISTS flow_service.public_verification_receipts (
    instance_id varchar(36) PRIMARY KEY,
    organization_id varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    payload_delete_after timestamptz NOT NULL,
    receipt_delete_after timestamptz NOT NULL,
    CONSTRAINT ck_public_verification_payload_deadline CHECK (
        payload_delete_after > created_at AND payload_delete_after <= created_at + INTERVAL '2 days'
    ),
    CONSTRAINT ck_public_verification_receipt_deadline CHECK (
        receipt_delete_after = created_at + INTERVAL '720 hours'
    )
);
CREATE INDEX IF NOT EXISTS ix_public_verification_receipts_org_created
    ON flow_service.public_verification_receipts (organization_id, created_at);
CREATE INDEX IF NOT EXISTS ix_public_verification_receipts_payload_due
    ON flow_service.public_verification_receipts (payload_delete_after);
CREATE INDEX IF NOT EXISTS ix_public_verification_receipts_delete_due
    ON flow_service.public_verification_receipts (receipt_delete_after);
REVOKE ALL ON flow_service.public_verification_receipts FROM PUBLIC;
-- Match the existing self-host application role without granting schema DDL or
-- receipt UPDATE/TRUNCATE/TRIGGER rights. Other deployments use their normal
-- schema-owner/default-privilege provisioning.
DO $public_receipt_app_acl$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='marty') THEN
        GRANT SELECT, INSERT, DELETE ON flow_service.public_verification_receipts TO marty;
    END IF;
END
$public_receipt_app_acl$;
INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_public_retention_0001') ON CONFLICT DO NOTHING;
