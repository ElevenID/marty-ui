-- Reserve a stable Flow identity before the native passport side effect.
-- The intent deliberately contains no MRZ, data groups, or other request body.
CREATE TABLE IF NOT EXISTS flow_service.physical_start_intents (
    organization_id varchar(255) NOT NULL,
    key_hash varchar(64) NOT NULL,
    request_hash varchar(64) NOT NULL,
    key_source varchar(16) NOT NULL,
    flow_definition_id varchar(36) NOT NULL,
    instance_id varchar(36) NOT NULL UNIQUE,
    status varchar(16) NOT NULL DEFAULT 'pending',
    claim_token uuid,
    claim_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, key_hash),
    CONSTRAINT ck_physical_start_intent_hashes CHECK (
        key_hash ~ '^[0-9a-f]{64}$' AND request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_physical_start_intent_status CHECK (status IN ('pending','completed')),
    CONSTRAINT ck_physical_start_key_source CHECK (key_source IN ('client','generated')),
    CONSTRAINT ck_physical_start_claim_pair CHECK (
        (claim_token IS NULL) = (claim_expires_at IS NULL))
);

CREATE INDEX IF NOT EXISTS ix_physical_start_intents_pending
    ON flow_service.physical_start_intents (organization_id, created_at)
    WHERE status='pending';

INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_0002') ON CONFLICT DO NOTHING;
