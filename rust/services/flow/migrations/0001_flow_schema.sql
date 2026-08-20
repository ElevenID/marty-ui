CREATE SCHEMA IF NOT EXISTS flow_service;

CREATE TABLE IF NOT EXISTS flow_service.flow_definitions (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(255) NOT NULL,
    name varchar(255) NOT NULL,
    description text,
    status varchar(50) NOT NULL,
    flow_type varchar(50) NOT NULL,
    steps json NOT NULL DEFAULT '[]',
    transitions json NOT NULL DEFAULT '[]',
    start_step_id varchar(36),
    credential_template_id varchar(36),
    application_template_id varchar(36),
    presentation_policy_id varchar(36),
    delivery_destination_profile_id varchar(128),
    deployment_profile_id varchar(36),
    deployment_profile_ids json NOT NULL DEFAULT '[]',
    trust_profile_id varchar(36),
    approval_strategy varchar(50) NOT NULL DEFAULT 'AUTO',
    hooks json NOT NULL DEFAULT '{}',
    trigger json,
    extension json,
    preconditions json NOT NULL DEFAULT '[]',
    default_timeout_seconds integer NOT NULL DEFAULT 600,
    max_retries integer NOT NULL DEFAULT 3,
    retry_cooldown_minutes integer NOT NULL DEFAULT 5,
    enable_resume boolean NOT NULL DEFAULT true,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_flow_definitions_timeout CHECK (default_timeout_seconds > 0),
    CONSTRAINT ck_flow_definitions_retries CHECK (max_retries >= 0),
    CONSTRAINT ck_flow_definitions_retry_cooldown CHECK (retry_cooldown_minutes >= 0),
    CONSTRAINT ck_flow_definitions_version CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS flow_service.flow_instances (
    id varchar(36) PRIMARY KEY,
    flow_definition_id varchar(36) NOT NULL,
    organization_id varchar(255) NOT NULL,
    status varchar(50) NOT NULL DEFAULT 'created',
    current_step_id varchar(36),
    context json NOT NULL DEFAULT '{}',
    step_history json NOT NULL DEFAULT '[]',
    state_history json NOT NULL DEFAULT '[]',
    subject_id varchar(255),
    subject_type varchar(50) NOT NULL DEFAULT 'applicant',
    external_reference varchar(255),
    application_flow_key_hash varchar(64),
    started_at timestamptz,
    completed_at timestamptz,
    expires_at timestamptz,
    result json,
    error text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_flow_instances_application_flow_key_hash CHECK (
        application_flow_key_hash IS NULL OR application_flow_key_hash ~ '^[0-9a-f]{64}$'
    )
);

CREATE TABLE IF NOT EXISTS flow_service.flow_nonce_consumptions (
    nonce_digest varchar(64) PRIMARY KEY,
    flow_instance_id varchar(36) NOT NULL UNIQUE,
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT ck_flow_nonce_digest CHECK (nonce_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS flow_service.flow_callback_outbox (
    event_id varchar(36) PRIMARY KEY,
    flow_instance_id varchar(36) NOT NULL UNIQUE REFERENCES flow_service.flow_instances(id) ON DELETE CASCADE,
    organization_id varchar(255) NOT NULL,
    destination_url text NOT NULL,
    audience varchar(255) NOT NULL,
    event_type varchar(128) NOT NULL,
    payload json NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    lease_token varchar(36),
    lease_expires_at timestamptz,
    last_error_code varchar(128),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    delivered_at timestamptz,
    expires_at timestamptz NOT NULL,
    CONSTRAINT ck_flow_callback_outbox_status CHECK (
        status IN ('pending','delivering','retry','delivered','dead_letter','expired')
    ),
    CONSTRAINT ck_flow_callback_attempt_count CHECK (attempt_count >= 0)
);

CREATE TABLE IF NOT EXISTS flow_service.flow_application_event_receipts (
    event_id_sha256 varchar(64) PRIMARY KEY,
    payload_sha256 varchar(64) NOT NULL,
    organization_id varchar(255) NOT NULL,
    application_id varchar(255) NOT NULL,
    flow_plan json NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_flow_application_event_hash CHECK (event_id_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_flow_application_payload_hash CHECK (payload_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS flow_service.flow_instance_artifacts (
    id varchar(36) PRIMARY KEY,
    flow_instance_id varchar(36) NOT NULL REFERENCES flow_service.flow_instances(id) ON DELETE CASCADE,
    issuance_transaction_id varchar(36),
    credential_offer_uri text,
    credential_offer_uris json NOT NULL DEFAULT '{}',
    credential_offer_labels json NOT NULL DEFAULT '{}',
    pre_authorized_code varchar(255),
    issuance_status varchar(50),
    qr_payload text,
    expires_at timestamptz,
    scanned_at timestamptz,
    status varchar(50) NOT NULL,
    state varchar(255),
    wallet_metadata json NOT NULL DEFAULT '{}',
    attempt_number integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_flow_artifact_attempt CHECK (attempt_number > 0)
);

ALTER TABLE flow_service.flow_definitions
    ADD COLUMN IF NOT EXISTS retry_cooldown_minutes integer NOT NULL DEFAULT 5;
ALTER TABLE flow_service.flow_instances
    ADD COLUMN IF NOT EXISTS state_history json NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS ix_flow_definitions_organization_id ON flow_service.flow_definitions (organization_id);
CREATE INDEX IF NOT EXISTS ix_flow_definitions_status ON flow_service.flow_definitions (status);
CREATE INDEX IF NOT EXISTS ix_flow_definitions_flow_type ON flow_service.flow_definitions (flow_type);
CREATE INDEX IF NOT EXISTS ix_flow_definitions_org_status ON flow_service.flow_definitions (organization_id, status);
CREATE INDEX IF NOT EXISTS ix_flow_instances_organization_id ON flow_service.flow_instances (organization_id);
CREATE INDEX IF NOT EXISTS ix_flow_instances_flow_definition_id ON flow_service.flow_instances (flow_definition_id);
CREATE INDEX IF NOT EXISTS ix_flow_instances_status ON flow_service.flow_instances (status);
CREATE INDEX IF NOT EXISTS ix_flow_instances_subject_id ON flow_service.flow_instances (subject_id);
CREATE INDEX IF NOT EXISTS ix_flow_instances_external_reference ON flow_service.flow_instances (external_reference);
CREATE UNIQUE INDEX IF NOT EXISTS ux_flow_instances_org_application_flow_key
    ON flow_service.flow_instances (organization_id, application_flow_key_hash);
CREATE INDEX IF NOT EXISTS ix_flow_nonce_consumptions_expires_at ON flow_service.flow_nonce_consumptions (expires_at);
CREATE INDEX IF NOT EXISTS ix_flow_callback_outbox_due ON flow_service.flow_callback_outbox (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_flow_callback_outbox_expires_at ON flow_service.flow_callback_outbox (expires_at);
CREATE INDEX IF NOT EXISTS ix_flow_application_event_receipts_org_application
    ON flow_service.flow_application_event_receipts (organization_id, application_id);
CREATE INDEX IF NOT EXISTS ix_flow_instance_artifacts_pre_authorized_code
    ON flow_service.flow_instance_artifacts (pre_authorized_code);
CREATE UNIQUE INDEX IF NOT EXISTS ux_flow_instance_artifacts_issuance_transaction_id
    ON flow_service.flow_instance_artifacts (issuance_transaction_id);

CREATE TABLE IF NOT EXISTS flow_service.rust_schema_versions (
    version varchar(64) PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_0001') ON CONFLICT DO NOTHING;
