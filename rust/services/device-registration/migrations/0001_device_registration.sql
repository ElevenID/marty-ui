CREATE SCHEMA IF NOT EXISTS device_registration_service;

CREATE TABLE IF NOT EXISTS device_registration_service.device_registrations (
    id varchar(36) PRIMARY KEY,
    user_id varchar(255) NOT NULL,
    organization_id varchar(36),
    device_id varchar(255) NOT NULL,
    platform varchar(32) NOT NULL,
    fcm_token text NOT NULL,
    app_version varchar(64),
    os_version varchar(128),
    device_model varchar(255),
    preferences json NOT NULL DEFAULT '{}'::json,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz
);
CREATE INDEX IF NOT EXISTS ix_device_registrations_user_id ON device_registration_service.device_registrations(user_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_organization_id ON device_registration_service.device_registrations(organization_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_device_id ON device_registration_service.device_registrations(device_id);
CREATE INDEX IF NOT EXISTS ix_device_registrations_user_org ON device_registration_service.device_registrations(user_id, organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_registrations_active_identity
    ON device_registration_service.device_registrations(user_id, COALESCE(organization_id, ''), device_id)
    WHERE is_active;

CREATE TABLE IF NOT EXISTS device_registration_service.device_holder_credentials (
    id varchar(36) PRIMARY KEY,
    registration_id varchar(36) NOT NULL REFERENCES device_registration_service.device_registrations(id) ON DELETE RESTRICT,
    user_id varchar(255) NOT NULL,
    organization_id varchar(36) NOT NULL,
    token_sha256 bytea NOT NULL CONSTRAINT ck_device_holder_token_digest CHECK (octet_length(token_sha256) = 32),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT uq_device_holder_token_digest UNIQUE (token_sha256),
    CONSTRAINT ck_device_holder_lifetime CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '30 days'),
    CONSTRAINT ck_device_holder_revocation CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_holder_one_current
    ON device_registration_service.device_holder_credentials(registration_id)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_device_holder_scope
    ON device_registration_service.device_holder_credentials(user_id, organization_id, registration_id);

CREATE TABLE IF NOT EXISTS device_registration_service.device_holder_keys (
    id varchar(36) PRIMARY KEY,
    registration_id varchar(36) NOT NULL REFERENCES device_registration_service.device_registrations(id) ON DELETE RESTRICT,
    user_id varchar(255) NOT NULL,
    organization_id varchar(36) NOT NULL,
    purpose varchar(32) NOT NULL CONSTRAINT ck_device_holder_key_purpose CHECK (purpose IN ('holder_binding','presentation_signing')),
    algorithm varchar(16) NOT NULL CONSTRAINT ck_device_holder_key_algorithm CHECK (algorithm IN ('EdDSA','ES256')),
    provider_reference varchar(128) NOT NULL UNIQUE CONSTRAINT ck_device_holder_key_reference CHECK (
        (purpose='holder_binding' AND provider_reference ~ '^cred-holder-[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}$') OR
        (purpose='presentation_signing' AND provider_reference ~ '^cred-presenter-[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}$')
    ),
    remote_version bigint NOT NULL CONSTRAINT ck_device_holder_key_version CHECK (remote_version > 0),
    public_x varchar(43) NOT NULL CONSTRAINT ck_device_holder_key_public_x CHECK (public_x ~ '^[A-Za-z0-9_-]{43}$'),
    public_y varchar(43),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CONSTRAINT ck_device_holder_key_public_y CHECK ((algorithm='EdDSA' AND public_y IS NULL) OR (algorithm='ES256' AND public_y ~ '^[A-Za-z0-9_-]{43}$')),
    CONSTRAINT ck_device_holder_key_revocation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_holder_key_one_current
    ON device_registration_service.device_holder_keys(registration_id, purpose)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_device_holder_key_scope
    ON device_registration_service.device_holder_keys(user_id, organization_id, registration_id);

CREATE TABLE IF NOT EXISTS device_registration_service.device_holder_key_provisions (
    provider_reference varchar(128) PRIMARY KEY,
    registration_id varchar(36) NOT NULL REFERENCES device_registration_service.device_registrations(id) ON DELETE RESTRICT,
    user_id varchar(255) NOT NULL,
    organization_id varchar(36) NOT NULL,
    purpose varchar(32) NOT NULL CONSTRAINT ck_device_holder_provision_purpose CHECK (purpose IN ('holder_binding','presentation_signing')),
    algorithm varchar(16) NOT NULL CONSTRAINT ck_device_holder_provision_algorithm CHECK (algorithm IN ('EdDSA','ES256')),
    reserved_at timestamptz NOT NULL,
    cleanup_after timestamptz NOT NULL,
    retry_after timestamptz NOT NULL,
    bound_at timestamptz,
    cleaned_at timestamptz,
    CONSTRAINT ck_device_holder_provision_times CHECK (
        cleanup_after > reserved_at AND retry_after >= cleanup_after
        AND (bound_at IS NULL OR (bound_at >= reserved_at AND cleaned_at IS NULL))
        AND (cleaned_at IS NULL OR (cleaned_at >= cleanup_after AND bound_at IS NULL))
    ),
    CONSTRAINT ck_device_holder_provision_reference CHECK (
        (purpose='holder_binding' AND provider_reference ~ '^cred-holder-[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}$') OR
        (purpose='presentation_signing' AND provider_reference ~ '^cred-presenter-[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}$')
    )
);
CREATE INDEX IF NOT EXISTS ix_device_holder_provisions_cleanup
    ON device_registration_service.device_holder_key_provisions(retry_after)
    WHERE bound_at IS NULL AND cleaned_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_device_holder_one_unbound_provision
    ON device_registration_service.device_holder_key_provisions(registration_id, purpose)
    WHERE bound_at IS NULL AND cleaned_at IS NULL;

CREATE TABLE IF NOT EXISTS device_registration_service.device_holder_key_deletions (
    provider_reference varchar(128) PRIMARY KEY REFERENCES device_registration_service.device_holder_keys(provider_reference) ON DELETE RESTRICT,
    queued_at timestamptz NOT NULL,
    retry_after timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CONSTRAINT ck_device_holder_key_deletion_attempts CHECK (attempts >= 0),
    deleted_at timestamptz,
    CONSTRAINT ck_device_holder_key_deletion_time CHECK (retry_after >= queued_at AND (deleted_at IS NULL OR deleted_at >= queued_at))
);
CREATE INDEX IF NOT EXISTS ix_device_holder_key_deletions_pending
    ON device_registration_service.device_holder_key_deletions(retry_after, queued_at)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS device_registration_service.alembic_version (
    version_num varchar(32) PRIMARY KEY
);
INSERT INTO device_registration_service.alembic_version(version_num)
VALUES ('20261009_0001')
ON CONFLICT (version_num) DO NOTHING;
