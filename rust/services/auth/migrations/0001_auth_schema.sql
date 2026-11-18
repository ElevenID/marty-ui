CREATE SCHEMA IF NOT EXISTS auth_service;

CREATE TABLE IF NOT EXISTS auth_service.rust_schema_versions (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_service.audit_logs (
    id UUID PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    organization_id VARCHAR(255),
    session_id VARCHAR(255),
    authentication_method VARCHAR(50),
    success BOOLEAN DEFAULT TRUE,
    ip_address INET,
    user_agent TEXT,
    event_metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id
    ON auth_service.audit_logs (user_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_organization_id
    ON auth_service.audit_logs (organization_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_event_type
    ON auth_service.audit_logs (event_type);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at
    ON auth_service.audit_logs (created_at);
CREATE INDEX IF NOT EXISTS ix_audit_logs_success
    ON auth_service.audit_logs (success);
CREATE INDEX IF NOT EXISTS ix_audit_logs_composite_user_created
    ON auth_service.audit_logs (user_id, created_at);

CREATE TABLE IF NOT EXISTS auth_service.session_history (
    id UUID PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    organization_id VARCHAR(255),
    user_type VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    expired_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    device_info JSONB,
    last_activity TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_session_history_user_id
    ON auth_service.session_history (user_id);
CREATE INDEX IF NOT EXISTS ix_session_history_organization_id
    ON auth_service.session_history (organization_id);
CREATE INDEX IF NOT EXISTS ix_session_history_created_at
    ON auth_service.session_history (created_at);
CREATE INDEX IF NOT EXISTS ix_session_history_expired_at
    ON auth_service.session_history (expired_at);
CREATE INDEX IF NOT EXISTS ix_session_history_composite_user_created
    ON auth_service.session_history (user_id, created_at);

INSERT INTO auth_service.rust_schema_versions (version)
VALUES ('rust_auth_0001')
ON CONFLICT (version) DO NOTHING;
