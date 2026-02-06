-- Database Initialization Script for Marty Microservices
-- 
-- Creates schemas for each service following schema-per-service pattern

-- Create schemas
CREATE SCHEMA IF NOT EXISTS auth_service;
CREATE SCHEMA IF NOT EXISTS organization_service;
CREATE SCHEMA IF NOT EXISTS credential_service;
CREATE SCHEMA IF NOT EXISTS trust_service;
CREATE SCHEMA IF NOT EXISTS issuance_service;
CREATE SCHEMA IF NOT EXISTS applicant_service;
CREATE SCHEMA IF NOT EXISTS notification_service;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA auth_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA organization_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA credential_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA trust_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA issuance_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA applicant_service TO marty;
GRANT ALL PRIVILEGES ON SCHEMA notification_service TO marty;

-- ============================================================================
-- Organization Service Tables
-- ============================================================================

CREATE TABLE organization_service.organizations (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    org_type VARCHAR(50) NOT NULL DEFAULT 'startup',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    contact_email VARCHAR(255),
    contact_phone VARCHAR(50),
    website VARCHAR(255),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_service.members (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(36),
    email VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    invited_by VARCHAR(36),
    invited_at TIMESTAMPTZ,
    joined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_service.api_keys (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    key_prefix VARCHAR(20) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    scopes TEXT[] DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    rate_limit INTEGER,
    created_by VARCHAR(36) NOT NULL,
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(45),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_members_org_id ON organization_service.members(organization_id);
CREATE INDEX idx_members_user_id ON organization_service.members(user_id);
CREATE INDEX idx_api_keys_org_id ON organization_service.api_keys(organization_id);
CREATE INDEX idx_api_keys_hash ON organization_service.api_keys(key_hash);

-- ============================================================================
-- Credential Service Tables
-- ============================================================================

CREATE TABLE credential_service.credential_types (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    format VARCHAR(50) NOT NULL DEFAULT 'sd_jwt_vc',
    status VARCHAR(50) NOT NULL DEFAULT 'draft',
    schema_definition JSONB DEFAULT '{}',
    display_config JSONB DEFAULT '{}',
    validity_days INTEGER DEFAULT 365,
    revocable BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_credential_types_org_id ON credential_service.credential_types(organization_id);

-- ============================================================================
-- Trust Service Tables
-- ============================================================================

CREATE TABLE trust_service.trusted_issuers (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    issuer_did VARCHAR(500) NOT NULL,
    issuer_url VARCHAR(500),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    credential_types TEXT[] DEFAULT '{}',
    verification_keys JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE trust_service.verification_policies (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    required_credential_types TEXT[] DEFAULT '{}',
    allowed_issuers TEXT[] DEFAULT '{}',
    check_revocation BOOLEAN DEFAULT TRUE,
    max_credential_age_days INTEGER,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_trusted_issuers_org_id ON trust_service.trusted_issuers(organization_id);
CREATE INDEX idx_verification_policies_org_id ON trust_service.verification_policies(organization_id);

-- ============================================================================
-- Issuance Service Tables
-- ============================================================================

CREATE TABLE issuance_service.transactions (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    credential_type_id VARCHAR(36) NOT NULL,
    applicant_id VARCHAR(36) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    pre_auth_code VARCHAR(64) NOT NULL UNIQUE,
    access_token VARCHAR(64),
    c_nonce VARCHAR(32),
    claims JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ
);

CREATE TABLE issuance_service.issued_credentials (
    id VARCHAR(36) PRIMARY KEY,
    transaction_id VARCHAR(36) NOT NULL REFERENCES issuance_service.transactions(id),
    organization_id VARCHAR(36) NOT NULL,
    credential_type_id VARCHAR(36) NOT NULL,
    applicant_id VARCHAR(36) NOT NULL,
    credential_jwt TEXT NOT NULL,
    credential_hash VARCHAR(64) NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_transactions_org_id ON issuance_service.transactions(organization_id);
CREATE INDEX idx_transactions_pre_auth ON issuance_service.transactions(pre_auth_code);
CREATE INDEX idx_issued_credentials_applicant ON issuance_service.issued_credentials(applicant_id);

-- ============================================================================
-- Applicant Service Tables
-- ============================================================================

CREATE TABLE applicant_service.applicants (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    phone VARCHAR(50),
    oidc_subject VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    vetting_level VARCHAR(50) NOT NULL DEFAULT 'basic',
    vetting_data JSONB DEFAULT '{}',
    verification_results JSONB DEFAULT '[]',
    reviewer_notes TEXT,
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    last_login TIMESTAMPTZ,
    UNIQUE(organization_id, email)
);

CREATE INDEX idx_applicants_org_id ON applicant_service.applicants(organization_id);
CREATE INDEX idx_applicants_email ON applicant_service.applicants(email);
CREATE INDEX idx_applicants_oidc_subject ON applicant_service.applicants(oidc_subject);

-- ============================================================================
-- Notification Service Tables
-- ============================================================================

CREATE TABLE notification_service.notifications (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36),
    recipient_id VARCHAR(36),
    recipient_email VARCHAR(255),
    recipient_phone VARCHAR(50),
    notification_type VARCHAR(50) NOT NULL DEFAULT 'email',
    template_id VARCHAR(36),
    subject VARCHAR(500),
    body TEXT,
    data JSONB DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    priority VARCHAR(50) NOT NULL DEFAULT 'normal',
    attempts INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_at TIMESTAMPTZ
);

CREATE TABLE notification_service.templates (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(36),
    name VARCHAR(255) NOT NULL,
    notification_type VARCHAR(50) NOT NULL DEFAULT 'email',
    subject_template TEXT,
    body_template TEXT NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_org_id ON notification_service.notifications(organization_id);
CREATE INDEX idx_notifications_recipient ON notification_service.notifications(recipient_id);
CREATE INDEX idx_notifications_status ON notification_service.notifications(status);

-- Insert default templates
INSERT INTO notification_service.templates (id, name, notification_type, subject_template, body_template) VALUES
('invitation', 'Member Invitation', 'email', 'You''ve been invited to join {{organization_name}}', 'Hello,\n\nYou''ve been invited to join {{organization_name}} on Marty.\n\nClick here to accept: {{invitation_link}}'),
('approval', 'Application Approved', 'email', 'Your application has been approved', 'Hello {{given_name}},\n\nYour application for {{credential_type}} has been approved.'),
('credential-ready', 'Credential Ready', 'email', 'Your credential is ready to claim', 'Hello {{given_name}},\n\nYour {{credential_type}} credential is ready.\n\nClaim it here: {{claim_link}}');
