CREATE SCHEMA IF NOT EXISTS presentation_policy_service;

CREATE TABLE IF NOT EXISTS presentation_policy_service.presentation_policies (
    id VARCHAR(36) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL,
    display_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    credential_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
    alternative_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
    compliance_profile_id VARCHAR(36),
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    policy_document JSONB NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE presentation_policy_service.presentation_policies
    ADD COLUMN IF NOT EXISTS policy_document JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS ix_presentation_policies_organization_id
    ON presentation_policy_service.presentation_policies (organization_id);
CREATE INDEX IF NOT EXISTS ix_presentation_policies_status
    ON presentation_policy_service.presentation_policies (status);
CREATE INDEX IF NOT EXISTS ix_presentation_policies_org_status
    ON presentation_policy_service.presentation_policies (organization_id, status);
