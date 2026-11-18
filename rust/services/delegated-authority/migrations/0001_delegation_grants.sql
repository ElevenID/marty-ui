CREATE SCHEMA IF NOT EXISTS delegated_authority_service;
CREATE TABLE IF NOT EXISTS delegated_authority_service.delegation_grants (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED','EXPIRED')),
    revision BIGINT NOT NULL CHECK (revision > 0),
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    grant_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT delegation_grants_org_id_unique UNIQUE (organization_id, id)
);
CREATE INDEX IF NOT EXISTS delegation_grants_org_status_created
    ON delegated_authority_service.delegation_grants (organization_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS delegation_grants_delegate
    ON delegated_authority_service.delegation_grants ((grant_document #>> '{terms,delegate,id}'));
CREATE INDEX IF NOT EXISTS delegation_grants_subject
    ON delegated_authority_service.delegation_grants ((grant_document #>> '{terms,subject,id}'));
COMMENT ON TABLE delegated_authority_service.delegation_grants IS
    'Authoritative organization-scoped Marty DelegationGrant v1 snapshots. Lifecycle changes require revision-checked transitions.';
