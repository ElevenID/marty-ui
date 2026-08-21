CREATE SCHEMA IF NOT EXISTS trust_profile_service;

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_profiles (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    trust_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    revocation_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    revocation_profile_id TEXT,
    time_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    supported_formats JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_trust_profiles_organization_id ON trust_profile_service.trust_profiles (organization_id);
CREATE INDEX IF NOT EXISTS ix_trust_profiles_status ON trust_profile_service.trust_profiles (status);
CREATE INDEX IF NOT EXISTS ix_trust_profiles_org_status ON trust_profile_service.trust_profiles (organization_id, status);

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_frameworks (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    pkd_endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_algorithms JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_formats JSONB NOT NULL DEFAULT '[]'::jsonb,
    validation_ruleset JSONB NOT NULL DEFAULT '{}'::jsonb,
    sync_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_trust_frameworks_code ON trust_profile_service.trust_frameworks (code);
CREATE INDEX IF NOT EXISTS ix_trust_frameworks_system ON trust_profile_service.trust_frameworks (is_system);

CREATE TABLE IF NOT EXISTS trust_profile_service.organization_trust_profiles (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    framework_id TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    use_case_tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    compliance_status TEXT NOT NULL,
    auto_generated BOOLEAN NOT NULL DEFAULT FALSE,
    revocation_policy JSONB,
    time_policy JSONB,
    allowed_algorithms JSONB,
    allowed_formats JSONB,
    allowed_issuers JSONB,
    denied_issuers JSONB,
    jurisdiction_filter JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_org_trust_profiles_org ON trust_profile_service.organization_trust_profiles (organization_id);
CREATE INDEX IF NOT EXISTS ix_org_trust_profiles_framework ON trust_profile_service.organization_trust_profiles (framework_id);
CREATE INDEX IF NOT EXISTS ix_org_trust_profiles_compliance_status ON trust_profile_service.organization_trust_profiles (compliance_status);
CREATE INDEX IF NOT EXISTS ix_org_trust_profiles_org_name ON trust_profile_service.organization_trust_profiles (organization_id, name);

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_registry_entries (
    id TEXT PRIMARY KEY,
    anchor_type TEXT NOT NULL,
    operation TEXT NOT NULL DEFAULT 'ADD',
    country_code TEXT NOT NULL,
    certificate_pem TEXT,
    subject_key_id TEXT,
    not_before TIMESTAMPTZ,
    not_after TIMESTAMPTZ,
    source TEXT NOT NULL,
    framework_code TEXT,
    sequence INTEGER NOT NULL DEFAULT 0,
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_trust_registry_entries_anchor_type ON trust_profile_service.trust_registry_entries (anchor_type);
CREATE INDEX IF NOT EXISTS ix_trust_registry_entries_country_code ON trust_profile_service.trust_registry_entries (country_code);
CREATE INDEX IF NOT EXISTS ix_trust_registry_entries_sequence ON trust_profile_service.trust_registry_entries (sequence);
CREATE INDEX IF NOT EXISTS ix_trust_registry_entries_current ON trust_profile_service.trust_registry_entries (is_current);
CREATE INDEX IF NOT EXISTS ix_trust_registry_entries_source ON trust_profile_service.trust_registry_entries (source);

CREATE TABLE IF NOT EXISTS trust_profile_service.issuer_entities (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    issuer_id TEXT NOT NULL,
    issuer_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    is_system_issuer BOOLEAN NOT NULL DEFAULT FALSE,
    compliance_status TEXT NOT NULL,
    accreditation_body TEXT,
    accreditations JSONB NOT NULL DEFAULT '[]'::jsonb,
    accreditation_date TIMESTAMPTZ,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    trust_anchor_id TEXT,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    revoked_by TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE trust_profile_service.issuer_entities ADD COLUMN IF NOT EXISTS accreditations JSONB NOT NULL DEFAULT '[]'::jsonb;
CREATE INDEX IF NOT EXISTS ix_issuer_entities_org ON trust_profile_service.issuer_entities (organization_id);
CREATE INDEX IF NOT EXISTS ix_issuer_entities_identifier ON trust_profile_service.issuer_entities (issuer_id);
CREATE INDEX IF NOT EXISTS ix_issuer_entities_status ON trust_profile_service.issuer_entities (compliance_status);
CREATE INDEX IF NOT EXISTS ix_issuer_entities_system ON trust_profile_service.issuer_entities (is_system_issuer);
CREATE INDEX IF NOT EXISTS ix_issuer_entities_org_identifier ON trust_profile_service.issuer_entities (organization_id, issuer_id);

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_registry_sources (
    id TEXT PRIMARY KEY,
    trust_profile_id TEXT NOT NULL,
    registry_type TEXT NOT NULL,
    registry_name TEXT NOT NULL,
    registry_url TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sync_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at TIMESTAMPTZ,
    next_sync_at TIMESTAMPTZ,
    sync_interval_hours INTEGER NOT NULL DEFAULT 24,
    credential_format_filter JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_registry_sources_trust_profile ON trust_profile_service.trust_registry_sources (trust_profile_id);
CREATE INDEX IF NOT EXISTS ix_registry_sources_type ON trust_profile_service.trust_registry_sources (registry_type);
CREATE INDEX IF NOT EXISTS ix_registry_sources_enabled ON trust_profile_service.trust_registry_sources (enabled);
CREATE INDEX IF NOT EXISTS ix_registry_sources_sync_enabled ON trust_profile_service.trust_registry_sources (sync_enabled);

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_registry_issuers (
    id TEXT PRIMARY KEY,
    registry_source_id TEXT NOT NULL,
    trust_profile_id TEXT NOT NULL,
    issuer_did TEXT NOT NULL,
    issuer_name TEXT,
    country_code TEXT,
    issuer_type TEXT,
    verification_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    credential_templates JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    imported_at TIMESTAMPTZ NOT NULL,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_registry_issuers_registry_source ON trust_profile_service.trust_registry_issuers (registry_source_id);
CREATE INDEX IF NOT EXISTS ix_registry_issuers_trust_profile ON trust_profile_service.trust_registry_issuers (trust_profile_id);
CREATE INDEX IF NOT EXISTS ix_registry_issuers_did ON trust_profile_service.trust_registry_issuers (issuer_did);
CREATE INDEX IF NOT EXISTS ix_registry_issuers_status ON trust_profile_service.trust_registry_issuers (status);
CREATE INDEX IF NOT EXISTS ix_registry_issuers_country ON trust_profile_service.trust_registry_issuers (country_code);

CREATE TABLE IF NOT EXISTS trust_profile_service.trust_profile_issuers (
    id TEXT PRIMARY KEY,
    trust_profile_id TEXT NOT NULL,
    issuer_id TEXT NOT NULL,
    trust_level INTEGER NOT NULL DEFAULT 100,
    relationship_status TEXT NOT NULL,
    cascade_revocation_policy TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_trust_profile_issuers_profile ON trust_profile_service.trust_profile_issuers (trust_profile_id);
CREATE INDEX IF NOT EXISTS ix_trust_profile_issuers_issuer ON trust_profile_service.trust_profile_issuers (issuer_id);
CREATE INDEX IF NOT EXISTS ix_trust_profile_issuers_relationship ON trust_profile_service.trust_profile_issuers (relationship_status);
CREATE INDEX IF NOT EXISTS ix_trust_profile_issuers_profile_issuer ON trust_profile_service.trust_profile_issuers (trust_profile_id, issuer_id);
