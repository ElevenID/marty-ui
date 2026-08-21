CREATE SCHEMA IF NOT EXISTS organization_service;

CREATE TABLE IF NOT EXISTS organization_service.organizations (
    id uuid PRIMARY KEY,
    name varchar(255) NOT NULL,
    display_name varchar(255),
    description text,
    logo_url varchar(1024),
    website_url varchar(1024),
    status varchar(50) NOT NULL,
    metadata jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    created_by varchar(255),
    updated_by varchar(255),
    owner_id varchar(255),
    slug varchar(255),
    org_type varchar(50),
    contact_email varchar(255),
    contact_phone varchar(50),
    website varchar(1024),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    plan varchar(50) NOT NULL DEFAULT 'free',
    plan_expires_at timestamptz,
    join_mechanism varchar(50) NOT NULL DEFAULT 'invite',
    requires_approval boolean NOT NULL DEFAULT false,
    is_discoverable boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_organization_service_organizations_slug
    ON organization_service.organizations(slug);
CREATE INDEX IF NOT EXISTS ix_organization_service_organizations_status
    ON organization_service.organizations(status);
CREATE INDEX IF NOT EXISTS ix_organizations_plan
    ON organization_service.organizations(plan);

CREATE TABLE IF NOT EXISTS organization_service.members (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    user_id varchar(255),
    email varchar(255),
    status varchar(50) NOT NULL,
    invited_by varchar(255),
    invited_at timestamptz,
    joined_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_organization_service_members_organization_id
    ON organization_service.members(organization_id);
CREATE INDEX IF NOT EXISTS ix_organization_service_members_status
    ON organization_service.members(status);
CREATE UNIQUE INDEX IF NOT EXISTS ux_organization_members_user
    ON organization_service.members(organization_id, user_id)
    WHERE user_id IS NOT NULL AND user_id <> '';
CREATE INDEX IF NOT EXISTS ix_organization_members_email
    ON organization_service.members(organization_id, lower(email));

CREATE TABLE IF NOT EXISTS organization_service.api_keys (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    name varchar(255) NOT NULL,
    description text,
    key_prefix varchar(20) NOT NULL,
    key_hash varchar(64) NOT NULL UNIQUE,
    scopes text[] NOT NULL DEFAULT ARRAY[]::text[],
    scope_type varchar(50) NOT NULL DEFAULT 'ORGANIZATION',
    deployment_profile_id uuid,
    status varchar(50) NOT NULL DEFAULT 'active',
    enabled boolean NOT NULL DEFAULT true,
    rate_limit integer,
    created_by varchar(255) NOT NULL,
    last_used_at timestamptz,
    last_used_ip varchar(45),
    expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_organization_api_key_hash CHECK (key_hash ~ '^[0-9a-f]{64}$')
);

ALTER TABLE organization_service.api_keys
    ADD COLUMN IF NOT EXISTS scope_type varchar(50) NOT NULL DEFAULT 'ORGANIZATION',
    ADD COLUMN IF NOT EXISTS deployment_profile_id uuid,
    ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT clock_timestamp();

CREATE INDEX IF NOT EXISTS ix_organization_service_api_keys_organization_id
    ON organization_service.api_keys(organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_organization_service_api_keys_key_hash
    ON organization_service.api_keys(key_hash);
CREATE INDEX IF NOT EXISTS ix_organization_service_api_keys_status
    ON organization_service.api_keys(status);

CREATE TABLE IF NOT EXISTS organization_service.console_context_preferences (
    id uuid PRIMARY KEY,
    user_id varchar(255) NOT NULL UNIQUE,
    last_view_mode varchar(50) NOT NULL DEFAULT 'applicant',
    last_active_org_id uuid,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_service.join_codes (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    code varchar(8) NOT NULL UNIQUE,
    created_by varchar(255) NOT NULL,
    expires_at timestamptz,
    max_uses integer,
    use_count integer NOT NULL DEFAULT 0,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT ck_organization_join_code_length CHECK (char_length(code) = 8),
    CONSTRAINT ck_organization_join_code_use_count CHECK (use_count >= 0),
    CONSTRAINT ck_organization_join_code_max_uses CHECK (max_uses IS NULL OR max_uses >= 0)
);

CREATE INDEX IF NOT EXISTS ix_organization_service_join_codes_organization_id
    ON organization_service.join_codes(organization_id);

CREATE TABLE IF NOT EXISTS organization_service.permissions (
    id uuid PRIMARY KEY,
    resource varchar(100) NOT NULL,
    action varchar(100) NOT NULL,
    description text,
    CONSTRAINT uq_permissions_resource_action UNIQUE(resource, action)
);

CREATE INDEX IF NOT EXISTS ix_permissions_resource
    ON organization_service.permissions(resource);

CREATE TABLE IF NOT EXISTS organization_service.roles (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    name varchar(100) NOT NULL,
    display_name varchar(255),
    description text,
    is_system boolean NOT NULL DEFAULT false,
    is_default_for_new_members boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_roles_org_name UNIQUE(organization_id, name)
);

CREATE INDEX IF NOT EXISTS ix_roles_organization_id
    ON organization_service.roles(organization_id);

CREATE TABLE IF NOT EXISTS organization_service.role_permissions (
    role_id uuid NOT NULL REFERENCES organization_service.roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES organization_service.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS organization_service.member_roles (
    member_id uuid NOT NULL REFERENCES organization_service.members(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES organization_service.roles(id) ON DELETE CASCADE,
    PRIMARY KEY(member_id, role_id)
);

CREATE TABLE IF NOT EXISTS organization_service.policy_sets (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    name varchar(255) NOT NULL,
    description text,
    policy_type varchar(50) NOT NULL DEFAULT 'CUSTOM',
    status varchar(50) NOT NULL DEFAULT 'DRAFT',
    cedar_policies text NOT NULL,
    cedar_schema_version varchar(50) NOT NULL DEFAULT 'MIP/1.0',
    created_by varchar(255),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT uq_policy_sets_org_name UNIQUE(organization_id, name)
);

CREATE INDEX IF NOT EXISTS ix_policy_sets_organization_id
    ON organization_service.policy_sets(organization_id);
CREATE INDEX IF NOT EXISTS ix_policy_sets_status
    ON organization_service.policy_sets(status);

CREATE TABLE IF NOT EXISTS organization_service.audit_events (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organization_service.organizations(id) ON DELETE CASCADE,
    event_type varchar(120) NOT NULL,
    action varchar(120) NOT NULL,
    category varchar(100) NOT NULL DEFAULT 'settings',
    resource_type varchar(100) NOT NULL DEFAULT 'settings',
    resource_id varchar(255),
    resource_name varchar(255),
    actor_id varchar(255),
    actor_type varchar(50) NOT NULL DEFAULT 'system',
    severity varchar(50) NOT NULL DEFAULT 'info',
    message text NOT NULL DEFAULT '',
    changes jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_events_org_created_at
    ON organization_service.audit_events(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_events_org_category
    ON organization_service.audit_events(organization_id, category);
CREATE INDEX IF NOT EXISTS ix_audit_events_org_resource
    ON organization_service.audit_events(organization_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_org_actor
    ON organization_service.audit_events(organization_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_audit_events_org_severity
    ON organization_service.audit_events(organization_id, severity);

CREATE TABLE IF NOT EXISTS organization_service.rust_schema_versions (
    version varchar(64) PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO organization_service.rust_schema_versions(version)
VALUES ('rust_organization_0001')
ON CONFLICT (version) DO NOTHING;
