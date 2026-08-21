CREATE SCHEMA IF NOT EXISTS credential_template_service;

CREATE TABLE IF NOT EXISTS credential_template_service.credential_templates (
    id varchar(36) PRIMARY KEY,
    organization_id varchar(36) NOT NULL,
    name varchar(255) NOT NULL,
    description text,
    status varchar(20) NOT NULL DEFAULT 'draft',
    credential_type varchar(255) NOT NULL,
    vct text NOT NULL,
    doctype text,
    claims jsonb NOT NULL DEFAULT '[]'::jsonb,
    privacy_posture varchar(30) NOT NULL DEFAULT 'selective_disclosure',
    selective_disclosure_fields jsonb NOT NULL DEFAULT '[]'::jsonb,
    zk_predicate_claims jsonb NOT NULL DEFAULT '[]'::jsonb,
    derived_attributes jsonb NOT NULL DEFAULT '[]'::jsonb,
    display_style jsonb NOT NULL DEFAULT '{}'::jsonb,
    validity_rules jsonb NOT NULL DEFAULT '{}'::jsonb,
    issuer_requirements jsonb NOT NULL DEFAULT '{}'::jsonb,
    supported_formats jsonb NOT NULL DEFAULT '[]'::jsonb,
    credential_payload_format varchar(30) NOT NULL DEFAULT 'w3c_vcdm_v2_sd_jwt',
    wallet_configs jsonb NOT NULL DEFAULT '[]'::jsonb,
    compliance_profile jsonb,
    compliance_profile_id varchar(36),
    application_template_id varchar(36),
    trust_profile_id varchar(36),
    revocation_profile_id varchar(36),
    issuer_algorithm varchar(20),
    issuer_did text,
    issuance_protocol varchar(64) NOT NULL DEFAULT 'oid4vci',
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

ALTER TABLE credential_template_service.credential_templates
    ADD COLUMN IF NOT EXISTS zk_predicate_claims jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS credential_payload_format varchar(30) NOT NULL DEFAULT 'w3c_vcdm_v2_sd_jwt',
    ADD COLUMN IF NOT EXISTS wallet_configs jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS compliance_profile jsonb,
    ADD COLUMN IF NOT EXISTS compliance_profile_id varchar(36),
    ADD COLUMN IF NOT EXISTS application_template_id varchar(36),
    ADD COLUMN IF NOT EXISTS trust_profile_id varchar(36),
    ADD COLUMN IF NOT EXISTS revocation_profile_id varchar(36),
    ADD COLUMN IF NOT EXISTS issuer_algorithm varchar(20),
    ADD COLUMN IF NOT EXISTS issuer_did text,
    ADD COLUMN IF NOT EXISTS issuance_protocol varchar(64) NOT NULL DEFAULT 'oid4vci';

-- Cached custody routing was retired before the Rust cutover.  A database that
-- arrives from any older Python head must converge on the same live-DID-only
-- model as a fresh Rust database.
ALTER TABLE credential_template_service.credential_templates
    DROP COLUMN IF EXISTS auto_generate_artifacts,
    DROP COLUMN IF EXISTS issuer_certificate_chain_pem,
    DROP COLUMN IF EXISTS remote_signing_config,
    DROP COLUMN IF EXISTS issuer_key_id,
    DROP COLUMN IF EXISTS key_access_mode,
    DROP COLUMN IF EXISTS issuer_profile_id;

CREATE INDEX IF NOT EXISTS ix_credential_template_service_credential_templates_organization_id
    ON credential_template_service.credential_templates(organization_id);
CREATE INDEX IF NOT EXISTS ix_credential_template_service_credential_templates_status
    ON credential_template_service.credential_templates(status);
CREATE INDEX IF NOT EXISTS ix_credential_templates_credential_type
    ON credential_template_service.credential_templates(credential_type);
CREATE INDEX IF NOT EXISTS ix_credential_templates_org_status
    ON credential_template_service.credential_templates(organization_id, status);

CREATE TABLE IF NOT EXISTS credential_template_service.wallet_registry (
    id varchar(64) PRIMARY KEY,
    organization_id varchar(64),
    is_override boolean NOT NULL DEFAULT false,
    override_precedence integer NOT NULL DEFAULT 50,
    merge_strategy varchar(16) NOT NULL DEFAULT 'APPEND',
    credential_format varchar(64),
    issuance_protocol varchar(64),
    compliance_profile_code varchar(128),
    name varchar(255) NOT NULL,
    description text,
    wallet_apps jsonb NOT NULL DEFAULT '[]'::jsonb,
    specifications jsonb NOT NULL DEFAULT '[]'::jsonb,
    logo_url text,
    deep_link_template text NOT NULL DEFAULT 'openid-credential-offer://?credential_offer_uri={offer_uri}',
    routing_templates jsonb NOT NULL DEFAULT '{}'::jsonb,
    install_urls jsonb NOT NULL DEFAULT '{}'::jsonb,
    ios_scheme varchar(128),
    universal_link_template text,
    android_package varchar(255),
    supported_formats jsonb NOT NULL DEFAULT '[]'::jsonb,
    supported_protocols jsonb NOT NULL DEFAULT '["OID4VCI_PRE_AUTH"]'::jsonb,
    platforms jsonb NOT NULL DEFAULT '[]'::jsonb,
    supports_qr boolean NOT NULL DEFAULT true,
    supports_deeplink boolean NOT NULL DEFAULT true,
    supports_digital_credentials boolean NOT NULL DEFAULT false,
    supports_haip boolean NOT NULL DEFAULT false,
    docs_url text,
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

ALTER TABLE credential_template_service.wallet_registry
    ADD COLUMN IF NOT EXISTS organization_id varchar(64),
    ADD COLUMN IF NOT EXISTS is_override boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS override_precedence integer NOT NULL DEFAULT 50,
    ADD COLUMN IF NOT EXISTS merge_strategy varchar(16) NOT NULL DEFAULT 'APPEND',
    ADD COLUMN IF NOT EXISTS credential_format varchar(64),
    ADD COLUMN IF NOT EXISTS issuance_protocol varchar(64),
    ADD COLUMN IF NOT EXISTS compliance_profile_code varchar(128),
    ADD COLUMN IF NOT EXISTS description text,
    ADD COLUMN IF NOT EXISTS wallet_apps jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS specifications jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS routing_templates jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS install_urls jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS ios_scheme varchar(128),
    ADD COLUMN IF NOT EXISTS universal_link_template text,
    ADD COLUMN IF NOT EXISTS android_package varchar(255),
    ADD COLUMN IF NOT EXISTS supports_digital_credentials boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS supports_haip boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS ix_wallet_registry_organization_id
    ON credential_template_service.wallet_registry(organization_id);
CREATE INDEX IF NOT EXISTS ix_wallet_registry_credential_format
    ON credential_template_service.wallet_registry(credential_format);
CREATE INDEX IF NOT EXISTS ix_wallet_registry_issuance_protocol
    ON credential_template_service.wallet_registry(issuance_protocol);
CREATE INDEX IF NOT EXISTS ix_wallet_registry_compliance_profile_code
    ON credential_template_service.wallet_registry(compliance_profile_code);

CREATE TABLE IF NOT EXISTS credential_template_service.delivery_destinations (
    id varchar(128) PRIMARY KEY,
    organization_id varchar(64),
    is_system boolean NOT NULL DEFAULT false,
    name varchar(255) NOT NULL,
    description text,
    provider varchar(64) NOT NULL,
    mode varchar(40) NOT NULL,
    setup_actor varchar(40) NOT NULL,
    delivery_target varchar(64) NOT NULL,
    wallet_profile_id varchar(128),
    credential_format varchar(64),
    issuance_protocol varchar(64),
    compliance_profile_code varchar(128),
    connector_type varchar(64),
    connector_id varchar(128),
    requires_consent boolean NOT NULL DEFAULT false,
    claim_projection_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    setup_requirements jsonb NOT NULL DEFAULT '[]'::jsonb,
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
    docs_url text,
    is_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_delivery_destinations_organization_id
    ON credential_template_service.delivery_destinations(organization_id);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_provider
    ON credential_template_service.delivery_destinations(provider);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_mode
    ON credential_template_service.delivery_destinations(mode);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_delivery_target
    ON credential_template_service.delivery_destinations(delivery_target);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_credential_format
    ON credential_template_service.delivery_destinations(credential_format);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_issuance_protocol
    ON credential_template_service.delivery_destinations(issuance_protocol);
CREATE INDEX IF NOT EXISTS ix_delivery_destinations_compliance_profile_code
    ON credential_template_service.delivery_destinations(compliance_profile_code);

CREATE TABLE IF NOT EXISTS credential_template_service.rust_schema_versions (
    version varchar(64) PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO credential_template_service.rust_schema_versions(version)
VALUES ('rust_credential_template_0001')
ON CONFLICT (version) DO NOTHING;
