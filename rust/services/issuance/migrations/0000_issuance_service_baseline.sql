-- Rust-only fresh issuance schema baseline.
-- Source: marty-credentials v0.1.78 OCI sha256:e7bb482120837c68af6cec2f6d1d5276488de440b93fc811987860b7b99b4657
-- Official Alembic head: issuance_event_owner. Migrations are unchanged through v0.1.79.
-- Source pg_dump SHA-256: f76acaebbc74cd7ea8c232d347c9a878ebe4967f284177e9681e0a19256552cd
-- Excludes only the Alembic version ledger; data seeds are handled separately.

--
-- PostgreSQL database dump
--


-- Dumped from database version 15.19 (Debian 15.19-1.pgdg13+2)
-- Dumped by pg_dump version 15.19 (Debian 15.19-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: issuance_service; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA IF NOT EXISTS issuance_service;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alembic_version; Type: TABLE; Schema: issuance_service; Owner: -
--



--
-- Name: application_templates; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.application_templates (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    name character varying NOT NULL,
    description character varying,
    credential_template_id character varying NOT NULL,
    form_fields json NOT NULL,
    evidence_requirements json NOT NULL,
    claim_collection_rules json NOT NULL,
    approval_strategy character varying NOT NULL,
    application_validity_days integer NOT NULL,
    ui_config json NOT NULL,
    notification_config json NOT NULL,
    status character varying DEFAULT 'DRAFT'::character varying NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    required_checks json DEFAULT '[]'::json NOT NULL,
    approval_policy_set_id character varying(36),
    management_version bigint DEFAULT 1 NOT NULL,
    idempotency_key_hash character varying(64),
    idempotency_request_hash character varying(64),
    CONSTRAINT ck_application_templates_idempotency_key_hash CHECK (((idempotency_key_hash IS NULL) OR ((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT ck_application_templates_idempotency_pair CHECK ((((idempotency_key_hash IS NULL) AND (idempotency_request_hash IS NULL)) OR ((idempotency_key_hash IS NOT NULL) AND (idempotency_request_hash IS NOT NULL)))),
    CONSTRAINT ck_application_templates_idempotency_request_hash CHECK (((idempotency_request_hash IS NULL) OR ((idempotency_request_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT ck_application_templates_management_version CHECK ((management_version > 0))
);


--
-- Name: applications; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.applications (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    application_template_id character varying NOT NULL,
    applicant_identifier character varying NOT NULL,
    form_data json NOT NULL,
    submitted_evidence json NOT NULL,
    status character varying NOT NULL,
    review_notes character varying,
    rejection_reason character varying,
    derived_claims json NOT NULL,
    credential_id character varying,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    reviewer_id character varying,
    issuance_transaction_id character varying,
    submitted_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    reviewed_at timestamp with time zone,
    expires_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP + '30 days'::interval) NOT NULL,
    integration_context json DEFAULT '{}'::json NOT NULL
);


--
-- Name: authorization_sessions; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.authorization_sessions (
    id character varying NOT NULL,
    code character varying NOT NULL,
    client_id character varying NOT NULL,
    redirect_uri character varying,
    scope character varying,
    state character varying,
    issuer_state character varying,
    credential_configuration_ids json DEFAULT '[]'::json NOT NULL,
    organization_id character varying,
    code_challenge character varying,
    code_challenge_method character varying,
    access_token character varying,
    c_nonce character varying,
    status character varying DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '00:10:00'::interval) NOT NULL,
    dpop_jkt character varying
);


--
-- Name: canvas_award_candidates; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_award_candidates (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    platform_id character varying NOT NULL,
    binding_id character varying NOT NULL,
    learner_identity_id character varying,
    candidate_key character varying NOT NULL,
    canvas_user_id character varying,
    lti_subject character varying,
    state character varying(40) DEFAULT 'observed'::character varying NOT NULL,
    application_id character varying,
    claimed_credential_id character varying,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_award_candidates_key CHECK ((btrim((candidate_key)::text) <> ''::text)),
    CONSTRAINT ck_canvas_award_candidates_state CHECK (((state)::text = ANY ((ARRAY['observed'::character varying, 'identity_link_required'::character varying, 'eligible'::character varying, 'pending_claim'::character varying, 'claimed'::character varying, 'dismissed'::character varying])::text[])))
);


--
-- Name: canvas_candidate_observations; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_candidate_observations (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    candidate_id character varying NOT NULL,
    requirement_id character varying NOT NULL,
    logical_key character varying(64) NOT NULL,
    assertion json DEFAULT '{}'::json NOT NULL,
    verification json DEFAULT '{}'::json NOT NULL,
    payload_hash character varying(64) NOT NULL,
    superseded_observation_id character varying,
    is_current boolean DEFAULT true NOT NULL,
    observed_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_candidate_observations_revision CHECK (((btrim((requirement_id)::text) <> ''::text) AND (btrim((logical_key)::text) <> ''::text) AND (btrim((payload_hash)::text) <> ''::text)))
);


--
-- Name: canvas_event_receipts; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_event_receipts (
    id character varying(36) NOT NULL,
    provider_event_id character varying(255) NOT NULL,
    organization_id character varying(36) NOT NULL,
    credential_template_id character varying(36) NOT NULL,
    canvas_account_id character varying(255),
    payload_hash character varying(64) NOT NULL,
    issuance_transaction_id character varying(36),
    issuance_response json DEFAULT '{}'::json NOT NULL,
    status character varying(50) DEFAULT 'processed'::character varying NOT NULL,
    error_summary text,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: canvas_evidence_sync_jobs; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_evidence_sync_jobs (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    target_id character varying NOT NULL,
    status character varying(32) DEFAULT 'queued'::character varying NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 8 NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_owner character varying,
    lease_expires_at timestamp with time zone,
    last_error_code character varying(120),
    last_error_summary text,
    result json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT ck_canvas_sync_jobs_attempts CHECK (((max_attempts >= 1) AND (attempt_count >= 0) AND (attempt_count <= max_attempts))),
    CONSTRAINT ck_canvas_sync_jobs_lease CHECK (((((status)::text = 'leased'::text) AND (lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL)) OR (((status)::text <> 'leased'::text) AND (lease_owner IS NULL) AND (lease_expires_at IS NULL)))),
    CONSTRAINT ck_canvas_sync_jobs_status CHECK (((status)::text = ANY ((ARRAY['queued'::character varying, 'leased'::character varying, 'retry'::character varying, 'succeeded'::character varying, 'dead_letter'::character varying, 'cancelled'::character varying])::text[])))
);


--
-- Name: canvas_evidence_sync_targets; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_evidence_sync_targets (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    platform_id character varying NOT NULL,
    binding_id character varying NOT NULL,
    target_type character varying(40) NOT NULL,
    logical_key character varying NOT NULL,
    application_id character varying,
    candidate_id character varying,
    enabled boolean DEFAULT true NOT NULL,
    schedule_seconds integer DEFAULT 900 NOT NULL,
    next_run_at timestamp with time zone DEFAULT now() NOT NULL,
    last_enqueued_at timestamp with time zone,
    last_succeeded_at timestamp with time zone,
    config_version integer DEFAULT 1 NOT NULL,
    metadata json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_sync_targets_config_version CHECK ((config_version >= 1)),
    CONSTRAINT ck_canvas_sync_targets_logical_key CHECK ((btrim((logical_key)::text) <> ''::text)),
    CONSTRAINT ck_canvas_sync_targets_schedule CHECK ((schedule_seconds >= 60)),
    CONSTRAINT ck_canvas_sync_targets_type CHECK (((target_type)::text = ANY ((ARRAY['learner_application'::character varying, 'background_roster'::character varying, 'award_candidate'::character varying, 'issued_drift'::character varying])::text[])))
);


--
-- Name: canvas_learner_identities; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_learner_identities (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    platform_id character varying NOT NULL,
    deployment_id character varying NOT NULL,
    lti_subject character varying NOT NULL,
    canvas_user_id character varying,
    sis_user_id character varying,
    status character varying(32) DEFAULT 'linked'::character varying NOT NULL,
    conflict_reason text,
    verified_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_learner_identities_status CHECK (((status)::text = ANY ((ARRAY['subject_verified'::character varying, 'linked'::character varying, 'quarantined'::character varying])::text[]))),
    CONSTRAINT ck_canvas_learner_identities_subject CHECK (((btrim((deployment_id)::text) <> ''::text) AND (btrim((lti_subject)::text) <> ''::text)))
);


--
-- Name: canvas_lti_launch_states; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_lti_launch_states (
    id character varying(36) NOT NULL,
    platform_id character varying(36) NOT NULL,
    organization_id character varying(36) NOT NULL,
    canvas_account_id character varying(255) NOT NULL,
    state character varying(255) NOT NULL,
    nonce character varying(255) NOT NULL,
    login_hint text,
    target_link_uri text,
    lti_message_hint text,
    redirect_uri text,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    metadata json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone
);


--
-- Name: canvas_oauth_authorizations; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_oauth_authorizations (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    platform_id character varying NOT NULL,
    canvas_base_url text NOT NULL,
    platform_config_version integer NOT NULL,
    client_id text NOT NULL,
    client_secret_ref text NOT NULL,
    state_hash character varying(64) NOT NULL,
    capabilities json DEFAULT '[]'::json NOT NULL,
    scopes json DEFAULT '[]'::json NOT NULL,
    redirect_uri text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_oauth_authorizations_platform_snapshot CHECK (((platform_config_version >= 1) AND ("left"(lower(canvas_base_url), 8) = 'https://'::text))),
    CONSTRAINT ck_canvas_oauth_authorizations_state_hash CHECK ((length((state_hash)::text) = 64)),
    CONSTRAINT ck_canvas_oauth_authorizations_tenant_secret_ref CHECK (("left"(client_secret_ref, length((('org_secret://'::text || (organization_id)::text) || '/'::text))) = (('org_secret://'::text || (organization_id)::text) || '/'::text)))
);


--
-- Name: canvas_oauth_connections; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_oauth_connections (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    platform_id character varying NOT NULL,
    canvas_base_url text NOT NULL,
    platform_config_version integer NOT NULL,
    client_id text NOT NULL,
    client_secret_ref text NOT NULL,
    capabilities json DEFAULT '[]'::json NOT NULL,
    scopes json DEFAULT '[]'::json NOT NULL,
    access_token_secret_ref text,
    refresh_token_secret_ref text,
    token_expires_at timestamp with time zone,
    status character varying(40) DEFAULT 'connected'::character varying NOT NULL,
    reauthorization_required boolean DEFAULT false NOT NULL,
    refresh_lease_owner character varying,
    refresh_lease_expires_at timestamp with time zone,
    revoke_retry_count integer DEFAULT 0 NOT NULL,
    revoke_retry_at timestamp with time zone,
    revoke_last_error_code character varying(120),
    connected_at timestamp with time zone DEFAULT now() NOT NULL,
    last_refreshed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_canvas_oauth_connections_platform_snapshot CHECK (((platform_config_version >= 1) AND ("left"(lower(canvas_base_url), 8) = 'https://'::text))),
    CONSTRAINT ck_canvas_oauth_connections_refresh_lease CHECK ((((refresh_lease_owner IS NULL) AND (refresh_lease_expires_at IS NULL)) OR ((refresh_lease_owner IS NOT NULL) AND (refresh_lease_expires_at IS NOT NULL)))),
    CONSTRAINT ck_canvas_oauth_connections_revoke_retry_count CHECK ((revoke_retry_count >= 0)),
    CONSTRAINT ck_canvas_oauth_connections_status CHECK (((status)::text = ANY ((ARRAY['connected'::character varying, 'reauthorization_required'::character varying, 'revocation_pending'::character varying, 'disconnected'::character varying])::text[]))),
    CONSTRAINT ck_canvas_oauth_connections_tenant_secret_refs CHECK ((("left"(client_secret_ref, length((('org_secret://'::text || (organization_id)::text) || '/'::text))) = (('org_secret://'::text || (organization_id)::text) || '/'::text)) AND ((access_token_secret_ref IS NULL) OR ("left"(access_token_secret_ref, length((('org_secret://'::text || (organization_id)::text) || '/'::text))) = (('org_secret://'::text || (organization_id)::text) || '/'::text))) AND ((refresh_token_secret_ref IS NULL) OR ("left"(refresh_token_secret_ref, length((('org_secret://'::text || (organization_id)::text) || '/'::text))) = (('org_secret://'::text || (organization_id)::text) || '/'::text)))))
);


--
-- Name: canvas_platform_state_backups; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_platform_state_backups (
    platform_id character varying NOT NULL,
    organization_id character varying NOT NULL,
    enabled boolean NOT NULL,
    backed_up_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: canvas_platforms; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_platforms (
    id character varying(36) NOT NULL,
    organization_id character varying(36) NOT NULL,
    canvas_account_id character varying(255) NOT NULL,
    display_name character varying(255),
    canvas_base_url text,
    lti_client_id text,
    lti_deployment_id text,
    lti_issuer text,
    lti_jwks_url text,
    lti_jwks_json json,
    lti_jwks_fetched_at timestamp with time zone,
    lti_jwks_expires_at timestamp with time zone,
    lti_openid_configuration json,
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    lti_trust_profile character varying(40) DEFAULT 'hosted_global'::character varying NOT NULL,
    registration_status character varying(40) DEFAULT 'draft'::character varying NOT NULL,
    connection_config json DEFAULT '{}'::json NOT NULL,
    capability_snapshot json DEFAULT '{}'::json NOT NULL,
    last_validated_at timestamp with time zone,
    last_connection_error text,
    config_version integer DEFAULT 1 NOT NULL,
    archived_at timestamp with time zone,
    CONSTRAINT ck_canvas_platforms_archival_state CHECK (((archived_at IS NULL) OR (enabled = false))),
    CONSTRAINT ck_canvas_platforms_config_version CHECK ((config_version >= 1)),
    CONSTRAINT ck_canvas_platforms_lti_trust_profile CHECK (((lti_trust_profile)::text = ANY ((ARRAY['hosted_global'::character varying, 'self_managed_same_origin'::character varying])::text[]))),
    CONSTRAINT ck_canvas_platforms_registration_status CHECK (((registration_status)::text = ANY ((ARRAY['draft'::character varying, 'verified'::character varying, 'installed'::character varying, 'active'::character varying, 'archived'::character varying])::text[])))
);


--
-- Name: canvas_program_binding_requirement_backups; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_program_binding_requirement_backups (
    binding_id character varying NOT NULL,
    organization_id character varying NOT NULL,
    evidence_requirements json NOT NULL,
    enabled boolean NOT NULL,
    direct_issue_enabled boolean NOT NULL,
    auto_approve_on_evidence boolean NOT NULL,
    backed_up_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: canvas_program_bindings; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_program_bindings (
    id character varying(36) NOT NULL,
    organization_id character varying(36) NOT NULL,
    platform_id character varying(36) NOT NULL,
    application_template_id character varying(36) NOT NULL,
    credential_template_id character varying(36) NOT NULL,
    display_name character varying(255),
    flow_mode character varying(80) DEFAULT 'elevenid_orchestrated_canvas_evidence'::character varying NOT NULL,
    direct_issue_enabled boolean DEFAULT false NOT NULL,
    auto_approve_on_evidence boolean DEFAULT false NOT NULL,
    evidence_requirements json DEFAULT '[]'::json NOT NULL,
    canvas_scope json DEFAULT '{}'::json NOT NULL,
    delivery_mode character varying(40) DEFAULT 'wallet_only'::character varying NOT NULL,
    issuer_mode character varying(40) DEFAULT 'org_managed'::character varying NOT NULL,
    approval_policy_set_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deployment_profile_id text,
    feature_flags json DEFAULT '{}'::json NOT NULL,
    canvas_credentials json DEFAULT '{}'::json NOT NULL,
    config_version integer DEFAULT 1 NOT NULL,
    validated_config_version integer,
    readiness_checks json DEFAULT '[]'::json NOT NULL,
    readiness_validated_at timestamp with time zone,
    activated_at timestamp with time zone,
    archived_at timestamp with time zone,
    credential_template_snapshot json DEFAULT '{}'::json NOT NULL,
    CONSTRAINT ck_canvas_program_bindings_activation_state CHECK (((enabled = false) OR ((activated_at IS NOT NULL) AND (validated_config_version = config_version)))),
    CONSTRAINT ck_canvas_program_bindings_archival_state CHECK (((archived_at IS NULL) OR (enabled = false))),
    CONSTRAINT ck_canvas_program_bindings_config_versions CHECK (((config_version >= 1) AND ((validated_config_version IS NULL) OR ((validated_config_version >= 1) AND (validated_config_version <= config_version)))))
);


--
-- Name: canvas_worker_heartbeats; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.canvas_worker_heartbeats (
    worker_id character varying NOT NULL,
    role character varying(80) DEFAULT 'canvas_sync'::character varying NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    last_heartbeat_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata json DEFAULT '{}'::json NOT NULL
);


--
-- Name: credential_delivery_records; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.credential_delivery_records (
    id character varying NOT NULL,
    credential_id character varying NOT NULL,
    transaction_id character varying NOT NULL,
    organization_id character varying NOT NULL,
    delivery_target character varying(40) NOT NULL,
    delivery_mode character varying(40) DEFAULT 'wallet_only'::character varying NOT NULL,
    status character varying(40) DEFAULT 'pending'::character varying NOT NULL,
    canvas_account_id character varying(255),
    external_credential_id character varying(255),
    external_issuer_id character varying(255),
    last_error text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: evidence_fact_heads; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.evidence_fact_heads (
    organization_id character varying NOT NULL,
    application_id character varying NOT NULL,
    logical_key character varying(64) NOT NULL,
    fact_id character varying NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_evidence_fact_heads_logical_key CHECK ((btrim((logical_key)::text) <> ''::text))
);


--
-- Name: evidence_facts; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.evidence_facts (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    application_id character varying NOT NULL,
    subject_id character varying NOT NULL,
    provider character varying(80) NOT NULL,
    fact_type character varying(160) NOT NULL,
    scope jsonb DEFAULT '{}'::jsonb NOT NULL,
    assertion jsonb DEFAULT '{}'::jsonb NOT NULL,
    verification jsonb DEFAULT '{}'::jsonb NOT NULL,
    source jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    requirement_id character varying,
    logical_key character varying(64) DEFAULT ''::character varying NOT NULL,
    source_revision character varying DEFAULT ''::character varying NOT NULL,
    payload_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    effective_at timestamp with time zone NOT NULL,
    superseded_fact_id character varying,
    CONSTRAINT ck_evidence_facts_revision_metadata CHECK ((((logical_key)::text <> ''::text) AND ((source_revision)::text <> ''::text) AND ((payload_hash)::text <> ''::text)))
);


--
-- Name: evidence_policy_reviews; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.evidence_policy_reviews (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    application_id character varying NOT NULL,
    credential_id character varying NOT NULL,
    binding_id character varying,
    status character varying(32) DEFAULT 'open'::character varying NOT NULL,
    prior_decision json DEFAULT '{}'::json NOT NULL,
    current_decision json DEFAULT '{}'::json NOT NULL,
    triggering_fact_id character varying,
    resolution_action character varying(32),
    resolution_notes text,
    resolved_by character varying,
    resolved_at timestamp with time zone,
    resolution_claim_token character varying(128),
    resolution_claim_action character varying(32),
    resolution_claimed_at timestamp with time zone,
    resolution_recovery_pending boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_evidence_policy_reviews_resolution_claim CHECK ((((resolution_claim_token IS NULL) AND (resolution_claim_action IS NULL) AND (resolution_claimed_at IS NULL)) OR (((status)::text = 'open'::text) AND (resolution_claim_token IS NOT NULL) AND ((resolution_claim_action)::text = ANY ((ARRAY['dismiss'::character varying, 'suspend'::character varying, 'revoke'::character varying, 'evidence_recovered'::character varying])::text[])) AND (resolution_claimed_at IS NOT NULL)))),
    CONSTRAINT ck_evidence_policy_reviews_status CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'dismissed'::character varying, 'suspended'::character varying, 'revoked'::character varying, 'resolved'::character varying])::text[])))
);


--
-- Name: issuance_events; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.issuance_events (
    id character varying NOT NULL,
    transaction_id character varying,
    application_id character varying,
    event_type character varying(50) NOT NULL,
    metadata json DEFAULT '{}'::json NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id character varying
);


--
-- Name: issuance_transactions; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.issuance_transactions (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    credential_template_id character varying NOT NULL,
    applicant_id character varying,
    subject_did character varying,
    status character varying NOT NULL,
    pre_auth_code character varying NOT NULL,
    access_token character varying,
    c_nonce character varying,
    claims json NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    issued_at timestamp with time zone,
    application_id character varying,
    credential_type character varying,
    zk_predicate_claims json,
    credential_payload_format character varying(30) DEFAULT 'w3c_vcdm_v2_sd_jwt'::character varying NOT NULL,
    wallet_configs json DEFAULT '[]'::json,
    revoked_at timestamp with time zone,
    revocation_reason character varying,
    selective_disclosure_claims json DEFAULT '[]'::json,
    issuer_did_override character varying,
    signing_service_id character varying,
    issuer_profile_id character varying(80),
    issuer_mode character varying(40) DEFAULT 'org_managed'::character varying NOT NULL,
    delivery_mode character varying(40) DEFAULT 'wallet_only'::character varying NOT NULL,
    revocation_profile_id character varying,
    renewal_of_credential_id character varying,
    validity_days integer DEFAULT 365 NOT NULL,
    renewable boolean DEFAULT false NOT NULL,
    renewal_window_days integer DEFAULT 30 NOT NULL,
    reserved_credential_id character varying,
    oid4vci_client_id character varying(512),
    issuer_algorithm character varying(20),
    idempotency_key_hash character varying(64),
    idempotency_request_hash character varying(64),
    CONSTRAINT ck_issuance_transactions_idempotency_key_hash CHECK (((idempotency_key_hash IS NULL) OR ((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT ck_issuance_transactions_idempotency_pair CHECK ((((idempotency_key_hash IS NULL) AND (idempotency_request_hash IS NULL)) OR ((idempotency_key_hash IS NOT NULL) AND (idempotency_request_hash IS NOT NULL)))),
    CONSTRAINT ck_issuance_transactions_idempotency_request_hash CHECK (((idempotency_request_hash IS NULL) OR ((idempotency_request_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT ck_issuance_transactions_issuer_algorithm CHECK (((issuer_algorithm IS NULL) OR ((issuer_algorithm)::text = ANY ((ARRAY['ES256'::character varying, 'ES384'::character varying, 'RS256'::character varying, 'EdDSA'::character varying])::text[]))))
);


--
-- Name: issued_credentials; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.issued_credentials (
    id character varying NOT NULL,
    transaction_id character varying NOT NULL,
    organization_id character varying NOT NULL,
    credential_template_id character varying NOT NULL,
    applicant_id character varying,
    subject_did character varying,
    credential_jwt character varying NOT NULL,
    credential_hash character varying NOT NULL,
    status character varying NOT NULL,
    status_updated_at timestamp with time zone NOT NULL,
    revoked boolean NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason character varying,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    issuer_did character varying,
    revocation_profile_id character varying(36),
    status_list_entries json DEFAULT '[]'::json NOT NULL,
    renewed_from_credential_id character varying,
    renewed_to_credential_id character varying
);


--
-- Name: oid4vci_client_assertions; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.oid4vci_client_assertions (
    organization_id character varying NOT NULL,
    client_id character varying(512) NOT NULL,
    jti character varying(256) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL
);


--
-- Name: oid4vci_ephemeral_capabilities; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.oid4vci_ephemeral_capabilities (
    purpose character varying(32) NOT NULL,
    key_digest character varying(64) NOT NULL,
    payload json,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT ck_oid4vci_ephemeral_capabilities_payload CHECK (((((purpose)::text = 'par'::text) AND (payload IS NOT NULL)) OR (((purpose)::text = 'proof_nonce'::text) AND (payload IS NULL)))),
    CONSTRAINT ck_oid4vci_ephemeral_capabilities_purpose CHECK (((purpose)::text = ANY ((ARRAY['par'::character varying, 'proof_nonce'::character varying])::text[])))
);


--
-- Name: oid4vci_registered_clients; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.oid4vci_registered_clients (
    organization_id character varying NOT NULL,
    client_id character varying(512) NOT NULL,
    jwks json NOT NULL,
    redirect_uris json NOT NULL,
    token_endpoint_auth_method character varying(40) DEFAULT 'private_key_jwt'::character varying NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


--
-- Name: organization_integration_secrets; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.organization_integration_secrets (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    name character varying(255) NOT NULL,
    provider character varying(80) NOT NULL,
    purpose character varying(80) DEFAULT 'api_token'::character varying NOT NULL,
    encrypted_secret_value text NOT NULL,
    secret_hint character varying(80),
    metadata json DEFAULT '{}'::json NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: physical_document_jobs; Type: TABLE; Schema: issuance_service; Owner: -
--

CREATE TABLE issuance_service.physical_document_jobs (
    id character varying NOT NULL,
    organization_id character varying NOT NULL,
    flow_execution_id character varying NOT NULL,
    application_id character varying NOT NULL,
    application_template_id character varying NOT NULL,
    credential_template_id character varying NOT NULL,
    delivery_destination_profile_id character varying(128) NOT NULL,
    document_type character varying(3) NOT NULL,
    country_code character varying(3) NOT NULL,
    secure_artifact_ciphertext text NOT NULL,
    secure_artifact_reference character varying(512) NOT NULL,
    sod_sha256 character varying(64),
    bureau_job_id character varying(255),
    tracking_number character varying(255),
    status character varying(40) DEFAULT 'DRAFT'::character varying NOT NULL,
    quality_result json,
    error_code character varying(128),
    error_message character varying(1024),
    submitted_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    revocation_profile_id character varying
);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--



--
-- Name: application_templates application_templates_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.application_templates
    ADD CONSTRAINT application_templates_pkey PRIMARY KEY (id);


--
-- Name: applications applications_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.applications
    ADD CONSTRAINT applications_pkey PRIMARY KEY (id);


--
-- Name: authorization_sessions authorization_sessions_code_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.authorization_sessions
    ADD CONSTRAINT authorization_sessions_code_key UNIQUE (code);


--
-- Name: authorization_sessions authorization_sessions_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.authorization_sessions
    ADD CONSTRAINT authorization_sessions_pkey PRIMARY KEY (id);


--
-- Name: canvas_award_candidates canvas_award_candidates_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_pkey PRIMARY KEY (id);


--
-- Name: canvas_candidate_observations canvas_candidate_observations_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_candidate_observations
    ADD CONSTRAINT canvas_candidate_observations_pkey PRIMARY KEY (id);


--
-- Name: canvas_event_receipts canvas_event_receipts_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_event_receipts
    ADD CONSTRAINT canvas_event_receipts_pkey PRIMARY KEY (id);


--
-- Name: canvas_evidence_sync_jobs canvas_evidence_sync_jobs_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_jobs
    ADD CONSTRAINT canvas_evidence_sync_jobs_pkey PRIMARY KEY (id);


--
-- Name: canvas_evidence_sync_targets canvas_evidence_sync_targets_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT canvas_evidence_sync_targets_pkey PRIMARY KEY (id);


--
-- Name: canvas_learner_identities canvas_learner_identities_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_learner_identities
    ADD CONSTRAINT canvas_learner_identities_pkey PRIMARY KEY (id);


--
-- Name: canvas_lti_launch_states canvas_lti_launch_states_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_lti_launch_states
    ADD CONSTRAINT canvas_lti_launch_states_pkey PRIMARY KEY (id);


--
-- Name: canvas_lti_launch_states canvas_lti_launch_states_state_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_lti_launch_states
    ADD CONSTRAINT canvas_lti_launch_states_state_key UNIQUE (state);


--
-- Name: canvas_oauth_authorizations canvas_oauth_authorizations_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_authorizations
    ADD CONSTRAINT canvas_oauth_authorizations_pkey PRIMARY KEY (id);


--
-- Name: canvas_oauth_authorizations canvas_oauth_authorizations_state_hash_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_authorizations
    ADD CONSTRAINT canvas_oauth_authorizations_state_hash_key UNIQUE (state_hash);


--
-- Name: canvas_oauth_connections canvas_oauth_connections_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_connections
    ADD CONSTRAINT canvas_oauth_connections_pkey PRIMARY KEY (id);


--
-- Name: canvas_platform_state_backups canvas_platform_state_backups_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_platform_state_backups
    ADD CONSTRAINT canvas_platform_state_backups_pkey PRIMARY KEY (platform_id);


--
-- Name: canvas_platforms canvas_platforms_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_platforms
    ADD CONSTRAINT canvas_platforms_pkey PRIMARY KEY (id);


--
-- Name: canvas_program_binding_requirement_backups canvas_program_binding_requirement_backups_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_program_binding_requirement_backups
    ADD CONSTRAINT canvas_program_binding_requirement_backups_pkey PRIMARY KEY (binding_id);


--
-- Name: canvas_program_bindings canvas_program_bindings_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_program_bindings
    ADD CONSTRAINT canvas_program_bindings_pkey PRIMARY KEY (id);


--
-- Name: canvas_worker_heartbeats canvas_worker_heartbeats_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_worker_heartbeats
    ADD CONSTRAINT canvas_worker_heartbeats_pkey PRIMARY KEY (worker_id);


--
-- Name: credential_delivery_records credential_delivery_records_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.credential_delivery_records
    ADD CONSTRAINT credential_delivery_records_pkey PRIMARY KEY (id);


--
-- Name: evidence_fact_heads evidence_fact_heads_fact_id_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT evidence_fact_heads_fact_id_key UNIQUE (fact_id);


--
-- Name: evidence_fact_heads evidence_fact_heads_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT evidence_fact_heads_pkey PRIMARY KEY (application_id, logical_key);


--
-- Name: evidence_facts evidence_facts_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_facts
    ADD CONSTRAINT evidence_facts_pkey PRIMARY KEY (id);


--
-- Name: evidence_policy_reviews evidence_policy_reviews_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT evidence_policy_reviews_pkey PRIMARY KEY (id);


--
-- Name: issuance_events issuance_events_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.issuance_events
    ADD CONSTRAINT issuance_events_pkey PRIMARY KEY (id);


--
-- Name: issuance_transactions issuance_transactions_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.issuance_transactions
    ADD CONSTRAINT issuance_transactions_pkey PRIMARY KEY (id);


--
-- Name: issuance_transactions issuance_transactions_pre_auth_code_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.issuance_transactions
    ADD CONSTRAINT issuance_transactions_pre_auth_code_key UNIQUE (pre_auth_code);


--
-- Name: issued_credentials issued_credentials_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.issued_credentials
    ADD CONSTRAINT issued_credentials_pkey PRIMARY KEY (id);


--
-- Name: oid4vci_client_assertions oid4vci_client_assertions_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.oid4vci_client_assertions
    ADD CONSTRAINT oid4vci_client_assertions_pkey PRIMARY KEY (organization_id, client_id, jti);


--
-- Name: oid4vci_ephemeral_capabilities oid4vci_ephemeral_capabilities_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.oid4vci_ephemeral_capabilities
    ADD CONSTRAINT oid4vci_ephemeral_capabilities_pkey PRIMARY KEY (purpose, key_digest);


--
-- Name: oid4vci_registered_clients oid4vci_registered_clients_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.oid4vci_registered_clients
    ADD CONSTRAINT oid4vci_registered_clients_pkey PRIMARY KEY (organization_id, client_id);


--
-- Name: organization_integration_secrets organization_integration_secrets_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.organization_integration_secrets
    ADD CONSTRAINT organization_integration_secrets_pkey PRIMARY KEY (id);


--
-- Name: physical_document_jobs physical_document_jobs_application_id_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.physical_document_jobs
    ADD CONSTRAINT physical_document_jobs_application_id_key UNIQUE (application_id);


--
-- Name: physical_document_jobs physical_document_jobs_pkey; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.physical_document_jobs
    ADD CONSTRAINT physical_document_jobs_pkey PRIMARY KEY (id);


--
-- Name: canvas_award_candidates ux_canvas_award_candidates_binding_key; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT ux_canvas_award_candidates_binding_key UNIQUE (binding_id, candidate_key);


--
-- Name: canvas_learner_identities ux_canvas_learner_identity_subject; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_learner_identities
    ADD CONSTRAINT ux_canvas_learner_identity_subject UNIQUE (platform_id, deployment_id, lti_subject);


--
-- Name: canvas_oauth_connections ux_canvas_oauth_connections_platform; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_connections
    ADD CONSTRAINT ux_canvas_oauth_connections_platform UNIQUE (organization_id, platform_id);


--
-- Name: canvas_platforms ux_canvas_platforms_org_account; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_platforms
    ADD CONSTRAINT ux_canvas_platforms_org_account UNIQUE (organization_id, canvas_account_id);


--
-- Name: canvas_evidence_sync_targets ux_canvas_sync_targets_org_logical; Type: CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT ux_canvas_sync_targets_org_logical UNIQUE (organization_id, logical_key);


--
-- Name: ix_application_templates_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_application_templates_organization_id ON issuance_service.application_templates USING btree (organization_id);


--
-- Name: ix_application_templates_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_application_templates_status ON issuance_service.application_templates USING btree (status);


--
-- Name: ix_applications_applicant_identifier; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_applications_applicant_identifier ON issuance_service.applications USING btree (applicant_identifier);


--
-- Name: ix_applications_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_applications_organization_id ON issuance_service.applications USING btree (organization_id);


--
-- Name: ix_applications_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_applications_status ON issuance_service.applications USING btree (status);


--
-- Name: ix_applications_template_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_applications_template_id ON issuance_service.applications USING btree (application_template_id);


--
-- Name: ix_authorization_sessions_code; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_authorization_sessions_code ON issuance_service.authorization_sessions USING btree (code);


--
-- Name: ix_authorization_sessions_issuer_state; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_authorization_sessions_issuer_state ON issuance_service.authorization_sessions USING btree (issuer_state);


--
-- Name: ix_authorization_sessions_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_authorization_sessions_status ON issuance_service.authorization_sessions USING btree (status);


--
-- Name: ix_canvas_award_candidates_organization_state; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_award_candidates_organization_state ON issuance_service.canvas_award_candidates USING btree (organization_id, state);


--
-- Name: ix_canvas_binding_requirement_backups_organization; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_binding_requirement_backups_organization ON issuance_service.canvas_program_binding_requirement_backups USING btree (organization_id);


--
-- Name: ix_canvas_candidate_observations_payload; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_candidate_observations_payload ON issuance_service.canvas_candidate_observations USING btree (candidate_id, logical_key, payload_hash);


--
-- Name: ix_canvas_event_receipts_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_event_receipts_organization_id ON issuance_service.canvas_event_receipts USING btree (organization_id);


--
-- Name: ix_canvas_event_receipts_provider_event_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_event_receipts_provider_event_id ON issuance_service.canvas_event_receipts USING btree (provider_event_id);


--
-- Name: ix_canvas_learner_identities_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_learner_identities_organization_id ON issuance_service.canvas_learner_identities USING btree (organization_id);


--
-- Name: ix_canvas_lti_launch_states_organization_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_lti_launch_states_organization_status ON issuance_service.canvas_lti_launch_states USING btree (organization_id, status);


--
-- Name: ix_canvas_lti_launch_states_platform_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_lti_launch_states_platform_id ON issuance_service.canvas_lti_launch_states USING btree (platform_id);


--
-- Name: ix_canvas_lti_launch_states_state; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_lti_launch_states_state ON issuance_service.canvas_lti_launch_states USING btree (state);


--
-- Name: ix_canvas_oauth_authorizations_expiry; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_oauth_authorizations_expiry ON issuance_service.canvas_oauth_authorizations USING btree (expires_at, consumed_at);


--
-- Name: ix_canvas_oauth_authorizations_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_oauth_authorizations_organization_id ON issuance_service.canvas_oauth_authorizations USING btree (organization_id);


--
-- Name: ix_canvas_oauth_authorizations_platform_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_oauth_authorizations_platform_id ON issuance_service.canvas_oauth_authorizations USING btree (platform_id);


--
-- Name: ix_canvas_oauth_connections_revoke_retry; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_oauth_connections_revoke_retry ON issuance_service.canvas_oauth_connections USING btree (status, revoke_retry_at);


--
-- Name: ix_canvas_oauth_connections_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_oauth_connections_status ON issuance_service.canvas_oauth_connections USING btree (status, reauthorization_required);


--
-- Name: ix_canvas_platform_state_backups_organization; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_platform_state_backups_organization ON issuance_service.canvas_platform_state_backups USING btree (organization_id);


--
-- Name: ix_canvas_platforms_canvas_account_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_platforms_canvas_account_id ON issuance_service.canvas_platforms USING btree (canvas_account_id);


--
-- Name: ix_canvas_platforms_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_platforms_organization_id ON issuance_service.canvas_platforms USING btree (organization_id);


--
-- Name: ix_canvas_program_bindings_application_template_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_program_bindings_application_template_id ON issuance_service.canvas_program_bindings USING btree (application_template_id);


--
-- Name: ix_canvas_program_bindings_credential_template_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_program_bindings_credential_template_id ON issuance_service.canvas_program_bindings USING btree (credential_template_id);


--
-- Name: ix_canvas_program_bindings_deployment_profile_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_program_bindings_deployment_profile_id ON issuance_service.canvas_program_bindings USING btree (deployment_profile_id);


--
-- Name: ix_canvas_program_bindings_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_program_bindings_organization_id ON issuance_service.canvas_program_bindings USING btree (organization_id);


--
-- Name: ix_canvas_program_bindings_platform_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_program_bindings_platform_id ON issuance_service.canvas_program_bindings USING btree (platform_id);


--
-- Name: ix_canvas_sync_jobs_claim; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_sync_jobs_claim ON issuance_service.canvas_evidence_sync_jobs USING btree (status, available_at, lease_expires_at);


--
-- Name: ix_canvas_sync_jobs_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_sync_jobs_organization_id ON issuance_service.canvas_evidence_sync_jobs USING btree (organization_id);


--
-- Name: ix_canvas_sync_targets_candidate_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_sync_targets_candidate_id ON issuance_service.canvas_evidence_sync_targets USING btree (candidate_id) WHERE (candidate_id IS NOT NULL);


--
-- Name: ix_canvas_sync_targets_due; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_sync_targets_due ON issuance_service.canvas_evidence_sync_targets USING btree (enabled, next_run_at);


--
-- Name: ix_canvas_worker_heartbeats_role_fresh; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_canvas_worker_heartbeats_role_fresh ON issuance_service.canvas_worker_heartbeats USING btree (role, last_heartbeat_at);


--
-- Name: ix_credential_delivery_records_canvas_account_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_canvas_account_id ON issuance_service.credential_delivery_records USING btree (canvas_account_id);


--
-- Name: ix_credential_delivery_records_credential_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_credential_id ON issuance_service.credential_delivery_records USING btree (credential_id);


--
-- Name: ix_credential_delivery_records_delivery_target; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_delivery_target ON issuance_service.credential_delivery_records USING btree (delivery_target);


--
-- Name: ix_credential_delivery_records_external_credential_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_external_credential_id ON issuance_service.credential_delivery_records USING btree (external_credential_id);


--
-- Name: ix_credential_delivery_records_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_organization_id ON issuance_service.credential_delivery_records USING btree (organization_id);


--
-- Name: ix_credential_delivery_records_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_status ON issuance_service.credential_delivery_records USING btree (status);


--
-- Name: ix_credential_delivery_records_transaction_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_credential_delivery_records_transaction_id ON issuance_service.credential_delivery_records USING btree (transaction_id);


--
-- Name: ix_evidence_fact_heads_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_fact_heads_organization_id ON issuance_service.evidence_fact_heads USING btree (organization_id);


--
-- Name: ix_evidence_facts_application_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_application_id ON issuance_service.evidence_facts USING btree (application_id);


--
-- Name: ix_evidence_facts_application_logical_key; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_application_logical_key ON issuance_service.evidence_facts USING btree (application_id, logical_key);


--
-- Name: ix_evidence_facts_application_logical_payload; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_application_logical_payload ON issuance_service.evidence_facts USING btree (application_id, logical_key, payload_hash);


--
-- Name: ix_evidence_facts_fact_type; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_fact_type ON issuance_service.evidence_facts USING btree (fact_type);


--
-- Name: ix_evidence_facts_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_organization_id ON issuance_service.evidence_facts USING btree (organization_id);


--
-- Name: ix_evidence_facts_provider; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_facts_provider ON issuance_service.evidence_facts USING btree (provider);


--
-- Name: ix_evidence_policy_reviews_application_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_policy_reviews_application_id ON issuance_service.evidence_policy_reviews USING btree (application_id);


--
-- Name: ix_evidence_policy_reviews_organization_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_evidence_policy_reviews_organization_status ON issuance_service.evidence_policy_reviews USING btree (organization_id, status);


--
-- Name: ix_issuance_events_application_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_events_application_id ON issuance_service.issuance_events USING btree (application_id);


--
-- Name: ix_issuance_events_event_type; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_events_event_type ON issuance_service.issuance_events USING btree (event_type);


--
-- Name: ix_issuance_events_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_events_organization_id ON issuance_service.issuance_events USING btree (organization_id);


--
-- Name: ix_issuance_events_transaction_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_events_transaction_id ON issuance_service.issuance_events USING btree (transaction_id);


--
-- Name: ix_issuance_transactions_applicant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_applicant_id ON issuance_service.issuance_transactions USING btree (applicant_id);


--
-- Name: ix_issuance_transactions_application_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_application_id ON issuance_service.issuance_transactions USING btree (application_id);


--
-- Name: ix_issuance_transactions_delivery_mode; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_delivery_mode ON issuance_service.issuance_transactions USING btree (delivery_mode);


--
-- Name: ix_issuance_transactions_issuer_mode; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_issuer_mode ON issuance_service.issuance_transactions USING btree (issuer_mode);


--
-- Name: ix_issuance_transactions_issuer_profile_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_issuer_profile_id ON issuance_service.issuance_transactions USING btree (issuer_profile_id);


--
-- Name: ix_issuance_transactions_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_organization_id ON issuance_service.issuance_transactions USING btree (organization_id);


--
-- Name: ix_issuance_transactions_pre_auth_code; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_pre_auth_code ON issuance_service.issuance_transactions USING btree (pre_auth_code);


--
-- Name: ix_issuance_transactions_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issuance_transactions_status ON issuance_service.issuance_transactions USING btree (status);


--
-- Name: ix_issued_credentials_applicant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issued_credentials_applicant_id ON issuance_service.issued_credentials USING btree (applicant_id);


--
-- Name: ix_issued_credentials_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issued_credentials_organization_id ON issuance_service.issued_credentials USING btree (organization_id);


--
-- Name: ix_issued_credentials_revocation_profile_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issued_credentials_revocation_profile_id ON issuance_service.issued_credentials USING btree (revocation_profile_id);


--
-- Name: ix_issued_credentials_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issued_credentials_status ON issuance_service.issued_credentials USING btree (status);


--
-- Name: ix_issued_credentials_subject_did; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_issued_credentials_subject_did ON issuance_service.issued_credentials USING btree (subject_did);


--
-- Name: ix_oid4vci_client_assertions_expires_at; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_oid4vci_client_assertions_expires_at ON issuance_service.oid4vci_client_assertions USING btree (expires_at);


--
-- Name: ix_oid4vci_ephemeral_capabilities_expires_at; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_oid4vci_ephemeral_capabilities_expires_at ON issuance_service.oid4vci_ephemeral_capabilities USING btree (expires_at);


--
-- Name: ix_oid4vci_registered_clients_org_active; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_oid4vci_registered_clients_org_active ON issuance_service.oid4vci_registered_clients USING btree (organization_id, active);


--
-- Name: ix_org_integration_secrets_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_org_integration_secrets_organization_id ON issuance_service.organization_integration_secrets USING btree (organization_id);


--
-- Name: ix_org_integration_secrets_provider; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_org_integration_secrets_provider ON issuance_service.organization_integration_secrets USING btree (provider);


--
-- Name: ix_physical_document_jobs_bureau_job_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_physical_document_jobs_bureau_job_id ON issuance_service.physical_document_jobs USING btree (bureau_job_id);


--
-- Name: ix_physical_document_jobs_flow_execution_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_physical_document_jobs_flow_execution_id ON issuance_service.physical_document_jobs USING btree (flow_execution_id);


--
-- Name: ix_physical_document_jobs_organization_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_physical_document_jobs_organization_id ON issuance_service.physical_document_jobs USING btree (organization_id);


--
-- Name: ix_physical_document_jobs_status; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE INDEX ix_physical_document_jobs_status ON issuance_service.physical_document_jobs USING btree (status);


--
-- Name: ux_application_templates_org_idempotency_key_hash; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_application_templates_org_idempotency_key_hash ON issuance_service.application_templates USING btree (organization_id, idempotency_key_hash) WHERE (idempotency_key_hash IS NOT NULL);


--
-- Name: ux_application_templates_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_application_templates_tenant_id ON issuance_service.application_templates USING btree (organization_id, id);


--
-- Name: ux_applications_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_applications_tenant_id ON issuance_service.applications USING btree (organization_id, id);


--
-- Name: ux_canvas_award_candidates_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_award_candidates_tenant_id ON issuance_service.canvas_award_candidates USING btree (organization_id, id);


--
-- Name: ux_canvas_candidate_observations_current; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_candidate_observations_current ON issuance_service.canvas_candidate_observations USING btree (candidate_id, logical_key) WHERE is_current;


--
-- Name: ux_canvas_candidate_observations_tenant_candidate_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_candidate_observations_tenant_candidate_id ON issuance_service.canvas_candidate_observations USING btree (organization_id, candidate_id, id);


--
-- Name: ux_canvas_candidate_observations_tenant_candidate_logical_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_candidate_observations_tenant_candidate_logical_id ON issuance_service.canvas_candidate_observations USING btree (organization_id, candidate_id, logical_key, id);


--
-- Name: ux_canvas_candidate_observations_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_candidate_observations_tenant_id ON issuance_service.canvas_candidate_observations USING btree (organization_id, id);


--
-- Name: ux_canvas_event_receipts_account_event; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_event_receipts_account_event ON issuance_service.canvas_event_receipts USING btree (canvas_account_id, provider_event_id);


--
-- Name: ux_canvas_learner_identities_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_learner_identities_tenant_id ON issuance_service.canvas_learner_identities USING btree (organization_id, id);


--
-- Name: ux_canvas_learner_identity_numeric_link; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_learner_identity_numeric_link ON issuance_service.canvas_learner_identities USING btree (platform_id, deployment_id, canvas_user_id) WHERE (((status)::text = 'linked'::text) AND (canvas_user_id IS NOT NULL));


--
-- Name: ux_canvas_platforms_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_platforms_tenant_id ON issuance_service.canvas_platforms USING btree (organization_id, id);


--
-- Name: ux_canvas_program_bindings_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_program_bindings_tenant_id ON issuance_service.canvas_program_bindings USING btree (organization_id, id);


--
-- Name: ux_canvas_sync_jobs_one_active_target; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_sync_jobs_one_active_target ON issuance_service.canvas_evidence_sync_jobs USING btree (target_id) WHERE ((status)::text = ANY ((ARRAY['queued'::character varying, 'leased'::character varying, 'retry'::character varying])::text[]));


--
-- Name: ux_canvas_sync_targets_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_canvas_sync_targets_tenant_id ON issuance_service.canvas_evidence_sync_targets USING btree (organization_id, id);


--
-- Name: ux_evidence_facts_tenant_application_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_evidence_facts_tenant_application_id ON issuance_service.evidence_facts USING btree (organization_id, application_id, id);


--
-- Name: ux_evidence_facts_tenant_application_logical_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_evidence_facts_tenant_application_logical_id ON issuance_service.evidence_facts USING btree (organization_id, application_id, logical_key, id);


--
-- Name: ux_evidence_facts_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_evidence_facts_tenant_id ON issuance_service.evidence_facts USING btree (organization_id, id);


--
-- Name: ux_evidence_policy_reviews_one_open_application; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_evidence_policy_reviews_one_open_application ON issuance_service.evidence_policy_reviews USING btree (application_id) WHERE ((status)::text = 'open'::text);


--
-- Name: ux_issuance_transactions_org_idempotency_key_hash; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_issuance_transactions_org_idempotency_key_hash ON issuance_service.issuance_transactions USING btree (organization_id, idempotency_key_hash);


--
-- Name: ux_issued_credentials_tenant_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_issued_credentials_tenant_id ON issuance_service.issued_credentials USING btree (organization_id, id);


--
-- Name: ux_issued_credentials_transaction_id; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_issued_credentials_transaction_id ON issuance_service.issued_credentials USING btree (transaction_id);


--
-- Name: ux_org_integration_secrets_org_provider_name; Type: INDEX; Schema: issuance_service; Owner: -
--

CREATE UNIQUE INDEX ux_org_integration_secrets_org_provider_name ON issuance_service.organization_integration_secrets USING btree (organization_id, provider, name);


--
-- Name: canvas_award_candidates canvas_award_candidates_application_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_application_id_fkey FOREIGN KEY (application_id) REFERENCES issuance_service.applications(id) ON DELETE SET NULL;


--
-- Name: canvas_award_candidates canvas_award_candidates_binding_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE CASCADE;


--
-- Name: canvas_award_candidates canvas_award_candidates_claimed_credential_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_claimed_credential_id_fkey FOREIGN KEY (claimed_credential_id) REFERENCES issuance_service.issued_credentials(id) ON DELETE SET NULL;


--
-- Name: canvas_award_candidates canvas_award_candidates_learner_identity_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_learner_identity_id_fkey FOREIGN KEY (learner_identity_id) REFERENCES issuance_service.canvas_learner_identities(id) ON DELETE SET NULL;


--
-- Name: canvas_award_candidates canvas_award_candidates_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT canvas_award_candidates_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_candidate_observations canvas_candidate_observations_candidate_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_candidate_observations
    ADD CONSTRAINT canvas_candidate_observations_candidate_id_fkey FOREIGN KEY (candidate_id) REFERENCES issuance_service.canvas_award_candidates(id) ON DELETE CASCADE;


--
-- Name: canvas_candidate_observations canvas_candidate_observations_superseded_observation_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_candidate_observations
    ADD CONSTRAINT canvas_candidate_observations_superseded_observation_id_fkey FOREIGN KEY (superseded_observation_id) REFERENCES issuance_service.canvas_candidate_observations(id) ON DELETE SET NULL;


--
-- Name: canvas_event_receipts canvas_event_receipts_issuance_transaction_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_event_receipts
    ADD CONSTRAINT canvas_event_receipts_issuance_transaction_id_fkey FOREIGN KEY (issuance_transaction_id) REFERENCES issuance_service.issuance_transactions(id) ON DELETE SET NULL;


--
-- Name: canvas_evidence_sync_jobs canvas_evidence_sync_jobs_target_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_jobs
    ADD CONSTRAINT canvas_evidence_sync_jobs_target_id_fkey FOREIGN KEY (target_id) REFERENCES issuance_service.canvas_evidence_sync_targets(id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets canvas_evidence_sync_targets_application_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT canvas_evidence_sync_targets_application_id_fkey FOREIGN KEY (application_id) REFERENCES issuance_service.applications(id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets canvas_evidence_sync_targets_binding_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT canvas_evidence_sync_targets_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets canvas_evidence_sync_targets_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT canvas_evidence_sync_targets_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_learner_identities canvas_learner_identities_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_learner_identities
    ADD CONSTRAINT canvas_learner_identities_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_lti_launch_states canvas_lti_launch_states_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_lti_launch_states
    ADD CONSTRAINT canvas_lti_launch_states_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_oauth_authorizations canvas_oauth_authorizations_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_authorizations
    ADD CONSTRAINT canvas_oauth_authorizations_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_oauth_connections canvas_oauth_connections_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_connections
    ADD CONSTRAINT canvas_oauth_connections_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: canvas_program_bindings canvas_program_bindings_platform_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_program_bindings
    ADD CONSTRAINT canvas_program_bindings_platform_id_fkey FOREIGN KEY (platform_id) REFERENCES issuance_service.canvas_platforms(id) ON DELETE CASCADE;


--
-- Name: credential_delivery_records credential_delivery_records_credential_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.credential_delivery_records
    ADD CONSTRAINT credential_delivery_records_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES issuance_service.issued_credentials(id) ON DELETE CASCADE;


--
-- Name: credential_delivery_records credential_delivery_records_transaction_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.credential_delivery_records
    ADD CONSTRAINT credential_delivery_records_transaction_id_fkey FOREIGN KEY (transaction_id) REFERENCES issuance_service.issuance_transactions(id) ON DELETE CASCADE;


--
-- Name: evidence_fact_heads evidence_fact_heads_application_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT evidence_fact_heads_application_id_fkey FOREIGN KEY (application_id) REFERENCES issuance_service.applications(id) ON DELETE CASCADE;


--
-- Name: evidence_fact_heads evidence_fact_heads_fact_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT evidence_fact_heads_fact_id_fkey FOREIGN KEY (fact_id) REFERENCES issuance_service.evidence_facts(id) ON DELETE CASCADE;


--
-- Name: evidence_facts evidence_facts_application_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_facts
    ADD CONSTRAINT evidence_facts_application_id_fkey FOREIGN KEY (application_id) REFERENCES issuance_service.applications(id) ON DELETE CASCADE;


--
-- Name: evidence_policy_reviews evidence_policy_reviews_application_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT evidence_policy_reviews_application_id_fkey FOREIGN KEY (application_id) REFERENCES issuance_service.applications(id) ON DELETE CASCADE;


--
-- Name: evidence_policy_reviews evidence_policy_reviews_binding_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT evidence_policy_reviews_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES issuance_service.canvas_program_bindings(id) ON DELETE SET NULL;


--
-- Name: evidence_policy_reviews evidence_policy_reviews_credential_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT evidence_policy_reviews_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES issuance_service.issued_credentials(id) ON DELETE CASCADE;


--
-- Name: evidence_policy_reviews evidence_policy_reviews_triggering_fact_id_fkey; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT evidence_policy_reviews_triggering_fact_id_fkey FOREIGN KEY (triggering_fact_id) REFERENCES issuance_service.evidence_facts(id) ON DELETE SET NULL;


--
-- Name: canvas_award_candidates fk_canvas_award_candidates_tenant_application; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT fk_canvas_award_candidates_tenant_application FOREIGN KEY (organization_id, application_id) REFERENCES issuance_service.applications(organization_id, id);


--
-- Name: canvas_award_candidates fk_canvas_award_candidates_tenant_binding; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT fk_canvas_award_candidates_tenant_binding FOREIGN KEY (organization_id, binding_id) REFERENCES issuance_service.canvas_program_bindings(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_award_candidates fk_canvas_award_candidates_tenant_credential; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT fk_canvas_award_candidates_tenant_credential FOREIGN KEY (organization_id, claimed_credential_id) REFERENCES issuance_service.issued_credentials(organization_id, id);


--
-- Name: canvas_award_candidates fk_canvas_award_candidates_tenant_identity; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT fk_canvas_award_candidates_tenant_identity FOREIGN KEY (organization_id, learner_identity_id) REFERENCES issuance_service.canvas_learner_identities(organization_id, id);


--
-- Name: canvas_award_candidates fk_canvas_award_candidates_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_award_candidates
    ADD CONSTRAINT fk_canvas_award_candidates_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_candidate_observations fk_canvas_candidate_observations_tenant_candidate; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_candidate_observations
    ADD CONSTRAINT fk_canvas_candidate_observations_tenant_candidate FOREIGN KEY (organization_id, candidate_id) REFERENCES issuance_service.canvas_award_candidates(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_candidate_observations fk_canvas_candidate_observations_tenant_superseded; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_candidate_observations
    ADD CONSTRAINT fk_canvas_candidate_observations_tenant_superseded FOREIGN KEY (organization_id, candidate_id, logical_key, superseded_observation_id) REFERENCES issuance_service.canvas_candidate_observations(organization_id, candidate_id, logical_key, id);


--
-- Name: canvas_learner_identities fk_canvas_learner_identities_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_learner_identities
    ADD CONSTRAINT fk_canvas_learner_identities_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_oauth_authorizations fk_canvas_oauth_authorizations_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_authorizations
    ADD CONSTRAINT fk_canvas_oauth_authorizations_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_oauth_connections fk_canvas_oauth_connections_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_oauth_connections
    ADD CONSTRAINT fk_canvas_oauth_connections_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_program_bindings fk_canvas_program_bindings_tenant_application_template; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_program_bindings
    ADD CONSTRAINT fk_canvas_program_bindings_tenant_application_template FOREIGN KEY (organization_id, application_template_id) REFERENCES issuance_service.application_templates(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_program_bindings fk_canvas_program_bindings_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_program_bindings
    ADD CONSTRAINT fk_canvas_program_bindings_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_jobs fk_canvas_sync_jobs_tenant_target; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_jobs
    ADD CONSTRAINT fk_canvas_sync_jobs_tenant_target FOREIGN KEY (organization_id, target_id) REFERENCES issuance_service.canvas_evidence_sync_targets(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets fk_canvas_sync_targets_candidate_id; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT fk_canvas_sync_targets_candidate_id FOREIGN KEY (candidate_id) REFERENCES issuance_service.canvas_award_candidates(id) ON DELETE SET NULL;


--
-- Name: canvas_evidence_sync_targets fk_canvas_sync_targets_tenant_application; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT fk_canvas_sync_targets_tenant_application FOREIGN KEY (organization_id, application_id) REFERENCES issuance_service.applications(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets fk_canvas_sync_targets_tenant_binding; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT fk_canvas_sync_targets_tenant_binding FOREIGN KEY (organization_id, binding_id) REFERENCES issuance_service.canvas_program_bindings(organization_id, id) ON DELETE CASCADE;


--
-- Name: canvas_evidence_sync_targets fk_canvas_sync_targets_tenant_candidate; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT fk_canvas_sync_targets_tenant_candidate FOREIGN KEY (organization_id, candidate_id) REFERENCES issuance_service.canvas_award_candidates(organization_id, id);


--
-- Name: canvas_evidence_sync_targets fk_canvas_sync_targets_tenant_platform; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.canvas_evidence_sync_targets
    ADD CONSTRAINT fk_canvas_sync_targets_tenant_platform FOREIGN KEY (organization_id, platform_id) REFERENCES issuance_service.canvas_platforms(organization_id, id) ON DELETE CASCADE;


--
-- Name: evidence_fact_heads fk_evidence_fact_heads_tenant_application; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT fk_evidence_fact_heads_tenant_application FOREIGN KEY (organization_id, application_id) REFERENCES issuance_service.applications(organization_id, id) ON DELETE CASCADE;


--
-- Name: evidence_fact_heads fk_evidence_fact_heads_tenant_fact; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_fact_heads
    ADD CONSTRAINT fk_evidence_fact_heads_tenant_fact FOREIGN KEY (organization_id, application_id, logical_key, fact_id) REFERENCES issuance_service.evidence_facts(organization_id, application_id, logical_key, id) ON DELETE CASCADE;


--
-- Name: evidence_facts fk_evidence_facts_superseded_fact_id; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_facts
    ADD CONSTRAINT fk_evidence_facts_superseded_fact_id FOREIGN KEY (superseded_fact_id) REFERENCES issuance_service.evidence_facts(id) ON DELETE SET NULL;


--
-- Name: evidence_facts fk_evidence_facts_tenant_application; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_facts
    ADD CONSTRAINT fk_evidence_facts_tenant_application FOREIGN KEY (organization_id, application_id) REFERENCES issuance_service.applications(organization_id, id) ON DELETE CASCADE;


--
-- Name: evidence_facts fk_evidence_facts_tenant_superseded; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_facts
    ADD CONSTRAINT fk_evidence_facts_tenant_superseded FOREIGN KEY (organization_id, application_id, logical_key, superseded_fact_id) REFERENCES issuance_service.evidence_facts(organization_id, application_id, logical_key, id);


--
-- Name: evidence_policy_reviews fk_evidence_policy_reviews_tenant_application; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT fk_evidence_policy_reviews_tenant_application FOREIGN KEY (organization_id, application_id) REFERENCES issuance_service.applications(organization_id, id) ON DELETE CASCADE;


--
-- Name: evidence_policy_reviews fk_evidence_policy_reviews_tenant_binding; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT fk_evidence_policy_reviews_tenant_binding FOREIGN KEY (organization_id, binding_id) REFERENCES issuance_service.canvas_program_bindings(organization_id, id);


--
-- Name: evidence_policy_reviews fk_evidence_policy_reviews_tenant_credential; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT fk_evidence_policy_reviews_tenant_credential FOREIGN KEY (organization_id, credential_id) REFERENCES issuance_service.issued_credentials(organization_id, id) ON DELETE CASCADE;


--
-- Name: evidence_policy_reviews fk_evidence_policy_reviews_tenant_fact; Type: FK CONSTRAINT; Schema: issuance_service; Owner: -
--

ALTER TABLE ONLY issuance_service.evidence_policy_reviews
    ADD CONSTRAINT fk_evidence_policy_reviews_tenant_fact FOREIGN KEY (organization_id, application_id, triggering_fact_id) REFERENCES issuance_service.evidence_facts(organization_id, application_id, id);


--
-- PostgreSQL database dump complete
--
