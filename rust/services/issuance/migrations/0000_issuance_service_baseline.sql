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
