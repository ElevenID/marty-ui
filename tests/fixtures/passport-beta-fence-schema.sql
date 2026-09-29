CREATE SCHEMA issuance_service AUTHORIZATION marty;
CREATE SCHEMA flow_service AUTHORIZATION marty;
CREATE TABLE issuance_service.physical_document_jobs (
    id text PRIMARY KEY, organization_id text NOT NULL,
    flow_execution_id text NOT NULL, application_id text NOT NULL UNIQUE,
    application_template_id text NOT NULL, credential_template_id text NOT NULL,
    delivery_destination_profile_id varchar(128) NOT NULL,
    document_type varchar(3) NOT NULL, country_code varchar(3) NOT NULL,
    secure_artifact_ciphertext text NOT NULL,
    secure_artifact_reference varchar(512) NOT NULL, sod_sha256 varchar(64),
    bureau_job_id varchar(255), tracking_number varchar(255),
    status varchar(40) NOT NULL DEFAULT 'DRAFT', quality_result json,
    error_code varchar(128), error_message varchar(1024),
    submitted_at timestamptz, completed_at timestamptz,
    created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE TABLE issuance_service.other_issuance (
    id text PRIMARY KEY, status text NOT NULL
);
CREATE TABLE flow_service.flow_definitions (
    id text PRIMARY KEY, organization_id text, name text, status text,
    flow_type text NOT NULL, steps json, transitions json,
    default_timeout_seconds integer, max_retries integer,
    enable_resume boolean, version integer, created_at timestamptz,
    updated_at timestamptz, deployment_profile_ids json,
    approval_strategy text, hooks json, extension json
);
CREATE TABLE flow_service.flow_instances (
    id text PRIMARY KEY, flow_definition_id text NOT NULL,
    organization_id text NOT NULL, context json NOT NULL DEFAULT '{}',
    status text NOT NULL,
    expires_at timestamptz, current_step_id text,
    application_flow_key_hash text, step_history json DEFAULT '[]',
    subject_type text DEFAULT 'applicant', state_history json DEFAULT '[]',
    created_at timestamptz,
    completed_at timestamptz, updated_at timestamptz,
    result json, error text
);
ALTER TABLE issuance_service.physical_document_jobs OWNER TO marty;
ALTER TABLE issuance_service.other_issuance OWNER TO marty;
ALTER TABLE flow_service.flow_definitions OWNER TO marty;
ALTER TABLE flow_service.flow_instances OWNER TO marty;
GRANT USAGE ON SCHEMA issuance_service, flow_service TO marty;
