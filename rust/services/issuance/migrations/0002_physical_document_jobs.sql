-- Native counterpart of Credentials' add_physical_document_jobs migration,
-- including its later nullable revocation_profile_id addition. Retain the
-- released table and data when Python has already applied its migration.
CREATE SCHEMA IF NOT EXISTS issuance_service;

CREATE TABLE IF NOT EXISTS issuance_service.physical_document_jobs (
    id text PRIMARY KEY,
    organization_id text NOT NULL,
    flow_execution_id text NOT NULL,
    application_id text NOT NULL UNIQUE,
    application_template_id text NOT NULL,
    credential_template_id text NOT NULL,
    revocation_profile_id text,
    delivery_destination_profile_id varchar(128) NOT NULL,
    document_type varchar(3) NOT NULL,
    country_code varchar(3) NOT NULL,
    secure_artifact_ciphertext text NOT NULL,
    secure_artifact_reference varchar(512) NOT NULL,
    sod_sha256 varchar(64),
    bureau_job_id varchar(255),
    tracking_number varchar(255),
    status varchar(40) NOT NULL DEFAULT 'DRAFT',
    quality_result json,
    error_code varchar(128),
    error_message varchar(1024),
    submitted_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS revocation_profile_id text;

CREATE INDEX IF NOT EXISTS ix_physical_document_jobs_organization_id
    ON issuance_service.physical_document_jobs (organization_id);
CREATE INDEX IF NOT EXISTS ix_physical_document_jobs_flow_execution_id
    ON issuance_service.physical_document_jobs (flow_execution_id);
CREATE INDEX IF NOT EXISTS ix_physical_document_jobs_status
    ON issuance_service.physical_document_jobs (status);
CREATE INDEX IF NOT EXISTS ix_physical_document_jobs_bureau_job_id
    ON issuance_service.physical_document_jobs (bureau_job_id);
