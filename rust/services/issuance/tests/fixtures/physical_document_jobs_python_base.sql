-- Released Credentials Alembic revision add_physical_document_jobs before
-- physical_document_revocation_profile. This fixture is intentionally separate
-- from the Rust migration so an upgrade cannot pass by testing its own DDL.
DROP TABLE issuance_service.physical_document_jobs;
CREATE TABLE issuance_service.physical_document_jobs (
    id varchar NOT NULL PRIMARY KEY,
    organization_id varchar NOT NULL,
    flow_execution_id varchar NOT NULL,
    application_id varchar NOT NULL UNIQUE,
    application_template_id varchar NOT NULL,
    credential_template_id varchar NOT NULL,
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
CREATE INDEX ix_physical_document_jobs_organization_id
    ON issuance_service.physical_document_jobs (organization_id);
CREATE INDEX ix_physical_document_jobs_flow_execution_id
    ON issuance_service.physical_document_jobs (flow_execution_id);
CREATE INDEX ix_physical_document_jobs_status
    ON issuance_service.physical_document_jobs (status);
CREATE INDEX ix_physical_document_jobs_bureau_job_id
    ON issuance_service.physical_document_jobs (bureau_job_id);
INSERT INTO issuance_service.physical_document_jobs (
    id, organization_id, flow_execution_id, application_id,
    application_template_id, credential_template_id,
    delivery_destination_profile_id, document_type, country_code,
    secure_artifact_ciphertext, secure_artifact_reference,
    created_at, updated_at
) VALUES (
    'released-python-job', 'org-a', 'released-flow', 'released-application',
    'released-template', 'released-credential', 'released-destination',
    'TD2', 'USA', 'released-encrypted-artifact',
    'physical-artifact://released-python-job',
    '2026-07-11T00:00:00Z', '2026-07-11T00:00:00Z'
);
