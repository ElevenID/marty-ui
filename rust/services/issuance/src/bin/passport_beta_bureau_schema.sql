-- Private beta simulator schema; never part of the production issuance migrator.
-- The simulator persists no MRZ, data groups, SOD, certificate or raw payload.
CREATE TABLE IF NOT EXISTS issuance_service.passport_beta_bureau_jobs (
    bureau_job_id uuid PRIMARY KEY,
    organization_id varchar(256) NOT NULL,
    source_job_id varchar(256) NOT NULL,
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    status varchar(32) NOT NULL CHECK (status IN (
        'QUEUED', 'PRINTING', 'ENCODING', 'QUALITY_CHECK', 'SHIPPED'
    )),
    next_transition_at timestamptz,
    callback_lease_token uuid,
    callback_lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, source_job_id)
);
CREATE INDEX IF NOT EXISTS ix_passport_beta_bureau_due
    ON issuance_service.passport_beta_bureau_jobs (next_transition_at)
    WHERE status <> 'SHIPPED';
