-- Keep the two-job beta request identity on both source jobs across ambiguous
-- sends and successful binding. A single-job recovery must not replay either
-- member of a batch through the single-submit wire.
CREATE TABLE IF NOT EXISTS issuance_service.passport_beta_batch_intents (
    batch_id uuid PRIMARY KEY,
    organization_id text NOT NULL,
    selected_flow_instance_id varchar(36) NOT NULL,
    selected_job_id text NOT NULL,
    companion_job_id text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT ck_passport_beta_batch_distinct_jobs
        CHECK (selected_job_id <> companion_job_id)
);

ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_id uuid;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_selected_flow_instance_id varchar(36);
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_selected_job_id text;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_companion_job_id text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_submission_batch_identity'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_submission_batch_identity
            CHECK ((submission_batch_id IS NULL AND
                    submission_batch_selected_flow_instance_id IS NULL AND
                    submission_batch_selected_job_id IS NULL AND
                    submission_batch_companion_job_id IS NULL)
                   OR (submission_batch_id IS NOT NULL AND
                       submission_batch_selected_flow_instance_id IS NOT NULL AND
                       submission_batch_selected_job_id IS NOT NULL AND
                       submission_batch_companion_job_id IS NOT NULL AND
                       submission_batch_selected_job_id <> submission_batch_companion_job_id AND
                       id IN (submission_batch_selected_job_id,
                              submission_batch_companion_job_id)));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_physical_document_jobs_submission_batch
    ON issuance_service.physical_document_jobs (organization_id, submission_batch_id)
    WHERE submission_batch_id IS NOT NULL;
