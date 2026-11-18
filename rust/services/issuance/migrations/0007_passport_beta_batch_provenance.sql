-- Preserve the managed signing ceremony after an accepted batch clears its
-- outbound intent. Exact replay must remain verifiable across profile rotation.
ALTER TABLE issuance_service.passport_beta_batch_intents
    ADD COLUMN IF NOT EXISTS last_send_started_at timestamptz;
UPDATE issuance_service.passport_beta_batch_intents
   SET last_send_started_at = created_at
 WHERE last_send_started_at IS NULL;
ALTER TABLE issuance_service.passport_beta_batch_intents
    ALTER COLUMN last_send_started_at SET NOT NULL;
ALTER TABLE issuance_service.passport_beta_batch_intents
    ADD COLUMN IF NOT EXISTS send_attempts smallint NOT NULL DEFAULT 1;
ALTER TABLE issuance_service.passport_beta_batch_intents
    ADD COLUMN IF NOT EXISTS last_receipt_completion_started_at timestamptz,
    ADD COLUMN IF NOT EXISTS receipt_completion_attempts bigint NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.passport_beta_batch_intents'::regclass
          AND conname = 'ck_passport_beta_batch_send_attempts'
    ) THEN
        ALTER TABLE issuance_service.passport_beta_batch_intents
            ADD CONSTRAINT ck_passport_beta_batch_send_attempts
            CHECK (send_attempts BETWEEN 1 AND 2);
    END IF;
END $$;

ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_signing_provenance jsonb;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_bureau_endpoint_sha256 text;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_batch_material_digests jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_batch_provenance_identity'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_batch_provenance_identity
            CHECK ((submission_batch_signing_provenance IS NULL AND
                    submission_batch_bureau_endpoint_sha256 IS NULL AND
                    submission_batch_material_digests IS NULL) OR
                   (submission_batch_id IS NOT NULL AND
                    submission_batch_signing_provenance IS NOT NULL AND
                    submission_batch_bureau_endpoint_sha256 IS NOT NULL AND
                    submission_batch_material_digests IS NOT NULL));
    END IF;
END $$;
