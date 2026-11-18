-- Evidence captured atomically with the outbound submission claim. Existing
-- ambiguous intents have no provenance and cannot enter beta reconciliation.
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_intent_signing_provenance jsonb;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_submission_provenance_intent'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_submission_provenance_intent
            CHECK (submission_intent_id IS NOT NULL OR
                   submission_intent_signing_provenance IS NULL);
    END IF;
END $$;
