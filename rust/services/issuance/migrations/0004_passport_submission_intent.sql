-- A private, durable claim over the exact material sent to the bureau.
-- Existing Python rows remain unreserved until native submission claims them.
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_intent_id uuid;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_intent_started_at timestamptz;
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_intent_provider_profile_id varchar(128);
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS submission_intent_bureau_endpoint_sha256 varchar(64);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_submission_intent_pair'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_submission_intent_pair
            CHECK ((submission_intent_id IS NULL) = (submission_intent_started_at IS NULL)
                   AND (submission_intent_id IS NULL) =
                       (submission_intent_bureau_endpoint_sha256 IS NULL)
                   AND (submission_intent_id IS NOT NULL OR
                        submission_intent_provider_profile_id IS NULL));
    END IF;
END $$;

-- Old writers do not know these columns. Once native code has reserved a row,
-- prevent an old writer from changing its material or binding another bureau
-- job while it ignores the reservation. Only the owner clearing the intent can
-- finalize or release the row.
CREATE OR REPLACE FUNCTION issuance_service.guard_physical_document_submission_intent()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.submission_intent_id IS NOT NULL AND NEW.submission_intent_id IS NOT NULL THEN
        RAISE EXCEPTION 'physical document submission is reserved';
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_physical_document_submission_intent
    ON issuance_service.physical_document_jobs;
CREATE TRIGGER trg_physical_document_submission_intent
    BEFORE UPDATE ON issuance_service.physical_document_jobs
    FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_physical_document_submission_intent();
