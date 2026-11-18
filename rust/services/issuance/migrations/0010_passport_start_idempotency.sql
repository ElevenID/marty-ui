-- New keyed physical-document starts share the job's transaction. Existing
-- direct callers remain unkeyed and their historical rows remain unchanged.
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS start_idempotency_key_hash varchar(64);
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS start_idempotency_request_hash varchar(64);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_start_idempotency_pair'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_start_idempotency_pair
            CHECK ((start_idempotency_key_hash IS NULL) =
                   (start_idempotency_request_hash IS NULL)
                   AND (start_idempotency_key_hash IS NULL OR
                        (start_idempotency_key_hash ~ '^[0-9a-f]{64}$' AND
                         start_idempotency_request_hash ~ '^[0-9a-f]{64}$')));
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_physical_document_jobs_org_start_key
    ON issuance_service.physical_document_jobs (organization_id, start_idempotency_key_hash)
    WHERE start_idempotency_key_hash IS NOT NULL;
