-- Released Python jobs have no authenticated provider binding and must not
-- become eligible for the new physical-bureau ingress by inference.
ALTER TABLE issuance_service.physical_document_jobs
    ADD COLUMN IF NOT EXISTS bureau_provider_profile_id varchar(128);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.physical_document_jobs'::regclass
          AND conname = 'ck_physical_document_jobs_bureau_provider_binding'
    ) THEN
        ALTER TABLE issuance_service.physical_document_jobs
            ADD CONSTRAINT ck_physical_document_jobs_bureau_provider_binding
            CHECK (bureau_provider_profile_id IS NULL OR
                   (bureau_job_id IS NOT NULL AND
                    LENGTH(BTRIM(bureau_job_id)) BETWEEN 1 AND 255 AND
                    LENGTH(BTRIM(bureau_provider_profile_id)) BETWEEN 1 AND 128));
    END IF;
END $$;

-- A partially upgraded database may already carry bound rows. Diagnose them
-- before index creation so startup fails closed with no reassignment.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM issuance_service.physical_document_jobs
        WHERE bureau_provider_profile_id IS NOT NULL AND bureau_job_id IS NOT NULL
        GROUP BY bureau_provider_profile_id, bureau_job_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous passport bureau provider/job binding';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_physical_document_jobs_bureau_provider_job
    ON issuance_service.physical_document_jobs (bureau_provider_profile_id, bureau_job_id)
    WHERE bureau_provider_profile_id IS NOT NULL AND bureau_job_id IS NOT NULL;
