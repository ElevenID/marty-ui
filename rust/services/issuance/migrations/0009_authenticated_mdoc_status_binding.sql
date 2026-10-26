-- Local mdoc status references commit only authenticated MSO bytes and DSC.
-- Existing credentials have no fabricated index entry and remain unknown to
-- fingerprint status lookup until regenerated through native issuance.
ALTER TABLE issuance_service.issued_credentials
    ADD COLUMN IF NOT EXISTS mdoc_status_reference text;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conname='issued_credentials_mdoc_status_reference_shape'
          AND conrelid='issuance_service.issued_credentials'::regclass) THEN
        ALTER TABLE issuance_service.issued_credentials
            ADD CONSTRAINT issued_credentials_mdoc_status_reference_shape
            CHECK (mdoc_status_reference IS NULL OR
                   mdoc_status_reference ~ '^urn:mdoc-status:v1:[0-9a-f]{64}:[0-9a-f]{64}$');
    END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS issued_credentials_tenant_mdoc_status_reference
    ON issuance_service.issued_credentials (organization_id, mdoc_status_reference)
    WHERE mdoc_status_reference IS NOT NULL;
