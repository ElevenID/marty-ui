-- Keep only KMS-encrypted exact first-dispatch wire bodies and keyed proof in
-- tenant-bound private storage. A replay must never replace this evidence.
ALTER TABLE issuance_service.passport_beta_batch_intents
    ADD COLUMN IF NOT EXISTS first_dispatch_response_seen_at timestamptz,
    ADD COLUMN IF NOT EXISTS first_dispatch_wire_ciphertext text,
    ADD COLUMN IF NOT EXISTS first_dispatch_request_commitment text,
    ADD COLUMN IF NOT EXISTS first_dispatch_response_commitment text,
    ADD COLUMN IF NOT EXISTS first_dispatch_wire_key_sha256 text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'issuance_service.passport_beta_batch_intents'::regclass
          AND conname = 'ck_passport_beta_batch_wire_evidence'
    ) THEN
        ALTER TABLE issuance_service.passport_beta_batch_intents
            ADD CONSTRAINT ck_passport_beta_batch_wire_evidence
            CHECK (
                (first_dispatch_wire_ciphertext IS NULL AND
                 first_dispatch_request_commitment IS NULL AND
                 first_dispatch_response_commitment IS NULL AND
                 first_dispatch_wire_key_sha256 IS NULL)
                OR
                (first_dispatch_response_seen_at IS NOT NULL AND
                 first_dispatch_wire_ciphertext IS NOT NULL AND
                 first_dispatch_request_commitment ~ '^[0-9a-f]{64}$' AND
                 first_dispatch_response_commitment ~ '^[0-9a-f]{64}$' AND
                 first_dispatch_wire_key_sha256 ~ '^[0-9a-f]{64}$')
            );
    END IF;
END $$;
