ALTER TABLE issuance_service.issuance_transactions
    ADD COLUMN IF NOT EXISTS access_token_expires_at timestamptz;

ALTER TABLE issuance_service.authorization_sessions
    ADD COLUMN IF NOT EXISTS access_token_expires_at timestamptz;

-- One bounded token lifetime is granted to tokens minted before this native
-- column existed. This avoids an unbounded compatibility mode while allowing
-- an in-flight beta request to complete during the cutover.
UPDATE issuance_service.issuance_transactions
SET access_token_expires_at = transaction_timestamp() + interval '1800 seconds'
WHERE access_token IS NOT NULL AND access_token_expires_at IS NULL;

UPDATE issuance_service.authorization_sessions
SET access_token_expires_at = transaction_timestamp() + interval '1800 seconds'
WHERE access_token IS NOT NULL AND access_token_expires_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_issuance_transactions_access_token_live
    ON issuance_service.issuance_transactions (access_token, access_token_expires_at)
    WHERE access_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_authorization_sessions_access_token_live
    ON issuance_service.authorization_sessions (access_token, access_token_expires_at)
    WHERE access_token IS NOT NULL;

UPDATE issuance_service.issuance_events AS binding
SET application_id = transaction.application_id,
    metadata = (binding.metadata::jsonb || jsonb_build_object(
        'organization_id', transaction.organization_id
    ))::json
FROM issuance_service.issuance_transactions AS transaction
JOIN issuance_service.issued_credentials AS credential
  ON credential.transaction_id = transaction.id
 AND credential.organization_id = transaction.organization_id
WHERE binding.event_type = 'oid4vci_notification_binding'
  AND binding.transaction_id = transaction.id
  AND binding.metadata ->> 'credential_id' = credential.id
  AND (binding.metadata ->> 'organization_id') IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM issuance_service.issuance_events AS binding
        LEFT JOIN issuance_service.issuance_transactions AS transaction
          ON transaction.id = binding.transaction_id
        LEFT JOIN issuance_service.issued_credentials AS credential
          ON credential.transaction_id = transaction.id
         AND credential.id = binding.metadata ->> 'credential_id'
         AND credential.organization_id = transaction.organization_id
        WHERE binding.event_type = 'oid4vci_notification_binding'
          AND (transaction.id IS NULL
               OR credential.id IS NULL
               OR binding.metadata ->> 'organization_id' IS DISTINCT FROM transaction.organization_id
               OR binding.application_id IS DISTINCT FROM transaction.application_id)
    ) THEN
        RAISE EXCEPTION 'inconsistent legacy OID4VCI notification binding';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_issuance_events_oid4vci_notification_id
    ON issuance_service.issuance_events ((metadata ->> 'notification_id'))
    WHERE event_type = 'oid4vci_notification_binding';
