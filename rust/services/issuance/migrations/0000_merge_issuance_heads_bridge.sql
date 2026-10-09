-- Complete the four published issuance revisions after merge_issuance_heads.
-- Existing rows are retained; the event owner backfill matches the published
-- issuance_event_owner migration. A fresh Rust baseline has no Alembic table.
DO $bridge$
DECLARE
    heads text[];
BEGIN
    IF to_regclass('issuance_service.alembic_version') IS NULL THEN
        RETURN;
    END IF;
    SELECT array_agg(version_num ORDER BY version_num) INTO heads
    FROM issuance_service.alembic_version;
    IF heads = ARRAY['issuance_event_owner'] THEN
        RETURN;
    END IF;
    IF heads IS DISTINCT FROM ARRAY['merge_issuance_heads'] THEN
        RAISE EXCEPTION 'unsupported issuance Alembic head: %', heads;
    END IF;

    ALTER TABLE issuance_service.evidence_policy_reviews
        DROP CONSTRAINT ck_evidence_policy_reviews_resolution_claim;
    ALTER TABLE issuance_service.evidence_policy_reviews
        ADD CONSTRAINT ck_evidence_policy_reviews_resolution_claim CHECK (
            (resolution_claim_token IS NULL AND resolution_claim_action IS NULL
                AND resolution_claimed_at IS NULL)
            OR (status = 'open' AND resolution_claim_token IS NOT NULL
                AND resolution_claim_action IN
                    ('dismiss', 'suspend', 'revoke', 'evidence_recovered')
                AND resolution_claimed_at IS NOT NULL)
        );

    ALTER TABLE issuance_service.application_templates
        ADD COLUMN management_version BIGINT NOT NULL DEFAULT 1,
        ADD COLUMN idempotency_key_hash VARCHAR(64),
        ADD COLUMN idempotency_request_hash VARCHAR(64),
        ADD CONSTRAINT ck_application_templates_management_version
            CHECK (management_version > 0),
        ADD CONSTRAINT ck_application_templates_idempotency_pair CHECK (
            (idempotency_key_hash IS NULL AND idempotency_request_hash IS NULL)
            OR (idempotency_key_hash IS NOT NULL AND idempotency_request_hash IS NOT NULL)
        ),
        ADD CONSTRAINT ck_application_templates_idempotency_key_hash CHECK (
            idempotency_key_hash IS NULL OR idempotency_key_hash ~ '^[0-9a-f]{64}$'
        ),
        ADD CONSTRAINT ck_application_templates_idempotency_request_hash CHECK (
            idempotency_request_hash IS NULL OR idempotency_request_hash ~ '^[0-9a-f]{64}$'
        );
    CREATE UNIQUE INDEX ux_application_templates_org_idempotency_key_hash
        ON issuance_service.application_templates
            (organization_id, idempotency_key_hash)
        WHERE idempotency_key_hash IS NOT NULL;

    ALTER TABLE issuance_service.physical_document_jobs
        ADD COLUMN revocation_profile_id VARCHAR;
    ALTER TABLE issuance_service.issuance_events
        ADD COLUMN organization_id VARCHAR;
    UPDATE issuance_service.issuance_events AS evt
        SET organization_id = tx.organization_id
        FROM issuance_service.issuance_transactions AS tx
        WHERE evt.transaction_id = tx.id;
    UPDATE issuance_service.issuance_events AS evt
        SET organization_id = app.organization_id
        FROM issuance_service.applications AS app
        WHERE evt.organization_id IS NULL AND evt.application_id = app.id;
    CREATE INDEX ix_issuance_events_organization_id
        ON issuance_service.issuance_events (organization_id);

    UPDATE issuance_service.alembic_version
        SET version_num = 'issuance_event_owner'
        WHERE version_num = 'merge_issuance_heads';
END
$bridge$;
