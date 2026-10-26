-- Local administrative disposition is separate from physical bureau activity.
-- Retain jobs and all their existing quality/material/bureau history.
CREATE UNIQUE INDEX IF NOT EXISTS ux_physical_document_jobs_id_organization
    ON issuance_service.physical_document_jobs (id, organization_id);

CREATE TABLE IF NOT EXISTS issuance_service.passport_job_administrative_cancellations (
    job_id text CONSTRAINT pk_passport_administrative_cancellation PRIMARY KEY,
    organization_id text NOT NULL,
    event_id uuid NOT NULL CONSTRAINT ux_passport_cancellation_event UNIQUE,
    prior_status varchar(40) NOT NULL,
    reason_code varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_reason_code CHECK (reason_code = 'ADMINISTRATIVE_ABANDONMENT'),
    reason text NOT NULL CONSTRAINT ck_passport_cancel_reason_length CHECK (octet_length(reason) BETWEEN 1 AND 512),
    actor_kind varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_actor_kind CHECK (actor_kind = 'AUTHENTICATED_PASSPORT_TENANT'),
    actor_organization_id text NOT NULL CONSTRAINT ck_passport_cancel_actor_tenant CHECK (actor_organization_id = organization_id),
    recorded_at timestamptz NOT NULL,
    idempotency_key_hash varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_key_hash CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    request_hash varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_request_hash CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    bureau_cancellation_requested boolean NOT NULL CONSTRAINT ck_passport_cancel_not_physical CHECK (NOT bureau_cancellation_requested),
    CONSTRAINT fk_passport_cancel_owned_job FOREIGN KEY (job_id,organization_id)
        REFERENCES issuance_service.physical_document_jobs (id,organization_id) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION issuance_service.guard_passport_cancellation_history()
RETURNS trigger LANGUAGE plpgsql AS $cancellation_history_guard$
BEGIN
    RAISE EXCEPTION 'passport administrative cancellation history is immutable';
END;
$cancellation_history_guard$;
DROP TRIGGER IF EXISTS trg_passport_cancellation_history
    ON issuance_service.passport_job_administrative_cancellations;
CREATE TRIGGER trg_passport_cancellation_history
    BEFORE UPDATE OR DELETE ON issuance_service.passport_job_administrative_cancellations
    FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_passport_cancellation_history();
DROP TRIGGER IF EXISTS trg_passport_cancellation_history_truncate
    ON issuance_service.passport_job_administrative_cancellations;
CREATE TRIGGER trg_passport_cancellation_history_truncate
    BEFORE TRUNCATE ON issuance_service.passport_job_administrative_cancellations
    FOR EACH STATEMENT EXECUTE FUNCTION issuance_service.guard_passport_cancellation_history();

CREATE OR REPLACE FUNCTION issuance_service.guard_administratively_cancelled_passport_job()
RETURNS trigger LANGUAGE plpgsql AS $cancelled_job_guard$
BEGIN
    IF OLD.status = 'CANCELLED' AND EXISTS (
        SELECT 1 FROM issuance_service.passport_job_administrative_cancellations
        WHERE job_id=OLD.id AND organization_id=OLD.organization_id
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'administratively cancelled passport job history is immutable';
        END IF;
        IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
            RAISE EXCEPTION 'administratively cancelled passport job history is immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$cancelled_job_guard$;
DROP TRIGGER IF EXISTS trg_administratively_cancelled_passport_job
    ON issuance_service.physical_document_jobs;
CREATE TRIGGER trg_administratively_cancelled_passport_job
    BEFORE UPDATE OR DELETE ON issuance_service.physical_document_jobs
    FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_administratively_cancelled_passport_job();
