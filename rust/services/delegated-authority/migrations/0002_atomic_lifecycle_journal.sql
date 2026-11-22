-- This service has not shipped an import path. Do not manufacture a lifecycle
-- history for pre-existing snapshots: an operator must reconcile those records
-- with their authoritative audit source before adopting the managed repository.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM delegated_authority_service.delegation_grants) THEN
        RAISE EXCEPTION 'delegation lifecycle journal requires an empty initial grant table';
    END IF;
END
$$;

CREATE FUNCTION delegated_authority_service.grant_instant(value TEXT)
RETURNS NUMERIC LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
BEGIN
    IF value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN
        RAISE EXCEPTION 'delegation timestamp must use canonical RFC3339 UTC';
    END IF;
    RETURN extract(epoch FROM (substring(value FROM 1 FOR 19)::TIMESTAMP AT TIME ZONE 'UTC'))
        + CASE WHEN length(value) > 20
            THEN ('0' || substring(value FROM 20 FOR length(value) - 20))::NUMERIC
            ELSE 0 END;
END
$$;

ALTER TABLE delegated_authority_service.delegation_grants
    ADD CONSTRAINT delegation_grants_protocol_revision
        CHECK (revision <= 9007199254740991),
    ADD CONSTRAINT delegation_grants_timestamp_order
        CHECK (created_at <= updated_at),
    ADD CONSTRAINT delegation_grants_document_columns
        CHECK (
            jsonb_typeof(grant_document) = 'object'
            AND (grant_document ->> 'id') IS NOT NULL
            AND (grant_document ->> 'id')::UUID = id
            AND (grant_document ->> 'organization_id') IS NOT NULL
            AND (grant_document ->> 'organization_id')::UUID = organization_id
            AND (grant_document ->> 'status') IS NOT NULL
            AND (grant_document ->> 'status') = status
            AND (grant_document ->> 'revision') IS NOT NULL
            AND (grant_document ->> 'revision')::BIGINT = revision
            AND (grant_document ->> 'terms_digest') IS NOT NULL
            AND (grant_document ->> 'terms_digest') = terms_digest
            AND (grant_document ->> 'created_at') IS NOT NULL
            AND (grant_document ->> 'created_at')::TIMESTAMPTZ = created_at
            AND (grant_document ->> 'updated_at') IS NOT NULL
            AND (grant_document ->> 'updated_at')::TIMESTAMPTZ = updated_at
        );

CREATE TABLE delegated_authority_service.grant_lifecycle_events (
    organization_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    previous_status TEXT CHECK (previous_status IN ('PENDING','ACTIVE','SUSPENDED')),
    status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED','EXPIRED')),
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at TEXT NOT NULL CHECK (occurred_at ~ 'Z$'),
    PRIMARY KEY (organization_id, grant_id, revision),
    FOREIGN KEY (organization_id, grant_id)
        REFERENCES delegated_authority_service.delegation_grants (organization_id, id),
    CONSTRAINT grant_lifecycle_events_initial_revision CHECK (
        (revision = 1 AND previous_status IS NULL AND status = 'PENDING')
        OR (revision > 1 AND previous_status IS NOT NULL AND status <> 'PENDING')
    )
);

COMMENT ON TABLE delegated_authority_service.grant_lifecycle_events IS
    'Atomic append-only lifecycle journal. Contains no actor, consent evidence, principal identifiers, or full grant document; runtime security audit attribution is separate.';

CREATE FUNCTION delegated_authority_service.guard_grant_lifecycle()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'authoritative delegation grants cannot be deleted';
    END IF;
    IF (NEW.grant_document #>> '{authority,mode}') IS DISTINCT FROM 'MANAGED' THEN
        RAISE EXCEPTION 'managed repository cannot own external authority';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'PENDING' OR NEW.revision <> 1
            OR NEW.created_at <> NEW.updated_at
            OR NEW.grant_document ? 'approval'
            OR (NEW.grant_document #>> '{terms,valid_until}') IS NULL
            OR delegated_authority_service.grant_instant(NEW.grant_document ->> 'created_at')
                >= delegated_authority_service.grant_instant(NEW.grant_document #>> '{terms,valid_until}')
        THEN
            RAISE EXCEPTION 'delegation insertion requires a new pending proposal';
        END IF;
    ELSE
        IF NEW.id <> OLD.id OR NEW.organization_id <> OLD.organization_id
            OR NEW.terms_digest <> OLD.terms_digest OR NEW.created_at <> OLD.created_at
            OR (NEW.grant_document - ARRAY['status','revision','updated_at','approval'])
                IS DISTINCT FROM
                (OLD.grant_document - ARRAY['status','revision','updated_at','approval'])
            OR (OLD.grant_document ? 'approval'
                AND (NEW.grant_document -> 'approval') IS DISTINCT FROM (OLD.grant_document -> 'approval'))
        THEN
            RAISE EXCEPTION 'immutable delegation identity, authority, terms or approval changed';
        END IF;
        IF OLD.revision >= 9007199254740991 OR NEW.revision <> OLD.revision + 1
            OR delegated_authority_service.grant_instant(NEW.grant_document ->> 'updated_at')
                <= delegated_authority_service.grant_instant(OLD.grant_document ->> 'updated_at')
        THEN
            RAISE EXCEPTION 'delegation revision and timestamp must advance once';
        END IF;
        IF NOT (
            (OLD.status = 'PENDING' AND NEW.status IN ('ACTIVE','REVOKED','EXPIRED'))
            OR (OLD.status = 'ACTIVE' AND NEW.status IN ('SUSPENDED','REVOKED','EXPIRED'))
            OR (OLD.status = 'SUSPENDED' AND NEW.status IN ('ACTIVE','REVOKED','EXPIRED'))
        ) THEN
            RAISE EXCEPTION 'delegation lifecycle transition is not allowed';
        END IF;
        IF NEW.status = 'ACTIVE' AND (
            (NEW.grant_document #>> '{terms,valid_from}') IS NULL
            OR (NEW.grant_document #>> '{terms,valid_until}') IS NULL
            OR delegated_authority_service.grant_instant(NEW.grant_document ->> 'updated_at')
                < delegated_authority_service.grant_instant(NEW.grant_document #>> '{terms,valid_from}')
            OR delegated_authority_service.grant_instant(NEW.grant_document ->> 'updated_at')
                >= delegated_authority_service.grant_instant(NEW.grant_document #>> '{terms,valid_until}')
        ) THEN
            RAISE EXCEPTION 'delegation activation is outside its validity interval';
        END IF;
        IF NEW.status = 'EXPIRED' AND (
            (NEW.grant_document #>> '{terms,valid_until}') IS NULL
            OR delegated_authority_service.grant_instant(NEW.grant_document ->> 'updated_at')
                < delegated_authority_service.grant_instant(NEW.grant_document #>> '{terms,valid_until}')
        ) THEN
            RAISE EXCEPTION 'delegation cannot expire before its validity interval ends';
        END IF;
        IF NEW.status IN ('ACTIVE','SUSPENDED')
            AND jsonb_typeof(NEW.grant_document -> 'approval') IS DISTINCT FROM 'object'
        THEN
            RAISE EXCEPTION 'delegation activation requires approval evidence';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER delegation_grants_guard
BEFORE INSERT OR UPDATE OR DELETE ON delegated_authority_service.delegation_grants
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_grant_lifecycle();

-- Owned by the migration role. Runtime writers need no INSERT privilege on the
-- journal; the fixed schema-qualified trigger is the sole writer they can use.
CREATE FUNCTION delegated_authority_service.journal_grant_lifecycle()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO delegated_authority_service.grant_lifecycle_events
        (organization_id, grant_id, revision, previous_status, status, terms_digest, occurred_at)
    VALUES (NEW.organization_id, NEW.id, NEW.revision,
        CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.status END,
        NEW.status, NEW.terms_digest, NEW.grant_document ->> 'updated_at');
    RETURN NEW;
END
$$;

CREATE TRIGGER delegation_grants_journal
AFTER INSERT OR UPDATE ON delegated_authority_service.delegation_grants
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.journal_grant_lifecycle();

CREATE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'delegation lifecycle records are append-only';
END
$$;

CREATE TRIGGER grant_lifecycle_events_append_only
BEFORE UPDATE OR DELETE ON delegated_authority_service.grant_lifecycle_events
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

CREATE TRIGGER delegation_grants_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.delegation_grants
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

CREATE TRIGGER grant_lifecycle_events_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.grant_lifecycle_events
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

-- Provision the runtime role separately: USAGE on this schema; SELECT, INSERT,
-- UPDATE on delegation_grants; SELECT on grant_lifecycle_events/schema_migrations;
-- and EXECUTE on the pure grant_instant(TEXT) validation helper. Do not give the
-- runtime ownership, DDL, DELETE, TRUNCATE, or journal INSERT/UPDATE privileges.
REVOKE ALL ON SCHEMA delegated_authority_service FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA delegated_authority_service FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA delegated_authority_service FROM PUBLIC;
