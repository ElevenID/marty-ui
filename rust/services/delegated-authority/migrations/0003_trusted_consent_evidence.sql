-- These records are written only by configured trusted confirmation/authority
-- producers. The lifecycle runtime gets SELECT access, never source-write access.
-- No payload arriving through a public request is authenticated by this schema.
CREATE TABLE delegated_authority_service.consent_confirmations (
    organization_id UUID NOT NULL,
    evidence_ref TEXT NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 1024),
    authority_evidence_ref TEXT NOT NULL CHECK (length(authority_evidence_ref) BETWEEN 1 AND 1024),
    grant_id UUID NOT NULL,
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    grantor JSONB NOT NULL CHECK (jsonb_typeof(grantor) = 'object'),
    subject JSONB NOT NULL CHECK (jsonb_typeof(subject) = 'object'),
    issuer JSONB NOT NULL CHECK (jsonb_typeof(issuer) = 'object'),
    profile TEXT NOT NULL CHECK (length(profile) BETWEEN 1 AND 1024),
    adapter_version TEXT NOT NULL CHECK (length(adapter_version) BETWEEN 1 AND 64),
    artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    confirmed_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision = 1),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,evidence_ref),
    FOREIGN KEY (organization_id,grant_id)
        REFERENCES delegated_authority_service.delegation_grants (organization_id,id),
    CHECK (delegated_authority_service.grant_instant(confirmed_at)
        < delegated_authority_service.grant_instant(valid_until))
);

CREATE TABLE delegated_authority_service.consent_withdrawals (
    organization_id UUID NOT NULL,
    evidence_ref TEXT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 2 CHECK (revision = 2),
    withdrawn_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,evidence_ref),
    FOREIGN KEY (organization_id,evidence_ref)
        REFERENCES delegated_authority_service.consent_confirmations (organization_id,evidence_ref)
);

CREATE TABLE delegated_authority_service.representation_authority_sources (
    organization_id UUID NOT NULL,
    authority_evidence_ref TEXT NOT NULL CHECK (length(authority_evidence_ref) BETWEEN 1 AND 1024),
    evidence_ref TEXT NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 1024),
    grant_id UUID NOT NULL,
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    grantor JSONB NOT NULL CHECK (jsonb_typeof(grantor) = 'object'),
    subject JSONB NOT NULL CHECK (jsonb_typeof(subject) = 'object'),
    issuer JSONB NOT NULL CHECK (jsonb_typeof(issuer) = 'object'),
    profile TEXT NOT NULL CHECK (length(profile) BETWEEN 1 AND 1024),
    adapter_version TEXT NOT NULL CHECK (length(adapter_version) BETWEEN 1 AND 64),
    artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,authority_evidence_ref),
    FOREIGN KEY (organization_id,grant_id)
        REFERENCES delegated_authority_service.delegation_grants (organization_id,id)
);

CREATE TABLE delegated_authority_service.representation_authority_assertions (
    organization_id UUID NOT NULL,
    authority_evidence_ref TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('AUTHORIZED','REVOKED')),
    asserted_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,authority_evidence_ref,revision),
    FOREIGN KEY (organization_id,authority_evidence_ref)
        REFERENCES delegated_authority_service.representation_authority_sources (organization_id,authority_evidence_ref)
);

-- Fixed, qualified trigger code runs as the migration owner so producers need
-- INSERT/SELECT only; it does not require granting UPDATE to take a source lock.
CREATE FUNCTION delegated_authority_service.guard_consent_source()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    grant_record delegated_authority_service.delegation_grants%ROWTYPE;
BEGIN
    NEW.recorded_at := clock_timestamp();
    SELECT * INTO STRICT grant_record FROM delegated_authority_service.delegation_grants
        WHERE organization_id=NEW.organization_id AND id=NEW.grant_id;
    IF NEW.terms_digest IS DISTINCT FROM grant_record.terms_digest
        OR NEW.grantor IS DISTINCT FROM (grant_record.grant_document #> '{terms,grantor}')
        OR NEW.subject IS DISTINCT FROM (grant_record.grant_document #> '{terms,subject}')
        OR NEW.issuer IS DISTINCT FROM (grant_record.grant_document #> '{authority,issuer}')
        OR (grant_record.grant_document #>> '{authority,mode}') IS DISTINCT FROM 'MANAGED'
    THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='trusted evidence binding does not match the managed grant';
    END IF;
    IF TG_TABLE_NAME='consent_confirmations' THEN
        IF delegated_authority_service.grant_instant(NEW.confirmed_at)
                < delegated_authority_service.grant_instant(grant_record.grant_document ->> 'created_at')
            OR delegated_authority_service.grant_instant(NEW.confirmed_at) > extract(epoch FROM clock_timestamp())
            OR delegated_authority_service.grant_instant(NEW.valid_until)
                > delegated_authority_service.grant_instant(grant_record.grant_document #>> '{terms,valid_until}')
        THEN
            RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='trusted confirmation timing is invalid';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER consent_confirmations_binding
BEFORE INSERT ON delegated_authority_service.consent_confirmations
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_consent_source();
CREATE TRIGGER representation_authority_sources_binding
BEFORE INSERT ON delegated_authority_service.representation_authority_sources
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_consent_source();

CREATE FUNCTION delegated_authority_service.guard_authority_assertion()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    source_record delegated_authority_service.representation_authority_sources%ROWTYPE;
    previous delegated_authority_service.representation_authority_assertions%ROWTYPE;
    grant_record delegated_authority_service.delegation_grants%ROWTYPE;
BEGIN
    NEW.recorded_at := clock_timestamp();
    SELECT * INTO STRICT source_record FROM delegated_authority_service.representation_authority_sources
        WHERE organization_id=NEW.organization_id AND authority_evidence_ref=NEW.authority_evidence_ref
        FOR UPDATE;
    SELECT * INTO previous FROM delegated_authority_service.representation_authority_assertions
        WHERE organization_id=NEW.organization_id AND authority_evidence_ref=NEW.authority_evidence_ref
        ORDER BY revision DESC LIMIT 1;
    IF previous.revision IS NULL THEN
        IF NEW.revision<>1 OR NEW.state<>'AUTHORIZED' THEN
            RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='authority assertion initial revision conflict';
        END IF;
    ELSE
        IF previous.state='REVOKED' OR previous.revision>=9007199254740991
            OR NEW.revision<>previous.revision+1
            OR delegated_authority_service.grant_instant(NEW.asserted_at)
                <= delegated_authority_service.grant_instant(previous.asserted_at)
        THEN
            RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='authority assertion revision or state conflict';
        END IF;
    END IF;
    SELECT * INTO STRICT grant_record FROM delegated_authority_service.delegation_grants
        WHERE organization_id=source_record.organization_id AND id=source_record.grant_id;
    IF delegated_authority_service.grant_instant(NEW.asserted_at) > extract(epoch FROM clock_timestamp())
        OR delegated_authority_service.grant_instant(NEW.asserted_at)
            < delegated_authority_service.grant_instant(grant_record.grant_document ->> 'created_at')
        OR delegated_authority_service.grant_instant(NEW.valid_until)
            > delegated_authority_service.grant_instant(grant_record.grant_document #>> '{terms,valid_until}')
        OR (NEW.state='AUTHORIZED' AND (
            delegated_authority_service.grant_instant(NEW.asserted_at)
                >= delegated_authority_service.grant_instant(NEW.valid_until)
            OR grant_record.status IN ('REVOKED','EXPIRED')
        ))
    THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='authority assertion timing or grant status is invalid';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER representation_authority_assertions_guard
BEFORE INSERT ON delegated_authority_service.representation_authority_assertions
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_authority_assertion();

CREATE FUNCTION delegated_authority_service.stamp_consent_withdrawal()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    NEW.withdrawn_at := clock_timestamp();
    RETURN NEW;
END
$$;
CREATE TRIGGER consent_withdrawals_stamp
BEFORE INSERT ON delegated_authority_service.consent_withdrawals
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.stamp_consent_withdrawal();

CREATE TRIGGER consent_confirmations_immutable
BEFORE UPDATE OR DELETE ON delegated_authority_service.consent_confirmations
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER consent_confirmations_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.consent_confirmations
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER consent_withdrawals_immutable
BEFORE UPDATE OR DELETE ON delegated_authority_service.consent_withdrawals
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER consent_withdrawals_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.consent_withdrawals
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER representation_authority_sources_immutable
BEFORE UPDATE OR DELETE ON delegated_authority_service.representation_authority_sources
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER representation_authority_sources_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.representation_authority_sources
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER representation_authority_assertions_immutable
BEFORE UPDATE OR DELETE ON delegated_authority_service.representation_authority_assertions
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER representation_authority_assertions_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.representation_authority_assertions
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

COMMENT ON TABLE delegated_authority_service.consent_confirmations IS
    'Immutable explicit confirmations written only by a configured trusted approval surface. A database row is not a substitute for authenticating that surface.';
COMMENT ON TABLE delegated_authority_service.representation_authority_assertions IS
    'Append-only current representation-authority assertions, explicitly refreshed by the trusted source. Reads never renew assertion freshness; revocation is terminal.';

REVOKE ALL ON delegated_authority_service.consent_confirmations,
    delegated_authority_service.consent_withdrawals,
    delegated_authority_service.representation_authority_sources,
    delegated_authority_service.representation_authority_assertions FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_consent_source(),
    delegated_authority_service.guard_authority_assertion(),
    delegated_authority_service.stamp_consent_withdrawal() FROM PUBLIC;
