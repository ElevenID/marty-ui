-- Explicit human review/confirmation is separate from current representation
-- authority. Provision distinct, non-inheriting producer roles outside this
-- migration. Neither lifecycle/runtime readers nor the consent producer may
-- write authority observations; the authority producer may not write consent.
CREATE TABLE delegated_authority_service.approval_storage_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    instance_id UUID NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO delegated_authority_service.approval_storage_identity (singleton) VALUES (true);
CREATE TRIGGER approval_storage_identity_immutable BEFORE UPDATE OR DELETE ON delegated_authority_service.approval_storage_identity
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER approval_storage_identity_no_truncate BEFORE TRUNCATE ON delegated_authority_service.approval_storage_identity
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

CREATE TABLE delegated_authority_service.approval_reviews (
    organization_id UUID NOT NULL,
    review_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    grant_revision BIGINT NOT NULL CHECK (grant_revision BETWEEN 1 AND 9007199254740991),
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    grant_document JSONB NOT NULL,
    actor_id UUID NOT NULL,
    session_ref TEXT NOT NULL CHECK (session_ref ~ '^urn:marty:session:sha256:[0-9a-f]{64}$'),
    profile TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,review_id),
    FOREIGN KEY (organization_id,grant_id,grant_revision)
        REFERENCES delegated_authority_service.grant_lifecycle_events (organization_id,grant_id,revision),
    CHECK (delegated_authority_service.grant_instant(created_at)
        < delegated_authority_service.grant_instant(expires_at)),
    CHECK (delegated_authority_service.grant_instant(expires_at)
        <= delegated_authority_service.grant_instant(created_at) + 300)
);

CREATE TABLE delegated_authority_service.approval_confirmation_bindings (
    organization_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    confirmation_id UUID NOT NULL,
    review_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    terms_digest TEXT NOT NULL CHECK (terms_digest ~ '^sha256:[0-9a-f]{64}$'),
    session_ref TEXT NOT NULL CHECK (session_ref ~ '^urn:marty:session:sha256:[0-9a-f]{64}$'),
    evidence_ref TEXT NOT NULL,
    authority_evidence_ref TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,actor_id,confirmation_id),
    UNIQUE (organization_id,review_id),
    UNIQUE (organization_id,evidence_ref),
    FOREIGN KEY (organization_id,review_id)
        REFERENCES delegated_authority_service.approval_reviews (organization_id,review_id),
    FOREIGN KEY (organization_id,evidence_ref)
        REFERENCES delegated_authority_service.consent_confirmations (organization_id,evidence_ref),
    FOREIGN KEY (organization_id,authority_evidence_ref)
        REFERENCES delegated_authority_service.representation_authority_sources (organization_id,authority_evidence_ref)
);

-- Provenance of each independently performed Organization source check. A
-- refresh appends a new assertion AND observation in one authority transaction;
-- a read never changes either timestamp. Missing provenance fails admission.
CREATE TABLE delegated_authority_service.organization_authority_observations (
    organization_id UUID NOT NULL,
    authority_evidence_ref TEXT NOT NULL,
    revision BIGINT NOT NULL,
    user_id UUID NOT NULL,
    member_id UUID,
    source TEXT NOT NULL CHECK (source = 'urn:marty:organization-store:v1'),
    permission TEXT NOT NULL CHECK (permission = 'delegation-grant:approve'),
    authorized BOOLEAN NOT NULL,
    observed_at TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,authority_evidence_ref,revision),
    FOREIGN KEY (organization_id,authority_evidence_ref,revision)
        REFERENCES delegated_authority_service.representation_authority_assertions (organization_id,authority_evidence_ref,revision),
    CHECK (NOT authorized OR member_id IS NOT NULL)
);

CREATE FUNCTION delegated_authority_service.guard_approval_review()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    g delegated_authority_service.delegation_grants%ROWTYPE;
BEGIN
    SELECT * INTO STRICT g FROM delegated_authority_service.delegation_grants
      WHERE organization_id=NEW.organization_id AND id=NEW.grant_id FOR UPDATE;
    IF g.status <> 'PENDING' OR g.revision <> NEW.grant_revision
       OR g.terms_digest IS DISTINCT FROM NEW.terms_digest
       OR g.grant_document IS DISTINCT FROM NEW.grant_document
       OR (g.grant_document #>> '{terms,grantor,type}') IS DISTINCT FROM 'USER'
       OR (g.grant_document #>> '{terms,grantor,id}') IS DISTINCT FROM ('urn:marty:user:' || NEW.actor_id::TEXT)
       OR (g.grant_document #>> '{terms,subject,type}') IS DISTINCT FROM 'ORGANIZATION'
       OR (g.grant_document #>> '{terms,subject,id}') IS DISTINCT FROM ('urn:marty:organization:' || NEW.organization_id::TEXT)
       OR (g.grant_document #>> '{terms,binding,method}') IS DISTINCT FROM 'KEY'
       OR (g.grant_document #>> '{authority,mode}') IS DISTINCT FROM 'MANAGED'
       OR (g.grant_document #>> '{authority,issuer,type}') IS DISTINCT FROM 'ORGANIZATION'
       OR delegated_authority_service.grant_instant(NEW.created_at) < extract(epoch FROM g.created_at)
       OR delegated_authority_service.grant_instant(NEW.created_at) > extract(epoch FROM clock_timestamp())
       OR delegated_authority_service.grant_instant(NEW.expires_at) <= extract(epoch FROM clock_timestamp())
       OR delegated_authority_service.grant_instant(NEW.expires_at) > delegated_authority_service.grant_instant(g.grant_document #>> '{terms,valid_until}')
    THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='approval review does not match the immutable pending KEY grant';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION delegated_authority_service.guard_approval_confirmation_binding()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r delegated_authority_service.approval_reviews%ROWTYPE;
    c delegated_authority_service.consent_confirmations%ROWTYPE;
    g delegated_authority_service.delegation_grants%ROWTYPE;
BEGIN
    SELECT * INTO STRICT r FROM delegated_authority_service.approval_reviews
      WHERE organization_id=NEW.organization_id AND review_id=NEW.review_id;
    SELECT * INTO STRICT c FROM delegated_authority_service.consent_confirmations
      WHERE organization_id=NEW.organization_id AND evidence_ref=NEW.evidence_ref;
    SELECT * INTO STRICT g FROM delegated_authority_service.delegation_grants
      WHERE organization_id=NEW.organization_id AND id=NEW.grant_id FOR UPDATE;
    IF r.actor_id <> NEW.actor_id OR r.grant_id <> NEW.grant_id
       OR r.session_ref IS DISTINCT FROM NEW.session_ref OR r.terms_digest IS DISTINCT FROM NEW.terms_digest
       OR g.status <> 'PENDING' OR g.revision <> r.grant_revision OR g.grant_document IS DISTINCT FROM r.grant_document
       OR c.grant_id <> NEW.grant_id OR c.terms_digest IS DISTINCT FROM NEW.terms_digest
       OR c.authority_evidence_ref IS DISTINCT FROM NEW.authority_evidence_ref
       OR c.confirmed_at IS DISTINCT FROM NEW.confirmed_at OR c.valid_until IS DISTINCT FROM NEW.valid_until
       OR c.profile IS DISTINCT FROM r.profile OR c.adapter_version IS DISTINCT FROM r.adapter_version
       OR c.artifact_digest IS DISTINCT FROM r.artifact_digest
       OR delegated_authority_service.grant_instant(NEW.confirmed_at) < delegated_authority_service.grant_instant(r.created_at)
       OR delegated_authority_service.grant_instant(r.expires_at) <= extract(epoch FROM clock_timestamp())
    THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='explicit confirmation does not match its original review';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE FUNCTION delegated_authority_service.guard_organization_authority_observation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    a delegated_authority_service.representation_authority_assertions%ROWTYPE;
    s delegated_authority_service.representation_authority_sources%ROWTYPE;
BEGIN
    SELECT * INTO STRICT a FROM delegated_authority_service.representation_authority_assertions
      WHERE organization_id=NEW.organization_id AND authority_evidence_ref=NEW.authority_evidence_ref AND revision=NEW.revision;
    SELECT * INTO STRICT s FROM delegated_authority_service.representation_authority_sources
      WHERE organization_id=NEW.organization_id AND authority_evidence_ref=NEW.authority_evidence_ref;
    IF (s.grantor ->> 'type') IS DISTINCT FROM 'USER'
       OR (s.grantor ->> 'id') IS DISTINCT FROM ('urn:marty:user:' || NEW.user_id::TEXT)
       OR (s.subject ->> 'type') IS DISTINCT FROM 'ORGANIZATION'
       OR (s.subject ->> 'id') IS DISTINCT FROM ('urn:marty:organization:' || NEW.organization_id::TEXT)
       OR NEW.authorized IS DISTINCT FROM (a.state='AUTHORIZED')
       OR NEW.observed_at IS DISTINCT FROM a.asserted_at OR NEW.valid_until IS DISTINCT FROM a.valid_until
       OR (NEW.authorized AND delegated_authority_service.grant_instant(NEW.valid_until)
            > delegated_authority_service.grant_instant(NEW.observed_at) + 15)
    THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='authority provenance does not match its independent assertion';
    END IF;
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END
$$;

CREATE TRIGGER approval_reviews_binding BEFORE INSERT ON delegated_authority_service.approval_reviews
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_approval_review();
CREATE TRIGGER approval_reviews_immutable BEFORE UPDATE OR DELETE ON delegated_authority_service.approval_reviews
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER approval_reviews_no_truncate BEFORE TRUNCATE ON delegated_authority_service.approval_reviews
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER approval_confirmation_bindings_guard BEFORE INSERT ON delegated_authority_service.approval_confirmation_bindings
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_approval_confirmation_binding();
CREATE TRIGGER approval_confirmation_bindings_immutable BEFORE UPDATE OR DELETE ON delegated_authority_service.approval_confirmation_bindings
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER approval_confirmation_bindings_no_truncate BEFORE TRUNCATE ON delegated_authority_service.approval_confirmation_bindings
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER organization_authority_observations_guard BEFORE INSERT ON delegated_authority_service.organization_authority_observations
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_organization_authority_observation();
CREATE TRIGGER organization_authority_observations_immutable BEFORE UPDATE OR DELETE ON delegated_authority_service.organization_authority_observations
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER organization_authority_observations_no_truncate BEFORE TRUNCATE ON delegated_authority_service.organization_authority_observations
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

REVOKE ALL ON ALL TABLES IN SCHEMA delegated_authority_service FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA delegated_authority_service FROM PUBLIC;
-- Consent role: SELECT/INSERT approval_reviews, approval_confirmation_bindings,
-- consent_confirmations, consent_withdrawals; SELECT grants and authority records.
-- Authority role: SELECT/INSERT sources, assertions, organization_authority_observations;
-- SELECT grants. Runtime/read role: SELECT only. No role owns these objects,
-- can SET ROLE to another producer, or can create schema objects.
