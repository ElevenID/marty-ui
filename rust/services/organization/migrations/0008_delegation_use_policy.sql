-- Exact-operation delegation-use policy has its own owner and tables.
-- Generic policy-set CRUD and machine-authentication policy do not reach it.
CREATE TABLE IF NOT EXISTS organization_service.delegation_use_policies (
    organization_id UUID NOT NULL REFERENCES organization_service.organizations(id),
    policy_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    status TEXT NOT NULL CHECK (status IN ('DRAFT','ACTIVE','ARCHIVED')),
    snapshot_bytes BYTEA NOT NULL CHECK (octet_length(snapshot_bytes) BETWEEN 1 AND 262144),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY (organization_id,policy_id),
    CONSTRAINT delegation_policy_current_bytes CHECK (convert_from(snapshot_bytes,'UTF8')::JSONB=snapshot),
    CONSTRAINT delegation_policy_current_digest CHECK (snapshot_digest='sha256:'||encode(sha256(snapshot_bytes),'hex'))
);
CREATE TABLE IF NOT EXISTS organization_service.delegation_use_policy_history (
    organization_id UUID NOT NULL,
    policy_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    action TEXT NOT NULL CHECK (action IN ('CREATE','REPLACE','ACTIVATE','ARCHIVE')),
    actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 255),
    occurred_at TIMESTAMPTZ NOT NULL,
    snapshot_bytes BYTEA NOT NULL CHECK (octet_length(snapshot_bytes) BETWEEN 1 AND 262144),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY (organization_id,policy_id,revision),
    FOREIGN KEY (organization_id,policy_id) REFERENCES organization_service.delegation_use_policies(organization_id,policy_id),
    CONSTRAINT delegation_policy_history_bytes CHECK (convert_from(snapshot_bytes,'UTF8')::JSONB=snapshot),
    CONSTRAINT delegation_policy_history_digest CHECK (snapshot_digest='sha256:'||encode(sha256(snapshot_bytes),'hex'))
);
CREATE TABLE IF NOT EXISTS organization_service.delegation_use_policy_observations (
    organization_id UUID NOT NULL,
    evidence_ref TEXT NOT NULL,
    policy_id UUID NOT NULL,
    policy_revision BIGINT NOT NULL,
    evidence_bytes BYTEA NOT NULL CHECK (octet_length(evidence_bytes) BETWEEN 1 AND 1048576),
    evidence_document JSONB NOT NULL CHECK (jsonb_typeof(evidence_document)='object'),
    evidence_digest TEXT NOT NULL,
    original_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    retained_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,evidence_ref),
    FOREIGN KEY (organization_id,policy_id,policy_revision) REFERENCES organization_service.delegation_use_policy_history(organization_id,policy_id,revision),
    CONSTRAINT delegation_policy_observation_bytes CHECK (convert_from(evidence_bytes,'UTF8')::JSONB=evidence_document),
    CONSTRAINT delegation_policy_observation_digest CHECK (evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex')),
    CONSTRAINT delegation_policy_observation_reference CHECK (evidence_ref='urn:marty:delegation-use-policy-source:'||evidence_digest),
    CONSTRAINT delegation_policy_observation_times CHECK (original_at<=observed_at AND observed_at<=completed_at AND completed_at<=retained_at AND retained_at<valid_until AND valid_until<=original_at+INTERVAL '30 seconds')
);

CREATE OR REPLACE FUNCTION organization_service.guard_delegation_use_policy()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DELEGATION_POLICY_IMMUTABLE_IDENTITY'; END IF;
    IF NEW.snapshot->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
       OR NEW.snapshot->>'policy_id' IS DISTINCT FROM NEW.policy_id::TEXT
       OR NEW.snapshot->>'revision' IS DISTINCT FROM NEW.revision::TEXT
       OR NEW.snapshot->>'status' IS DISTINCT FROM NEW.status
       OR NEW.snapshot->>'policy_type' IS DISTINCT FROM 'DELEGATION_USE'
       OR NEW.snapshot->>'schema_version' IS DISTINCT FROM 'MartyDelegatedUse/1.0'
       OR length(NEW.snapshot->>'created_by') NOT BETWEEN 1 AND 255
       OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ>clock_timestamp()
       OR (NEW.snapshot->>'created_at')::TIMESTAMPTZ>(NEW.snapshot->>'updated_at')::TIMESTAMPTZ
       OR jsonb_typeof(NEW.snapshot->'actions') IS DISTINCT FROM 'array'
       OR jsonb_array_length(NEW.snapshot->'actions') NOT BETWEEN 1 AND 64
       OR jsonb_typeof(NEW.snapshot->'policies') IS DISTINCT FROM 'array'
       OR jsonb_array_length(NEW.snapshot->'policies') NOT BETWEEN 1 AND 32
       OR NEW.snapshot->>'policy_digest' !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_INVALID';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.status<>'DRAFT'
           OR NEW.snapshot->>'created_at' IS DISTINCT FROM NEW.snapshot->>'updated_at' THEN
            RAISE EXCEPTION 'DELEGATION_POLICY_EXPLICIT_CREATE_REQUIRED';
        END IF;
    ELSE
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.policy_id IS DISTINCT FROM OLD.policy_id
           OR NEW.revision IS DISTINCT FROM OLD.revision+1
           OR NEW.snapshot->>'created_by' IS DISTINCT FROM OLD.snapshot->>'created_by'
           OR NEW.snapshot->>'created_at' IS DISTINCT FROM OLD.snapshot->>'created_at'
           OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ<=(OLD.snapshot->>'updated_at')::TIMESTAMPTZ THEN
            RAISE EXCEPTION 'DELEGATION_POLICY_IMMUTABLE_IDENTITY';
        END IF;
        IF OLD.status='ACTIVE' AND (NEW.status<>'ARCHIVED'
           OR (NEW.snapshot-ARRAY['status','revision','updated_at']) IS DISTINCT FROM (OLD.snapshot-ARRAY['status','revision','updated_at'])) THEN
            RAISE EXCEPTION 'DELEGATION_POLICY_ARCHIVE_BEFORE_REPLACE';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_delegation_use_policy_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p organization_service.delegation_use_policies; previous JSONB;
BEGIN
    SELECT * INTO p FROM organization_service.delegation_use_policies WHERE organization_id=NEW.organization_id AND policy_id=NEW.policy_id;
    IF NOT FOUND OR p.revision IS DISTINCT FROM NEW.revision OR p.snapshot_bytes IS DISTINCT FROM NEW.snapshot_bytes
       OR p.snapshot IS DISTINCT FROM NEW.snapshot OR p.snapshot_digest IS DISTINCT FROM NEW.snapshot_digest
       OR (p.snapshot->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.occurred_at THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_HISTORY_BINDING';
    END IF;
    IF NEW.revision=1 THEN
        IF NEW.action<>'CREATE' OR p.status<>'DRAFT' OR NEW.actor_user_id IS DISTINCT FROM p.snapshot->>'created_by' THEN
            RAISE EXCEPTION 'DELEGATION_POLICY_CREATE_HISTORY';
        END IF;
    ELSE
        SELECT snapshot INTO previous FROM organization_service.delegation_use_policy_history
            WHERE organization_id=NEW.organization_id AND policy_id=NEW.policy_id AND revision=NEW.revision-1;
        IF NOT FOUND OR (previous->>'updated_at')::TIMESTAMPTZ>=NEW.occurred_at
           OR (NEW.action='ACTIVATE' AND (previous->>'status' NOT IN ('DRAFT','ARCHIVED') OR p.status<>'ACTIVE'
                OR (NEW.snapshot-ARRAY['revision','status','updated_at']) IS DISTINCT FROM (previous-ARRAY['revision','status','updated_at'])))
           OR (NEW.action='ARCHIVE' AND (previous->>'status'<>'ACTIVE' OR p.status<>'ARCHIVED'
                OR (NEW.snapshot-ARRAY['revision','status','updated_at']) IS DISTINCT FROM (previous-ARRAY['revision','status','updated_at'])))
           OR (NEW.action='REPLACE' AND (previous->>'status' NOT IN ('DRAFT','ARCHIVED') OR p.status<>'DRAFT'))
           OR NEW.action='CREATE' THEN RAISE EXCEPTION 'DELEGATION_POLICY_TRANSITION'; END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_delegation_use_policy_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p organization_service.delegation_use_policies; n BIGINT; maximum BIGINT; original BYTEA;
BEGIN
    SELECT * INTO p FROM organization_service.delegation_use_policies WHERE organization_id=NEW.organization_id AND policy_id=NEW.policy_id;
    SELECT count(*),max(revision) INTO n,maximum FROM organization_service.delegation_use_policy_history
        WHERE organization_id=p.organization_id AND policy_id=p.policy_id;
    SELECT snapshot_bytes INTO original FROM organization_service.delegation_use_policy_history
        WHERE organization_id=p.organization_id AND policy_id=p.policy_id AND revision=p.revision;
    IF n<>p.revision OR maximum IS DISTINCT FROM p.revision OR original IS DISTINCT FROM p.snapshot_bytes THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_HISTORY_REQUIRED';
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION organization_service.reject_delegation_use_policy_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'DELEGATION_POLICY_EVIDENCE_IMMUTABLE'; END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_delegation_use_policy_observation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p organization_service.delegation_use_policies; h organization_service.delegation_use_policy_history; s JSONB;
BEGIN
    SELECT * INTO p FROM organization_service.delegation_use_policies WHERE organization_id=NEW.organization_id AND policy_id=NEW.policy_id;
    IF NOT FOUND OR p.status<>'ACTIVE' OR p.revision IS DISTINCT FROM NEW.policy_revision
       OR NOT EXISTS(SELECT 1 FROM organization_service.organizations WHERE id=NEW.organization_id AND status='active') THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_SOURCE_NOT_CURRENT';
    END IF;
    SELECT * INTO h FROM organization_service.delegation_use_policy_history WHERE organization_id=NEW.organization_id AND policy_id=NEW.policy_id AND revision=NEW.policy_revision;
    s:=NEW.evidence_document->'scope';
    IF NOT FOUND OR p.snapshot_bytes IS DISTINCT FROM h.snapshot_bytes
       OR NEW.evidence_document->>'profile' IS DISTINCT FROM 'urn:marty:delegation-use-policy-source:v1'
       OR NEW.evidence_document->'policy_snapshot' IS DISTINCT FROM h.snapshot
       OR NEW.evidence_document->>'history_digest' IS DISTINCT FROM h.snapshot_digest
       OR NEW.evidence_document->>'policy_digest' IS DISTINCT FROM p.snapshot->>'policy_digest'
       OR NEW.evidence_document->>'schema' IS DISTINCT FROM p.snapshot->>'schema'
       OR NEW.evidence_document->'entities' IS DISTINCT FROM jsonb_build_array(
            jsonb_build_object('uid',jsonb_build_object('type','MartyDelegatedUse::Principal','id',s#>>'{actor,id}'),'attrs','{}'::JSONB,'parents','[]'::JSONB),
            jsonb_build_object('uid',jsonb_build_object('type','MartyDelegatedUse::Resource','id',s->>'resource'),'attrs','{}'::JSONB,'parents','[]'::JSONB))
       OR s->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
       OR s->'actor' IS DISTINCT FROM s->'delegate'
       OR NOT (p.snapshot->'actions' ? (s->>'action'))
       OR s->'constraint_context' IS DISTINCT FROM jsonb_build_object('mode','EXACT_OPERATION','request_profile',s->>'operation_profile','request_digest',s->>'operation_digest')
       OR s->>'constraint_evidence_digest' IS DISTINCT FROM s->>'operation_digest'
       OR (NEW.evidence_document->>'original_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.original_at
       OR (NEW.evidence_document->>'observed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.observed_at
       OR (NEW.evidence_document->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.completed_at
       OR (NEW.evidence_document->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
       OR (p.snapshot->>'updated_at')::TIMESTAMPTZ>NEW.observed_at
       OR NEW.retained_at>clock_timestamp() OR NEW.valid_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_OBSERVATION_BINDING';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_delegation_use_policy_observation_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.retained_at>clock_timestamp() OR NEW.valid_until<=clock_timestamp() THEN
        RAISE EXCEPTION 'DELEGATION_POLICY_OBSERVATION_EXPIRED';
    END IF;
    RETURN NULL;
END $$;

DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.delegation_use_policies'::regclass AND tgname='delegation_policy_guard') THEN
        CREATE TRIGGER delegation_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON organization_service.delegation_use_policies FOR EACH ROW EXECUTE FUNCTION organization_service.guard_delegation_use_policy();
        CREATE TRIGGER delegation_policy_no_truncate BEFORE TRUNCATE ON organization_service.delegation_use_policies FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_delegation_use_policy_mutation();
        CREATE CONSTRAINT TRIGGER delegation_policy_history_complete AFTER INSERT OR UPDATE ON organization_service.delegation_use_policies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_delegation_use_policy_history();
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.delegation_use_policy_history'::regclass AND tgname='delegation_policy_history_guard') THEN
        CREATE TRIGGER delegation_policy_history_guard BEFORE INSERT ON organization_service.delegation_use_policy_history FOR EACH ROW EXECUTE FUNCTION organization_service.guard_delegation_use_policy_history();
        CREATE TRIGGER delegation_policy_history_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.delegation_use_policy_history FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_delegation_use_policy_mutation();
    END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.delegation_use_policy_observations'::regclass AND tgname='delegation_policy_observation_guard') THEN
        CREATE TRIGGER delegation_policy_observation_guard BEFORE INSERT ON organization_service.delegation_use_policy_observations FOR EACH ROW EXECUTE FUNCTION organization_service.guard_delegation_use_policy_observation();
        CREATE TRIGGER delegation_policy_observation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.delegation_use_policy_observations FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_delegation_use_policy_mutation();
        CREATE CONSTRAINT TRIGGER delegation_policy_observation_commit AFTER INSERT ON organization_service.delegation_use_policy_observations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_delegation_use_policy_observation_commit();
    END IF;
END $$;
REVOKE ALL ON organization_service.delegation_use_policies,organization_service.delegation_use_policy_history,organization_service.delegation_use_policy_observations FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_service.guard_delegation_use_policy(),organization_service.guard_delegation_use_policy_history(),organization_service.check_delegation_use_policy_history(),organization_service.reject_delegation_use_policy_mutation(),organization_service.guard_delegation_use_policy_observation(),organization_service.check_delegation_use_policy_observation_commit() FROM PUBLIC;
INSERT INTO organization_service.rust_schema_versions(version) VALUES('rust_organization_delegation_use_policy_0008') ON CONFLICT(version) DO NOTHING;
