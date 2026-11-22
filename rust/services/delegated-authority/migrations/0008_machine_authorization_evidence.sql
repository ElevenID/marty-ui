-- Exact source/evaluation evidence for the named Organization machine policy
-- selection. The writer has no policy, machine registry, grant or use authority.
CREATE TABLE delegated_authority_service.machine_authorization_evidence (
    organization_id UUID NOT NULL CHECK (organization_id<>'00000000-0000-0000-0000-000000000000'),
    evidence_ref TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('SOURCE','EVALUATION')),
    evidence_bytes BYTEA NOT NULL CHECK (octet_length(evidence_bytes) BETWEEN 1 AND 524288),
    evidence_document JSONB NOT NULL CHECK (jsonb_typeof(evidence_document)='object'),
    evidence_digest TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL CHECK (completed_at>=observed_at),
    valid_until TIMESTAMPTZ NOT NULL CHECK (valid_until>completed_at AND valid_until<=observed_at+INTERVAL '30 seconds'),
    retained_at TIMESTAMPTZ NOT NULL CHECK (retained_at>=completed_at AND retained_at<valid_until),
    PRIMARY KEY (organization_id,evidence_ref),
    CONSTRAINT machine_authorization_evidence_bytes CHECK (convert_from(evidence_bytes,'UTF8')::JSONB=evidence_document),
    CONSTRAINT machine_authorization_evidence_digest CHECK (evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex')),
    CONSTRAINT machine_authorization_evidence_reference CHECK (evidence_ref=(CASE kind WHEN 'SOURCE' THEN 'urn:marty:machine-policy-source:' ELSE 'urn:marty:machine-authorization:' END)||evidence_digest)
);

CREATE FUNCTION delegated_authority_service.guard_machine_authorization_evidence()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE d JSONB := NEW.evidence_document; source delegated_authority_service.machine_authorization_evidence;
BEGIN
    IF d#>>'{scope,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
       OR d#>>'{scope,principal,type}' IS DISTINCT FROM 'MACHINE_IDENTITY'
       OR (d->>'observed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.observed_at
       OR (d->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
       OR NEW.retained_at>clock_timestamp() OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'MACHINE_AUTHORIZATION_EVIDENCE_BINDING';
    END IF;
    IF NEW.kind='SOURCE' THEN
        IF d->>'profile' IS DISTINCT FROM 'urn:marty:machine-policy-source-evidence:v1'
           OR (d->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.completed_at
           OR d#>>'{policy_snapshot,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
           OR d#>>'{policy_snapshot,policy_set_id}' IS DISTINCT FROM d->>'policy_set_id'
           OR d#>>'{policy_snapshot,revision}' IS DISTINCT FROM d->>'policy_revision'
           OR d#>>'{policy_snapshot,policy_type}' IS DISTINCT FROM 'MACHINE_AUTHORIZATION'
           OR d#>>'{policy_snapshot,status}' IS DISTINCT FROM 'ACTIVE'
           OR d#>>'{policy_snapshot,schema_version}' IS DISTINCT FROM 'MartyMachine/1.0'
           OR d#>>'{policy_snapshot,schema_digest}' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(d->>'schema','UTF8')),'hex')
           OR (d#>>'{policy_snapshot,updated_at}')::TIMESTAMPTZ>NEW.observed_at
           OR d->>'history_ref' IS NULL OR d->'entities' IS NULL THEN
            RAISE EXCEPTION 'MACHINE_POLICY_SOURCE_BINDING';
        END IF;
    ELSE
        SELECT * INTO source FROM delegated_authority_service.machine_authorization_evidence
            WHERE organization_id=NEW.organization_id AND evidence_ref=d->>'source_evidence_ref' AND kind='SOURCE';
        IF NOT FOUND OR d->>'profile' IS DISTINCT FROM 'urn:marty:machine-authorization-evidence:v1'
           OR d->>'decision' IS DISTINCT FROM 'PERMIT'
           OR (d->>'evaluated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.completed_at
           OR d->'scope' IS DISTINCT FROM source.evidence_document->'scope'
           OR d->>'policy_set_id' IS DISTINCT FROM source.evidence_document->>'policy_set_id'
           OR d->>'policy_revision' IS DISTINCT FROM source.evidence_document->>'policy_revision'
           OR d->>'policy_digest' IS DISTINCT FROM source.evidence_document->>'policy_digest'
           OR NEW.observed_at IS DISTINCT FROM source.observed_at
           OR NEW.completed_at<source.retained_at OR NEW.valid_until>source.valid_until THEN
            RAISE EXCEPTION 'MACHINE_AUTHORIZATION_SOURCE_REQUIRED';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION delegated_authority_service.check_machine_authorization_evidence_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF clock_timestamp()<NEW.retained_at OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'MACHINE_AUTHORIZATION_EVIDENCE_EXPIRED';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER machine_authorization_evidence_binding BEFORE INSERT
    ON delegated_authority_service.machine_authorization_evidence FOR EACH ROW
    EXECUTE FUNCTION delegated_authority_service.guard_machine_authorization_evidence();
CREATE CONSTRAINT TRIGGER machine_authorization_evidence_commit AFTER INSERT
    ON delegated_authority_service.machine_authorization_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION delegated_authority_service.check_machine_authorization_evidence_commit();
CREATE TRIGGER machine_authorization_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE
    ON delegated_authority_service.machine_authorization_evidence FOR EACH STATEMENT
    EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

-- Once this owner is installed, every newly retained machine proof selecting
-- MACHINE_AUTHORIZATION must bind the exact retained source and actual permit.
-- Existing machine audit rows remain historical and are never rewritten.
CREATE FUNCTION delegated_authority_service.guard_machine_authentication_authorization()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selection JSONB := NEW.audit_document->'machine_authorization';
        e delegated_authority_service.machine_authorization_evidence;
BEGIN
    IF selection IS NULL OR selection='null'::JSONB THEN RETURN NEW; END IF;
    SELECT * INTO e FROM delegated_authority_service.machine_authorization_evidence
        WHERE organization_id=NEW.organization_id AND evidence_ref=selection->>'evidence_ref' AND kind='EVALUATION';
    IF NOT FOUND OR e.evidence_document->'scope' IS DISTINCT FROM NEW.audit_document->'scope'
       OR selection->>'policy_type' IS DISTINCT FROM 'MACHINE_AUTHORIZATION'
       OR selection->>'policy_set_id' IS DISTINCT FROM e.evidence_document->>'policy_set_id'
       OR selection->>'revision' IS DISTINCT FROM e.evidence_document->>'policy_revision'
       OR selection->>'policy_digest' IS DISTINCT FROM e.evidence_document->>'policy_digest'
       OR (selection->>'observed_at')::TIMESTAMPTZ IS DISTINCT FROM e.observed_at
       OR (selection->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM e.valid_until
       OR NEW.completed_at<e.retained_at OR NEW.valid_until>e.valid_until THEN
        RAISE EXCEPTION 'MACHINE_AUTHORIZATION_RETAINED_PERMIT_REQUIRED';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER machine_authentication_authorization_binding BEFORE INSERT
    ON delegated_authority_service.machine_authentication_evidence FOR EACH ROW
    EXECUTE FUNCTION delegated_authority_service.guard_machine_authentication_authorization();

REVOKE ALL ON delegated_authority_service.machine_authorization_evidence FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_machine_authorization_evidence(),
    delegated_authority_service.check_machine_authorization_evidence_commit(),
    delegated_authority_service.guard_machine_authentication_authorization() FROM PUBLIC;
