-- Exact private machine-authentication audit bytes. Retention records an
-- already verified bounded observation; it never creates fresh authority.
CREATE TABLE delegated_authority_service.machine_authentication_evidence (
    organization_id UUID NOT NULL CHECK (organization_id <> '00000000-0000-0000-0000-000000000000'),
    evidence_ref TEXT NOT NULL,
    evidence_digest TEXT NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
    actor_type TEXT NOT NULL CHECK (actor_type='MACHINE_IDENTITY'),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 1024),
    machine_identity_id UUID NOT NULL CHECK (machine_identity_id <> '00000000-0000-0000-0000-000000000000'),
    grant_id UUID NOT NULL CHECK (grant_id <> '00000000-0000-0000-0000-000000000000'),
    grant_revision BIGINT NOT NULL CHECK (grant_revision BETWEEN 1 AND 9007199254740991),
    challenge_id UUID NOT NULL CHECK (challenge_id <> '00000000-0000-0000-0000-000000000000'),
    audit_bytes BYTEA NOT NULL CHECK (octet_length(audit_bytes) BETWEEN 1 AND 65536),
    audit_document JSONB NOT NULL CHECK (jsonb_typeof(audit_document)='object'),
    completed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL CHECK (valid_until>completed_at),
    retained_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id,evidence_ref),
    CONSTRAINT machine_evidence_digest_matches_bytes CHECK (evidence_digest='sha256:'||encode(sha256(audit_bytes),'hex')),
    CONSTRAINT machine_evidence_reference_matches_digest CHECK (evidence_ref='urn:marty:machine-authentication:'||evidence_digest),
    CONSTRAINT machine_evidence_document_matches_bytes CHECK (convert_from(audit_bytes,'UTF8')::JSONB=audit_document)
);

CREATE FUNCTION delegated_authority_service.guard_machine_authentication_evidence()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE scope JSONB := NEW.audit_document->'scope';
BEGIN
    IF (NEW.audit_document->>'profile') IS DISTINCT FROM 'urn:marty:machine-authentication-evidence:v1'
       OR scope->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
       OR scope#>>'{principal,type}' IS DISTINCT FROM NEW.actor_type
       OR scope#>>'{principal,id}' IS DISTINCT FROM NEW.actor_id
       OR scope->>'machine_identity_id' IS DISTINCT FROM NEW.machine_identity_id::TEXT
       OR scope->>'grant_id' IS DISTINCT FROM NEW.grant_id::TEXT
       OR scope->>'grant_revision' IS DISTINCT FROM NEW.grant_revision::TEXT
       OR scope->>'challenge_id' IS DISTINCT FROM NEW.challenge_id::TEXT
       OR (NEW.audit_document->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.completed_at
       OR (NEW.audit_document->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
       OR scope->>'proof_evidence_ref' IS DISTINCT FROM NEW.audit_document#>>'{proof,evidence_ref}'
       OR NEW.completed_at>NEW.retained_at OR NEW.retained_at>=NEW.valid_until
       OR NEW.retained_at>clock_timestamp() OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'DA_MACHINE_EVIDENCE_BINDING';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER machine_authentication_evidence_binding
BEFORE INSERT ON delegated_authority_service.machine_authentication_evidence
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_machine_authentication_evidence();

CREATE FUNCTION delegated_authority_service.check_machine_authentication_evidence_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF clock_timestamp()<NEW.retained_at OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'DA_MACHINE_EVIDENCE_EXPIRED';
    END IF;
    RETURN NEW;
END
$$;
CREATE CONSTRAINT TRIGGER machine_authentication_evidence_commit
AFTER INSERT ON delegated_authority_service.machine_authentication_evidence
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION delegated_authority_service.check_machine_authentication_evidence_commit();
CREATE TRIGGER machine_authentication_evidence_immutable
BEFORE UPDATE OR DELETE ON delegated_authority_service.machine_authentication_evidence
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER machine_authentication_evidence_no_truncate
BEFORE TRUNCATE ON delegated_authority_service.machine_authentication_evidence
FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();

-- This guard is additive: historical receipts remain unchanged. A future use
-- writer requires SELECT on this audit table, never INSERT/UPDATE/DELETE. The
-- separate machine evidence writer has no authority over the use ledger.
CREATE FUNCTION delegated_authority_service.guard_use_machine_evidence()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE evidence delegated_authority_service.machine_authentication_evidence;
        evaluation JSONB := NEW.receipt_document->'evaluation';
        scope JSONB;
        proof_ref TEXT := evaluation->>'proof_evidence_ref';
BEGIN
    IF NEW.actor_type<>'MACHINE_IDENTITY' THEN
        IF proof_ref LIKE 'urn:marty:machine-authentication:%' THEN
            RAISE EXCEPTION 'DA_USE_MACHINE_EVIDENCE_BINDING';
        END IF;
        RETURN NEW;
    END IF;
    IF proof_ref IS NULL OR proof_ref !~ '^urn:marty:machine-authentication:sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'DA_USE_MACHINE_EVIDENCE_REQUIRED';
    END IF;
    SELECT * INTO evidence FROM delegated_authority_service.machine_authentication_evidence
        WHERE organization_id=NEW.organization_id AND evidence_ref=proof_ref;
    IF NOT FOUND THEN RAISE EXCEPTION 'DA_USE_MACHINE_EVIDENCE_REQUIRED'; END IF;
    scope := evidence.audit_document->'scope';
    IF evidence.actor_type IS DISTINCT FROM NEW.actor_type OR evidence.actor_id IS DISTINCT FROM NEW.actor_id
       OR evidence.challenge_id IS DISTINCT FROM NEW.challenge_id
       OR scope->>'organization_id' IS DISTINCT FROM evaluation->>'organization_id'
       OR scope->'principal' IS DISTINCT FROM evaluation->'actor'
       OR scope->>'grant_id' IS DISTINCT FROM evaluation#>>'{grant,id}'
       OR scope->>'grant_revision' IS DISTINCT FROM evaluation#>>'{grant,revision}'
       OR scope->>'proof_evidence_ref' IS DISTINCT FROM ('urn:marty:oid4vp-proof:'||substr(NEW.proof_digest,8))
       OR scope->>'challenge_digest' IS DISTINCT FROM ('sha256:'||encode(sha256(convert_to(evaluation->>'challenge','UTF8')),'hex'))
       OR scope->>'action' IS DISTINCT FROM evaluation#>>'{operation,action}'
       OR scope->>'audience' IS DISTINCT FROM evaluation#>>'{operation,audience}'
       OR scope->>'resource' IS DISTINCT FROM evaluation#>>'{operation,resource_id}'
       OR scope->>'operation_profile' IS DISTINCT FROM evaluation#>>'{operation,request_profile}'
       OR scope->>'operation_digest' IS DISTINCT FROM evaluation#>>'{operation,request_digest}'
       OR evaluation#>>'{binding,method}' IS DISTINCT FROM 'KEY'
       OR scope->>'key_thumbprint' IS DISTINCT FROM evaluation#>>'{binding,key_thumbprint}'
       OR (evaluation->>'proof_verified_at')::TIMESTAMPTZ IS DISTINCT FROM (evidence.audit_document#>>'{proof,verified_at}')::TIMESTAMPTZ
       OR (evaluation->>'proof_valid_until')::TIMESTAMPTZ IS DISTINCT FROM evidence.valid_until
       OR (evaluation->>'evaluated_at')::TIMESTAMPTZ IS NULL
       OR (evaluation->>'evaluated_at')::TIMESTAMPTZ<evidence.completed_at
       OR (evaluation->>'evaluated_at')::TIMESTAMPTZ>=evidence.valid_until
       OR evidence.retained_at>NEW.recorded_at
       OR NEW.authorization_expires_at>evidence.valid_until
       OR clock_timestamp()>=evidence.valid_until THEN
        RAISE EXCEPTION 'DA_USE_MACHINE_EVIDENCE_BINDING';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER use_receipts_machine_evidence
BEFORE INSERT ON delegated_authority_service.use_receipts
FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_use_machine_evidence();

REVOKE ALL ON delegated_authority_service.machine_authentication_evidence FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_machine_authentication_evidence() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.check_machine_authentication_evidence_commit() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_use_machine_evidence() FROM PUBLIC;
COMMENT ON TABLE delegated_authority_service.machine_authentication_evidence IS
'Private immutable audit of a bounded authenticated MachineIdentity observation. Exact bytes are hash-bound. Historical retrieval never renews authentication or authorizes use; source qualification remains independent.';
