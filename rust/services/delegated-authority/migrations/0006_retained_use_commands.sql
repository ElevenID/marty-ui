-- Shared P03 identity registry. Retained use claims reserve identity before
-- external preparation/signing. Unresolved claims are never deleted/replayed.
CREATE TABLE delegated_authority_service.command_identities (
    organization_id UUID NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('USER','ORGANIZATION','SERVICE_ACCOUNT','MACHINE_IDENTITY','EXTERNAL')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 1024),
    command_id UUID NOT NULL,
    command_name TEXT NOT NULL CHECK (command_name IN ('CREATE_GRANT','APPROVE_GRANT','SUSPEND_GRANT','REINSTATE_GRANT','REVOKE_GRANT','START_USE','FINALIZE_USE')),
    command_digest TEXT NOT NULL CHECK (command_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (organization_id,actor_type,actor_id,command_id)
);
INSERT INTO delegated_authority_service.command_identities
    SELECT organization_id,actor_type,actor_id,command_id,command_document ->> 'command',command_digest
    FROM delegated_authority_service.command_results;

CREATE FUNCTION delegated_authority_service.register_lifecycle_command_identity()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO delegated_authority_service.command_identities
        (organization_id,actor_type,actor_id,command_id,command_name,command_digest)
        VALUES (NEW.organization_id,NEW.actor_type,NEW.actor_id,NEW.command_id,
            NEW.command_document ->> 'command',NEW.command_digest);
    RETURN NEW;
END
$$;
CREATE TRIGGER command_results_identity BEFORE INSERT ON delegated_authority_service.command_results
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.register_lifecycle_command_identity();

CREATE TABLE delegated_authority_service.use_command_claims (
    organization_id UUID NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    command_id UUID NOT NULL,
    command_name TEXT NOT NULL CHECK (command_name IN ('START_USE','FINALIZE_USE')),
    command_digest TEXT NOT NULL CHECK (command_digest ~ '^sha256:[0-9a-f]{64}$'),
    command_document JSONB NOT NULL CHECK (jsonb_typeof(command_document)='object'),
    challenge_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    grant_revision BIGINT NOT NULL CHECK (grant_revision BETWEEN 1 AND 9007199254740991),
    grant_document JSONB NOT NULL CHECK (jsonb_typeof(grant_document)='object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,actor_type,actor_id,command_id),
    FOREIGN KEY (organization_id,actor_type,actor_id,command_id)
        REFERENCES delegated_authority_service.command_identities,
    FOREIGN KEY (organization_id,grant_id,grant_revision)
        REFERENCES delegated_authority_service.grant_lifecycle_events (organization_id,grant_id,revision)
);
CREATE UNIQUE INDEX use_command_start_challenge ON delegated_authority_service.use_command_claims
    (organization_id,challenge_id) WHERE command_name='START_USE';
CREATE UNIQUE INDEX use_command_final_challenge ON delegated_authority_service.use_command_claims
    (organization_id,challenge_id) WHERE command_name='FINALIZE_USE';

CREATE FUNCTION delegated_authority_service.guard_use_command_claim()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE current_grant JSONB;
BEGIN
    SELECT grant_document INTO STRICT current_grant FROM delegated_authority_service.delegation_grants
        WHERE organization_id=NEW.organization_id AND id=NEW.grant_id FOR SHARE;
    IF NEW.grant_document IS DISTINCT FROM current_grant
        OR (current_grant ->> 'status') IS DISTINCT FROM 'ACTIVE'
        OR (current_grant ->> 'revision') IS DISTINCT FROM NEW.grant_revision::TEXT
        OR (current_grant #>> '{terms,delegate,type}') IS DISTINCT FROM NEW.actor_type
        OR (current_grant #>> '{terms,delegate,id}') IS DISTINCT FROM NEW.actor_id
        OR (current_grant #>> '{terms,binding,method}') IS DISTINCT FROM 'KEY'
        OR (NEW.command_document ->> 'profile') IS DISTINCT FROM 'urn:marty:delegation-command:v1'
        OR (NEW.command_document ->> 'command') IS DISTINCT FROM NEW.command_name
        OR (NEW.command_document ->> 'command_id') IS DISTINCT FROM NEW.command_id::TEXT
        OR clock_timestamp() < (current_grant #>> '{terms,valid_from}')::TIMESTAMPTZ
        OR clock_timestamp() >= (current_grant #>> '{terms,valid_until}')::TIMESTAMPTZ THEN
        RAISE EXCEPTION 'delegated use claim binding is invalid';
    END IF;
    IF NEW.command_name='START_USE' THEN
        IF (NEW.command_document #>> '{grant,id}') IS DISTINCT FROM NEW.grant_id::TEXT
            OR (NEW.command_document #>> '{grant,revision}') IS DISTINCT FROM NEW.grant_revision::TEXT
            OR (NEW.command_document #>> '{grant,terms_digest}') IS DISTINCT FROM (current_grant ->> 'terms_digest') THEN
            RAISE EXCEPTION 'delegated use start reference is invalid';
        END IF;
    ELSE
        IF (NEW.command_document ->> 'challenge_id') IS DISTINCT FROM NEW.challenge_id::TEXT THEN
            RAISE EXCEPTION 'delegated use final reference is invalid';
        END IF;
    END IF;
    INSERT INTO delegated_authority_service.command_identities
        (organization_id,actor_type,actor_id,command_id,command_name,command_digest)
        VALUES (NEW.organization_id,NEW.actor_type,NEW.actor_id,NEW.command_id,NEW.command_name,NEW.command_digest);
    RETURN NEW;
END
$$;
CREATE TRIGGER use_command_claims_binding BEFORE INSERT ON delegated_authority_service.use_command_claims
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_use_command_claim();

CREATE TABLE delegated_authority_service.use_admissions (
    organization_id UUID NOT NULL,
    challenge_id UUID NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    command_id UUID NOT NULL,
    verifier_id TEXT NOT NULL CHECK (length(verifier_id) BETWEEN 1 AND 1024),
    nonce TEXT NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{22,128}$'),
    challenge_document JSONB NOT NULL CHECK (jsonb_typeof(challenge_document)='object'),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>created_at),
    PRIMARY KEY (organization_id,challenge_id),
    UNIQUE (organization_id,verifier_id,nonce),
    FOREIGN KEY (organization_id,actor_type,actor_id,command_id)
        REFERENCES delegated_authority_service.use_command_claims
);
CREATE FUNCTION delegated_authority_service.guard_use_admission()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE claim delegated_authority_service.use_command_claims;
BEGIN
    SELECT * INTO STRICT claim FROM delegated_authority_service.use_command_claims
        WHERE organization_id=NEW.organization_id AND actor_type=NEW.actor_type AND actor_id=NEW.actor_id AND command_id=NEW.command_id;
    IF claim.command_name<>'START_USE' OR claim.challenge_id<>NEW.challenge_id
        OR (NEW.challenge_document ->> 'organization_id') IS DISTINCT FROM NEW.organization_id::TEXT
        OR (NEW.challenge_document ->> 'challenge_id') IS DISTINCT FROM NEW.challenge_id::TEXT
        OR (NEW.challenge_document -> 'grant') IS DISTINCT FROM claim.grant_document
        OR (NEW.challenge_document -> 'operation') IS DISTINCT FROM (claim.command_document -> 'operation')
        OR (NEW.challenge_document ->> 'nonce') IS DISTINCT FROM NEW.nonce
        OR (NEW.challenge_document ->> 'verifier_id') IS DISTINCT FROM NEW.verifier_id
        OR (NEW.challenge_document ->> 'created_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.created_at
        OR (NEW.challenge_document ->> 'expires_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.expires_at
        OR NEW.created_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp()
        OR NEW.expires_at>(claim.grant_document #>> '{terms,valid_until}')::TIMESTAMPTZ THEN
        RAISE EXCEPTION 'delegated use admission binding is invalid';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER use_admissions_binding BEFORE INSERT ON delegated_authority_service.use_admissions
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_use_admission();

CREATE TABLE delegated_authority_service.use_receipts (
    organization_id UUID NOT NULL,
    challenge_id UUID NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    command_id UUID NOT NULL,
    proof_submission_id UUID NOT NULL,
    proof_digest TEXT NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
    receipt_ref TEXT NOT NULL CHECK (length(receipt_ref) BETWEEN 1 AND 1024),
    receipt_digest TEXT NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    compact_jws TEXT NOT NULL CHECK (length(compact_jws) BETWEEN 1 AND 100000),
    receipt_document JSONB NOT NULL CHECK (jsonb_typeof(receipt_document)='object'),
    recorded_at TIMESTAMPTZ NOT NULL,
    authorization_expires_at TIMESTAMPTZ NOT NULL CHECK (authorization_expires_at>recorded_at),
    PRIMARY KEY (organization_id,challenge_id),
    UNIQUE (organization_id,receipt_ref),
    FOREIGN KEY (organization_id,challenge_id) REFERENCES delegated_authority_service.use_admissions,
    FOREIGN KEY (organization_id,actor_type,actor_id,command_id) REFERENCES delegated_authority_service.use_command_claims
);
CREATE FUNCTION delegated_authority_service.guard_use_receipt()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE claim delegated_authority_service.use_command_claims;
        admission delegated_authority_service.use_admissions;
        evaluation JSONB;
BEGIN
    SELECT * INTO STRICT claim FROM delegated_authority_service.use_command_claims
        WHERE organization_id=NEW.organization_id AND actor_type=NEW.actor_type AND actor_id=NEW.actor_id AND command_id=NEW.command_id;
    SELECT * INTO STRICT admission FROM delegated_authority_service.use_admissions
        WHERE organization_id=NEW.organization_id AND challenge_id=NEW.challenge_id;
    evaluation := NEW.receipt_document -> 'evaluation';
    IF claim.command_name<>'FINALIZE_USE' OR claim.challenge_id<>NEW.challenge_id
        OR admission.actor_type<>NEW.actor_type OR admission.actor_id<>NEW.actor_id
        OR (claim.command_document ->> 'proof_submission_id') IS DISTINCT FROM NEW.proof_submission_id::TEXT
        OR (NEW.receipt_document ->> 'profile') IS DISTINCT FROM 'urn:marty:delegated-decision-receipt:v1'
        OR COALESCE(NEW.receipt_document ->> 'decision','') NOT IN ('PERMIT','DENY')
        OR NEW.receipt_ref IS DISTINCT FROM ('urn:marty:delegated-receipt:'||(NEW.receipt_document ->> 'id'))
        OR (evaluation ->> 'organization_id') IS DISTINCT FROM NEW.organization_id::TEXT
        OR (evaluation ->> 'challenge') IS DISTINCT FROM admission.nonce
        OR (evaluation #>> '{actor,type}') IS DISTINCT FROM NEW.actor_type
        OR (evaluation #>> '{actor,id}') IS DISTINCT FROM NEW.actor_id
        OR (evaluation -> 'operation') IS DISTINCT FROM (admission.challenge_document -> 'operation')
        OR (evaluation #>> '{grant,id}') IS DISTINCT FROM claim.grant_id::TEXT
        OR (evaluation #>> '{grant,revision}') IS DISTINCT FROM claim.grant_revision::TEXT
        OR (evaluation #>> '{grant,terms_digest}') IS DISTINCT FROM (claim.grant_document ->> 'terms_digest')
        OR (NEW.receipt_document ->> 'expires_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.authorization_expires_at
        OR NEW.authorization_expires_at>admission.expires_at
        OR NEW.recorded_at>clock_timestamp() OR NEW.authorization_expires_at<=clock_timestamp()
        OR cardinality(string_to_array(NEW.compact_jws,'.')) IS DISTINCT FROM 3
        OR NEW.receipt_document IS DISTINCT FROM convert_from(decode(translate(split_part(NEW.compact_jws,'.',2),'-_','+/') || repeat('=',(4-length(split_part(NEW.compact_jws,'.',2))%4)%4),'base64'),'UTF8')::JSONB
        OR NEW.receipt_digest IS DISTINCT FROM ('sha256:'||encode(sha256(convert_to(NEW.compact_jws,'UTF8')),'hex')) THEN
        RAISE EXCEPTION 'delegated use receipt binding is invalid';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER use_receipts_binding BEFORE INSERT ON delegated_authority_service.use_receipts
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_use_receipt();

CREATE TABLE delegated_authority_service.use_command_results (
    organization_id UUID NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    command_id UUID NOT NULL,
    response_document JSONB NOT NULL CHECK (jsonb_typeof(response_document)='object'),
    checked_at TIMESTAMPTZ NOT NULL,
    commit_not_after TIMESTAMPTZ NOT NULL CHECK (commit_not_after>checked_at),
    PRIMARY KEY (organization_id,actor_type,actor_id,command_id),
    FOREIGN KEY (organization_id,actor_type,actor_id,command_id) REFERENCES delegated_authority_service.use_command_claims
);
CREATE FUNCTION delegated_authority_service.guard_use_result()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE claim delegated_authority_service.use_command_claims;
        admission delegated_authority_service.use_admissions;
        receipt delegated_authority_service.use_receipts;
        result JSONB;
BEGIN
    SELECT * INTO STRICT claim FROM delegated_authority_service.use_command_claims
        WHERE organization_id=NEW.organization_id AND actor_type=NEW.actor_type AND actor_id=NEW.actor_id AND command_id=NEW.command_id;
    result := NEW.response_document -> 'result';
    IF (NEW.response_document ->> 'profile') IS DISTINCT FROM 'urn:marty:delegation-command-response:v1'
        OR (NEW.response_document ->> 'original_command_id') IS DISTINCT FROM NEW.command_id::TEXT
        OR (NEW.response_document ->> 'command_digest') IS DISTINCT FROM claim.command_digest
        OR (NEW.response_document ->> 'recovered') IS DISTINCT FROM 'false'
        OR (result ->> 'challenge_id') IS DISTINCT FROM claim.challenge_id::TEXT THEN
        RAISE EXCEPTION 'delegated use original result is invalid';
    END IF;
    SELECT * INTO STRICT admission FROM delegated_authority_service.use_admissions
        WHERE organization_id=NEW.organization_id AND challenge_id=claim.challenge_id;
    IF claim.command_name='START_USE' THEN
        IF (result ->> 'kind') IS DISTINCT FROM 'CHALLENGE'
            OR (result -> 'operation') IS DISTINCT FROM (admission.challenge_document -> 'operation')
            OR (result -> 'grant') IS DISTINCT FROM (claim.command_document -> 'grant')
            OR (result ->> 'created_at')::TIMESTAMPTZ IS DISTINCT FROM admission.created_at
            OR (result ->> 'expires_at')::TIMESTAMPTZ IS DISTINCT FROM admission.expires_at THEN
            RAISE EXCEPTION 'delegated use challenge result is invalid';
        END IF;
    ELSE
        SELECT * INTO STRICT receipt FROM delegated_authority_service.use_receipts
            WHERE organization_id=NEW.organization_id AND challenge_id=claim.challenge_id AND command_id=NEW.command_id;
        IF (result ->> 'kind') IS DISTINCT FROM 'FINAL_USE'
            OR (result ->> 'semantics') IS DISTINCT FROM 'EVIDENCE_ONLY'
            OR (result ->> 'decision') IS DISTINCT FROM (receipt.receipt_document ->> 'decision')
            OR (result ->> 'receipt_ref') IS DISTINCT FROM receipt.receipt_ref
            OR (result ->> 'receipt_digest') IS DISTINCT FROM receipt.receipt_digest
            OR (result ->> 'recorded_at')::TIMESTAMPTZ IS DISTINCT FROM receipt.recorded_at
            OR (result ->> 'authorization_expires_at')::TIMESTAMPTZ IS DISTINCT FROM receipt.authorization_expires_at THEN
            RAISE EXCEPTION 'delegated use final result is invalid';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER use_command_results_binding BEFORE INSERT ON delegated_authority_service.use_command_results
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_use_result();
CREATE FUNCTION delegated_authority_service.check_use_result_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF clock_timestamp()<NEW.checked_at OR clock_timestamp()>=NEW.commit_not_after THEN
        RAISE EXCEPTION 'delegated use evidence expired before commit';
    END IF;
    RETURN NEW;
END
$$;
CREATE CONSTRAINT TRIGGER use_command_results_commit AFTER INSERT ON delegated_authority_service.use_command_results
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.check_use_result_commit();

DO $$
DECLARE table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['command_identities','use_command_claims','use_admissions','use_receipts','use_command_results'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON delegated_authority_service.%I FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation()',table_name||'_immutable',table_name);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON delegated_authority_service.%I FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation()',table_name||'_no_truncate',table_name);
        EXECUTE format('REVOKE ALL ON delegated_authority_service.%I FROM PUBLIC',table_name);
    END LOOP;
END
$$;
REVOKE ALL ON FUNCTION delegated_authority_service.register_lifecycle_command_identity() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_use_command_claim() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_use_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_use_receipt() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_use_result() FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.check_use_result_commit() FROM PUBLIC;
COMMENT ON TABLE delegated_authority_service.use_command_claims IS 'Immutable P03 intent retained before Flow preparation/signing. A missing result is unresolved, never permission to repeat work. No delete/retry lease.';
COMMENT ON TABLE delegated_authority_service.use_admissions IS 'Retained correlation to an authoritative Flow challenge and its original verifier nonce. Flow remains the challenge owner; production commit uses the same database transaction.';
COMMENT ON TABLE delegated_authority_service.use_receipts IS 'Immutable signed identity/authority decision evidence. EVIDENCE_ONLY; no merchant operation, payment, budget or business outcome state.';
