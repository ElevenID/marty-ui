-- Flow remains the authoritative owner of delegated OID4VP challenges. These
-- retained correlations never become a second caller-authored challenge source.
CREATE TABLE IF NOT EXISTS flow_service.delegated_use_storage_identity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    storage_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid()
);
INSERT INTO flow_service.delegated_use_storage_identity(singleton)
VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS flow_service.delegated_challenge_bindings (
    challenge_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    verifier_id text NOT NULL CHECK (length(verifier_id) BETWEEN 1 AND 2048),
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{22,128}$'),
    nonce_digest text NOT NULL CHECK (nonce_digest = encode(sha256(convert_to(nonce,'UTF8')),'hex')),
    instance_snapshot jsonb NOT NULL CHECK (jsonb_typeof(instance_snapshot)='object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at>created_at),
    UNIQUE (organization_id,verifier_id,nonce_digest)
);

CREATE TABLE IF NOT EXISTS flow_service.delegated_proof_submissions (
    submission_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL REFERENCES flow_service.delegated_challenge_bindings(challenge_id),
    organization_id uuid NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('USER','ORGANIZATION','SERVICE_ACCOUNT','MACHINE_IDENTITY','EXTERNAL')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 2048),
    proof bytea NOT NULL CHECK (octet_length(proof) BETWEEN 1 AND 262144),
    proof_digest text NOT NULL CHECK (proof_digest='sha256:'||encode(sha256(proof),'hex')),
    received_at timestamptz NOT NULL,
    UNIQUE (challenge_id,proof_digest)
);

CREATE TABLE IF NOT EXISTS flow_service.delegated_use_consumptions (
    challenge_id uuid PRIMARY KEY REFERENCES flow_service.delegated_challenge_bindings(challenge_id),
    organization_id uuid NOT NULL,
    proof_submission_id uuid NOT NULL UNIQUE REFERENCES flow_service.delegated_proof_submissions(submission_id),
    proof_digest text NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
    receipt_ref text NOT NULL UNIQUE,
    receipt_digest text NOT NULL CHECK (receipt_digest ~ '^sha256:[0-9a-f]{64}$'),
    decision text NOT NULL CHECK (decision IN ('PERMIT','DENY')),
    recorded_at timestamptz NOT NULL,
    authorization_expires_at timestamptz NOT NULL CHECK (authorization_expires_at>recorded_at)
);

CREATE OR REPLACE FUNCTION flow_service.reject_delegated_use_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'FLOW.DELEGATED_EVIDENCE_IMMUTABLE';
END;
$$;

CREATE OR REPLACE FUNCTION flow_service.guard_delegated_challenge_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source flow_service.flow_instances%ROWTYPE;
BEGIN
    SELECT * INTO source FROM flow_service.flow_instances
      WHERE id=NEW.challenge_id::text AND organization_id=NEW.organization_id::text FOR SHARE;
    IF NOT FOUND OR NEW.instance_snapshot IS DISTINCT FROM to_jsonb(source)
       OR source.status<>'awaiting_wallet' OR source.completed_at IS NOT NULL
       OR source.result IS NOT NULL OR source.error IS NOT NULL
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->>'challenge_id') IS DISTINCT FROM NEW.challenge_id::text
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->>'organization_id') IS DISTINCT FROM NEW.organization_id::text
       OR (source.context::jsonb->>'_marty_delegation_verifier_client_id_v1') IS DISTINCT FROM NEW.verifier_id
       OR (source.context::jsonb->>'nonce') IS DISTINCT FROM NEW.nonce
       OR (source.context::jsonb->'_marty_presentation_request_v1'->>'nonce') IS DISTINCT FROM NEW.nonce
       OR NEW.created_at IS DISTINCT FROM source.created_at
       OR NEW.expires_at IS DISTINCT FROM source.expires_at
       OR NEW.created_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp() THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_CHALLENGE_BINDING';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION flow_service.guard_delegated_proof_submission()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source flow_service.flow_instances%ROWTYPE;
DECLARE binding flow_service.delegated_challenge_bindings%ROWTYPE;
BEGIN
    SELECT * INTO source FROM flow_service.flow_instances
      WHERE id=NEW.challenge_id::text AND organization_id=NEW.organization_id::text FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'FLOW.DELEGATED_PROOF_BINDING'; END IF;
    SELECT * INTO binding FROM flow_service.delegated_challenge_bindings
      WHERE challenge_id=NEW.challenge_id AND organization_id=NEW.organization_id;
    IF NOT FOUND OR source.status<>'awaiting_wallet'
       OR source.completed_at IS NOT NULL OR source.result IS NOT NULL OR source.error IS NOT NULL
       -- Request retrieval may record progress and derived request metadata.
       -- The complete original authority/request scope remains unchanged.
       OR (binding.instance_snapshot - ARRAY['context','current_step_id','step_history','state_history','updated_at'])
          IS DISTINCT FROM (to_jsonb(source) - ARRAY['context','current_step_id','step_history','state_history','updated_at'])
       OR ((binding.instance_snapshot->'context') - ARRAY['request_retrieved','mip_messages',
          'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
          'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1'])
          IS DISTINCT FROM (source.context::jsonb - ARRAY['request_retrieved','mip_messages',
          'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
          'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1'])
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->'actor'->>'type') IS DISTINCT FROM NEW.actor_type
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->'actor'->>'id') IS DISTINCT FROM NEW.actor_id
       OR NEW.received_at<binding.created_at OR NEW.received_at>clock_timestamp()
       OR NEW.received_at>=binding.expires_at OR clock_timestamp()>=binding.expires_at
       OR EXISTS(SELECT 1 FROM flow_service.delegated_use_consumptions WHERE challenge_id=NEW.challenge_id) THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_PROOF_BINDING';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION flow_service.check_delegated_use_commit()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE binding flow_service.delegated_challenge_bindings%ROWTYPE;
DECLARE consumed flow_service.delegated_use_consumptions%ROWTYPE;
DECLARE proof flow_service.delegated_proof_submissions%ROWTYPE;
DECLARE source flow_service.flow_instances%ROWTYPE;
BEGIN
    SELECT * INTO binding FROM flow_service.delegated_challenge_bindings WHERE challenge_id=NEW.challenge_id;
    SELECT * INTO source FROM flow_service.flow_instances WHERE id=NEW.challenge_id::text;
    IF binding.challenge_id IS NULL OR source.id IS NULL
       OR source.organization_id<>binding.organization_id::text
       OR clock_timestamp()>=binding.expires_at THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_COMMIT_EXPIRED';
    END IF;
    IF TG_TABLE_NAME='delegated_challenge_bindings' THEN
        IF binding.instance_snapshot IS DISTINCT FROM to_jsonb(source) THEN
            RAISE EXCEPTION 'FLOW.DELEGATED_START_CHANGED';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO consumed FROM flow_service.delegated_use_consumptions WHERE challenge_id=NEW.challenge_id;
    SELECT * INTO proof FROM flow_service.delegated_proof_submissions WHERE submission_id=consumed.proof_submission_id;
    IF consumed.organization_id IS DISTINCT FROM binding.organization_id
       OR proof.challenge_id IS DISTINCT FROM binding.challenge_id
       OR proof.organization_id IS DISTINCT FROM binding.organization_id
       OR consumed.proof_digest IS DISTINCT FROM proof.proof_digest
       OR consumed.recorded_at<proof.received_at OR consumed.recorded_at>clock_timestamp()
       OR consumed.authorization_expires_at>binding.expires_at
       OR clock_timestamp()>=consumed.authorization_expires_at
       OR source.status<>'completed' OR source.completed_at IS DISTINCT FROM consumed.recorded_at
       OR source.updated_at IS DISTINCT FROM consumed.recorded_at OR source.error IS NOT NULL
       OR source.result::jsonb IS DISTINCT FROM jsonb_build_object(
          'kind','DELEGATED_USE','semantics','EVIDENCE_ONLY','decision',consumed.decision,
          'receipt_ref',consumed.receipt_ref,'receipt_digest',consumed.receipt_digest) THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_CONSUMPTION_BINDING';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION flow_service.guard_delegated_flow_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE consumed flow_service.delegated_use_consumptions%ROWTYPE;
BEGIN
    IF NOT (OLD.context::jsonb ? '_marty_delegation_oid4vp_v1') THEN RETURN NULL; END IF;
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'FLOW.DELEGATED_FLOW_RETAINED'; END IF;
    IF (NEW.context::jsonb - ARRAY['request_retrieved','mip_messages',
          'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
          'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1'])
       IS DISTINCT FROM (OLD.context::jsonb - ARRAY['request_retrieved','mip_messages',
          'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
          'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1'])
       OR NEW.flow_definition_id IS DISTINCT FROM OLD.flow_definition_id
       OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.started_at IS DISTINCT FROM OLD.started_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
       OR NEW.application_flow_key_hash IS DISTINCT FROM OLD.application_flow_key_hash
       OR NEW.external_reference IS DISTINCT FROM OLD.external_reference
       OR OLD.status NOT IN ('awaiting_wallet','in_progress') THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_FLOW_IMMUTABLE';
    END IF;
    -- Derived retrieval values can be added only for this original verifier and
    -- Flow URL. A cached signed request, once recorded, cannot be replaced.
    IF (NEW.context::jsonb ? 'request_retrieved' AND NEW.context::jsonb->'request_retrieved'<>'true'::jsonb)
       OR (NEW.context::jsonb ? 'oid4vp_response_uri' AND
           NEW.context::jsonb->>'oid4vp_response_uri' IS DISTINCT FROM
           regexp_replace(OLD.context::jsonb->>'request_uri','/request$','/submit'))
       OR (NEW.context::jsonb ? 'oid4vp_response_encryption_jwk' AND
           NEW.context::jsonb->'oid4vp_response_encryption_jwk'<>'null'::jsonb)
       OR (NEW.context::jsonb ? 'oid4vp_expected_state' AND NEW.context::jsonb->>'oid4vp_expected_state' IS DISTINCT FROM OLD.id)
       OR (NEW.context::jsonb ? 'verification_audience' AND NEW.context::jsonb->>'verification_audience' IS DISTINCT FROM OLD.context::jsonb->>'oid4vp_client_id')
       OR (NEW.context::jsonb ? 'oid4vp_verifier_context' AND NEW.context::jsonb->'oid4vp_verifier_context'<>'true'::jsonb)
       OR (OLD.context::jsonb ? 'paired_wallet_signed_request_v1' AND
           NEW.context::jsonb->'paired_wallet_signed_request_v1' IS DISTINCT FROM OLD.context::jsonb->'paired_wallet_signed_request_v1') THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_REQUEST_BINDING';
    END IF;
    IF NEW.status IN ('cancelled','expired') AND NEW.result IS NULL THEN RETURN NULL; END IF;
    IF NEW.status=OLD.status AND NEW.completed_at IS NULL AND NEW.result IS NULL AND NEW.error IS NULL
       AND NEW.updated_at>OLD.updated_at AND NEW.updated_at<=clock_timestamp()
       AND clock_timestamp()<OLD.expires_at THEN RETURN NULL; END IF;
    SELECT * INTO consumed FROM flow_service.delegated_use_consumptions WHERE challenge_id=NEW.id::uuid;
    IF NOT FOUND OR NEW.status<>'completed'
       OR NEW.completed_at IS DISTINCT FROM consumed.recorded_at
       OR NEW.organization_id<>consumed.organization_id::text THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_FINALIZATION_REQUIRED';
    END IF;
    RETURN NULL;
END;
$$;

DO $$
DECLARE name text;
BEGIN
    FOREACH name IN ARRAY ARRAY['delegated_use_storage_identity','delegated_challenge_bindings','delegated_proof_submissions','delegated_use_consumptions'] LOOP
        EXECUTE format('REVOKE ALL ON flow_service.%I FROM PUBLIC',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_immutable',name);
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON flow_service.%I FOR EACH ROW EXECUTE FUNCTION flow_service.reject_delegated_use_mutation()',name||'_immutable',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_no_truncate',name);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON flow_service.%I FOR EACH STATEMENT EXECUTE FUNCTION flow_service.reject_delegated_use_mutation()',name||'_no_truncate',name);
    END LOOP;
END;
$$;

DROP TRIGGER IF EXISTS delegated_challenge_binding_guard ON flow_service.delegated_challenge_bindings;
CREATE TRIGGER delegated_challenge_binding_guard BEFORE INSERT ON flow_service.delegated_challenge_bindings
FOR EACH ROW EXECUTE FUNCTION flow_service.guard_delegated_challenge_binding();
DROP TRIGGER IF EXISTS delegated_proof_submission_guard ON flow_service.delegated_proof_submissions;
CREATE TRIGGER delegated_proof_submission_guard BEFORE INSERT ON flow_service.delegated_proof_submissions
FOR EACH ROW EXECUTE FUNCTION flow_service.guard_delegated_proof_submission();
DROP TRIGGER IF EXISTS delegated_challenge_commit ON flow_service.delegated_challenge_bindings;
CREATE CONSTRAINT TRIGGER delegated_challenge_commit AFTER INSERT ON flow_service.delegated_challenge_bindings
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.check_delegated_use_commit();
DROP TRIGGER IF EXISTS delegated_consumption_commit ON flow_service.delegated_use_consumptions;
CREATE CONSTRAINT TRIGGER delegated_consumption_commit AFTER INSERT ON flow_service.delegated_use_consumptions
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.check_delegated_use_commit();
DROP TRIGGER IF EXISTS delegated_flow_mutation_guard ON flow_service.flow_instances;
CREATE CONSTRAINT TRIGGER delegated_flow_mutation_guard AFTER UPDATE OR DELETE ON flow_service.flow_instances
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.guard_delegated_flow_mutation();

REVOKE ALL ON FUNCTION flow_service.reject_delegated_use_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION flow_service.guard_delegated_challenge_binding() FROM PUBLIC;
REVOKE ALL ON FUNCTION flow_service.guard_delegated_proof_submission() FROM PUBLIC;
REVOKE ALL ON FUNCTION flow_service.check_delegated_use_commit() FROM PUBLIC;
REVOKE ALL ON FUNCTION flow_service.guard_delegated_flow_mutation() FROM PUBLIC;

INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_delegated_use_0005') ON CONFLICT DO NOTHING;
