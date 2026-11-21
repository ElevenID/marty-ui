-- Explicit authenticated request/proof ingress. A request claim precedes all
-- external request signing; unresolved claims are retained and never retried.
CREATE TABLE IF NOT EXISTS flow_service.delegated_request_claims (
    challenge_id uuid PRIMARY KEY REFERENCES flow_service.delegated_challenge_bindings(challenge_id),
    organization_id uuid NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('SERVICE_ACCOUNT','MACHINE_IDENTITY')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 2048),
    configuration_digest text NOT NULL CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
    instance_snapshot jsonb NOT NULL CHECK (jsonb_typeof(instance_snapshot)='object'),
    authentication_observed_at timestamptz NOT NULL,
    authentication_valid_until timestamptz NOT NULL,
    authorization_observed_at timestamptz NOT NULL,
    authorization_valid_until timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT delegated_request_claim_bounds CHECK (
        authentication_valid_until>authentication_observed_at AND authentication_valid_until<=authentication_observed_at+interval '30 seconds'
        AND authorization_valid_until>authorization_observed_at AND authorization_valid_until<=authorization_observed_at+interval '30 seconds'
        AND observed_at>=authentication_observed_at AND observed_at>=authorization_observed_at
        AND recorded_at>=observed_at AND valid_until>recorded_at
        AND valid_until<=authentication_valid_until AND valid_until<=authorization_valid_until)
);

CREATE TABLE IF NOT EXISTS flow_service.delegated_request_results (
    challenge_id uuid PRIMARY KEY REFERENCES flow_service.delegated_request_claims(challenge_id),
    organization_id uuid NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('SERVICE_ACCOUNT','MACHINE_IDENTITY')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 2048),
    configuration_digest text NOT NULL CHECK (configuration_digest ~ '^sha256:[0-9a-f]{64}$'),
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 65536),
    request_digest text NOT NULL CHECK (request_digest='sha256:'||encode(sha256(request_bytes),'hex')),
    instance_snapshot jsonb NOT NULL CHECK (jsonb_typeof(instance_snapshot)='object'),
    authentication_observed_at timestamptz NOT NULL,
    authentication_valid_until timestamptz NOT NULL,
    authorization_observed_at timestamptz NOT NULL,
    authorization_valid_until timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT delegated_request_result_bounds CHECK (
        authentication_valid_until>authentication_observed_at AND authentication_valid_until<=authentication_observed_at+interval '30 seconds'
        AND authorization_valid_until>authorization_observed_at AND authorization_valid_until<=authorization_observed_at+interval '30 seconds'
        AND observed_at>=authentication_observed_at AND observed_at>=authorization_observed_at
        AND recorded_at>=observed_at AND valid_until>recorded_at
        AND valid_until<=authentication_valid_until AND valid_until<=authorization_valid_until)
);

CREATE TABLE IF NOT EXISTS flow_service.delegated_proof_ingress (
    submission_id uuid PRIMARY KEY REFERENCES flow_service.delegated_proof_submissions(submission_id),
    challenge_id uuid NOT NULL REFERENCES flow_service.delegated_challenge_bindings(challenge_id),
    organization_id uuid NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('SERVICE_ACCOUNT','MACHINE_IDENTITY')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 2048),
    proof_digest text NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
    authentication_observed_at timestamptz NOT NULL,
    authentication_valid_until timestamptz NOT NULL,
    authorization_observed_at timestamptz NOT NULL,
    authorization_valid_until timestamptz NOT NULL,
    observed_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL,
    CONSTRAINT delegated_proof_ingress_bounds CHECK (
        authentication_valid_until>authentication_observed_at AND authentication_valid_until<=authentication_observed_at+interval '30 seconds'
        AND authorization_valid_until>authorization_observed_at AND authorization_valid_until<=authorization_observed_at+interval '30 seconds'
        AND observed_at>=authentication_observed_at AND observed_at>=authorization_observed_at
        AND recorded_at>=observed_at AND valid_until>recorded_at
        AND valid_until<=authentication_valid_until AND valid_until<=authorization_valid_until)
);

CREATE OR REPLACE FUNCTION flow_service.guard_delegated_ingress()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source flow_service.flow_instances%ROWTYPE;
DECLARE binding flow_service.delegated_challenge_bindings%ROWTYPE;
DECLARE claim flow_service.delegated_request_claims%ROWTYPE;
DECLARE proof flow_service.delegated_proof_submissions%ROWTYPE;
BEGIN
    SELECT * INTO source FROM flow_service.flow_instances
      WHERE id=NEW.challenge_id::text AND organization_id=NEW.organization_id::text FOR SHARE;
    SELECT * INTO binding FROM flow_service.delegated_challenge_bindings
      WHERE challenge_id=NEW.challenge_id AND organization_id=NEW.organization_id;
    IF source.id IS NULL OR binding.challenge_id IS NULL
       OR source.status<>'awaiting_wallet' OR source.completed_at IS NOT NULL
       OR source.result IS NOT NULL OR source.error IS NOT NULL
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->'actor'->>'type') IS DISTINCT FROM NEW.actor_type
       OR (source.context::jsonb->'_marty_delegation_oid4vp_v1'->'actor'->>'id') IS DISTINCT FROM NEW.actor_id
       OR NEW.valid_until>binding.expires_at OR NEW.recorded_at<binding.created_at
       OR NEW.recorded_at>clock_timestamp() OR NEW.observed_at>clock_timestamp()
       OR NEW.authentication_valid_until<=NEW.authentication_observed_at
       OR NEW.authentication_valid_until>NEW.authentication_observed_at+interval '30 seconds'
       OR NEW.authorization_valid_until<=NEW.authorization_observed_at
       OR NEW.authorization_valid_until>NEW.authorization_observed_at+interval '30 seconds'
       OR NEW.observed_at<NEW.authentication_observed_at OR NEW.observed_at<NEW.authorization_observed_at
       OR NEW.recorded_at<NEW.observed_at OR NEW.valid_until<=NEW.recorded_at
       OR NEW.valid_until>NEW.authentication_valid_until OR NEW.valid_until>NEW.authorization_valid_until
       OR clock_timestamp()>=NEW.valid_until
       OR EXISTS(SELECT 1 FROM flow_service.delegated_use_consumptions WHERE challenge_id=NEW.challenge_id) THEN
        RAISE EXCEPTION 'FLOW.DELEGATED_INGRESS_BINDING_OR_EXPIRY';
    END IF;
    IF TG_TABLE_NAME='delegated_request_claims' THEN
        IF NEW.instance_snapshot IS DISTINCT FROM to_jsonb(source) THEN
            RAISE EXCEPTION 'FLOW.DELEGATED_REQUEST_CLAIM_BINDING';
        END IF;
    ELSIF TG_TABLE_NAME='delegated_request_results' THEN
        SELECT * INTO claim FROM flow_service.delegated_request_claims WHERE challenge_id=NEW.challenge_id;
        IF claim.challenge_id IS NULL OR NEW.organization_id IS DISTINCT FROM claim.organization_id
           OR NEW.actor_type IS DISTINCT FROM claim.actor_type OR NEW.actor_id IS DISTINCT FROM claim.actor_id
           OR NEW.configuration_digest IS DISTINCT FROM claim.configuration_digest
           OR NEW.authentication_observed_at IS DISTINCT FROM claim.authentication_observed_at
           OR NEW.authentication_valid_until IS DISTINCT FROM claim.authentication_valid_until
           OR NEW.valid_until>claim.valid_until OR NEW.observed_at<claim.observed_at
           OR octet_length(NEW.request_bytes) NOT BETWEEN 1 AND 65536
           OR NEW.request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.request_bytes),'hex')
           OR NEW.recorded_at<claim.recorded_at OR NEW.instance_snapshot IS DISTINCT FROM to_jsonb(source)
           OR (NEW.instance_snapshot - ARRAY['context','current_step_id','step_history','state_history','updated_at'])
              IS DISTINCT FROM (claim.instance_snapshot - ARRAY['context','current_step_id','step_history','state_history','updated_at'])
           OR ((NEW.instance_snapshot->'context') - ARRAY['request_retrieved','mip_messages',
              'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
              'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1'])
              IS DISTINCT FROM ((claim.instance_snapshot->'context') - ARRAY['request_retrieved','mip_messages',
              'oid4vp_response_uri','oid4vp_response_encryption_jwk','oid4vp_expected_state',
              'verification_audience','oid4vp_verifier_context','paired_wallet_signed_request_v1']) THEN
            RAISE EXCEPTION 'FLOW.DELEGATED_REQUEST_RESULT_BINDING';
        END IF;
    ELSIF TG_TABLE_NAME='delegated_proof_ingress' THEN
        SELECT * INTO proof FROM flow_service.delegated_proof_submissions WHERE submission_id=NEW.submission_id;
        IF proof.submission_id IS NULL OR proof.challenge_id IS DISTINCT FROM NEW.challenge_id
           OR proof.organization_id IS DISTINCT FROM NEW.organization_id
           OR proof.actor_type IS DISTINCT FROM NEW.actor_type OR proof.actor_id IS DISTINCT FROM NEW.actor_id
           OR proof.proof_digest IS DISTINCT FROM NEW.proof_digest OR proof.received_at>NEW.recorded_at THEN
            RAISE EXCEPTION 'FLOW.DELEGATED_PROOF_INGRESS_BINDING';
        END IF;
    ELSE
        RAISE EXCEPTION 'FLOW.DELEGATED_INGRESS_UNKNOWN_SOURCE';
    END IF;
    RETURN NEW;
END;
$$;

-- PostgreSQL FOR SHARE requires UPDATE authority. Expose only the fixed owner
-- read/lock operation so an ingress role cannot mutate definition columns.
CREATE OR REPLACE FUNCTION flow_service.lock_delegated_ingress_definition(target_organization_id uuid, target_challenge_id uuid)
RETURNS SETOF flow_service.flow_definitions LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
    SELECT d.* FROM flow_service.flow_definitions d
    JOIN flow_service.flow_instances f ON f.flow_definition_id=d.id
    WHERE f.id=target_challenge_id::text AND f.organization_id=target_organization_id::text
      AND d.organization_id=f.organization_id
    FOR SHARE OF d;
$$;
REVOKE ALL ON FUNCTION flow_service.lock_delegated_ingress_definition(uuid,uuid) FROM PUBLIC;

DO $$
DECLARE name text;
BEGIN
    FOREACH name IN ARRAY ARRAY['delegated_request_claims','delegated_request_results','delegated_proof_ingress'] LOOP
        EXECUTE format('REVOKE ALL ON flow_service.%I FROM PUBLIC',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_immutable',name);
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON flow_service.%I FOR EACH ROW EXECUTE FUNCTION flow_service.reject_delegated_use_mutation()',name||'_immutable',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_no_truncate',name);
        EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON flow_service.%I FOR EACH STATEMENT EXECUTE FUNCTION flow_service.reject_delegated_use_mutation()',name||'_no_truncate',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_binding',name);
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON flow_service.%I FOR EACH ROW EXECUTE FUNCTION flow_service.guard_delegated_ingress()',name||'_binding',name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON flow_service.%I',name||'_commit',name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT ON flow_service.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION flow_service.guard_delegated_ingress()',name||'_commit',name);
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION flow_service.guard_delegated_ingress() FROM PUBLIC;
INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_delegated_use_ingress_0006') ON CONFLICT DO NOTHING;
