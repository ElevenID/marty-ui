-- Additive, purpose-specific key-control enrollment. This is not an operational
-- MAP credential, issuer qualification, runtime attestation or authority grant.
CREATE TABLE IF NOT EXISTS organization_service.agent_enrollment_challenges (
    challenge_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_id UUID NOT NULL REFERENCES organization_service.agent_identity_keys(key_id),
    expected_revision BIGINT NOT NULL CHECK (expected_revision BETWEEN 1 AND 9007199254740990),
    administrator_id UUID NOT NULL,
    session_ref TEXT NOT NULL CHECK (session_ref ~ '^urn:marty:session:sha256:[0-9a-f]{64}$'),
    document JSONB NOT NULL CHECK (jsonb_typeof(document)='object'),
    payload TEXT NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 8192),
    challenge_digest TEXT NOT NULL CHECK (challenge_digest ~ '^sha256:[0-9a-f]{64}$'),
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at>issued_at AND expires_at<=issued_at+INTERVAL '300 seconds'),
    authorization_observed_at TIMESTAMPTZ NOT NULL,
    authorization_valid_until TIMESTAMPTZ NOT NULL CHECK (authorization_valid_until>authorization_observed_at AND authorization_valid_until<=authorization_observed_at+INTERVAL '30 seconds'),
    FOREIGN KEY (organization_id,agent_id) REFERENCES organization_service.agent_identities(organization_id,id),
    UNIQUE (challenge_id,organization_id,agent_id)
);
CREATE INDEX IF NOT EXISTS agent_enrollment_challenge_identity
    ON organization_service.agent_enrollment_challenges(organization_id,agent_id,issued_at DESC,challenge_id);

CREATE TABLE IF NOT EXISTS organization_service.agent_enrollment_outcomes (
    challenge_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_id UUID NOT NULL REFERENCES organization_service.agent_identity_keys(key_id),
    enrolled_revision BIGINT NOT NULL CHECK (enrolled_revision BETWEEN 2 AND 9007199254740991),
    proof_digest TEXT NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
    completed_at TIMESTAMPTZ NOT NULL,
    authorization_observed_at TIMESTAMPTZ NOT NULL,
    authorization_valid_until TIMESTAMPTZ NOT NULL CHECK (authorization_valid_until>authorization_observed_at AND authorization_valid_until<=authorization_observed_at+INTERVAL '30 seconds'),
    result JSONB NOT NULL CHECK (jsonb_typeof(result)='object'),
    FOREIGN KEY (challenge_id,organization_id,agent_id) REFERENCES organization_service.agent_enrollment_challenges(challenge_id,organization_id,agent_id),
    UNIQUE (organization_id,agent_id,enrolled_revision)
);
CREATE TABLE IF NOT EXISTS organization_service.agent_enrollment_invalidations (
    challenge_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    invalidated_at TIMESTAMPTZ NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('EXPIRED','REVISION_CHANGED','SUPERSEDED')),
    FOREIGN KEY (challenge_id,organization_id,agent_id) REFERENCES organization_service.agent_enrollment_challenges(challenge_id,organization_id,agent_id)
);

-- The previous migration is preserved byte-for-byte. Only this additive step
-- opens the narrowly evidenced PROVISIONED -> ACTIVE transition.
-- PostgreSQL names the cross-column updated_at>=created_at check `check` and
-- the later managed-activation exclusion `check1`; preserve the timestamp check.
ALTER TABLE organization_service.agent_identities DROP CONSTRAINT IF EXISTS agent_identities_check1;
ALTER TABLE organization_service.agent_identity_history DROP CONSTRAINT IF EXISTS agent_identity_history_action_check;
ALTER TABLE organization_service.agent_identity_history ADD CONSTRAINT agent_identity_history_action_check
    CHECK (action IN ('REGISTER','UPDATE_METADATA','SUSPEND','REVOKE','RETIRE','ROTATE_KEY','ENROLL'));

CREATE OR REPLACE FUNCTION organization_service.guard_agent_identity()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE authoritative_owner TEXT;
BEGIN
    IF NEW.document->>'id' IS DISTINCT FROM NEW.id::TEXT
      OR NEW.document->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.document->>'kind' IS DISTINCT FROM NEW.kind
      OR NEW.document->>'status' IS DISTINCT FROM NEW.status
      OR NEW.document->>'revision' IS DISTINCT FROM NEW.revision::TEXT
      OR NEW.document->>'issuer' IS DISTINCT FROM NEW.issuer
      OR NEW.document->>'subject' IS DISTINCT FROM NEW.subject
      OR NEW.document->>'runtime_instance_ref' IS DISTINCT FROM NEW.runtime_instance_ref
      OR (NEW.document->>'created_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.created_at
      OR (NEW.document->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.updated_at
      OR NEW.document->>'authority_status' IS DISTINCT FROM 'NOT_ASSESSED'
      OR NEW.document#>>'{provenance,managed_enrollment}' IS NULL
      OR NEW.document#>>'{provenance,managed_enrollment}' NOT IN ('NOT_ASSESSED','KEY_CONTROL_VERIFIED')
      OR (NEW.kind='EXTERNAL' AND NEW.document#>>'{provenance,managed_enrollment}'<>'NOT_ASSESSED')
      OR (NEW.status='PROVISIONED' AND NEW.document#>>'{provenance,managed_enrollment}'<>'NOT_ASSESSED')
      OR (NEW.kind='MANAGED' AND NEW.status='ACTIVE' AND NEW.document#>>'{provenance,managed_enrollment}'<>'KEY_CONTROL_VERIFIED')
      OR NEW.document#>>'{provenance,external_authentication}' IS DISTINCT FROM 'NOT_ASSESSED'
      OR NEW.document#>>'{provenance,kind}' IS DISTINCT FROM 'OPERATOR_DECLARATION'
      OR jsonb_typeof(NEW.document->'keys') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'agent inventory projection is invalid';
    END IF;
    IF TG_OP='INSERT' THEN
        SELECT owner_id INTO STRICT authoritative_owner FROM organization_service.organizations WHERE id=NEW.organization_id;
        IF NEW.revision<>1 OR NEW.created_at<>NEW.updated_at
          OR NEW.document->>'owner_user_id' IS DISTINCT FROM authoritative_owner
          OR NEW.document#>>'{provenance,registered_by}' IS DISTINCT FROM (NEW.document->>'created_by')
          OR NEW.document#>>'{provenance,managed_enrollment}' IS DISTINCT FROM 'NOT_ASSESSED'
          OR NOT ((NEW.kind='EXTERNAL' AND NEW.status='ACTIVE') OR (NEW.kind='MANAGED' AND NEW.status='PROVISIONED')) THEN
            RAISE EXCEPTION 'agent registration must use accountable unqualified inventory state';
        END IF;
    ELSE
        IF NEW.id<>OLD.id OR NEW.organization_id<>OLD.organization_id OR NEW.kind<>OLD.kind
          OR NEW.created_at<>OLD.created_at OR NEW.issuer<>OLD.issuer OR NEW.subject<>OLD.subject
          OR NEW.runtime_instance_ref<>OLD.runtime_instance_ref
          OR (NEW.document-ARRAY['status','revision','metadata','keys','updated_at','provenance'])
             IS DISTINCT FROM (OLD.document-ARRAY['status','revision','metadata','keys','updated_at','provenance'])
          OR ((NEW.document->'provenance')-'managed_enrollment') IS DISTINCT FROM ((OLD.document->'provenance')-'managed_enrollment')
          OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at
          OR OLD.status='RETIRED' OR (OLD.status='REVOKED' AND NEW.status<>'RETIRED')
          OR (NEW.status IS DISTINCT FROM OLD.status AND NOT (
              (OLD.status IN ('PROVISIONED','ACTIVE') AND NEW.status IN ('SUSPENDED','REVOKED','RETIRED'))
              OR (OLD.status='SUSPENDED' AND NEW.status IN ('REVOKED','RETIRED'))
              OR (OLD.status='REVOKED' AND NEW.status='RETIRED')
              OR (NEW.kind='MANAGED' AND OLD.status='PROVISIONED' AND NEW.status='ACTIVE'
                  AND NEW.document->'keys'=OLD.document->'keys'
                  AND NEW.document#>>'{provenance,managed_enrollment}'='KEY_CONTROL_VERIFIED')
              OR (NEW.kind='MANAGED' AND OLD.status='ACTIVE' AND NEW.status='PROVISIONED'
                  AND NEW.document->'keys' IS DISTINCT FROM OLD.document->'keys'
                  AND NEW.document#>>'{provenance,managed_enrollment}'='NOT_ASSESSED')))
          OR (NEW.document#>'{provenance,managed_enrollment}' IS DISTINCT FROM OLD.document#>'{provenance,managed_enrollment}' AND NOT (
              (NEW.kind='MANAGED' AND OLD.status='PROVISIONED' AND NEW.status='ACTIVE'
                  AND NEW.document->'keys'=OLD.document->'keys' AND NEW.document->'metadata'=OLD.document->'metadata')
              OR (NEW.kind='MANAGED' AND NEW.document->'keys' IS DISTINCT FROM OLD.document->'keys'
                  AND NEW.document#>>'{provenance,managed_enrollment}'='NOT_ASSESSED'))) THEN
            RAISE EXCEPTION 'agent identity or lifecycle is immutable';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_agent_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_document JSONB; previous_document JSONB;
BEGIN
    SELECT document INTO STRICT current_document FROM organization_service.agent_identities WHERE organization_id=NEW.organization_id AND id=NEW.agent_id FOR SHARE;
    IF NEW.snapshot IS DISTINCT FROM current_document
      OR NEW.snapshot->>'revision' IS DISTINCT FROM NEW.revision::TEXT
      OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.occurred_at THEN
        RAISE EXCEPTION 'agent history must record the exact current revision';
    END IF;
    IF NEW.revision=1 THEN
        IF NEW.action<>'REGISTER' OR NEW.snapshot->>'created_by' IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'agent registration attribution is invalid';
        END IF;
    ELSE
        SELECT snapshot INTO STRICT previous_document FROM organization_service.agent_identity_history
          WHERE organization_id=NEW.organization_id AND agent_id=NEW.agent_id AND revision=NEW.revision-1;
        IF (NEW.action NOT IN ('ENROLL','ROTATE_KEY') AND NEW.snapshot->'provenance' IS DISTINCT FROM previous_document->'provenance')
          OR (NEW.action='UPDATE_METADATA' AND (NEW.snapshot->'keys' IS DISTINCT FROM previous_document->'keys' OR NEW.snapshot->'status' IS DISTINCT FROM previous_document->'status'))
          OR (NEW.action='ROTATE_KEY' AND (NEW.snapshot->'metadata' IS DISTINCT FROM previous_document->'metadata'
              OR NEW.snapshot->'keys' IS NOT DISTINCT FROM previous_document->'keys'
              OR (NEW.snapshot->'status' IS DISTINCT FROM previous_document->'status' AND NOT (
                  previous_document->>'kind'='MANAGED' AND previous_document->>'status'='ACTIVE' AND NEW.snapshot->>'status'='PROVISIONED'))
              OR (NEW.snapshot->>'kind'='MANAGED' AND NEW.snapshot#>>'{provenance,managed_enrollment}' IS DISTINCT FROM 'NOT_ASSESSED')
              OR (previous_document->>'kind'='MANAGED' AND previous_document->>'status'='ACTIVE' AND NEW.snapshot->>'status'<>'PROVISIONED')))
          OR (NEW.action IN ('SUSPEND','REVOKE','RETIRE') AND NEW.snapshot->'metadata' IS DISTINCT FROM previous_document->'metadata')
          OR (NEW.action='SUSPEND' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'SUSPENDED' OR NEW.snapshot->'keys' IS DISTINCT FROM previous_document->'keys'))
          OR (NEW.action='REVOKE' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'REVOKED' OR NEW.snapshot->'keys' IS DISTINCT FROM '[]'::JSONB))
          OR (NEW.action='RETIRE' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'RETIRED' OR NEW.snapshot->'keys' IS DISTINCT FROM '[]'::JSONB))
          OR (NEW.action='ENROLL' AND (previous_document->>'kind' IS DISTINCT FROM 'MANAGED'
              OR previous_document->>'status' IS DISTINCT FROM 'PROVISIONED'
              OR previous_document#>>'{provenance,managed_enrollment}' IS DISTINCT FROM 'NOT_ASSESSED'
              OR NEW.snapshot->>'status' IS DISTINCT FROM 'ACTIVE'
              OR NEW.snapshot#>>'{provenance,managed_enrollment}' IS DISTINCT FROM 'KEY_CONTROL_VERIFIED'
              OR NEW.snapshot->'keys' IS DISTINCT FROM previous_document->'keys'
              OR NEW.snapshot->'metadata' IS DISTINCT FROM previous_document->'metadata'
              OR NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_outcomes o
                    JOIN organization_service.agent_enrollment_challenges c USING (challenge_id)
                    WHERE o.organization_id=NEW.organization_id AND o.agent_id=NEW.agent_id
                      AND o.enrolled_revision=NEW.revision AND c.administrator_id::TEXT=NEW.actor_user_id
                      AND o.result->'identity'=NEW.snapshot)))
          OR NEW.action='REGISTER' THEN RAISE EXCEPTION 'agent history action is inconsistent'; END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_agent_inventory_complete()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE org UUID; agent UUID; identity_row RECORD; key_row RECORD; active_count BIGINT; history_count BIGINT; history_max BIGINT; expected_count INTEGER;
BEGIN
    org:=NEW.organization_id;
    IF TG_TABLE_NAME='agent_identities' THEN agent:=NEW.id; ELSE agent:=NEW.agent_id; END IF;
    SELECT * INTO STRICT identity_row FROM organization_service.agent_identities WHERE organization_id=org AND id=agent;
    SELECT count(*) INTO active_count FROM organization_service.agent_identity_keys WHERE organization_id=org AND agent_id=agent AND status='ACTIVE';
    expected_count:=CASE WHEN identity_row.status IN ('REVOKED','RETIRED') THEN 0 ELSE 1 END;
    IF active_count<>expected_count OR jsonb_array_length(identity_row.document->'keys')<>expected_count THEN
        RAISE EXCEPTION 'agent inventory must have exactly its current active key';
    END IF;
    IF expected_count=1 THEN
        SELECT * INTO STRICT key_row FROM organization_service.agent_identity_keys WHERE organization_id=org AND agent_id=agent AND status='ACTIVE';
        IF identity_row.document#>>'{keys,0,key_id}' IS DISTINCT FROM key_row.key_id::TEXT
          OR identity_row.document#>>'{keys,0,status}' IS DISTINCT FROM 'ACTIVE'
          OR identity_row.document#>>'{keys,0,algorithm}' IS DISTINCT FROM key_row.algorithm
          OR identity_row.document#>>'{keys,0,fingerprint,basis}' IS DISTINCT FROM 'JWK_RFC7638_SHA256'
          OR identity_row.document#>>'{keys,0,fingerprint,encoding}' IS DISTINCT FROM 'BASE64URL_SHA256'
          OR identity_row.document#>>'{keys,0,fingerprint,value}' IS DISTINCT FROM key_row.key_thumbprint
          OR identity_row.document#>'{keys,0,public_key_jwk}' IS DISTINCT FROM key_row.public_key_jwk
          OR (identity_row.document#>>'{keys,0,created_at}')::TIMESTAMPTZ IS DISTINCT FROM key_row.created_at THEN
            RAISE EXCEPTION 'agent key projection differs from authoritative inventory';
        END IF;
        IF identity_row.kind='MANAGED' AND identity_row.status='ACTIVE' AND NOT EXISTS (
            SELECT 1 FROM organization_service.agent_enrollment_outcomes o
              JOIN organization_service.agent_identity_history h ON h.organization_id=o.organization_id AND h.agent_id=o.agent_id AND h.revision=o.enrolled_revision
              WHERE o.organization_id=org AND o.agent_id=agent AND o.key_id=key_row.key_id
                AND o.enrolled_revision<=identity_row.revision AND h.action='ENROLL' AND h.snapshot=o.result->'identity') THEN
            RAISE EXCEPTION 'managed ACTIVE requires retained exact-key enrollment';
        END IF;
    END IF;
    SELECT count(*),max(revision) INTO history_count,history_max FROM organization_service.agent_identity_history WHERE organization_id=org AND agent_id=agent;
    IF history_count<>identity_row.revision OR history_max IS DISTINCT FROM identity_row.revision THEN
        RAISE EXCEPTION 'agent history must commit with every revision';
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_agent_enrollment_challenge()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE identity_row RECORD; key_row RECORD; observed TIMESTAMPTZ;
BEGIN
    SELECT * INTO STRICT identity_row FROM organization_service.agent_identities WHERE organization_id=NEW.organization_id AND id=NEW.agent_id FOR UPDATE;
    SELECT * INTO STRICT key_row FROM organization_service.agent_identity_keys WHERE organization_id=NEW.organization_id AND agent_id=NEW.agent_id AND status='ACTIVE' FOR SHARE;
    observed:=clock_timestamp();
    IF identity_row.kind<>'MANAGED' OR identity_row.status<>'PROVISIONED' OR identity_row.revision<>NEW.expected_revision
      OR NEW.key_id<>key_row.key_id OR NEW.document->>'profile' IS DISTINCT FROM 'urn:marty:managed-key-enrollment:v1'
      OR NEW.document->>'purpose' IS DISTINCT FROM 'ENROLL_MANAGED_KEY'
      OR NEW.document->>'challenge_id' IS DISTINCT FROM NEW.challenge_id::TEXT
      OR NEW.document->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.document->>'agent_id' IS DISTINCT FROM NEW.agent_id::TEXT
      OR NEW.document->>'key_id' IS DISTINCT FROM NEW.key_id::TEXT
      OR NEW.document->>'expected_revision' IS DISTINCT FROM NEW.expected_revision::TEXT
      OR NEW.document->>'administrator_id' IS DISTINCT FROM NEW.administrator_id::TEXT
      OR NEW.document->>'session_ref' IS DISTINCT FROM NEW.session_ref
      OR NEW.document->>'issuer' IS DISTINCT FROM identity_row.issuer
      OR NEW.document->>'subject' IS DISTINCT FROM identity_row.subject
      OR NEW.document->>'runtime_instance_ref' IS DISTINCT FROM identity_row.runtime_instance_ref
      OR NEW.document->>'key_algorithm' IS DISTINCT FROM key_row.algorithm
      OR NEW.document#>>'{key_thumbprint,basis}' IS DISTINCT FROM 'JWK_RFC7638_SHA256'
      OR NEW.document#>>'{key_thumbprint,encoding}' IS DISTINCT FROM 'BASE64URL_SHA256'
      OR NEW.document#>>'{key_thumbprint,value}' IS DISTINCT FROM key_row.key_thumbprint
      OR NEW.issued_at IS DISTINCT FROM to_timestamp((NEW.document->>'iat')::DOUBLE PRECISION)
      OR NEW.expires_at IS DISTINCT FROM to_timestamp((NEW.document->>'exp')::DOUBLE PRECISION)
      OR NEW.payload::JSONB IS DISTINCT FROM NEW.document
      OR NEW.challenge_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(NEW.payload,'UTF8')),'hex')
      OR observed<NEW.issued_at OR observed>=NEW.expires_at
      OR observed<NEW.authorization_observed_at OR observed>=NEW.authorization_valid_until
      OR EXISTS (SELECT 1 FROM organization_service.agent_enrollment_challenges c WHERE c.organization_id=NEW.organization_id AND c.agent_id=NEW.agent_id
          AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_outcomes o WHERE o.challenge_id=c.challenge_id)
          AND NOT EXISTS (SELECT 1 FROM organization_service.agent_enrollment_invalidations i WHERE i.challenge_id=c.challenge_id)) THEN
        RAISE EXCEPTION 'managed enrollment challenge binding is invalid';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_agent_enrollment_outcome()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE challenge RECORD; identity_row RECORD; observed TIMESTAMPTZ;
BEGIN
    SELECT * INTO STRICT identity_row FROM organization_service.agent_identities WHERE organization_id=NEW.organization_id AND id=NEW.agent_id FOR UPDATE;
    SELECT * INTO STRICT challenge FROM organization_service.agent_enrollment_challenges WHERE challenge_id=NEW.challenge_id FOR UPDATE;
    observed:=clock_timestamp();
    IF NEW.organization_id<>challenge.organization_id OR NEW.agent_id<>challenge.agent_id
      OR NEW.key_id<>challenge.key_id OR NEW.enrolled_revision<>challenge.expected_revision+1
      OR identity_row.kind<>'MANAGED' OR identity_row.status<>'ACTIVE' OR identity_row.revision<>NEW.enrolled_revision
      OR identity_row.document#>>'{keys,0,key_id}' IS DISTINCT FROM NEW.key_id::TEXT
      OR NEW.completed_at<>identity_row.updated_at
      OR NEW.completed_at<challenge.issued_at OR NEW.completed_at>=challenge.expires_at
      OR observed<NEW.completed_at OR observed>=challenge.expires_at
      OR observed<NEW.authorization_observed_at OR observed>=NEW.authorization_valid_until
      OR EXISTS (SELECT 1 FROM organization_service.agent_enrollment_invalidations i WHERE i.challenge_id=NEW.challenge_id)
      OR NEW.result IS DISTINCT FROM jsonb_build_object(
          'challenge_id',NEW.challenge_id,'organization_id',NEW.organization_id,'agent_id',NEW.agent_id,
          'key_id',NEW.key_id,'previous_revision',challenge.expected_revision,'enrolled_revision',NEW.enrolled_revision,
          'completed_at',NEW.result->'completed_at','proof_digest',NEW.proof_digest,'challenge_digest',challenge.challenge_digest,
          'enrollment','KEY_CONTROL_VERIFIED','authority_status','NOT_ASSESSED','identity',identity_row.document,'recovered',false)
      OR (NEW.result->>'completed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.completed_at THEN
        RAISE EXCEPTION 'managed enrollment outcome binding is invalid';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_agent_enrollment_invalidation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE challenge RECORD;
BEGIN
    PERFORM 1 FROM organization_service.agent_identities WHERE organization_id=NEW.organization_id AND id=NEW.agent_id FOR UPDATE;
    SELECT * INTO STRICT challenge FROM organization_service.agent_enrollment_challenges WHERE challenge_id=NEW.challenge_id FOR UPDATE;
    IF NEW.organization_id<>challenge.organization_id OR NEW.agent_id<>challenge.agent_id OR NEW.invalidated_at<challenge.issued_at
      OR EXISTS (SELECT 1 FROM organization_service.agent_enrollment_outcomes o WHERE o.challenge_id=NEW.challenge_id) THEN
        RAISE EXCEPTION 'completed enrollment cannot be invalidated or reused';
    END IF;
    RETURN NEW;
END $$;

-- This runs during COMMIT, including after audit/constraint lock waits. An
-- earlier application-clock check alone must not outlive challenge or session.
CREATE OR REPLACE FUNCTION organization_service.check_agent_enrollment_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE challenge RECORD; observed TIMESTAMPTZ;
BEGIN
    SELECT * INTO STRICT challenge FROM organization_service.agent_enrollment_challenges WHERE challenge_id=NEW.challenge_id;
    observed:=clock_timestamp();
    IF observed<challenge.issued_at OR observed>=challenge.expires_at
      OR observed<NEW.authorization_observed_at OR observed>=NEW.authorization_valid_until THEN
        RAISE EXCEPTION 'managed enrollment or session expired before commit';
    END IF;
    IF TG_TABLE_NAME='agent_enrollment_outcomes' THEN
        IF observed<NEW.completed_at OR NOT EXISTS (
            SELECT 1 FROM organization_service.agent_identity_history h WHERE h.organization_id=NEW.organization_id AND h.agent_id=NEW.agent_id
              AND h.revision=NEW.enrolled_revision AND h.action='ENROLL' AND h.snapshot=NEW.result->'identity') THEN
            RAISE EXCEPTION 'managed enrollment must commit with its exact history';
        END IF;
    END IF;
    RETURN NULL;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_enrollment_challenges'::regclass AND tgname='agent_enrollment_challenge_guard') THEN
        CREATE TRIGGER agent_enrollment_challenge_guard BEFORE INSERT ON organization_service.agent_enrollment_challenges FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_enrollment_challenge();
        CREATE TRIGGER agent_enrollment_challenge_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.agent_enrollment_challenges FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
        CREATE CONSTRAINT TRIGGER agent_enrollment_challenge_commit AFTER INSERT ON organization_service.agent_enrollment_challenges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_enrollment_commit();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_enrollment_outcomes'::regclass AND tgname='agent_enrollment_outcome_guard') THEN
        CREATE TRIGGER agent_enrollment_outcome_guard BEFORE INSERT ON organization_service.agent_enrollment_outcomes FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_enrollment_outcome();
        CREATE TRIGGER agent_enrollment_outcome_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.agent_enrollment_outcomes FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
        CREATE CONSTRAINT TRIGGER agent_enrollment_outcome_commit AFTER INSERT ON organization_service.agent_enrollment_outcomes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_enrollment_commit();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_enrollment_invalidations'::regclass AND tgname='agent_enrollment_invalidation_guard') THEN
        CREATE TRIGGER agent_enrollment_invalidation_guard BEFORE INSERT ON organization_service.agent_enrollment_invalidations FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_enrollment_invalidation();
        CREATE TRIGGER agent_enrollment_invalidation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.agent_enrollment_invalidations FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
    END IF;
END $$;
COMMENT ON TABLE organization_service.agent_enrollment_outcomes IS
    'Immutable evidence of administrator-approved control of one exact managed inventory key. Retained proof digest and historical result only; never a MAP credential, runtime authentication or delegated authority. Replays cannot activate a changed identity.';
COMMENT ON TABLE organization_service.agent_identities IS
    'Administrative inventory. Managed ACTIVE eligibility requires retained administrator-approved current-key control enrollment. ACTIVE never establishes operational MAP authentication, external issuer or host trust, or delegated authority. Rotation preserves old evidence and resets managed eligibility.';
REVOKE ALL ON organization_service.agent_enrollment_challenges,organization_service.agent_enrollment_outcomes,organization_service.agent_enrollment_invalidations FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_service.guard_agent_enrollment_challenge(),organization_service.guard_agent_enrollment_outcome(),organization_service.guard_agent_enrollment_invalidation(),organization_service.check_agent_enrollment_commit() FROM PUBLIC;
INSERT INTO organization_service.rust_schema_versions(version) VALUES ('rust_organization_managed_enrollment_0004') ON CONFLICT (version) DO NOTHING;
