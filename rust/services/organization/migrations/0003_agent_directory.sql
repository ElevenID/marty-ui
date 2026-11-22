-- Additive operator inventory. No existing grant, key, membership or protocol
-- entity is rewritten. Managed inventory is not qualified machine enrollment.
CREATE TABLE IF NOT EXISTS organization_service.agent_identities (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organization_service.organizations(id),
    kind TEXT NOT NULL CHECK (kind IN ('EXTERNAL','MANAGED')),
    status TEXT NOT NULL CHECK (status IN ('PROVISIONED','ACTIVE','SUSPENDED','REVOKED','RETIRED')),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    runtime_instance_ref TEXT NOT NULL CHECK (length(runtime_instance_ref) BETWEEN 1 AND 1024),
    document JSONB NOT NULL CHECK (jsonb_typeof(document)='object'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at>=created_at),
    UNIQUE (organization_id,id),
    UNIQUE (organization_id,issuer,subject,runtime_instance_ref),
    CHECK (kind<>'MANAGED' OR status<>'ACTIVE')
);
CREATE INDEX IF NOT EXISTS agent_identities_tenant_order
    ON organization_service.agent_identities(organization_id,created_at DESC,id);

CREATE TABLE IF NOT EXISTS organization_service.agent_identity_keys (
    key_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm IN ('EdDSA','ES256')),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
    key_thumbprint TEXT NOT NULL CHECK (key_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    public_key_jwk JSONB NOT NULL CHECK (jsonb_typeof(public_key_jwk)='object'
        AND NOT public_key_jwk ?| ARRAY['d','p','q','dp','dq','qi','oth','k']),
    created_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id,agent_id) REFERENCES organization_service.agent_identities(organization_id,id),
    UNIQUE (organization_id,agent_id,key_thumbprint),
    CHECK ((status='ACTIVE' AND ended_at IS NULL) OR (status<>'ACTIVE' AND ended_at IS NOT NULL AND ended_at>=created_at))
);
CREATE UNIQUE INDEX IF NOT EXISTS agent_identity_one_active_key
    ON organization_service.agent_identity_keys(organization_id,agent_id) WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS organization_service.agent_identity_history (
    organization_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    action TEXT NOT NULL CHECK (action IN ('REGISTER','UPDATE_METADATA','SUSPEND','REVOKE','RETIRE','ROTATE_KEY')),
    actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 255),
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    PRIMARY KEY (organization_id,agent_id,revision),
    FOREIGN KEY (organization_id,agent_id) REFERENCES organization_service.agent_identities(organization_id,id)
);
COMMENT ON TABLE organization_service.agent_identities IS
    'Administrative inventory only. ACTIVE does not establish authentication or authority. Managed entries remain PROVISIONED pending qualified enrollment. No grant references are retargeted by key changes.';
COMMENT ON TABLE organization_service.agent_identity_history IS
    'Immutable tenant-scoped operator history. Human actor and owner are resolved from trusted service context. Preserve historical snapshots and keys; no automatic erasure or key reuse.';

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
      OR NEW.document#>>'{provenance,managed_enrollment}' IS DISTINCT FROM 'NOT_ASSESSED'
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
          OR NOT ((NEW.kind='EXTERNAL' AND NEW.status='ACTIVE') OR (NEW.kind='MANAGED' AND NEW.status='PROVISIONED')) THEN
            RAISE EXCEPTION 'agent registration must use accountable unqualified inventory state';
        END IF;
    ELSE
        IF NEW.id<>OLD.id OR NEW.organization_id<>OLD.organization_id OR NEW.kind<>OLD.kind
          OR NEW.created_at<>OLD.created_at OR NEW.issuer<>OLD.issuer OR NEW.subject<>OLD.subject
          OR NEW.runtime_instance_ref<>OLD.runtime_instance_ref
          OR (NEW.document-ARRAY['status','revision','metadata','keys','updated_at'])
             IS DISTINCT FROM (OLD.document-ARRAY['status','revision','metadata','keys','updated_at'])
          OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at
          OR OLD.status='RETIRED' OR (OLD.status='REVOKED' AND NEW.status<>'RETIRED')
          OR (NEW.status IS DISTINCT FROM OLD.status AND NOT (
              (OLD.status IN ('PROVISIONED','ACTIVE') AND NEW.status IN ('SUSPENDED','REVOKED','RETIRED'))
              OR (OLD.status='SUSPENDED' AND NEW.status IN ('REVOKED','RETIRED'))
              OR (OLD.status='REVOKED' AND NEW.status='RETIRED'))) THEN
            RAISE EXCEPTION 'agent identity or lifecycle is immutable';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_agent_key()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.status<>'ACTIVE' OR NEW.ended_at IS NOT NULL THEN RAISE EXCEPTION 'new agent key requires ACTIVE inventory state'; END IF;
    ELSIF (to_jsonb(NEW)-ARRAY['status','ended_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','ended_at'])
      OR OLD.status<>'ACTIVE' OR NEW.status NOT IN ('RETIRED','REVOKED') OR NEW.ended_at IS NULL THEN
        RAISE EXCEPTION 'historical agent keys cannot be changed or reactivated';
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
        IF (NEW.action='UPDATE_METADATA' AND (NEW.snapshot->'keys' IS DISTINCT FROM previous_document->'keys' OR NEW.snapshot->'status' IS DISTINCT FROM previous_document->'status'))
          OR (NEW.action='ROTATE_KEY' AND (NEW.snapshot->'metadata' IS DISTINCT FROM previous_document->'metadata' OR NEW.snapshot->'status' IS DISTINCT FROM previous_document->'status' OR NEW.snapshot->'keys' IS NOT DISTINCT FROM previous_document->'keys'))
          OR (NEW.action IN ('SUSPEND','REVOKE','RETIRE') AND NEW.snapshot->'metadata' IS DISTINCT FROM previous_document->'metadata')
          OR (NEW.action='SUSPEND' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'SUSPENDED' OR NEW.snapshot->'keys' IS DISTINCT FROM previous_document->'keys'))
          OR (NEW.action='REVOKE' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'REVOKED' OR NEW.snapshot->'keys' IS DISTINCT FROM '[]'::JSONB))
          OR (NEW.action='RETIRE' AND (NEW.snapshot->>'status' IS DISTINCT FROM 'RETIRED' OR NEW.snapshot->'keys' IS DISTINCT FROM '[]'::JSONB))
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
    END IF;
    SELECT count(*),max(revision) INTO history_count,history_max FROM organization_service.agent_identity_history WHERE organization_id=org AND agent_id=agent;
    IF history_count<>identity_row.revision OR history_max IS DISTINCT FROM identity_row.revision THEN
        RAISE EXCEPTION 'agent history must commit with every revision';
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION organization_service.reject_agent_directory_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'agent history, identities and retired keys must be preserved'; END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_identities'::regclass AND tgname='agent_identity_guard') THEN
        CREATE TRIGGER agent_identity_guard BEFORE INSERT OR UPDATE ON organization_service.agent_identities FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_identity();
        CREATE TRIGGER agent_identity_no_removal BEFORE DELETE OR TRUNCATE ON organization_service.agent_identities FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
        CREATE CONSTRAINT TRIGGER agent_identity_complete AFTER INSERT OR UPDATE ON organization_service.agent_identities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_inventory_complete();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_identity_keys'::regclass AND tgname='agent_key_guard') THEN
        CREATE TRIGGER agent_key_guard BEFORE INSERT OR UPDATE ON organization_service.agent_identity_keys FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_key();
        CREATE TRIGGER agent_key_no_removal BEFORE DELETE OR TRUNCATE ON organization_service.agent_identity_keys FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
        CREATE CONSTRAINT TRIGGER agent_keys_complete AFTER INSERT OR UPDATE ON organization_service.agent_identity_keys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_agent_inventory_complete();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.agent_identity_history'::regclass AND tgname='agent_history_guard') THEN
        CREATE TRIGGER agent_history_guard BEFORE INSERT ON organization_service.agent_identity_history FOR EACH ROW EXECUTE FUNCTION organization_service.guard_agent_history();
        CREATE TRIGGER agent_history_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.agent_identity_history FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_agent_directory_mutation();
    END IF;
END $$;
REVOKE ALL ON organization_service.agent_identities,organization_service.agent_identity_keys,organization_service.agent_identity_history FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_service.guard_agent_identity(),organization_service.guard_agent_key(),organization_service.guard_agent_history(),organization_service.check_agent_inventory_complete(),organization_service.reject_agent_directory_mutation() FROM PUBLIC;
INSERT INTO organization_service.rust_schema_versions(version) VALUES ('rust_organization_agent_directory_0003') ON CONFLICT (version) DO NOTHING;
