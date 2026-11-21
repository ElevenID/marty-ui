-- Explicit machine policy ownership inside the existing policy-set owner.
-- Existing CUSTOM/access/credential/approval policies are never reinterpreted.
ALTER TABLE organization_service.policy_sets
    ADD COLUMN IF NOT EXISTS machine_policy_revision BIGINT;

CREATE TABLE IF NOT EXISTS organization_service.machine_authorization_policy_history (
    organization_id UUID NOT NULL REFERENCES organization_service.organizations(id),
    policy_set_id UUID NOT NULL REFERENCES organization_service.policy_sets(id),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    action TEXT NOT NULL CHECK (action IN ('CREATE','REPLACE','ACTIVATE','ARCHIVE')),
    actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 255),
    occurred_at TIMESTAMPTZ NOT NULL,
    snapshot_bytes BYTEA NOT NULL CHECK (octet_length(snapshot_bytes) BETWEEN 1 AND 262144),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY (organization_id,policy_set_id,revision),
    CONSTRAINT machine_policy_history_bytes CHECK (convert_from(snapshot_bytes,'UTF8')::JSONB=snapshot),
    CONSTRAINT machine_policy_history_digest CHECK (snapshot_digest='sha256:'||encode(sha256(snapshot_bytes),'hex'))
);

CREATE OR REPLACE FUNCTION organization_service.guard_machine_authorization_policy()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF OLD.policy_type='MACHINE_AUTHORIZATION' THEN RAISE EXCEPTION 'MACHINE_POLICY_HISTORY_REQUIRED'; END IF;
        RETURN OLD;
    END IF;
    IF TG_OP='UPDATE' AND OLD.policy_type='MACHINE_AUTHORIZATION' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
           OR NEW.policy_type IS DISTINCT FROM OLD.policy_type OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.created_by IS DISTINCT FROM OLD.created_by
           OR NEW.machine_policy_revision IS DISTINCT FROM OLD.machine_policy_revision+1
           OR NEW.updated_at<=OLD.updated_at THEN
            RAISE EXCEPTION 'MACHINE_POLICY_IMMUTABLE_IDENTITY';
        END IF;
    ELSIF NEW.policy_type='MACHINE_AUTHORIZATION' THEN
        IF TG_OP<>'INSERT' OR NEW.machine_policy_revision IS DISTINCT FROM 1 OR NEW.status<>'DRAFT'
           OR NEW.created_at IS DISTINCT FROM NEW.updated_at THEN
            RAISE EXCEPTION 'MACHINE_POLICY_EXPLICIT_CREATE_REQUIRED';
        END IF;
    END IF;
    IF NEW.policy_type='MACHINE_AUTHORIZATION' THEN
        IF NEW.machine_policy_revision IS NULL OR NEW.machine_policy_revision NOT BETWEEN 1 AND 9007199254740991
           OR NEW.cedar_schema_version<>'MartyMachine/1.0' OR NEW.status NOT IN ('DRAFT','ACTIVE','ARCHIVED')
           OR NEW.created_by IS NULL OR length(NEW.created_by)=0
           OR NEW.updated_at>clock_timestamp() THEN
            RAISE EXCEPTION 'MACHINE_POLICY_INVALID';
        END IF;
        IF TG_OP='UPDATE' AND OLD.status='ACTIVE' AND (
            NEW.status<>'ARCHIVED' OR NEW.cedar_policies IS DISTINCT FROM OLD.cedar_policies
            OR NEW.name IS DISTINCT FROM OLD.name OR NEW.description IS DISTINCT FROM OLD.description
        ) THEN RAISE EXCEPTION 'MACHINE_POLICY_ARCHIVE_BEFORE_REPLACE'; END IF;
    ELSIF NEW.machine_policy_revision IS NOT NULL THEN
        RAISE EXCEPTION 'MACHINE_POLICY_TYPE_REQUIRED';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_authorization_policy_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p organization_service.policy_sets; previous JSONB;
BEGIN
    SELECT * INTO p FROM organization_service.policy_sets WHERE id=NEW.policy_set_id;
    IF NOT FOUND OR p.organization_id IS DISTINCT FROM NEW.organization_id OR p.policy_type<>'MACHINE_AUTHORIZATION'
       OR p.machine_policy_revision IS DISTINCT FROM NEW.revision OR p.updated_at IS DISTINCT FROM NEW.occurred_at
       OR NEW.snapshot->>'organization_id' IS DISTINCT FROM p.organization_id::TEXT
       OR NEW.snapshot->>'policy_set_id' IS DISTINCT FROM p.id::TEXT
       OR NEW.snapshot->>'revision' IS DISTINCT FROM p.machine_policy_revision::TEXT
       OR NEW.snapshot->>'policy_type' IS DISTINCT FROM p.policy_type
       OR NEW.snapshot->>'status' IS DISTINCT FROM p.status
       OR NEW.snapshot->>'name' IS DISTINCT FROM p.name
       OR NEW.snapshot->>'description' IS DISTINCT FROM p.description
       OR NEW.snapshot->'policies' IS DISTINCT FROM p.cedar_policies::JSONB
       OR NEW.snapshot->>'schema_version' IS DISTINCT FROM p.cedar_schema_version
       OR NEW.snapshot->>'created_by' IS DISTINCT FROM p.created_by
       OR (NEW.snapshot->>'created_at')::TIMESTAMPTZ IS DISTINCT FROM p.created_at
       OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM p.updated_at THEN
        RAISE EXCEPTION 'MACHINE_POLICY_HISTORY_BINDING';
    END IF;
    IF NEW.revision=1 THEN
        IF NEW.action<>'CREATE' OR p.status<>'DRAFT' OR NEW.actor_user_id<>p.created_by THEN
            RAISE EXCEPTION 'MACHINE_POLICY_CREATE_HISTORY';
        END IF;
    ELSE
        SELECT snapshot INTO previous FROM organization_service.machine_authorization_policy_history
            WHERE organization_id=NEW.organization_id AND policy_set_id=NEW.policy_set_id AND revision=NEW.revision-1;
        IF NOT FOUND OR (previous->>'updated_at')::TIMESTAMPTZ>=NEW.occurred_at
           OR (NEW.action='ACTIVATE' AND (previous->>'status' NOT IN ('DRAFT','ARCHIVED') OR p.status<>'ACTIVE'
                OR (NEW.snapshot - ARRAY['revision','status','updated_at']) IS DISTINCT FROM (previous - ARRAY['revision','status','updated_at'])))
           OR (NEW.action='ARCHIVE' AND (previous->>'status'<>'ACTIVE' OR p.status<>'ARCHIVED'
                OR (NEW.snapshot - ARRAY['revision','status','updated_at']) IS DISTINCT FROM (previous - ARRAY['revision','status','updated_at'])))
           OR (NEW.action='REPLACE' AND (previous->>'status' NOT IN ('DRAFT','ARCHIVED') OR p.status<>'DRAFT'))
           OR NEW.action='CREATE' THEN
            RAISE EXCEPTION 'MACHINE_POLICY_TRANSITION';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_machine_authorization_policy_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE p organization_service.policy_sets; n BIGINT; maximum BIGINT;
BEGIN
    SELECT * INTO p FROM organization_service.policy_sets WHERE id=NEW.id;
    IF p.policy_type='MACHINE_AUTHORIZATION' THEN
        SELECT count(*),max(revision) INTO n,maximum FROM organization_service.machine_authorization_policy_history
            WHERE organization_id=p.organization_id AND policy_set_id=p.id;
        IF n<>p.machine_policy_revision OR maximum IS DISTINCT FROM p.machine_policy_revision THEN
            RAISE EXCEPTION 'MACHINE_POLICY_HISTORY_REQUIRED';
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION organization_service.reject_machine_authorization_history_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'MACHINE_POLICY_HISTORY_IMMUTABLE'; END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.policy_sets'::regclass AND tgname='machine_policy_guard') THEN
        CREATE TRIGGER machine_policy_guard BEFORE INSERT OR UPDATE OR DELETE ON organization_service.policy_sets
            FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_authorization_policy();
        CREATE CONSTRAINT TRIGGER machine_policy_history_complete AFTER INSERT OR UPDATE ON organization_service.policy_sets
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_machine_authorization_policy_history();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='organization_service.machine_authorization_policy_history'::regclass AND tgname='machine_policy_history_guard') THEN
        CREATE TRIGGER machine_policy_history_guard BEFORE INSERT ON organization_service.machine_authorization_policy_history
            FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_authorization_policy_history();
        CREATE TRIGGER machine_policy_history_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.machine_authorization_policy_history
            FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_authorization_history_mutation();
    END IF;
END $$;

REVOKE ALL ON organization_service.machine_authorization_policy_history FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_service.guard_machine_authorization_policy(),
    organization_service.guard_machine_authorization_policy_history(),
    organization_service.check_machine_authorization_policy_history(),
    organization_service.reject_machine_authorization_history_mutation() FROM PUBLIC;
INSERT INTO organization_service.rust_schema_versions(version)
    VALUES ('rust_organization_machine_authorization_0006') ON CONFLICT (version) DO NOTHING;
