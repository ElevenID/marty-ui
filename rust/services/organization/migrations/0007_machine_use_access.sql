-- Human-owned component access for full machines. This grants access to Marty
-- use entrypoints; it is not a key proof, delegation grant or domain permission.
CREATE TABLE IF NOT EXISTS organization_service.machine_use_access (
    organization_id UUID NOT NULL,
    machine_identity_id UUID NOT NULL,
    deployment_profile_id UUID NOT NULL CHECK (deployment_profile_id<>'00000000-0000-0000-0000-000000000000'),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 1024),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    permissions TEXT[] NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    snapshot_bytes BYTEA NOT NULL CHECK (octet_length(snapshot_bytes) BETWEEN 1 AND 16384),
    snapshot_digest TEXT NOT NULL,
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (updated_at>=created_at),
    PRIMARY KEY (organization_id,machine_identity_id),
    FOREIGN KEY (organization_id,machine_identity_id)
        REFERENCES organization_service.machine_registry_entries(organization_id,machine_identity_id),
    CONSTRAINT machine_use_access_bytes CHECK (convert_from(snapshot_bytes,'UTF8')::JSONB=snapshot),
    CONSTRAINT machine_use_access_digest CHECK (snapshot_digest='sha256:'||encode(sha256(snapshot_bytes),'hex')),
    CONSTRAINT machine_use_access_window CHECK (valid_until>valid_from),
    CONSTRAINT machine_use_access_permissions CHECK (cardinality(permissions) BETWEEN 1 AND 5 AND permissions <@ ARRAY['START_USE','FINALIZE_USE','RECOVER_RESULT','RETRIEVE_REQUEST','SUBMIT_PROOF']::TEXT[])
);
CREATE TABLE IF NOT EXISTS organization_service.machine_use_access_history (
    organization_id UUID NOT NULL,
    machine_identity_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    action TEXT NOT NULL CHECK (action IN ('GRANT','REPLACE','REVOKE')),
    actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 255),
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL,
    snapshot_bytes BYTEA NOT NULL,
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY (organization_id,machine_identity_id,revision),
    FOREIGN KEY (organization_id,machine_identity_id)
        REFERENCES organization_service.machine_use_access(organization_id,machine_identity_id),
    CONSTRAINT machine_use_access_history_bytes CHECK (convert_from(snapshot_bytes,'UTF8')::JSONB=snapshot),
    CONSTRAINT machine_use_access_history_digest CHECK (snapshot_digest='sha256:'||encode(sha256(snapshot_bytes),'hex'))
);
COMMENT ON TABLE organization_service.machine_use_access IS
    'Explicit human-managed access to Marty use commands, historical result recovery, wallet request retrieval and proof submission for a registered full MachineIdentity in one immutable deployment. No domain permission or authenticated key proof is implied.';

CREATE OR REPLACE FUNCTION organization_service.reject_machine_use_access_history_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'machine use access history cannot be rewritten or removed'; END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_use_access()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE registry_principal TEXT; registry_deployment UUID; current_status TEXT;
BEGIN
    SELECT r.principal_id,r.deployment_profile_id,r.status INTO STRICT registry_principal,registry_deployment,current_status
      FROM organization_service.machine_registry_entries r
      JOIN organization_service.organizations o ON o.id=r.organization_id AND o.status='active'
      WHERE r.organization_id=NEW.organization_id AND r.machine_identity_id=NEW.machine_identity_id FOR SHARE OF r;
    IF NEW.principal_id IS DISTINCT FROM registry_principal OR NEW.deployment_profile_id IS DISTINCT FROM registry_deployment
      OR (NEW.status='ACTIVE' AND current_status<>'ACTIVE')
      OR NEW.updated_at>clock_timestamp()
      OR cardinality(NEW.permissions)<>(SELECT count(DISTINCT value) FROM unnest(NEW.permissions) value)
      OR NEW.snapshot->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.snapshot->>'machine_identity_id' IS DISTINCT FROM NEW.machine_identity_id::TEXT
      OR NEW.snapshot->>'deployment_profile_id' IS DISTINCT FROM NEW.deployment_profile_id::TEXT
      OR NEW.snapshot->>'principal_id' IS DISTINCT FROM NEW.principal_id
      OR NEW.snapshot->>'revision' IS DISTINCT FROM NEW.revision::TEXT
      OR NEW.snapshot->>'status' IS DISTINCT FROM NEW.status
      OR NEW.snapshot->'permissions' IS DISTINCT FROM to_jsonb(NEW.permissions)
      OR (NEW.snapshot->>'valid_from')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_from
      OR (NEW.snapshot->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
      OR NEW.snapshot->>'created_by' IS DISTINCT FROM NEW.created_by
      OR (NEW.snapshot->>'created_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.created_at
      OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.updated_at THEN
        RAISE EXCEPTION 'machine use access projection or registered identity is invalid';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.status<>'ACTIVE' OR NEW.created_at<>NEW.updated_at THEN
            RAISE EXCEPTION 'machine use access needs initial attributable grant'; END IF;
    ELSE
        IF NEW.organization_id<>OLD.organization_id OR NEW.machine_identity_id<>OLD.machine_identity_id
          OR NEW.deployment_profile_id<>OLD.deployment_profile_id OR NEW.principal_id<>OLD.principal_id
          OR NEW.created_by<>OLD.created_by OR NEW.created_at<>OLD.created_at
          OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at OR OLD.status<>'ACTIVE'
          OR (NEW.status='REVOKED' AND (NEW.permissions<>OLD.permissions OR NEW.valid_from<>OLD.valid_from OR NEW.valid_until<>OLD.valid_until)) THEN
            RAISE EXCEPTION 'machine use access identity, revision or revocation is invalid'; END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_use_access_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source organization_service.machine_use_access%ROWTYPE;
BEGIN
    SELECT * INTO STRICT source FROM organization_service.machine_use_access
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id FOR SHARE;
    IF NEW.revision<>source.revision OR NEW.snapshot IS DISTINCT FROM source.snapshot
      OR NEW.snapshot_bytes IS DISTINCT FROM source.snapshot_bytes OR NEW.snapshot_digest IS DISTINCT FROM source.snapshot_digest
      OR NEW.occurred_at<>source.updated_at
      OR (NEW.revision=1 AND (NEW.action<>'GRANT' OR NEW.actor_user_id<>source.created_by))
      OR (NEW.revision>1 AND (NEW.action='GRANT' OR (NEW.action='REVOKE')<>(source.status='REVOKED')))
      OR (NEW.revision>1 AND NOT EXISTS (SELECT 1 FROM organization_service.machine_use_access_history
        WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id AND revision=NEW.revision-1)) THEN
        RAISE EXCEPTION 'machine use access history must retain the exact current owner revision';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_machine_use_access_complete()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source organization_service.machine_use_access%ROWTYPE; history organization_service.machine_use_access_history%ROWTYPE; history_count BIGINT;
BEGIN
    SELECT * INTO STRICT source FROM organization_service.machine_use_access
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id;
    SELECT * INTO STRICT history FROM organization_service.machine_use_access_history
      WHERE organization_id=source.organization_id AND machine_identity_id=source.machine_identity_id AND revision=source.revision;
    SELECT count(*) INTO history_count FROM organization_service.machine_use_access_history
      WHERE organization_id=source.organization_id AND machine_identity_id=source.machine_identity_id;
    IF history_count<>source.revision OR history.snapshot IS DISTINCT FROM source.snapshot
      OR history.snapshot_bytes IS DISTINCT FROM source.snapshot_bytes OR history.snapshot_digest IS DISTINCT FROM source.snapshot_digest
      OR NOT EXISTS(SELECT 1 FROM organization_service.audit_events a
        WHERE a.organization_id=source.organization_id AND a.event_type='machine_use_access.changed'
          AND a.resource_id=source.machine_identity_id::TEXT AND a.actor_type='USER' AND a.actor_id=history.actor_user_id
          AND a.metadata->>'request_id'=history.request_id::TEXT
          AND a.metadata->>'revision'=source.revision::TEXT AND a.metadata->>'snapshot_digest'=source.snapshot_digest) THEN
        RAISE EXCEPTION 'machine use access requires complete attributable history and audit';
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS machine_use_access_guard ON organization_service.machine_use_access;
CREATE TRIGGER machine_use_access_guard BEFORE INSERT OR UPDATE ON organization_service.machine_use_access FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_use_access();
DROP TRIGGER IF EXISTS machine_use_access_no_removal ON organization_service.machine_use_access;
CREATE TRIGGER machine_use_access_no_removal BEFORE DELETE OR TRUNCATE ON organization_service.machine_use_access FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_use_access_history_mutation();
DROP TRIGGER IF EXISTS machine_use_access_complete ON organization_service.machine_use_access;
CREATE CONSTRAINT TRIGGER machine_use_access_complete AFTER INSERT OR UPDATE ON organization_service.machine_use_access DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_machine_use_access_complete();
DROP TRIGGER IF EXISTS machine_use_access_history_guard ON organization_service.machine_use_access_history;
CREATE TRIGGER machine_use_access_history_guard BEFORE INSERT ON organization_service.machine_use_access_history FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_use_access_history();
DROP TRIGGER IF EXISTS machine_use_access_history_immutable ON organization_service.machine_use_access_history;
CREATE TRIGGER machine_use_access_history_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.machine_use_access_history FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_use_access_history_mutation();

INSERT INTO organization_service.rust_schema_versions(version) VALUES ('rust_organization_machine_use_access_0007') ON CONFLICT(version) DO NOTHING;
