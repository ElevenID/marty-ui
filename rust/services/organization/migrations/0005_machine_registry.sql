-- Distinct full MachineIdentity/MAP owner. No inventory, enrollment, credential,
-- grant, legacy row or protocol document is promoted or rewritten.
CREATE TABLE IF NOT EXISTS organization_service.machine_registry_entries (
    organization_id UUID NOT NULL REFERENCES organization_service.organizations(id),
    machine_identity_id UUID NOT NULL CHECK (machine_identity_id<>'00000000-0000-0000-0000-000000000000'),
    deployment_profile_id UUID NOT NULL CHECK (deployment_profile_id<>'00000000-0000-0000-0000-000000000000'),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 1024),
    runtime_instance_ref TEXT NOT NULL CHECK (length(runtime_instance_ref) BETWEEN 1 AND 1024),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 1024),
    key_thumbprint TEXT NOT NULL CHECK (key_thumbprint ~ '^sha256:[0-9a-f]{64}$'),
    policy_id UUID NOT NULL CHECK (policy_id<>'00000000-0000-0000-0000-000000000000'),
    policy_digest TEXT NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED','RETIRED')),
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    documents JSONB NOT NULL CHECK (jsonb_typeof(documents)='object'),
    document_bytes BYTEA NOT NULL CHECK (octet_length(document_bytes) BETWEEN 1 AND 262144),
    document_digest TEXT NOT NULL,
    documents_recorded_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 255),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL CHECK (created_at<=documents_recorded_at AND documents_recorded_at<=updated_at),
    PRIMARY KEY (organization_id,machine_identity_id),
    UNIQUE (organization_id,principal_id),
    CONSTRAINT machine_registry_document_bytes CHECK (convert_from(document_bytes,'UTF8')::JSONB=documents),
    CONSTRAINT machine_registry_document_digest CHECK (document_digest='sha256:'||encode(sha256(document_bytes),'hex'))
);
CREATE TABLE IF NOT EXISTS organization_service.machine_registry_history (
    organization_id UUID NOT NULL,
    machine_identity_id UUID NOT NULL,
    revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    action TEXT NOT NULL CHECK (action IN ('REGISTER','REPLACE','SUSPEND','REVOKE','RETIRE')),
    actor_user_id TEXT NOT NULL CHECK (length(actor_user_id) BETWEEN 1 AND 255),
    request_id UUID NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    PRIMARY KEY (organization_id,machine_identity_id,revision),
    FOREIGN KEY (organization_id,machine_identity_id)
        REFERENCES organization_service.machine_registry_entries(organization_id,machine_identity_id)
);
CREATE TABLE IF NOT EXISTS organization_service.machine_registry_observations (
    organization_id UUID NOT NULL,
    machine_identity_id UUID NOT NULL,
    revision BIGINT NOT NULL,
    evidence_ref TEXT PRIMARY KEY,
    evidence_digest TEXT NOT NULL,
    document JSONB NOT NULL CHECK (jsonb_typeof(document)='object'),
    evidence_bytes BYTEA NOT NULL CHECK (octet_length(evidence_bytes) BETWEEN 1 AND 1048576),
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    retained_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (organization_id,machine_identity_id,revision)
        REFERENCES organization_service.machine_registry_history(organization_id,machine_identity_id,revision),
    CONSTRAINT machine_registry_observation_bytes CHECK (convert_from(evidence_bytes,'UTF8')::JSONB=document),
    CONSTRAINT machine_registry_observation_digest CHECK (evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex')),
    CONSTRAINT machine_registry_observation_ref CHECK (evidence_ref='urn:marty:machine-registry:sha256:'||encode(sha256(evidence_bytes),'hex')),
    CONSTRAINT machine_registry_observation_window CHECK (valid_until>observed_at AND valid_until<=observed_at+INTERVAL '30 seconds'),
    CONSTRAINT machine_registry_observation_retention_window CHECK (retained_at>=observed_at AND retained_at<valid_until)
);
COMMENT ON TABLE organization_service.machine_registry_entries IS
    'Explicit human-administered full MachineIdentity/deployment/MAP source; separate from SERVICE_ACCOUNT inventory. Current registration is not operational key proof, credential trust, attestation, delegated authority or a domain permission.';
COMMENT ON TABLE organization_service.machine_registry_observations IS
    'Exact immutable bounded source observations. Historical evidence cannot be converted to current machine authentication.';

CREATE OR REPLACE FUNCTION organization_service.reject_machine_registry_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'machine registry history cannot be rewritten or removed'; END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_registry_entry()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF convert_from(NEW.document_bytes,'UTF8')::JSONB IS DISTINCT FROM NEW.documents
      OR NEW.document_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.document_bytes),'hex')
      OR NEW.documents#>>'{machine_identity,id}' IS DISTINCT FROM NEW.machine_identity_id::TEXT
      OR NEW.documents#>>'{machine_identity,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.documents#>>'{machine_identity,status}' IS DISTINCT FROM 'ACTIVE'
      OR NEW.documents#>>'{binding_record,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.documents#>>'{binding_record,principal,type}' IS DISTINCT FROM 'MACHINE_IDENTITY'
      OR NEW.documents#>>'{binding_record,principal,id}' IS DISTINCT FROM NEW.principal_id
      OR NEW.documents#>>'{binding_record,authentication,issuer}' IS DISTINCT FROM NEW.principal_id
      OR NEW.documents#>>'{binding_record,authentication,subject}' IS DISTINCT FROM NEW.principal_id
      OR NEW.documents#>>'{binding_record,runtime,kind}' IS DISTINCT FROM 'MANAGED'
      OR NEW.documents#>>'{binding_record,runtime,instance_ref}' IS DISTINCT FROM NEW.runtime_instance_ref
      OR NEW.documents#>>'{binding_record,runtime,machine_identity_id}' IS DISTINCT FROM NEW.machine_identity_id::TEXT
      OR NEW.documents#>>'{binding_configuration,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.documents#>>'{binding_configuration,deployment_profile_id}' IS DISTINCT FROM NEW.deployment_profile_id::TEXT
      OR NEW.documents#>>'{binding_configuration,principal,id}' IS DISTINCT FROM NEW.principal_id
      OR NEW.documents#>>'{binding_configuration,principal,type}' IS DISTINCT FROM 'MACHINE_IDENTITY'
      OR NEW.documents#>>'{binding_configuration,runtime,active_key_id}' IS DISTINCT FROM NEW.key_id
      OR NEW.documents#>>'{machine_authentication_policy,id}' IS DISTINCT FROM NEW.policy_id::TEXT
      OR NEW.documents#>>'{machine_authentication_policy,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.documents#>>'{machine_authentication_policy,status}' IS DISTINCT FROM 'ACTIVE'
      OR NEW.updated_at>clock_timestamp() THEN
        RAISE EXCEPTION 'full machine registry projection is invalid';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.revision<>1 OR NEW.status<>'ACTIVE' OR NEW.created_at<>NEW.updated_at
          OR NEW.documents_recorded_at<>NEW.updated_at THEN RAISE EXCEPTION 'invalid initial machine registry state'; END IF;
    ELSE
        IF NEW.organization_id<>OLD.organization_id OR NEW.machine_identity_id<>OLD.machine_identity_id
          OR NEW.principal_id<>OLD.principal_id OR NEW.deployment_profile_id<>OLD.deployment_profile_id
          OR NEW.runtime_instance_ref<>OLD.runtime_instance_ref OR NEW.created_by<>OLD.created_by
          OR NEW.created_at<>OLD.created_at OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at
          OR NEW.documents#>'{machine_identity,machine_id}' IS DISTINCT FROM OLD.documents#>'{machine_identity,machine_id}'
          OR NEW.documents#>'{machine_identity,created_at}' IS DISTINCT FROM OLD.documents#>'{machine_identity,created_at}'
          OR OLD.status='RETIRED' THEN RAISE EXCEPTION 'machine registry identity is immutable'; END IF;
        IF NEW.status=OLD.status THEN
            IF OLD.status<>'ACTIVE' OR NEW.document_digest=OLD.document_digest
              OR NEW.documents_recorded_at<>NEW.updated_at
              OR (NEW.key_id=OLD.key_id AND NEW.key_thumbprint<>OLD.key_thumbprint)
              OR (NEW.key_id<>OLD.key_id AND EXISTS (
                  SELECT 1 FROM organization_service.machine_registry_history h
                  WHERE h.organization_id=NEW.organization_id AND h.machine_identity_id=NEW.machine_identity_id
                    AND (h.snapshot->>'key_id'=NEW.key_id OR h.snapshot->>'key_thumbprint'=NEW.key_thumbprint))) THEN
                RAISE EXCEPTION 'invalid machine registry replacement or historical key reuse';
            END IF;
        ELSIF NOT ((OLD.status='ACTIVE' AND NEW.status IN ('SUSPENDED','REVOKED','RETIRED'))
            OR (OLD.status='SUSPENDED' AND NEW.status IN ('REVOKED','RETIRED'))
            OR (OLD.status='REVOKED' AND NEW.status='RETIRED'))
          OR (to_jsonb(NEW)-ARRAY['status','revision','updated_at']) IS DISTINCT FROM
             (to_jsonb(OLD)-ARRAY['status','revision','updated_at']) THEN
            RAISE EXCEPTION 'machine registry lifecycle cannot resume or replace identity';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_registry_history()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_document JSONB; previous_document JSONB;
BEGIN
    SELECT to_jsonb(r) INTO STRICT current_document FROM organization_service.machine_registry_entries r
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id FOR SHARE;
    IF NEW.snapshot IS DISTINCT FROM current_document
      OR NEW.snapshot->>'revision' IS DISTINCT FROM NEW.revision::TEXT
      OR (NEW.snapshot->>'updated_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.occurred_at THEN
        RAISE EXCEPTION 'machine registry history must match current revision';
    END IF;
    IF NEW.revision=1 THEN
        IF NEW.action<>'REGISTER' OR NEW.snapshot->>'created_by' IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'machine registry registration needs its exact administrator'; END IF;
    ELSE
        SELECT snapshot INTO STRICT previous_document FROM organization_service.machine_registry_history
          WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id AND revision=NEW.revision-1;
        IF NEW.action='REGISTER'
          OR (NEW.action='REPLACE' AND (NEW.snapshot->>'status'<>'ACTIVE' OR previous_document->>'status'<>'ACTIVE'))
          OR (NEW.action='SUSPEND' AND NEW.snapshot->>'status'<>'SUSPENDED')
          OR (NEW.action='REVOKE' AND NEW.snapshot->>'status'<>'REVOKED')
          OR (NEW.action='RETIRE' AND NEW.snapshot->>'status'<>'RETIRED') THEN
            RAISE EXCEPTION 'machine registry history action is inconsistent'; END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION organization_service.check_machine_registry_complete()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_document JSONB; count_history BIGINT; latest_history JSONB; latest_actor TEXT; latest_request UUID;
BEGIN
    SELECT to_jsonb(r) INTO STRICT current_document FROM organization_service.machine_registry_entries r
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id;
    SELECT count(*) INTO count_history FROM organization_service.machine_registry_history
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id;
    SELECT snapshot,actor_user_id,request_id INTO STRICT latest_history,latest_actor,latest_request
      FROM organization_service.machine_registry_history
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id
        AND revision=(current_document->>'revision')::BIGINT;
    IF count_history<>(current_document->>'revision')::BIGINT OR latest_history IS DISTINCT FROM current_document
      OR NOT EXISTS (SELECT 1 FROM organization_service.audit_events a
        WHERE a.organization_id=NEW.organization_id AND a.resource_id=NEW.machine_identity_id::TEXT
          AND a.event_type='machine_registry.changed' AND a.actor_type='USER' AND a.actor_id=latest_actor
          AND a.metadata->>'request_id'=latest_request::TEXT
          AND a.metadata->>'revision'=current_document->>'revision'
          AND a.metadata->>'document_digest'=current_document->>'document_digest') THEN
        RAISE EXCEPTION 'machine registry requires complete attributable history and audit'; END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION organization_service.guard_machine_registry_observation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE source_snapshot JSONB; current_snapshot JSONB; key_until TIMESTAMPTZ;
BEGIN
    SELECT snapshot INTO STRICT source_snapshot FROM organization_service.machine_registry_history
      WHERE organization_id=NEW.organization_id AND machine_identity_id=NEW.machine_identity_id AND revision=NEW.revision;
    SELECT to_jsonb(r) INTO STRICT current_snapshot FROM organization_service.machine_registry_entries r
      JOIN organization_service.organizations o ON o.id=r.organization_id AND o.status='active'
      WHERE r.organization_id=NEW.organization_id AND r.machine_identity_id=NEW.machine_identity_id AND r.status='ACTIVE';
    SELECT (k->>'valid_until')::TIMESTAMPTZ INTO STRICT key_until
      FROM jsonb_array_elements(source_snapshot#>'{documents,machine_identity,identity_keys}') k
      WHERE k->>'status'='ACTIVE' AND k->>'key_id'=source_snapshot->>'key_id';
    IF convert_from(NEW.evidence_bytes,'UTF8')::JSONB IS DISTINCT FROM NEW.document
      OR NEW.evidence_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.evidence_bytes),'hex')
      OR NEW.evidence_ref IS DISTINCT FROM 'urn:marty:machine-registry:sha256:'||encode(sha256(NEW.evidence_bytes),'hex')
      OR source_snapshot->>'status' IS DISTINCT FROM 'ACTIVE'
      OR current_snapshot IS DISTINCT FROM source_snapshot
      OR NEW.document->>'profile' IS DISTINCT FROM 'urn:marty:machine-registry-observation:v1'
      OR NEW.document->>'organization_id' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.document->>'machine_identity_id' IS DISTINCT FROM NEW.machine_identity_id::TEXT
      OR NEW.document->>'registry_revision' IS DISTINCT FROM NEW.revision::TEXT
      OR NEW.document->'source_snapshot' IS DISTINCT FROM source_snapshot
      OR NEW.document#>>'{scope,organization_id}' IS DISTINCT FROM NEW.organization_id::TEXT
      OR NEW.document#>>'{scope,principal_id}' IS DISTINCT FROM source_snapshot->>'principal_id'
      OR NEW.document#>>'{scope,key_thumbprint}' IS DISTINCT FROM source_snapshot->>'key_thumbprint'
      OR NEW.document->>'deployment_profile_id' IS DISTINCT FROM source_snapshot->>'deployment_profile_id'
      OR (NEW.document->>'observed_at')::TIMESTAMPTZ IS DISTINCT FROM NEW.observed_at
      OR (NEW.document->>'valid_until')::TIMESTAMPTZ IS DISTINCT FROM NEW.valid_until
      OR (NEW.document->>'started_at')::TIMESTAMPTZ IS NULL
      OR NEW.observed_at<(NEW.document->>'started_at')::TIMESTAMPTZ
      OR NEW.valid_until>(NEW.document->>'started_at')::TIMESTAMPTZ+INTERVAL '30 seconds'
      OR (key_until IS NOT NULL AND NEW.valid_until>key_until)
      OR NEW.observed_at<(source_snapshot->>'updated_at')::TIMESTAMPTZ
      OR NEW.retained_at<NEW.observed_at OR NEW.retained_at>=NEW.valid_until
      OR NEW.retained_at>clock_timestamp() OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'machine registry observation must retain the exact bounded source'; END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION organization_service.check_machine_registry_observation_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF clock_timestamp()<NEW.observed_at OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'machine registry observation expired before commit'; END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS machine_registry_entry_guard ON organization_service.machine_registry_entries;
CREATE TRIGGER machine_registry_entry_guard BEFORE INSERT OR UPDATE ON organization_service.machine_registry_entries
    FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_registry_entry();
DROP TRIGGER IF EXISTS machine_registry_entry_no_removal ON organization_service.machine_registry_entries;
CREATE TRIGGER machine_registry_entry_no_removal BEFORE DELETE OR TRUNCATE ON organization_service.machine_registry_entries
    FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_registry_mutation();
DROP TRIGGER IF EXISTS machine_registry_entry_complete ON organization_service.machine_registry_entries;
CREATE CONSTRAINT TRIGGER machine_registry_entry_complete AFTER INSERT OR UPDATE ON organization_service.machine_registry_entries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_machine_registry_complete();
DROP TRIGGER IF EXISTS machine_registry_history_guard ON organization_service.machine_registry_history;
CREATE TRIGGER machine_registry_history_guard BEFORE INSERT ON organization_service.machine_registry_history
    FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_registry_history();
DROP TRIGGER IF EXISTS machine_registry_history_immutable ON organization_service.machine_registry_history;
CREATE TRIGGER machine_registry_history_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.machine_registry_history
    FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_registry_mutation();
DROP TRIGGER IF EXISTS machine_registry_observation_guard ON organization_service.machine_registry_observations;
CREATE TRIGGER machine_registry_observation_guard BEFORE INSERT ON organization_service.machine_registry_observations
    FOR EACH ROW EXECUTE FUNCTION organization_service.guard_machine_registry_observation();
DROP TRIGGER IF EXISTS machine_registry_observation_immutable ON organization_service.machine_registry_observations;
CREATE TRIGGER machine_registry_observation_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON organization_service.machine_registry_observations
    FOR EACH STATEMENT EXECUTE FUNCTION organization_service.reject_machine_registry_mutation();
DROP TRIGGER IF EXISTS machine_registry_observation_commit ON organization_service.machine_registry_observations;
CREATE CONSTRAINT TRIGGER machine_registry_observation_commit AFTER INSERT ON organization_service.machine_registry_observations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization_service.check_machine_registry_observation_commit();

INSERT INTO organization_service.rust_schema_versions(version)
VALUES ('rust_organization_machine_registry_0005') ON CONFLICT (version) DO NOTHING;
