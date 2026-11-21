-- Private source evidence is separate from the issuer's credential store, the
-- Trust Profile graph, and the aggregate authentication/use ledgers.
CREATE SCHEMA machine_credential_source;
CREATE TABLE machine_credential_source.schema_migrations (
    version TEXT PRIMARY KEY,
    content_digest TEXT NOT NULL CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE machine_credential_source.observations (
    organization_id UUID NOT NULL CHECK (organization_id <> '00000000-0000-0000-0000-000000000000'),
    evidence_ref TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    scope_digest TEXT NOT NULL CHECK (scope_digest ~ '^sha256:[0-9a-f]{64}$'),
    credential_id UUID NOT NULL CHECK (credential_id <> '00000000-0000-0000-0000-000000000000'),
    credential_digest TEXT NOT NULL CHECK (credential_digest ~ '^sha256:[0-9a-f]{64}$'),
    evidence_bytes BYTEA NOT NULL CHECK (octet_length(evidence_bytes) BETWEEN 1 AND 2200000),
    evidence_document JSONB NOT NULL CHECK (jsonb_typeof(evidence_document)='object'),
    observed_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    retained_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id,evidence_ref),
    CONSTRAINT machine_credential_source_digest CHECK (evidence_digest='sha256:'||encode(sha256(evidence_bytes),'hex')),
    CONSTRAINT machine_credential_source_reference CHECK (evidence_ref='urn:marty:machine-credential-source:'||evidence_digest),
    CONSTRAINT machine_credential_source_bytes CHECK (convert_from(evidence_bytes,'UTF8')::jsonb=evidence_document),
    CONSTRAINT machine_credential_source_window CHECK (observed_at<=completed_at AND completed_at<=retained_at AND retained_at<valid_until AND valid_until<=observed_at+interval '30 seconds')
);

CREATE FUNCTION machine_credential_source.check_observation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE selection JSONB := NEW.evidence_document->'selection';
BEGIN
    IF NEW.evidence_document->>'profile' IS DISTINCT FROM 'urn:marty:machine-credential-source:v1'
       OR selection->>'organization_id' IS DISTINCT FROM NEW.organization_id::text
       OR selection->>'credential_id' IS DISTINCT FROM NEW.credential_id::text
       OR selection->>'credential_digest' IS DISTINCT FROM NEW.credential_digest
       OR selection->>'scope_digest' IS DISTINCT FROM NEW.scope_digest
       OR NEW.evidence_document#>>'{scope,organization_id}' IS DISTINCT FROM NEW.organization_id::text
       OR NEW.evidence_document#>>'{scope,principal,type}' IS DISTINCT FROM 'MACHINE_IDENTITY'
       OR NEW.evidence_document#>>'{scope,principal,id}' IS DISTINCT FROM selection->>'subject'
       OR NEW.evidence_document#>'{status,selection}' IS DISTINCT FROM selection
       OR NEW.evidence_document#>'{trust,selection}' IS DISTINCT FROM selection
       OR NEW.evidence_document#>>'{status,securing_profile}' IS DISTINCT FROM 'marty_nested_vc2_jwt_v1'
       OR NEW.evidence_document#>>'{trust,securing_profile}' IS DISTINCT FROM 'marty_nested_vc2_jwt_v1'
       OR NEW.evidence_document#>>'{status,state}' IS DISTINCT FROM 'ACTIVE'
       OR jsonb_typeof(NEW.evidence_document#>'{status,credential_types}') IS DISTINCT FROM 'array'
       OR jsonb_typeof(NEW.evidence_document#>'{trust,authorized_credential_types}') IS DISTINCT FROM 'array'
       OR NEW.evidence_document#>'{status,credential_types}' IS DISTINCT FROM NEW.evidence_document#>'{trust,credential_types}'
       OR NEW.evidence_document#>>'{status,observed_at}' IS NULL
       OR NEW.evidence_document#>>'{trust,observed_at}' IS NULL
       OR NEW.evidence_document#>>'{status,valid_until}' IS NULL
       OR NEW.evidence_document#>>'{trust,valid_until}' IS NULL
       OR (NEW.evidence_document->>'observed_at')::timestamptz IS DISTINCT FROM NEW.observed_at
       OR (NEW.evidence_document->>'completed_at')::timestamptz IS DISTINCT FROM NEW.completed_at
       OR (NEW.evidence_document->>'valid_until')::timestamptz IS DISTINCT FROM NEW.valid_until
       OR NEW.valid_until>(NEW.evidence_document#>>'{status,valid_until}')::timestamptz
       OR NEW.valid_until>(NEW.evidence_document#>>'{trust,valid_until}')::timestamptz
       OR NEW.observed_at IS DISTINCT FROM LEAST((NEW.evidence_document#>>'{status,observed_at}')::timestamptz,(NEW.evidence_document#>>'{trust,observed_at}')::timestamptz)
       OR NEW.retained_at>clock_timestamp() OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'MACHINE_CREDENTIAL_SOURCE_BINDING';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER machine_credential_source_binding BEFORE INSERT
ON machine_credential_source.observations FOR EACH ROW
EXECUTE FUNCTION machine_credential_source.check_observation();

CREATE FUNCTION machine_credential_source.check_observation_commit()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF clock_timestamp()<NEW.retained_at OR clock_timestamp()>=NEW.valid_until THEN
        RAISE EXCEPTION 'MACHINE_CREDENTIAL_SOURCE_EXPIRED';
    END IF;
    RETURN NEW;
END
$$;
CREATE CONSTRAINT TRIGGER machine_credential_source_commit AFTER INSERT
ON machine_credential_source.observations DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION machine_credential_source.check_observation_commit();

CREATE FUNCTION machine_credential_source.reject_mutation()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'MACHINE_CREDENTIAL_SOURCE_IMMUTABLE';
END
$$;
CREATE TRIGGER machine_credential_source_immutable BEFORE UPDATE OR DELETE
ON machine_credential_source.observations FOR EACH ROW
EXECUTE FUNCTION machine_credential_source.reject_mutation();
CREATE TRIGGER machine_credential_source_no_truncate BEFORE TRUNCATE
ON machine_credential_source.observations FOR EACH STATEMENT
EXECUTE FUNCTION machine_credential_source.reject_mutation();

REVOKE ALL ON SCHEMA machine_credential_source FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA machine_credential_source FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA machine_credential_source FROM PUBLIC;
