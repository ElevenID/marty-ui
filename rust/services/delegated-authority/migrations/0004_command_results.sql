-- P03 lifecycle command outcomes. Request serving credentials receive only
-- SELECT/INSERT; confirmation and representation-authority producers need none.
-- Original results are retained indefinitely in this milestone. Never delete a
-- result and allow its command identity to be reused; a future retention design
-- must retain a qualified command tombstone/reconciliation boundary.
CREATE TABLE delegated_authority_service.command_results (
    organization_id UUID NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('USER','ORGANIZATION','SERVICE_ACCOUNT','MACHINE_IDENTITY','EXTERNAL')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 1024),
    command_id UUID NOT NULL,
    command_digest TEXT NOT NULL CHECK (command_digest ~ '^sha256:[0-9a-f]{64}$'),
    command_document JSONB NOT NULL CHECK (jsonb_typeof(command_document) = 'object'),
    grant_id UUID NOT NULL,
    grant_revision BIGINT NOT NULL CHECK (grant_revision BETWEEN 1 AND 9007199254740991),
    result_document JSONB NOT NULL CHECK (jsonb_typeof(result_document) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id,actor_type,actor_id,command_id),
    FOREIGN KEY (organization_id,grant_id,grant_revision)
        REFERENCES delegated_authority_service.grant_lifecycle_events (organization_id,grant_id,revision)
);

CREATE FUNCTION delegated_authority_service.guard_command_result()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    current_grant JSONB;
    command_name TEXT;
    expected_status TEXT;
BEGIN
    SELECT grant_document INTO STRICT current_grant
        FROM delegated_authority_service.delegation_grants
        WHERE organization_id = NEW.organization_id AND id = NEW.grant_id FOR SHARE;
    command_name := NEW.command_document ->> 'command';
    expected_status := CASE command_name
        WHEN 'CREATE_GRANT' THEN 'PENDING'
        WHEN 'APPROVE_GRANT' THEN 'ACTIVE'
        WHEN 'SUSPEND_GRANT' THEN 'SUSPENDED'
        WHEN 'REINSTATE_GRANT' THEN 'ACTIVE'
        WHEN 'REVOKE_GRANT' THEN 'REVOKED'
        ELSE NULL END;
    IF expected_status IS NULL
        OR (NEW.command_document ->> 'profile') IS DISTINCT FROM 'urn:marty:delegation-command:v1'
        OR (NEW.command_document ->> 'command_id') IS DISTINCT FROM NEW.command_id::TEXT
        OR NEW.result_document IS DISTINCT FROM current_grant
        OR (NEW.result_document ->> 'organization_id') IS DISTINCT FROM NEW.organization_id::TEXT
        OR (NEW.result_document ->> 'id') IS DISTINCT FROM NEW.grant_id::TEXT
        OR (NEW.result_document ->> 'revision') IS DISTINCT FROM NEW.grant_revision::TEXT
        OR (NEW.result_document ->> 'status') IS DISTINCT FROM expected_status THEN
        RAISE EXCEPTION 'delegation command result binding is invalid';
    END IF;
    IF command_name = 'CREATE_GRANT' THEN
        IF NEW.grant_revision <> 1
            OR (NEW.command_document -> 'terms') IS DISTINCT FROM (NEW.result_document -> 'terms') THEN
            RAISE EXCEPTION 'delegation create result is invalid';
        END IF;
    ELSE
        IF (NEW.command_document #>> '{grant,id}') IS DISTINCT FROM NEW.grant_id::TEXT
            OR (NEW.command_document #>> '{grant,terms_digest}') IS DISTINCT FROM (NEW.result_document ->> 'terms_digest')
            OR (NEW.command_document #>> '{grant,revision}') IS DISTINCT FROM (NEW.grant_revision - 1)::TEXT THEN
            RAISE EXCEPTION 'delegation transition result is invalid';
        END IF;
        IF command_name = 'APPROVE_GRANT' AND (
            (NEW.result_document #>> '{approval,approver,type}') IS DISTINCT FROM NEW.actor_type
            OR (NEW.result_document #>> '{approval,approver,id}') IS DISTINCT FROM NEW.actor_id
        ) THEN
            RAISE EXCEPTION 'delegation approval result actor is invalid';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER command_results_binding BEFORE INSERT ON delegated_authority_service.command_results
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.guard_command_result();
CREATE TRIGGER command_results_immutable BEFORE UPDATE OR DELETE ON delegated_authority_service.command_results
    FOR EACH ROW EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
CREATE TRIGGER command_results_no_truncate BEFORE TRUNCATE ON delegated_authority_service.command_results
    FOR EACH STATEMENT EXECUTE FUNCTION delegated_authority_service.reject_lifecycle_event_mutation();
COMMENT ON TABLE delegated_authority_service.command_results IS
    'Immutable original-caller lifecycle command outcomes, committed with the grant and lifecycle journal. Historical results are not current authority. Contains actor and grant data; restrict reads and retention. No domain execution state.';
REVOKE ALL ON delegated_authority_service.command_results FROM PUBLIC;
REVOKE ALL ON FUNCTION delegated_authority_service.guard_command_result() FROM PUBLIC;
