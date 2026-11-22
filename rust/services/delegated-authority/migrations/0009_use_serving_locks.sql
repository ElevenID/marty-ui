-- Selected internal serving roles may lock exact source rows without UPDATE authority.
-- No migration grants an application role or changes retained evidence.

CREATE FUNCTION delegated_authority_service.lock_use_grant(organization uuid, grant_id uuid)
RETURNS SETOF delegated_authority_service.delegation_grants
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $lock$
    SELECT source.* FROM delegated_authority_service.delegation_grants source
    WHERE source.organization_id=$1 AND source.id=$2 FOR UPDATE OF source;
$lock$;
REVOKE ALL ON FUNCTION delegated_authority_service.lock_use_grant(uuid,uuid) FROM PUBLIC;

CREATE FUNCTION delegated_authority_service.lock_use_claim(organization uuid, principal_type text, principal_id text, command uuid)
RETURNS SETOF delegated_authority_service.use_command_claims
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $lock$
    SELECT source.* FROM delegated_authority_service.use_command_claims source
    WHERE source.organization_id=$1 AND source.actor_type=$2 AND source.actor_id=$3 AND source.command_id=$4 FOR UPDATE OF source;
$lock$;
REVOKE ALL ON FUNCTION delegated_authority_service.lock_use_claim(uuid,text,text,uuid) FROM PUBLIC;

CREATE FUNCTION delegated_authority_service.lock_use_admission(organization uuid, principal_type text, principal_id text, challenge uuid)
RETURNS SETOF delegated_authority_service.use_admissions
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $lock$
    SELECT source.* FROM delegated_authority_service.use_admissions source
    WHERE source.organization_id=$1 AND source.actor_type=$2 AND source.actor_id=$3 AND source.challenge_id=$4 FOR UPDATE OF source;
$lock$;
REVOKE ALL ON FUNCTION delegated_authority_service.lock_use_admission(uuid,text,text,uuid) FROM PUBLIC;

-- Preserve the complete original claim checks; only delegate the source row lock.
CREATE OR REPLACE FUNCTION delegated_authority_service.guard_use_command_claim()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE current_grant JSONB;
BEGIN
    SELECT grant_document INTO STRICT current_grant
        FROM delegated_authority_service.lock_use_grant(NEW.organization_id,NEW.grant_id);
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
