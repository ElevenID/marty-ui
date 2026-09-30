-- Draft: do not run on beta until the identity-checked operator, effective
-- privilege audit, and separate migration executor have passed review.
-- Session attestation below only rejects accidental direct execution; the
-- operator must independently bind it to Docker/Compose and protected source.
-- This transaction is all-or-nothing and intentionally refuses a second install.
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';
DO $target$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper)
        OR current_database() <> 'marty'
        OR current_setting('marty.passport_beta_verified_project', true)
            IS DISTINCT FROM 'elevenid-beta'
        OR current_setting('marty.passport_beta_expected_system_identifier', true)
            IS DISTINCT FROM (SELECT system_identifier::text FROM pg_control_system())
        OR current_setting('marty.passport_beta_expected_database_oid', true)
            IS DISTINCT FROM (SELECT oid::text FROM pg_database WHERE datname = current_database()) THEN
        RAISE EXCEPTION 'passport fence lacks exact beta target attestation';
    END IF;
END
$target$;
LOCK TABLE issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances
    IN ACCESS EXCLUSIVE MODE;
-- This include runs under the same table locks and transaction. It refuses
-- installation if any in-flight work or incompatible artifact remains.
\ir passport-beta-fence-drain.sql

DO $preflight$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
        RAISE EXCEPTION 'passport fence installation requires a privileged operator';
    END IF;
    IF current_database() <> 'marty' OR to_regnamespace('passport_cutover') IS NOT NULL THEN
        RAISE EXCEPTION 'passport fence target database or prior installation is invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE (n.nspname, c.relname) IN (
            ('issuance_service', 'physical_document_jobs'),
            ('flow_service', 'flow_definitions'), ('flow_service', 'flow_instances'))
          AND pg_get_userbyid(c.relowner) <> 'marty'
    ) OR (
        SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE (n.nspname, c.relname) IN (
            ('issuance_service', 'physical_document_jobs'),
            ('flow_service', 'flow_definitions'), ('flow_service', 'flow_instances'))
    ) <> 3 THEN
        RAISE EXCEPTION 'guarded beta tables do not match the reviewed owner inventory';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles
               WHERE rolname IN ('marty_passport_fence_owner', 'marty_beta_migrator')) THEN
        RAISE EXCEPTION 'passport fence guard or migration role already exists';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolname = 'marty'
          AND (role.rolsuper OR role.rolcreaterole OR role.rolbypassrls)
    ) OR EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolsuper AND pg_has_role('marty', role.oid, 'MEMBER')
    ) THEN
        RAISE EXCEPTION 'live marty role can bypass a trusted fence owner';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_roles AS role
        WHERE role.rolcanlogin AND role.rolname <> 'marty' AND NOT role.rolsuper
          AND (
            has_table_privilege(role.rolname, 'issuance_service.physical_document_jobs', 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
            OR has_table_privilege(role.rolname, 'flow_service.flow_definitions', 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
            OR has_table_privilege(role.rolname, 'flow_service.flow_instances', 'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER')
          )
    ) THEN
        RAISE EXCEPTION 'unexpected live writer role on guarded tables';
    END IF;
END
$preflight$;

CREATE ROLE marty_passport_fence_owner NOLOGIN NOINHERIT;
-- The later official release may temporarily activate this dedicated role
-- inside maintenance. It has no login or memberships at rest.
CREATE ROLE marty_beta_migrator NOLOGIN NOINHERIT;
CREATE SCHEMA passport_cutover AUTHORIZATION marty_passport_fence_owner;
REVOKE ALL ON SCHEMA passport_cutover FROM PUBLIC;
CREATE TABLE passport_cutover.state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    phase text NOT NULL CHECK (phase = 'fully_fenced'),
    epoch bigint NOT NULL CHECK (epoch > 0),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE passport_cutover.state OWNER TO marty_passport_fence_owner;
INSERT INTO passport_cutover.state (singleton, phase, epoch)
VALUES (true, 'fully_fenced', txid_current());

CREATE FUNCTION passport_cutover.phase() RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE selected text;
BEGIN
    SELECT phase INTO STRICT selected FROM passport_cutover.state
    WHERE singleton = true FOR SHARE;
    RETURN selected;
END
$function$;

CREATE FUNCTION passport_cutover.physical_definition(definition_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE selected boolean;
BEGIN
    SELECT lower(coalesce(flow_type, '')) = 'physical_document_issuance'
        OR (lower(coalesce(flow_type, '')) = 'custom'
            AND extension::jsonb->>'extends_flow_type'
                = 'physical_document_issuance')
    INTO selected FROM flow_service.flow_definitions
    WHERE id = definition_id FOR SHARE;
    RETURN coalesce(selected, false);
END
$function$;

CREATE FUNCTION passport_cutover.physical_context(context_value json)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $function$
    SELECT coalesce(context_value::jsonb ? 'physical_document_job', false)
$function$;

CREATE FUNCTION passport_cutover.guard_job() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
BEGIN
    PERFORM passport_cutover.phase();
    RAISE EXCEPTION 'beta passport job writes are fenced' USING ERRCODE = '55000';
END
$function$;

CREATE FUNCTION passport_cutover.guard_definition() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE old_physical boolean := false;
DECLARE new_physical boolean := false;
BEGIN
    PERFORM passport_cutover.phase();
    IF TG_OP <> 'INSERT' THEN
        old_physical := lower(coalesce(OLD.flow_type, '')) = 'physical_document_issuance'
            OR (lower(coalesce(OLD.flow_type, '')) = 'custom'
                AND OLD.extension::jsonb->>'extends_flow_type'
                    = 'physical_document_issuance');
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_physical := lower(coalesce(NEW.flow_type, '')) = 'physical_document_issuance'
            OR (lower(coalesce(NEW.flow_type, '')) = 'custom'
                AND NEW.extension::jsonb->>'extends_flow_type'
                    = 'physical_document_issuance');
    END IF;
    IF old_physical OR new_physical THEN
        RAISE EXCEPTION 'beta physical-document Flow definition writes are fenced'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION passport_cutover.guard_instance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE old_physical boolean := false;
DECLARE new_physical boolean := false;
BEGIN
    PERFORM passport_cutover.phase();
    IF TG_OP <> 'INSERT' THEN
        old_physical := passport_cutover.physical_context(OLD.context)
            OR passport_cutover.physical_definition(OLD.flow_definition_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_physical := passport_cutover.physical_context(NEW.context)
            OR passport_cutover.physical_definition(NEW.flow_definition_id);
    END IF;
    IF old_physical OR new_physical THEN
        RAISE EXCEPTION 'beta physical-document Flow writes are fenced'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END
$function$;

CREATE FUNCTION passport_cutover.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
BEGIN
    PERFORM passport_cutover.phase();
    RAISE EXCEPTION 'beta passport evidence truncation is fenced' USING ERRCODE = '55000';
END
$function$;

ALTER FUNCTION passport_cutover.phase()
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.physical_definition(text)
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.physical_context(json)
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.guard_job()
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.guard_definition()
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.guard_instance()
    OWNER TO marty_passport_fence_owner;
ALTER FUNCTION passport_cutover.guard_truncate()
    OWNER TO marty_passport_fence_owner;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA passport_cutover FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA passport_cutover FROM PUBLIC;

CREATE TRIGGER passport_fence_job BEFORE INSERT OR UPDATE OR DELETE
ON issuance_service.physical_document_jobs FOR EACH ROW
EXECUTE FUNCTION passport_cutover.guard_job();
CREATE TRIGGER passport_fence_definition BEFORE INSERT OR UPDATE OR DELETE
ON flow_service.flow_definitions FOR EACH ROW
EXECUTE FUNCTION passport_cutover.guard_definition();
CREATE TRIGGER passport_fence_instance BEFORE INSERT OR UPDATE OR DELETE
ON flow_service.flow_instances FOR EACH ROW
EXECUTE FUNCTION passport_cutover.guard_instance();
CREATE TRIGGER passport_fence_job_truncate BEFORE TRUNCATE
ON issuance_service.physical_document_jobs FOR EACH STATEMENT
EXECUTE FUNCTION passport_cutover.guard_truncate();
CREATE TRIGGER passport_fence_definition_truncate BEFORE TRUNCATE
ON flow_service.flow_definitions FOR EACH STATEMENT
EXECUTE FUNCTION passport_cutover.guard_truncate();
CREATE TRIGGER passport_fence_instance_truncate BEFORE TRUNCATE
ON flow_service.flow_instances FOR EACH STATEMENT
EXECUTE FUNCTION passport_cutover.guard_truncate();

ALTER TABLE issuance_service.physical_document_jobs
    ENABLE ALWAYS TRIGGER passport_fence_job;
ALTER TABLE flow_service.flow_definitions
    ENABLE ALWAYS TRIGGER passport_fence_definition;
ALTER TABLE flow_service.flow_instances
    ENABLE ALWAYS TRIGGER passport_fence_instance;
ALTER TABLE issuance_service.physical_document_jobs
    ENABLE ALWAYS TRIGGER passport_fence_job_truncate;
ALTER TABLE flow_service.flow_definitions
    ENABLE ALWAYS TRIGGER passport_fence_definition_truncate;
ALTER TABLE flow_service.flow_instances
    ENABLE ALWAYS TRIGGER passport_fence_instance_truncate;

ALTER SCHEMA issuance_service OWNER TO marty_passport_fence_owner;
ALTER SCHEMA flow_service OWNER TO marty_passport_fence_owner;
REVOKE CREATE ON SCHEMA issuance_service, flow_service FROM marty, PUBLIC;
ALTER TABLE issuance_service.physical_document_jobs
    OWNER TO marty_passport_fence_owner;
ALTER TABLE flow_service.flow_definitions
    OWNER TO marty_passport_fence_owner;
ALTER TABLE flow_service.flow_instances
    OWNER TO marty_passport_fence_owner;
REVOKE TRUNCATE, TRIGGER ON
    issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances
    FROM marty, PUBLIC;
GRANT USAGE ON SCHEMA issuance_service, flow_service TO marty;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances TO marty;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA issuance_service, flow_service TO marty;

DO $acl$
BEGIN
    IF has_schema_privilege('marty', 'issuance_service', 'CREATE')
        OR has_schema_privilege('marty', 'flow_service', 'CREATE')
        OR has_table_privilege('marty', 'issuance_service.physical_document_jobs', 'TRUNCATE, TRIGGER')
        OR has_table_privilege('marty', 'flow_service.flow_definitions', 'TRUNCATE, TRIGGER')
        OR has_table_privilege('marty', 'flow_service.flow_instances', 'TRUNCATE, TRIGGER')
        OR EXISTS (SELECT 1 FROM pg_auth_members
            WHERE roleid IN ('marty_passport_fence_owner'::regrole,
                             'marty_beta_migrator'::regrole))
        OR EXISTS (SELECT 1 FROM pg_auth_members
            WHERE member = 'marty_beta_migrator'::regrole)
        OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'marty_beta_migrator'
                   AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreaterole
                        OR rolcreatedb OR rolbypassrls)) THEN
        RAISE EXCEPTION 'passport fence owner, migration role, or app ACL is unsafe';
    END IF;
END
$acl$;

COMMIT;
