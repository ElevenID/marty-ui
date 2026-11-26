-- Fresh native feature profile only. No runtime role is an owner or member.
\set ON_ERROR_STOP on
\getenv feature_password_inventory FEATURE_DATABASE_PASSWORDS
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('elevenid.native-feature-database/v1',0));
CREATE TEMP TABLE feature_input(payload jsonb) ON COMMIT DROP;
INSERT INTO feature_input VALUES (:'feature_password_inventory'::jsonb);
DO $feature_roles$
DECLARE
    expected text[] := ARRAY[
        'feature_delegation_owner','feature_credential_owner',
        'feature_approval_runtime','feature_approval_consent','feature_approval_authority','feature_approval_organization',
        'feature_command_writer','feature_command_runtime','feature_command_organization',
        'feature_use_writer','feature_use_runtime_reader','feature_use_organization_authority',
        'feature_use_registry_source','feature_use_access_source','feature_use_machine_policy_source',
        'feature_use_machine_policy_evidence','feature_use_delegation_policy_source','feature_use_machine_audit',
        'feature_use_flow_reader','feature_use_flow_ingress','feature_use_credential_trust',
        'feature_use_credential_status','feature_use_credential_evidence',
        'feature_issuance_runtime','feature_observation','feature_association'
    ];
    supplied jsonb;
    entry record;
    capacity integer;
BEGIN
    IF current_user <> 'postgres' OR current_user <> session_user OR current_database() <> 'marty'
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
       OR current_setting('server_version_num')::integer < 150000
       OR to_regnamespace('passport_cutover') IS NOT NULL
       OR to_regnamespace('delegated_authority_service') IS NOT NULL
       OR to_regnamespace('machine_credential_source') IS NOT NULL
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=ANY(expected)) THEN
        RAISE EXCEPTION 'feature role bootstrap requires a fresh, verified native PostgreSQL owner';
    END IF;
    SELECT payload INTO STRICT supplied FROM feature_input;
    IF jsonb_typeof(supplied) <> 'object'
       OR supplied->>'schema' IS DISTINCT FROM 'elevenid.feature-database-passwords/v1'
       OR supplied - ARRAY['schema','roles'] <> '{}'::jsonb
       OR jsonb_typeof(supplied->'roles') <> 'object' THEN
        RAISE EXCEPTION 'invalid feature database credential inventory';
    END IF;
    IF (SELECT count(*) FROM jsonb_each(supplied->'roles')) <> cardinality(expected)
       OR EXISTS (SELECT 1 FROM jsonb_each(supplied->'roles') x
                  WHERE NOT x.key=ANY(expected) OR jsonb_typeof(x.value)<>'string'
                     OR x.value #>> '{}' !~ '^[0-9a-f]{64}$'
                     OR x.value #>> '{}' = repeat('0',64))
       OR (SELECT count(DISTINCT value) FROM jsonb_each_text(supplied->'roles')) <> cardinality(expected) THEN
        RAISE EXCEPTION 'invalid feature database credential inventory';
    END IF;
    FOR entry IN SELECT key,value FROM jsonb_each_text(supplied->'roles') ORDER BY key LOOP
        capacity := CASE
            WHEN entry.key IN ('feature_delegation_owner','feature_credential_owner') THEN 1
            -- Both canonical Issuance aliases use a pool of two. The isolated
            -- observation/association aliases each use one of their role's two.
            WHEN entry.key='feature_issuance_runtime' THEN 4
            ELSE 2 END;
        EXECUTE format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %s PASSWORD %L',
                       entry.key,capacity,entry.value);
        EXECUTE format('GRANT CONNECT ON DATABASE marty TO %I',entry.key);
    END LOOP;
    -- Only the two one-shot migration owners may create their source-owned
    -- schemas. The final grants phase revokes this temporary authority.
    GRANT CREATE ON DATABASE marty TO feature_delegation_owner,feature_credential_owner;
    REVOKE CREATE,TEMPORARY ON DATABASE marty FROM PUBLIC;
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EXCEPTION WHEN OTHERS THEN
    -- Do not retain a dynamic CREATE ROLE statement containing its password in
    -- a child exception context. The native job preserves its refusal record.
    RAISE EXCEPTION 'feature role bootstrap refused; preserve installation evidence';
END
$feature_roles$;
COMMIT;
