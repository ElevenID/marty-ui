-- Protected beta-only postmigration step. Run from the source-bound operator
-- after the reviewed Rust SQL has committed and before either Rust service starts.
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';

DO $target$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
        OR current_database() <> 'marty'
        OR current_setting('marty.passport_beta_verified_project', true)
            IS DISTINCT FROM 'elevenid-beta'
        OR current_setting('marty.passport_beta_expected_system_identifier', true)
            IS DISTINCT FROM (SELECT system_identifier::text FROM pg_control_system())
        OR current_setting('marty.passport_beta_expected_database_oid', true)
            IS DISTINCT FROM (SELECT oid::text FROM pg_database
                              WHERE datname=current_database())
        OR current_setting('marty.passport_beta_expected_fence_epoch', true)
            IS DISTINCT FROM (SELECT epoch::text FROM passport_cutover.state
                              WHERE singleton=true AND phase='fully_fenced')
        OR (SELECT count(*) FROM passport_cutover.state
            WHERE singleton=true AND phase='fully_fenced' AND epoch>0) <> 1
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname IN ('marty','marty_beta_migrator') AND rolcanlogin)
        OR (SELECT count(*) FROM pg_roles
            WHERE rolname IN ('marty','marty_beta_migrator')) <> 2
        OR EXISTS (SELECT 1 FROM pg_stat_activity
                   WHERE usename IN ('marty','marty_beta_migrator')
                     AND pid<>pg_backend_pid()) THEN
        RAISE EXCEPTION 'passport batch ACL finalizer lacks exact fenced beta target';
    END IF;
END
$target$;

LOCK TABLE issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances,
    issuance_service.passport_beta_batch_intents IN ACCESS EXCLUSIVE MODE;

DO $owners$
BEGIN
    IF (SELECT count(*) FROM pg_namespace
        WHERE nspname IN ('issuance_service','flow_service')
          AND pg_get_userbyid(nspowner)='marty_passport_fence_owner') <> 2
        OR (SELECT count(*) FROM pg_class AS c JOIN pg_namespace AS n
            ON n.oid=c.relnamespace
            WHERE (n.nspname,c.relname) IN (
                ('issuance_service','physical_document_jobs'),
                ('flow_service','flow_definitions'),
                ('flow_service','flow_instances'))
              AND pg_get_userbyid(c.relowner)='marty_passport_fence_owner') <> 3
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='marty_passport_fence_owner'
                     AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_auth_members
                   WHERE roleid='marty_passport_fence_owner'::regrole
                      OR member='marty_passport_fence_owner'::regrole)
        OR has_schema_privilege('marty','issuance_service','CREATE')
        OR has_schema_privilege('marty','flow_service','CREATE') THEN
        RAISE EXCEPTION 'passport batch ACL finalizer found changed fence ownership';
    END IF;
END
$owners$;

ALTER TABLE issuance_service.passport_beta_batch_intents
    OWNER TO marty_passport_fence_owner;
REVOKE ALL ON issuance_service.passport_beta_batch_intents FROM PUBLIC, marty;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON issuance_service.passport_beta_batch_intents TO marty;

DO $access$
BEGIN
    IF (SELECT pg_get_userbyid(relowner) FROM pg_class
        WHERE oid='issuance_service.passport_beta_batch_intents'::regclass)
            IS DISTINCT FROM 'marty_passport_fence_owner'
        OR NOT has_schema_privilege('marty','issuance_service','USAGE')
        OR NOT has_table_privilege('marty',
            'issuance_service.passport_beta_batch_intents','SELECT')
        OR NOT has_table_privilege('marty',
            'issuance_service.passport_beta_batch_intents','INSERT')
        OR NOT has_table_privilege('marty',
            'issuance_service.passport_beta_batch_intents','UPDATE')
        OR NOT has_table_privilege('marty',
            'issuance_service.passport_beta_batch_intents','DELETE')
        OR has_table_privilege('marty',
            'issuance_service.passport_beta_batch_intents','TRUNCATE,TRIGGER')
        OR EXISTS (SELECT 1 FROM pg_roles AS role
                   WHERE role.rolcanlogin AND role.rolname<>'marty'
                     AND NOT role.rolsuper
                     AND has_table_privilege(role.rolname,
                        'issuance_service.passport_beta_batch_intents',
                        'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')) THEN
        RAISE EXCEPTION 'passport batch ACL finalizer failed app access audit';
    END IF;
END
$access$;
COMMIT;
