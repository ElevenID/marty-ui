-- Protected beta-only handoff after the native Rust SQL and batch ACL gates.
-- The source-bound aggregate operator must prove old beta containers remain
-- stopped, then start only the reviewed Rust release with schema validation.
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
        OR (SELECT count(*) FROM pg_roles
            WHERE rolname IN ('marty','marty_beta_migrator')) <> 2
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname IN ('marty','marty_beta_migrator')
                     AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='marty_beta_migrator' AND rolcanlogin)
        OR EXISTS (SELECT 1 FROM pg_auth_members
                   WHERE roleid IN ('marty'::regrole,
                                    'marty_beta_migrator'::regrole)
                      OR member IN ('marty'::regrole,
                                    'marty_beta_migrator'::regrole))
        OR EXISTS (SELECT 1 FROM pg_stat_activity
                   WHERE usename IN ('marty','marty_beta_migrator')
                     AND pid<>pg_backend_pid()) THEN
        RAISE EXCEPTION 'passport app login lacks exact drained beta target';
    END IF;
END
$target$;

DO $native$
BEGIN
    IF to_regclass('passport_cutover.native_migration_receipt') IS NULL THEN
        RAISE EXCEPTION 'passport app login lacks committed native migrations';
    END IF;
    IF (SELECT count(*) FROM pg_class
        WHERE oid='passport_cutover.native_migration_receipt'::regclass
          AND relkind='r'
          AND pg_get_userbyid(relowner)='marty_passport_fence_owner') <> 1
        OR has_table_privilege('marty',
            'passport_cutover.native_migration_receipt','SELECT,INSERT,UPDATE,DELETE')
        OR (SELECT count(*) FROM passport_cutover.native_migration_receipt
            WHERE singleton=true
              AND fence_epoch=(SELECT epoch FROM passport_cutover.state
                               WHERE singleton=true AND phase='fully_fenced')
              AND source_commit=current_setting(
                  'marty.passport_beta_expected_source_commit', true)
              AND migration_set_sha256=current_setting(
                  'marty.passport_beta_expected_native_migration_sha256', true)) <> 1 THEN
        RAISE EXCEPTION 'passport app login lacks committed native migrations';
    END IF;
END
$native$;

LOCK TABLE issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances,
    issuance_service.passport_beta_batch_intents IN ACCESS EXCLUSIVE MODE;

DO $access$
BEGIN
    IF (SELECT count(*) FROM pg_namespace
        WHERE nspname IN ('issuance_service','flow_service')
          AND pg_get_userbyid(nspowner)='marty_passport_fence_owner') <> 2
        OR (SELECT count(*) FROM pg_class AS c JOIN pg_namespace AS n
            ON n.oid=c.relnamespace
            WHERE (n.nspname,c.relname) IN (
                ('issuance_service','physical_document_jobs'),
                ('issuance_service','passport_beta_batch_intents'),
                ('flow_service','flow_definitions'),
                ('flow_service','flow_instances'))
              AND pg_get_userbyid(c.relowner)='marty_passport_fence_owner') <> 4
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='marty_passport_fence_owner'
                     AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb
                          OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_auth_members
                   WHERE roleid='marty_passport_fence_owner'::regrole
                      OR member='marty_passport_fence_owner'::regrole)
        OR has_schema_privilege('marty','issuance_service','CREATE')
        OR has_schema_privilege('marty','flow_service','CREATE')
        OR NOT has_schema_privilege('marty','issuance_service','USAGE')
        OR NOT has_schema_privilege('marty','flow_service','USAGE')
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
        RAISE EXCEPTION 'passport app login lacks guarded batch access';
    END IF;
END
$access$;

ALTER ROLE marty LOGIN;
COMMIT;
