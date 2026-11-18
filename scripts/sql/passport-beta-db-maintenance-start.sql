-- Protected beta-only maintenance step. The operator must bind this script to
-- the locked host, approved container, protected source, and fence receipt.
-- Stop application containers first so they cannot race to reconnect.
-- A failed drain leaves marty NOLOGIN; do not reopen it until maintenance ends.
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
                   WHERE rolname='marty' AND
                       (rolsuper OR rolcreaterole OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='marty_beta_migrator' AND
                       (rolcanlogin OR rolsuper OR rolcreaterole OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_auth_members
                   WHERE roleid IN ('marty'::regrole,
                                    'marty_beta_migrator'::regrole)
                      OR member='marty_beta_migrator'::regrole)
        OR EXISTS (SELECT 1 FROM pg_stat_activity
                   WHERE usename='marty_beta_migrator')
        OR EXISTS (SELECT 1 FROM pg_stat_activity
                   WHERE usename='marty' AND state IS DISTINCT FROM 'idle')
        OR (SELECT count(*) FROM pg_namespace
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
                   WHERE rolname='marty_passport_fence_owner' AND
                       (rolcanlogin OR rolsuper OR rolcreaterole OR rolbypassrls))
        OR EXISTS (SELECT 1 FROM pg_auth_members
                   WHERE roleid='marty_passport_fence_owner'::regrole
                      OR member='marty_passport_fence_owner'::regrole) THEN
        RAISE EXCEPTION 'passport maintenance lacks exact fenced beta target';
    END IF;
END
$target$;

ALTER ROLE marty NOLOGIN;
COMMIT;

-- NOLOGIN is committed before terminating clients, so new connections cannot
-- replace the sessions being drained. Recheck the target after that commit.
SET statement_timeout = '60s';
DO $drain$
DECLARE session_pid integer;
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
        OR (SELECT rolcanlogin FROM pg_roles WHERE rolname='marty')
            IS DISTINCT FROM false
        OR EXISTS (SELECT 1 FROM pg_roles
                   WHERE rolname='marty_beta_migrator' AND rolcanlogin)
        OR EXISTS (SELECT 1 FROM pg_stat_activity
                   WHERE usename='marty' AND state IS DISTINCT FROM 'idle') THEN
        RAISE EXCEPTION 'passport maintenance target changed before drain';
    END IF;
    FOR session_pid IN SELECT pid FROM pg_stat_activity
                       WHERE usename='marty' AND pid<>pg_backend_pid() LOOP
        IF NOT pg_terminate_backend(session_pid, 5000) THEN
            RAISE EXCEPTION 'passport maintenance could not drain marty session %',
                session_pid;
        END IF;
    END LOOP;
    PERFORM pg_stat_clear_snapshot();
    IF EXISTS (SELECT 1 FROM pg_stat_activity
               WHERE usename IN ('marty','marty_beta_migrator')
                 AND pid<>pg_backend_pid()) THEN
        RAISE EXCEPTION 'passport maintenance left application sessions open';
    END IF;
END
$drain$;
