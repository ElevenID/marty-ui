-- Operational metadata only. Run after independently verified source-bound
-- Rust migrate + verify-owned-schema commands, while all22 remain stopped.
-- This is NOT a domain/schema migration or a retired SQL handoff executor.
-- The protected operator binds the target, fence, source and migration-set
-- settings and consumes a durable one-shot intent before this transaction.
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '60s';
DO $target$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
        OR current_database() <> 'marty'
        OR current_setting('marty.passport_beta_verified_project',true) IS DISTINCT FROM 'elevenid-beta'
        OR current_setting('marty.passport_beta_expected_system_identifier',true)
            IS DISTINCT FROM (SELECT system_identifier::text FROM pg_control_system())
        OR current_setting('marty.passport_beta_expected_database_oid',true)
            IS DISTINCT FROM (SELECT oid::text FROM pg_database WHERE datname=current_database())
        OR coalesce(current_setting('marty.passport_beta_expected_source_commit',true),'') !~ '^[a-f0-9]{40}$'
        OR coalesce(current_setting('marty.passport_beta_expected_native_migration_sha256',true),'') !~ '^[a-f0-9]{64}$'
        OR to_regclass('passport_cutover.native_migration_receipt') IS NOT NULL THEN
        RAISE EXCEPTION 'native migration attestation lacks an exact new beta target';
    END IF;
END
$target$;
LOCK TABLE passport_cutover.state IN ACCESS EXCLUSIVE MODE;
DO $fence$
BEGIN
    IF coalesce(current_setting('marty.passport_beta_expected_fence_epoch',true),'') !~ '^[1-9][0-9]*$'
        OR (SELECT count(*) FROM passport_cutover.state) <> 1
        OR NOT EXISTS (SELECT 1 FROM passport_cutover.state WHERE singleton=true AND phase='fully_fenced' AND epoch>0)
        OR current_setting('marty.passport_beta_expected_fence_epoch',true)
            IS DISTINCT FROM (SELECT epoch::text FROM passport_cutover.state
                              WHERE singleton=true AND phase='fully_fenced' AND epoch>0)
        OR (SELECT count(*) FROM pg_roles WHERE rolname IN ('marty','marty_beta_migrator')) <> 2
        OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('marty','marty_beta_migrator') AND rolcanlogin)
        OR EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename IN ('marty','marty_beta_migrator')
                   AND pid<>pg_backend_pid()) THEN
        RAISE EXCEPTION 'native migration attestation requires the current drained fence';
    END IF;
END
$fence$;
-- Preserve the canonical metadata columns consumed by the existing login and
-- Rust-owner SQL guards. No business migration SQL is assembled or repeated.
CREATE TABLE passport_cutover.native_migration_receipt (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    fence_epoch bigint NOT NULL,
    source_commit text NOT NULL,
    migration_set_sha256 text NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE passport_cutover.native_migration_receipt OWNER TO marty_passport_fence_owner;
REVOKE ALL ON passport_cutover.native_migration_receipt FROM PUBLIC,marty,marty_beta_migrator;
INSERT INTO passport_cutover.native_migration_receipt
    (singleton,fence_epoch,source_commit,migration_set_sha256)
VALUES (true,current_setting('marty.passport_beta_expected_fence_epoch')::bigint,
    current_setting('marty.passport_beta_expected_source_commit'),
    current_setting('marty.passport_beta_expected_native_migration_sha256'));
SELECT json_build_object(
    'schema','marty.passport-beta-native-migration-attestation/v1',
    'fence_epoch',fence_epoch,'source_commit',source_commit,
    'migration_set_sha256',migration_set_sha256,'installed_at',installed_at,
    'relation_owner',(SELECT pg_get_userbyid(relowner) FROM pg_class
                      WHERE oid='passport_cutover.native_migration_receipt'::regclass),
    'app_can_read',has_table_privilege('marty','passport_cutover.native_migration_receipt','SELECT')
) FROM passport_cutover.native_migration_receipt WHERE singleton=true;
COMMIT;
