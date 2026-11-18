-- Draft, forward-only beta passport ownership transition. This file is not a
-- deployment entry point: the protected aggregate operator must first prove
-- the exact post-deletion service generation and keep passport ingress closed.
-- All included SQL must be staged from the same signed, source-bound release.
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
        OR coalesce(current_setting('marty.passport_beta_expected_source_commit', true), '')
            !~ '^[a-f0-9]{40}$'
        OR coalesce(current_setting('marty.passport_beta_expected_native_migration_sha256', true), '')
            !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'Rust owner transition lacks exact beta target and source attestation';
    END IF;
END
$target$;

LOCK TABLE passport_cutover.state,
    issuance_service.physical_document_jobs,
    flow_service.flow_definitions, flow_service.flow_instances
    IN ACCESS EXCLUSIVE MODE;

-- Recheck every current fence owner, grant, function and trigger before
-- changing the functions. The same frozen drain selectors run under locks.
\ir passport-beta-fence-verify.sql
\ir passport-beta-fence-drain.sql

DO $native$
BEGIN
    IF to_regclass('passport_cutover.native_migration_receipt') IS NULL THEN
        RAISE EXCEPTION 'Rust owner transition lacks committed native migrations';
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
        RAISE EXCEPTION 'Rust owner transition lacks committed native migrations';
    END IF;
END
$native$;

-- CREATE OR REPLACE in migration 0004 retains any pre-existing function owner.
-- Move the native submission guard away from the shared app role before DML
-- can reopen. The trigger keeps invoking it as a SECURITY INVOKER function.
ALTER FUNCTION issuance_service.guard_physical_document_submission_intent()
    OWNER TO marty_passport_fence_owner;
REVOKE ALL ON FUNCTION issuance_service.guard_physical_document_submission_intent()
    FROM PUBLIC, marty;

-- Keep the original fence epoch immutable for predeletion receipt lineage.
-- The transition marker identifies this separate, one-way transaction.
ALTER TABLE passport_cutover.state
    ADD COLUMN transition_txid bigint,
    ADD COLUMN transitioned_at timestamptz;
ALTER TABLE passport_cutover.state DROP CONSTRAINT state_phase_check;
ALTER TABLE passport_cutover.state ADD CONSTRAINT state_phase_check
    CHECK (phase IN ('fully_fenced', 'rust_owner'));
ALTER TABLE passport_cutover.state ADD CONSTRAINT state_transition_shape_check
    CHECK ((phase='fully_fenced' AND transition_txid IS NULL AND transitioned_at IS NULL)
        OR (phase='rust_owner' AND transition_txid > epoch AND transitioned_at IS NOT NULL));

CREATE OR REPLACE FUNCTION passport_cutover.guard_job() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
BEGIN
    IF passport_cutover.phase() = 'rust_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'beta passport job writes are fenced' USING ERRCODE = '55000';
END
$function$;

CREATE OR REPLACE FUNCTION passport_cutover.guard_definition() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE old_physical boolean := false;
DECLARE new_physical boolean := false;
BEGIN
    IF passport_cutover.phase() = 'rust_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
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

CREATE OR REPLACE FUNCTION passport_cutover.guard_instance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $function$
DECLARE old_physical boolean := false;
DECLARE new_physical boolean := false;
BEGIN
    IF passport_cutover.phase() = 'rust_owner' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
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

UPDATE passport_cutover.state
SET phase='rust_owner', transition_txid=txid_current(),
    transitioned_at=clock_timestamp()
WHERE singleton=true AND phase='fully_fenced'
  AND epoch=current_setting('marty.passport_beta_expected_fence_epoch')::bigint;

DO $committed_shape$
BEGIN
    IF (SELECT count(*) FROM passport_cutover.state
        WHERE singleton=true AND phase='rust_owner' AND epoch>0
          AND transition_txid>epoch AND transitioned_at IS NOT NULL) <> 1
        OR (SELECT count(*) FROM passport_cutover.state) <> 1
        OR (SELECT count(*) FROM pg_proc AS p JOIN pg_namespace AS n
            ON n.oid=p.pronamespace
            WHERE n.nspname='passport_cutover' AND p.proname IN
                ('guard_job','guard_definition','guard_instance')
              AND pg_get_userbyid(p.proowner)='marty_passport_fence_owner'
              AND p.prosecdef) <> 3
        OR has_schema_privilege('marty','issuance_service','CREATE')
        OR has_schema_privilege('marty','flow_service','CREATE')
        OR has_table_privilege('marty',
            'issuance_service.physical_document_jobs','TRUNCATE,TRIGGER')
        OR has_table_privilege('marty',
            'flow_service.flow_definitions','TRUNCATE,TRIGGER')
        OR has_table_privilege('marty',
            'flow_service.flow_instances','TRUNCATE,TRIGGER') THEN
        RAISE EXCEPTION 'Rust owner transition did not preserve guarded state';
    END IF;
END
$committed_shape$;

-- The read-only verifier must pass inside this transaction before the new
-- DML phase becomes visible to any other session. Its later protected run
-- must bind this returned transition marker independently.
SELECT set_config('marty.passport_beta_expected_transition_txid',
    transition_txid::text, true)
FROM passport_cutover.state WHERE singleton=true;
\ir passport-beta-rust-owner-verify.sql

SELECT jsonb_build_object(
    'schema', 'marty.passport-beta-rust-owner-transition/v1',
    'phase', phase, 'fence_epoch', epoch,
    'transition_txid', transition_txid, 'transitioned_at', transitioned_at,
    'functions_md5', (SELECT jsonb_object_agg(p.proname,
        md5(pg_get_functiondef(p.oid)) ORDER BY p.proname)
        FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid=p.pronamespace
        WHERE n.nspname='passport_cutover')
) FROM passport_cutover.state WHERE singleton=true;
COMMIT;
