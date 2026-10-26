-- ACL-only isolated fixture. This does NOT install/qualify the complete fence.
-- Run ONLY in a fresh uniquely-owned localhost PostgreSQL test cluster.
\set ON_ERROR_STOP on
DO $fixture$
BEGIN
    IF current_database()<>'marty'
       OR current_setting('marty.disposable_test_owner',true)
            IS DISTINCT FROM 'android-wallet-d12-role-fixture'
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolsuper)
       OR to_regnamespace('issuance_service') IS NOT NULL
       OR to_regnamespace('flow_service') IS NOT NULL
       OR to_regnamespace('passport_cutover') IS NOT NULL
       OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN
            ('marty','marty_passport_fence_owner','marty_beta_migrator')) THEN
        RAISE EXCEPTION 'not a fresh owned disposable ACL fixture';
    END IF;
END
$fixture$;
CREATE ROLE marty NOLOGIN;
CREATE ROLE marty_passport_fence_owner NOLOGIN NOINHERIT;
CREATE ROLE marty_beta_migrator NOLOGIN NOINHERIT;
\ir ../../rust/services/flow/migrations/0001_flow_schema.sql
\ir ../../rust/services/flow/migrations/0002_builtin_flows.sql
\ir ../../rust/services/flow/migrations/0003_physical_start_intents.sql
\ir ../../rust/services/issuance/migrations/0002_physical_document_jobs.sql
\ir ../../rust/services/issuance/migrations/0003_passport_bureau_provider_binding.sql
\ir ../../rust/services/issuance/migrations/0004_passport_submission_intent.sql
\ir ../../rust/services/issuance/migrations/0005_passport_submission_provenance.sql
\ir ../../rust/services/issuance/migrations/0006_passport_beta_batch_identity.sql
\ir ../../rust/services/issuance/migrations/0007_passport_beta_batch_provenance.sql
\ir ../../rust/services/issuance/migrations/0008_passport_beta_batch_wire_evidence.sql
\ir ../../rust/services/issuance/migrations/0010_passport_start_idempotency.sql
\ir ../../rust/services/issuance/migrations/0011_passport_administrative_cancellation.sql
CREATE SCHEMA passport_cutover AUTHORIZATION marty_passport_fence_owner;
REVOKE ALL ON SCHEMA passport_cutover FROM PUBLIC;
CREATE TABLE passport_cutover.state (
    singleton boolean PRIMARY KEY, phase text NOT NULL, epoch bigint NOT NULL);
INSERT INTO passport_cutover.state VALUES (true,'fully_fenced',1);
ALTER TABLE passport_cutover.state OWNER TO marty_passport_fence_owner;
ALTER SCHEMA issuance_service OWNER TO marty_passport_fence_owner;
ALTER SCHEMA flow_service OWNER TO marty_passport_fence_owner;
REVOKE CREATE ON SCHEMA issuance_service,flow_service FROM PUBLIC,marty;
GRANT USAGE ON SCHEMA issuance_service,flow_service TO marty;
ALTER TABLE issuance_service.physical_document_jobs OWNER TO marty_passport_fence_owner;
ALTER TABLE flow_service.flow_definitions OWNER TO marty_passport_fence_owner;
ALTER TABLE flow_service.flow_instances OWNER TO marty_passport_fence_owner;
-- Existing application surfaces required by real repository operations. New
-- cancellation/intent permissions come ONLY from the actual reviewed finalizer.
GRANT SELECT,INSERT,UPDATE,DELETE ON
    issuance_service.physical_document_jobs,
    flow_service.flow_definitions,flow_service.flow_instances,
    flow_service.flow_nonce_consumptions,flow_service.flow_callback_outbox,
    flow_service.flow_application_event_receipts,flow_service.flow_instance_artifacts
    TO marty;
GRANT SELECT ON flow_service.rust_schema_versions,flow_service.rust_seed_versions TO marty;
SELECT set_config('marty.passport_beta_verified_project','elevenid-beta',false);
SELECT set_config('marty.passport_beta_expected_system_identifier',
                  (SELECT system_identifier::text FROM pg_control_system()),false);
SELECT set_config('marty.passport_beta_expected_database_oid',
                  (SELECT oid::text FROM pg_database WHERE datname=current_database()),false);
SELECT set_config('marty.passport_beta_expected_fence_epoch','1',false);
-- The real production SQL, with unchanged owner/epoch/NOLOGIN/no-session guards.
\ir ../../scripts/sql/passport-beta-batch-acl-finalize.sql
DO $fixture_ready$
BEGIN
    IF NOT issuance_service.passport_cancellation_acl_ready()
       OR NOT flow_service.physical_start_acl_ready() THEN
        RAISE EXCEPTION 'actual finalizer did not establish both role contracts';
    END IF;
END
$fixture_ready$;
-- Fixture-only admission follows the actual finalizer. The owned localhost
-- test cluster uses synthetic local authentication; no beta login handoff claim.
ALTER ROLE marty LOGIN;
