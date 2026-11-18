-- Local administrative disposition is separate from physical bureau activity.
-- Retain jobs and all their existing quality/material/bureau history.
CREATE UNIQUE INDEX IF NOT EXISTS ux_physical_document_jobs_id_organization
    ON issuance_service.physical_document_jobs (id, organization_id);

CREATE TABLE IF NOT EXISTS issuance_service.passport_job_administrative_cancellations (
    job_id text CONSTRAINT pk_passport_administrative_cancellation PRIMARY KEY,
    organization_id text NOT NULL,
    event_id uuid NOT NULL CONSTRAINT ux_passport_cancellation_event UNIQUE,
    prior_status varchar(40) NOT NULL,
    reason_code varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_reason_code CHECK (reason_code = 'ADMINISTRATIVE_ABANDONMENT'),
    reason text NOT NULL CONSTRAINT ck_passport_cancel_reason_length CHECK (octet_length(reason) BETWEEN 1 AND 512),
    actor_kind varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_actor_kind CHECK (actor_kind = 'AUTHENTICATED_PASSPORT_TENANT'),
    actor_organization_id text NOT NULL CONSTRAINT ck_passport_cancel_actor_tenant CHECK (actor_organization_id = organization_id),
    recorded_at timestamptz NOT NULL,
    idempotency_key_hash varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_key_hash CHECK (idempotency_key_hash ~ '^[0-9a-f]{64}$'),
    request_hash varchar(64) NOT NULL CONSTRAINT ck_passport_cancel_request_hash CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    bureau_cancellation_requested boolean NOT NULL CONSTRAINT ck_passport_cancel_not_physical CHECK (NOT bureau_cancellation_requested),
    CONSTRAINT fk_passport_cancel_owned_job FOREIGN KEY (job_id,organization_id)
        REFERENCES issuance_service.physical_document_jobs (id,organization_id) ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION issuance_service.guard_passport_cancellation_history()
RETURNS trigger LANGUAGE plpgsql AS $cancellation_history_guard$
BEGIN
    RAISE EXCEPTION 'passport administrative cancellation history is immutable';
END;
$cancellation_history_guard$;
DROP TRIGGER IF EXISTS trg_passport_cancellation_history
    ON issuance_service.passport_job_administrative_cancellations;
CREATE TRIGGER trg_passport_cancellation_history
    BEFORE UPDATE OR DELETE ON issuance_service.passport_job_administrative_cancellations
    FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_passport_cancellation_history();
DROP TRIGGER IF EXISTS trg_passport_cancellation_history_truncate
    ON issuance_service.passport_job_administrative_cancellations;
CREATE TRIGGER trg_passport_cancellation_history_truncate
    BEFORE TRUNCATE ON issuance_service.passport_job_administrative_cancellations
    FOR EACH STATEMENT EXECUTE FUNCTION issuance_service.guard_passport_cancellation_history();

CREATE OR REPLACE FUNCTION issuance_service.guard_administratively_cancelled_passport_job()
RETURNS trigger LANGUAGE plpgsql AS $cancelled_job_guard$
BEGIN
    IF OLD.status = 'CANCELLED' AND EXISTS (
        SELECT 1 FROM issuance_service.passport_job_administrative_cancellations
        WHERE job_id=OLD.id AND organization_id=OLD.organization_id
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'administratively cancelled passport job history is immutable';
        END IF;
        IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
            RAISE EXCEPTION 'administratively cancelled passport job history is immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$cancelled_job_guard$;
DROP TRIGGER IF EXISTS trg_administratively_cancelled_passport_job
    ON issuance_service.physical_document_jobs;
CREATE TRIGGER trg_administratively_cancelled_passport_job
    BEFORE UPDATE OR DELETE ON issuance_service.physical_document_jobs
    FOR EACH ROW EXECUTE FUNCTION issuance_service.guard_administratively_cancelled_passport_job();

-- Catalog-only shared fence contract, usable without granting access to the
-- protected cutover state. The existing attested ACL finalizer owns provisioning.
CREATE OR REPLACE FUNCTION issuance_service.passport_cancellation_acl_ready()
RETURNS boolean LANGUAGE sql STABLE AS $cancellation_acl_guard$
SELECT COALESCE((
    SELECT
        pg_catalog.pg_get_userbyid(audit.relowner) = owner_role.rolname
        AND NOT (owner_role.rolcanlogin OR owner_role.rolinherit OR owner_role.rolsuper
                 OR owner_role.rolcreatedb OR owner_role.rolcreaterole OR owner_role.rolbypassrls)
        AND NOT (app.rolsuper OR app.rolcreatedb OR app.rolcreaterole OR app.rolbypassrls)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members
                        WHERE roleid IN (app.oid,owner_role.oid)
                           OR member IN (app.oid,owner_role.oid))
        AND app.oid <> audit.relowner
        AND pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'USAGE')
        AND NOT pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'CREATE')
        AND pg_catalog.has_table_privilege(app.oid, audit.oid, 'SELECT')
        AND pg_catalog.has_table_privilege(app.oid, audit.oid, 'INSERT')
        AND NOT pg_catalog.has_table_privilege(app.oid, audit.oid,
                                   'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        AND NOT pg_catalog.has_any_column_privilege(app.oid, audit.oid, 'UPDATE,REFERENCES')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(audit.relacl,
                                                pg_catalog.acldefault('r',audit.relowner)))
                        WHERE grantee=0)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute
                        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS grant_entry
                        WHERE attribute.attrelid=audit.oid AND grant_entry.grantee=0)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS other_role
                        WHERE other_role.rolcanlogin AND NOT other_role.rolsuper
                          AND other_role.oid<>app.oid
                          AND (pg_catalog.has_table_privilege(other_role.oid, audit.oid,
                              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                               OR pg_catalog.has_any_column_privilege(other_role.oid, audit.oid,
                                                                      'SELECT,INSERT,UPDATE,REFERENCES')))
        AND (SELECT count(*) FROM pg_catalog.pg_proc AS procedure
             WHERE procedure.pronamespace=namespace.oid AND procedure.pronargs=0
               AND procedure.proname IN ('guard_passport_cancellation_history',
                    'guard_administratively_cancelled_passport_job',
                    'passport_cancellation_acl_ready')
               AND procedure.proowner=owner_role.oid AND NOT procedure.prosecdef) = 3
    FROM pg_catalog.pg_class AS audit
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=audit.relnamespace
    JOIN pg_catalog.pg_roles AS app ON app.rolname='marty'
    JOIN pg_catalog.pg_roles AS owner_role ON owner_role.rolname='marty_passport_fence_owner'
    WHERE namespace.nspname='issuance_service'
      AND audit.relname='passport_job_administrative_cancellations'
      AND audit.relkind='r'
),false)
$cancellation_acl_guard$;
