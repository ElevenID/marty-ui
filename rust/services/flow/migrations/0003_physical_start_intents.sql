-- Reserve a stable Flow identity before the native passport side effect.
-- The intent deliberately contains no MRZ, data groups, or other request body.
CREATE TABLE IF NOT EXISTS flow_service.physical_start_intents (
    organization_id varchar(255) NOT NULL,
    key_hash varchar(64) NOT NULL,
    request_hash varchar(64) NOT NULL,
    -- Flow configuration and validated issuer DID only; never holder request input.
    definition_snapshot jsonb NOT NULL,
    initial_actor varchar(255) NOT NULL,
    original_deadline_at timestamptz NOT NULL,
    key_source varchar(16) NOT NULL,
    flow_definition_id varchar(36) NOT NULL,
    instance_id varchar(36) NOT NULL UNIQUE,
    status varchar(16) NOT NULL DEFAULT 'pending',
    claim_token uuid,
    claim_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (organization_id, key_hash),
    CONSTRAINT ck_physical_start_intent_hashes CHECK (
        key_hash ~ '^[0-9a-f]{64}$' AND request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_physical_start_definition_snapshot CHECK (
        jsonb_typeof(definition_snapshot) = 'object'
        AND definition_snapshot ? 'definition'
        AND definition_snapshot ? 'issuer_did'
        AND definition_snapshot - 'definition' - 'issuer_did' = '{}'::jsonb
        AND jsonb_typeof(definition_snapshot->'definition') = 'object'
        AND jsonb_typeof(definition_snapshot->'issuer_did') = 'string'),
    CONSTRAINT ck_physical_start_intent_status CHECK (status IN ('pending','completed')),
    CONSTRAINT ck_physical_start_key_source CHECK (key_source IN ('client','generated')),
    CONSTRAINT ck_physical_start_claim_pair CHECK (
        (claim_token IS NULL) = (claim_expires_at IS NULL))
);

CREATE INDEX IF NOT EXISTS ix_physical_start_intents_pending
    ON flow_service.physical_start_intents (organization_id, created_at)
    WHERE status='pending';

-- The fenced beta operator grants narrow DML after privileged migration.
-- This catalog-only predicate contains no security-definer privilege or data read.
CREATE OR REPLACE FUNCTION flow_service.physical_start_acl_ready()
RETURNS boolean LANGUAGE sql STABLE AS $physical_start_acl_guard$
SELECT COALESCE((
    SELECT
        pg_catalog.pg_get_userbyid(intent.relowner) = owner_role.rolname
        AND NOT (owner_role.rolcanlogin OR owner_role.rolinherit OR owner_role.rolsuper
                 OR owner_role.rolcreatedb OR owner_role.rolcreaterole OR owner_role.rolbypassrls)
        AND NOT (app.rolsuper OR app.rolcreatedb OR app.rolcreaterole OR app.rolbypassrls)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members
                        WHERE roleid IN (app.oid,owner_role.oid)
                           OR member IN (app.oid,owner_role.oid))
        AND app.oid <> intent.relowner
        AND pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'USAGE')
        AND NOT pg_catalog.has_schema_privilege(app.oid, namespace.oid, 'CREATE')
        AND pg_catalog.has_table_privilege(app.oid, intent.oid, 'SELECT')
        AND pg_catalog.has_table_privilege(app.oid, intent.oid, 'INSERT')
        AND NOT pg_catalog.has_table_privilege(app.oid, intent.oid,
                                    'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        AND NOT pg_catalog.has_any_column_privilege(app.oid, intent.oid, 'REFERENCES')
        AND pg_catalog.has_column_privilege(app.oid, intent.oid, 'status', 'UPDATE')
        AND pg_catalog.has_column_privilege(app.oid, intent.oid, 'claim_token', 'UPDATE')
        AND pg_catalog.has_column_privilege(app.oid, intent.oid, 'claim_expires_at', 'UPDATE')
        AND pg_catalog.has_column_privilege(app.oid, intent.oid, 'updated_at', 'UPDATE')
        AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_attribute AS attribute
            WHERE attribute.attrelid=intent.oid AND attribute.attnum>0
              AND NOT attribute.attisdropped
              AND attribute.attname NOT IN
                  ('status','claim_token','claim_expires_at','updated_at')
              AND pg_catalog.has_column_privilege(app.oid, intent.oid,
                                                   attribute.attnum, 'UPDATE'))
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(COALESCE(intent.relacl,
                                                pg_catalog.acldefault('r',intent.relowner)))
                        WHERE grantee=0)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute AS attribute
                        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS grant_entry
                        WHERE attribute.attrelid=intent.oid AND grant_entry.grantee=0)
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles AS other_role
                        WHERE other_role.rolcanlogin AND NOT other_role.rolsuper
                          AND other_role.oid<>app.oid
                          AND (pg_catalog.has_table_privilege(other_role.oid, intent.oid,
                              'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                               OR pg_catalog.has_any_column_privilege(other_role.oid, intent.oid,
                                                                      'SELECT,INSERT,UPDATE,REFERENCES')))
        AND (SELECT count(*) FROM pg_catalog.pg_proc AS procedure
             WHERE procedure.pronamespace=namespace.oid AND procedure.pronargs=0
               AND procedure.proname='physical_start_acl_ready'
               AND procedure.proowner=owner_role.oid AND NOT procedure.prosecdef) = 1
    FROM pg_catalog.pg_class AS intent
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=intent.relnamespace
    JOIN pg_catalog.pg_roles AS app ON app.rolname='marty'
    JOIN pg_catalog.pg_roles AS owner_role ON owner_role.rolname='marty_passport_fence_owner'
    WHERE namespace.nspname='flow_service'
      AND intent.relname='physical_start_intents'
      AND intent.relkind='r'
),false)
$physical_start_acl_guard$;

INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_0002') ON CONFLICT DO NOTHING;
