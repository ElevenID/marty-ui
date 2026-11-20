-- SPDX-License-Identifier: AGPL-3.0-only
-- Read-only qualification of the authenticated LOGIN and every reachable role.
WITH reachable AS (
 SELECT r.* FROM pg_catalog.pg_roles r
 WHERE pg_catalog.pg_has_role(current_user::regrole::oid,r.oid,'MEMBER')
), owned_tables(name) AS (VALUES
 ('issuance_service.external_association_sources'),('issuance_service.external_association_operations'),
 ('issuance_service.external_association_identities'),('issuance_service.external_association_challenges'),
 ('issuance_service.external_association_bindings')
), canonical_tables(name) AS (VALUES
 ('organization_service.organizations'),('organization_service.api_keys'),('organization_service.members'),
 ('organization_service.roles'),('organization_service.member_roles'),('organization_service.role_permissions'),
 ('organization_service.permissions'),('issuance_service.applications'),('issuance_service.application_ownerships'),
 ('issuance_service.application_ownership_operations'),('issuance_service.external_observation_bindings'),
 ('issuance_service.rust_schema_migrations')
), canonical_relations AS (
 SELECT c.oid,c.relowner FROM canonical_tables t
 JOIN pg_catalog.pg_namespace n ON n.nspname=split_part(t.name,'.',1)
 JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid AND c.relname=split_part(t.name,'.',2)
), mutable_columns(table_name,column_name) AS (VALUES
 ('external_association_sources','api_key_id'),('external_association_sources','key_revision'),
 ('external_association_sources','active'),('external_association_sources','revision'),
 ('external_association_sources','expires_at'),('external_association_sources','approved_by'),
 ('external_association_sources','approved_at'),('external_association_sources','updated_at'),
 ('external_association_identities','active'),('external_association_identities','consent_generation'),
 ('external_association_identities','revision'),('external_association_identities','updated_at'),
 ('external_association_challenges','phase'),('external_association_challenges','revision'),
 ('external_association_challenges','updated_at'),('external_association_bindings','binding_revision'),
 ('external_association_bindings','challenge_id'),('external_association_bindings','active'),
 ('external_association_bindings','revision'),('external_association_bindings','updated_at')
), required_functions(name) AS (VALUES
 ('issuance_service.mutate_external_association_source(uuid,text,uuid,uuid,text,bigint,jsonb)'),
 ('issuance_service.read_external_association_source(uuid,text,uuid,uuid)'),
 ('issuance_service.create_external_association_challenge(uuid,uuid,uuid,uuid,uuid,bigint,text,bigint,text,bigint,text,bigint)'),
 ('issuance_service.mutate_external_association_consent(uuid,text,uuid,uuid,text,bigint,text,bigint)'),
 ('issuance_service.read_external_association_challenge(uuid,text,text,uuid,uuid)'),
 ('issuance_service.close_external_association_challenge(uuid,uuid,uuid,uuid,text,bigint)'),
 ('issuance_service.unlink_external_association(uuid,text,uuid,uuid,bigint)'),
 ('issuance_service.read_external_association_unlink_receipt(uuid,text,uuid,uuid)'),
 ('issuance_service.external_association_lock_context(uuid,uuid,uuid,bigint,text,bigint)'),
 ('issuance_service.external_association_lock_administrator(uuid,text)'),
 ('issuance_service.external_observation_lock_organization(uuid)'),
 ('issuance_service.external_observation_lock_api_keys(uuid,uuid[])')
)
SELECT current_user=session_user AND pg_catalog.current_setting('session_replication_role')='origin'
 AND NOT EXISTS(SELECT 1 FROM reachable WHERE left(rolname,3)='pg_' OR rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication)
 AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN pg_catalog.pg_parameter_acl p
  WHERE pg_catalog.has_parameter_privilege(r.oid,p.parname,'SET') OR pg_catalog.has_parameter_privilege(r.oid,p.parname,'ALTER SYSTEM'))
 AND NOT EXISTS(SELECT 1 FROM reachable r WHERE pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
  OR pg_catalog.has_schema_privilege(r.oid,'issuance_service','CREATE') OR pg_catalog.has_schema_privilege(r.oid,'organization_service','CREATE'))
 AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN owned_tables t
  JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(t.name)
  WHERE c.relowner=r.oid OR pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE')
   OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN owned_tables t
  JOIN pg_catalog.pg_class c ON c.oid=pg_catalog.to_regclass(t.name)
  JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
  WHERE pg_catalog.has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE')
   AND NOT EXISTS(SELECT 1 FROM mutable_columns m WHERE m.table_name=c.relname AND m.column_name=a.attname))
 AND (SELECT count(*)=12 FROM canonical_relations)
 AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN canonical_relations c
  WHERE c.relowner=r.oid OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'INSERT')
   OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'UPDATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE')
   OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE') OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRIGGER'))
 AND NOT EXISTS(SELECT 1 FROM reachable r JOIN pg_catalog.pg_proc p ON p.proowner=r.oid
  JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='issuance_service'
   AND (p.proname ~ '(external_association|application_ownership)' OR p.proname IN
    ('external_observation_lock_organization','external_observation_lock_api_keys','external_observation_lock_application','bump_external_observation_revision')))
 AND (SELECT bool_and(pg_catalog.has_table_privilege(current_user,t.name,'SELECT')
  AND pg_catalog.has_table_privilege(current_user,t.name,'INSERT')) FROM owned_tables t)
 AND (SELECT bool_and(pg_catalog.has_column_privilege(current_user,
  pg_catalog.to_regclass('issuance_service.'||m.table_name),m.column_name,'UPDATE')) FROM mutable_columns m)
 AND (SELECT count(*)=12 AND bool_and(p.oid IS NOT NULL AND pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE'))
  FROM required_functions f LEFT JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(f.name));
