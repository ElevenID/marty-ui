-- Read-only metadata projection adapted from the reviewed four-role observer.
-- No domain rows, fence installation or readiness decisions are performed here.
BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT json_build_object(
    'schema','marty.native-maintenance-catalog/v1',
    'control',json_build_object('database',current_database(),'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),'systemIdentifier',(SELECT system_identifier::text FROM pg_control_system()),'roles',(SELECT json_agg(json_build_object('name',rolname,'canLogin',rolcanlogin,'superuser',rolsuper) ORDER BY rolname) FROM pg_roles WHERE rolname IN ('marty','marty_beta_migrator','marty_passport_fence_owner')),'activeMartyConnections',(SELECT count(*) FROM pg_stat_activity WHERE usename='marty'),'activeMigratorConnections',(SELECT count(*) FROM pg_stat_activity WHERE usename='marty_beta_migrator'),'fenceTable',to_regclass('passport_cutover.state')::text),
    'ledgerTables',json_build_object('issuance',to_regclass('issuance_service.rust_schema_migrations')::text,'flow',to_regclass('flow_service.rust_schema_versions')::text),
    'relations',(SELECT coalesce(json_agg(json_build_object('schema',n.nspname,'name',c.relname,'kind',c.relkind,'owner',pg_get_userbyid(c.relowner)) ORDER BY n.nspname,c.relname),'[]'::json) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='flow_service' AND c.relname IN ('physical_start_intents','flow_definitions','flow_instances','rust_schema_versions')) OR (n.nspname='issuance_service' AND c.relname IN ('physical_document_jobs','passport_beta_batch_intents','passport_job_administrative_cancellations','rust_schema_migrations')) OR (n.nspname='passport_cutover' AND c.relname IN ('state','native_migration_receipt'))),
    'aclTables',json_build_object('flowIntent',to_regclass('flow_service.physical_start_intents')::text,'cancellationHistory',to_regclass('issuance_service.passport_job_administrative_cancellations')::text),
    'acl',json_build_object('appIssuanceCreate',has_schema_privilege('marty','issuance_service','CREATE'),'appFlowCreate',has_schema_privilege('marty','flow_service','CREATE')),
    'ledgers',json_build_object('issuance',(SELECT coalesce(json_agg(version ORDER BY version),'[]'::json) FROM issuance_service.rust_schema_migrations),'flow',(SELECT coalesce(json_agg(version ORDER BY version),'[]'::json) FROM flow_service.rust_schema_versions))
);
COMMIT;
