-- Pin the catalog-only readiness predicate without changing its body, owner,
-- security mode, or existing EXECUTE grants. Earlier migrations remain immutable.
ALTER FUNCTION flow_service.physical_start_acl_ready() SET search_path = pg_catalog;

INSERT INTO flow_service.rust_schema_versions(version)
VALUES ('rust_flow_catalog_search_path_0008') ON CONFLICT DO NOTHING;
