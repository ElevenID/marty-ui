// SPDX-License-Identifier: AGPL-3.0-only
//! Registered schema-owner migration and exact catalog validation. This module
//! performs no DDL at runtime; only the protected owner migration installs SQL.
use serde_json::Value;
use sqlx::PgConnection;

pub const JOURNAL_VERSION: &str = "0014_external_observation_authority";
pub const VERSION: &str = "0015_external_observation_runtime_locks";
pub const MIGRATION_SQL: &str =
    include_str!("../migrations/0014_external_observation_authority.sql");
pub const LOCK_MIGRATION_SQL: &str =
    include_str!("../migrations/0015_external_observation_runtime_locks.sql");
pub const MATERIALIZATION_VERSION: &str = "0019_observation_materialization_locks";
pub const MATERIALIZATION_MIGRATION_SQL: &str =
    include_str!("../migrations/0019_observation_materialization_locks.sql");
pub const CATALOG_QUERY: &str = concat!(
    include_str!("../schema/external_observation_catalog_scope.sql"),
    include_str!("../schema/scoped_catalog_query.sql"),
);
const CATALOG: &str = include_str!("../schema/external_observation_catalog.json");
// Registered0017 adds incoming foreign-key triggers to canonical bindings.
// Keep the original owner catalog valid for14/15 databases and pin the exact
// extended catalog when the association owner migration has been installed.
const ASSOCIATION_CATALOG: &str =
    include_str!("../schema/external_observation_with_association_catalog.json");

pub async fn validate(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *connection)
        .await?;
    let ledger: bool = sqlx::query_scalar(
        "SELECT to_regclass('issuance_service.rust_schema_migrations') IS NOT NULL",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !ledger {
        return Err(sqlx::Error::Protocol(
            "Observation schema-owner ledger is missing".into(),
        ));
    }
    for version in [JOURNAL_VERSION, VERSION] {
        let installed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM issuance_service.rust_schema_migrations WHERE version=$1)",
        )
        .bind(version)
        .fetch_one(&mut *connection)
        .await?;
        if !installed {
            return Err(sqlx::Error::Protocol(
                "Registered observation migration is missing".into(),
            ));
        }
    }
    let associations_installed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM issuance_service.rust_schema_migrations WHERE version='0017_external_associations')",
    ).fetch_one(&mut *connection).await?;
    let expected: Value = serde_json::from_str(if associations_installed {
        ASSOCIATION_CATALOG
    } else {
        CATALOG
    })
    .map_err(|_| sqlx::Error::Protocol("Invalid embedded observation schema catalog".into()))?;
    let actual: Value = sqlx::query_scalar(CATALOG_QUERY)
        .fetch_one(connection)
        .await?;
    if actual != expected {
        // Do not log actual function bodies or arbitrary database definitions.
        return Err(sqlx::Error::Protocol(
            "Canonical observation schema catalog differs from registered migration".into(),
        ));
    }
    Ok(())
}

/// A separate closed function family keeps the historical 0014/0015 catalogs
/// unchanged. Fresh owners register 0019, and canonical materialization always
/// qualifies the exact current helper definitions before exposing its routes.
pub async fn validate_materialization_locks(
    connection: &mut PgConnection,
) -> Result<(), sqlx::Error> {
    let invalid = || {
        sqlx::Error::Protocol(
            "Canonical observation row-lock helpers differ from the registered migration".into(),
        )
    };
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *connection)
        .await?;
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM issuance_service.rust_schema_migrations WHERE version=$1)",
    )
    .bind(MATERIALIZATION_VERSION)
    .fetch_one(&mut *connection)
    .await?;
    if !installed {
        return Err(invalid());
    }
    let actual: Value = sqlx::query_scalar(
        "SELECT coalesce(jsonb_agg(jsonb_build_object(
          'name',p.proname,'arguments',pg_get_function_arguments(p.oid),
          'result',pg_get_function_result(p.oid),'language',l.lanname,
          'kind',p.prokind,'volatility',p.provolatile,'strict',p.proisstrict,
          'definer',p.prosecdef,'settings',p.proconfig,'returns_set',p.proretset,
          'body',replace(p.prosrc,E'\\r\\n',E'\\n'),
          'same_owner',(SELECT count(*)=4 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='issuance_service' AND c.relname IN
              ('external_observation_bindings','external_observation_receipts','external_observation_audit','external_observation_heads'))
            AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='issuance_service' AND c.relname IN
              ('external_observation_bindings','external_observation_receipts','external_observation_audit','external_observation_heads')
              AND c.relowner<>p.proowner),
          'public_privileges',EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0))
          ORDER BY p.proname COLLATE \"C\",p.oid::regprocedure::text COLLATE \"C\"),'[]'::jsonb)
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
          WHERE n.nspname='issuance_service' AND p.proname ~ '^materialization_lock_'"
    ).fetch_one(&mut *connection).await?;
    let definitions = [
        ("materialization_lock_binding", "requested_organization uuid, requested_source text, requested_binding text",
         "SETOF issuance_service.external_observation_bindings", "$materialization_binding$"),
        ("materialization_lock_head", "requested_organization text, requested_source text, requested_binding text",
         "SETOF issuance_service.external_observation_heads", "$materialization_head$"),
        ("materialization_lock_journal", "requested_receipt uuid, requested_organization text",
         "TABLE(receipt issuance_service.external_observation_receipts, admission_event text, admission_received_at_ms bigint)", "$materialization_journal$"),
    ];
    let mut expected = Vec::new();
    for (name, arguments, result, delimiter) in definitions {
        let body = MATERIALIZATION_MIGRATION_SQL
            .split(delimiter)
            .nth(1)
            .ok_or_else(invalid)?;
        expected.push(serde_json::json!({
            "name":name,"arguments":arguments,"result":result,"language":"sql",
            "kind":"f","volatility":"v","strict":false,"definer":true,
            "settings":["search_path=pg_catalog"],"returns_set":true,"body":body,
            "same_owner":true,"public_privileges":false,
        }));
    }
    if actual != Value::Array(expected) {
        return Err(invalid());
    }
    Ok(())
}
