// SPDX-License-Identifier: AGPL-3.0-only
//! Registered schema-owner migration and exact catalog validation. This module
//! performs no DDL at runtime; only the protected owner migration installs SQL.
use serde_json::Value;
use sqlx::PgConnection;

pub const VERSION: &str = "0014_external_observation_authority";
pub const MIGRATION_SQL: &str =
    include_str!("../migrations/0014_external_observation_authority.sql");
pub const CATALOG_QUERY: &str = include_str!("../schema/external_observation_catalog_query.sql");
const CATALOG: &str = include_str!("../schema/external_observation_catalog.json");

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
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM issuance_service.rust_schema_migrations WHERE version=$1)",
    )
    .bind(VERSION)
    .fetch_one(&mut *connection)
    .await?;
    if !installed {
        return Err(sqlx::Error::Protocol(
            "Registered observation migration is missing".into(),
        ));
    }
    let expected: Value = serde_json::from_str(CATALOG)
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
