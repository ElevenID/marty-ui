// SPDX-License-Identifier: AGPL-3.0-only
//! Exact protected-owner catalog handoff; no runtime DDL or grant installation.
use serde_json::Value;
use sqlx::PgConnection;

pub const VERSION: &str = "0016_application_ownership";
pub const CATALOG_QUERY: &str = concat!(
    include_str!("../schema/application_ownership_catalog_scope.sql"),
    include_str!("../schema/scoped_catalog_query.sql"),
);
const CATALOG: &str = include_str!("../schema/application_ownership_catalog.json");

pub async fn validate(connection: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SET LOCAL search_path=pg_catalog")
        .execute(&mut *connection)
        .await?;
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM issuance_service.rust_schema_migrations WHERE version=$1)",
    )
    .bind(VERSION)
    .fetch_one(&mut *connection)
    .await?;
    if !installed {
        return Err(sqlx::Error::Protocol(
            "Application ownership owner migration missing".into(),
        ));
    }
    let expected: Value = serde_json::from_str(CATALOG)
        .map_err(|_| sqlx::Error::Protocol("Invalid application ownership catalog".into()))?;
    let actual: Value = sqlx::query_scalar(CATALOG_QUERY)
        .fetch_one(connection)
        .await?;
    if actual != expected {
        return Err(sqlx::Error::Protocol(
            "Application ownership schema differs from protected owner".into(),
        ));
    }
    Ok(())
}
