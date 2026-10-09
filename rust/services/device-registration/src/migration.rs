use sqlx::{PgPool, Row};

use crate::DeviceError;

pub const REVISION: &str = "20261009_0001";

pub async fn migrate(pool: &PgPool) -> Result<(), DeviceError> {
    let mut transaction = pool.begin().await.map_err(persistence)?;
    sqlx::query("SELECT pg_advisory_xact_lock(801420260809)")
        .execute(&mut *transaction)
        .await
        .map_err(persistence)?;
    sqlx::raw_sql(include_str!("../migrations/0001_device_registration.sql"))
        .execute(&mut *transaction)
        .await
        .map_err(persistence)?;
    verify(&mut transaction).await?;
    transaction.commit().await.map_err(persistence)?;
    Ok(())
}

async fn verify(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), DeviceError> {
    let rows = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_schema='device_registration_service'")
        .fetch_all(&mut **transaction).await.map_err(persistence)?;
    let tables: std::collections::BTreeSet<String> = rows
        .into_iter()
        .filter_map(|row| row.try_get("table_name").ok())
        .collect();
    for required in [
        "device_registrations",
        "device_holder_credentials",
        "device_holder_keys",
        "device_holder_key_provisions",
        "device_holder_key_deletions",
        "alembic_version",
    ] {
        if !tables.contains(required) {
            return Err(DeviceError::Persistence(format!(
                "Device Registration migrations are required; missing table: {required}"
            )));
        }
    }
    for retired in ["device_registration_keys", "device_key_transitions"] {
        if tables.contains(retired) {
            return Err(DeviceError::Persistence(format!(
                "fresh KMS-only Device Registration schema required; retired table: {retired}"
            )));
        }
    }
    let retired_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='device_registration_service' AND table_name='device_registrations' AND column_name IN ('public_key_der','public_key_kid','key_valid_from','key_valid_until','key_version')",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(persistence)?;
    if !retired_columns.is_empty() {
        return Err(DeviceError::Persistence(
            "fresh KMS-only Device Registration schema required; retired device-key columns remain"
                .into(),
        ));
    }
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version_num FROM device_registration_service.alembic_version WHERE version_num=$1",
    )
    .bind(REVISION)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(persistence)?;
    if version.as_deref() != Some(REVISION) {
        return Err(DeviceError::Persistence(
            "Device Registration migration version is missing".into(),
        ));
    }
    Ok(())
}

fn persistence(error: sqlx::Error) -> DeviceError {
    DeviceError::Persistence(error.to_string())
}
