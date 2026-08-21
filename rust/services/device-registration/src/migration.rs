use sqlx::{PgPool, Row};

use crate::DeviceError;

pub const REVISION: &str = "20260809_0001";

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
        "device_registration_keys",
        "device_key_transitions",
        "alembic_version",
    ] {
        if !tables.contains(required) {
            return Err(DeviceError::Persistence(format!(
                "Device Registration migrations are required; missing table: {required}"
            )));
        }
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
