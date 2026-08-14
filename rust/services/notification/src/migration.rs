use crate::webhook::WebhookSecretEnvelope;
use sqlx::{PgPool, Row};
use thiserror::Error;

const HEAD: &str = "20260808_0002";

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("notification migration storage failure: {0}")]
    Database(#[from] sqlx::Error),
    #[error("legacy webhook secrets require available OpenBao protection: {0}")]
    Envelope(String),
    #[error("notification schema is incompatible: {0}")]
    Incompatible(String),
}

pub async fn migrate(
    pool: &PgPool,
    envelope: &WebhookSecretEnvelope,
) -> Result<(), MigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(718431207)")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("CREATE SCHEMA IF NOT EXISTS notification_service")
        .execute(&mut *transaction)
        .await?;
    let endpoint_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('notification_service.webhook_endpoints') IS NOT NULL",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if endpoint_exists {
        let columns = sqlx::query("SELECT column_name FROM information_schema.columns WHERE table_schema='notification_service' AND table_name='webhook_endpoints'")
            .fetch_all(&mut *transaction).await?.into_iter().map(|row| row.get::<String, _>("column_name")).collect::<Vec<_>>();
        if columns.iter().any(|value| value == "secret") {
            sqlx::query("ALTER TABLE notification_service.webhook_endpoints ADD COLUMN IF NOT EXISTS secret_envelope text, ADD COLUMN IF NOT EXISTS secret_hint varchar(8)").execute(&mut *transaction).await?;
            let rows = sqlx::query("SELECT id, organization_id, secret FROM notification_service.webhook_endpoints WHERE secret_envelope IS NULL").fetch_all(&mut *transaction).await?;
            for row in rows {
                let id: String = row.try_get("id")?;
                let organization_id: String = row.try_get("organization_id")?;
                let secret: String = row.try_get("secret")?;
                let ciphertext = envelope
                    .wrap(&organization_id, &id, &secret)
                    .await
                    .map_err(|error| MigrationError::Envelope(error.to_string()))?;
                sqlx::query("UPDATE notification_service.webhook_endpoints SET secret_envelope=$1, secret_hint=$2 WHERE id=$3")
                    .bind(ciphertext).bind(secret.chars().take(4).collect::<String>()).bind(id).execute(&mut *transaction).await?;
            }
            sqlx::query("ALTER TABLE notification_service.webhook_endpoints ALTER COLUMN secret_envelope SET NOT NULL, ALTER COLUMN secret_hint SET NOT NULL, DROP COLUMN secret")
                .execute(&mut *transaction).await?;
        }
    }
    sqlx::raw_sql(include_str!("../migrations/0001_notification_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate(pool: &PgPool) -> Result<(), MigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

async fn validate_connection(connection: &mut sqlx::PgConnection) -> Result<(), MigrationError> {
    let version: Option<String> =
        sqlx::query_scalar("SELECT version_num FROM notification_service.alembic_version LIMIT 1")
            .fetch_optional(&mut *connection)
            .await?;
    if version.as_deref() != Some(HEAD) {
        return Err(MigrationError::Incompatible(
            "migration head is missing".into(),
        ));
    }
    let forbidden: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='notification_service' AND ((table_name='webhook_endpoints' AND column_name='secret') OR (table_name='webhook_deliveries' AND column_name='response_body'))")
        .fetch_one(&mut *connection).await?;
    if forbidden != 0 {
        return Err(MigrationError::Incompatible(
            "plaintext secret or receiver-body storage remains".into(),
        ));
    }
    let protected: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='notification_service' AND table_name='webhook_endpoints' AND column_name IN ('secret_envelope','secret_hint')")
        .fetch_one(&mut *connection).await?;
    if protected != 2 {
        return Err(MigrationError::Incompatible(
            "protected webhook secret columns are missing".into(),
        ));
    }
    let checks: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_constraint WHERE conrelid='notification_service.webhook_endpoints'::regclass AND conname IN ('ck_webhook_endpoints_secret_envelope','ck_webhook_endpoints_secret_hint')")
        .fetch_one(&mut *connection).await?;
    if checks != 2 {
        return Err(MigrationError::Incompatible(
            "webhook secret storage constraints are missing".into(),
        ));
    }
    Ok(())
}
