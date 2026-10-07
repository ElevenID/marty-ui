//! Offline, resumable migration of legacy integration-secret ciphertext.
//!
//! Build explicitly with `--features integration-secret-migration --bin
//! marty-integration-secret-migrate`. This binary is excluded from service images.
//! Stop issuance and Canvas workers and snapshot the database before `migrate`.

use std::{env, fs, process::ExitCode};

use marty_issuance_service::{
    integration_secret::IntegrationSecretCipher, integration_secret_kms::KmsIntegrationSecretCipher,
};
use serde_json::Value;
use sqlx::{Connection, PgConnection, Row};
use thiserror::Error;
use zeroize::Zeroizing;

const PAGE_SIZE: i64 = 100;
const ENVELOPE_SCHEMA: &str = "marty.integration-secret-envelope/v1";

#[derive(Debug, Error)]
enum MigrationError {
    #[error("usage: marty-integration-secret-migrate audit|migrate")]
    Usage,
    #[error("migration configuration is incomplete or invalid")]
    Configuration,
    #[error("migration database is unavailable or its schema is invalid")]
    Database,
    #[error("another integration-secret migration is running")]
    ConcurrentMigration,
    #[error("a legacy integration-secret ciphertext cannot be authenticated")]
    LegacyCiphertext,
    #[error("remote integration-secret envelope cannot be verified")]
    RemoteEnvelope,
    #[error("integration-secret row changed during migration")]
    ConcurrentWrite,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Audit,
    Migrate,
}

struct SecretRow {
    id: String,
    organization_id: String,
    provider: String,
    purpose: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() -> Result<ExitCode, MigrationError> {
    let operation = match env::args().nth(1).as_deref() {
        Some("audit") if env::args().len() == 2 => Operation::Audit,
        Some("migrate") if env::args().len() == 2 => Operation::Migrate,
        _ => return Err(MigrationError::Usage),
    };
    let database_url =
        Zeroizing::new(env::var("DATABASE_URL").map_err(|_| MigrationError::Configuration)?);
    let base_url = env::var("SIGNING_KEYS_INTERNAL_URL")
        .map_err(|_| MigrationError::Configuration)?
        .parse()
        .map_err(|_| MigrationError::Configuration)?;
    let api_key = Zeroizing::new(secret_value("SIGNING_KEYS_INTERNAL_API_KEY")?);
    let remote = KmsIntegrationSecretCipher::new(base_url, &api_key)
        .map_err(|_| MigrationError::Configuration)?;
    let legacy_key = if operation == Operation::Migrate {
        Some(Zeroizing::new(secret_value(
            "INTEGRATION_SECRET_MASTER_KEY",
        )?))
    } else {
        None
    };
    let legacy = legacy_key
        .as_deref()
        .map(|key| IntegrationSecretCipher::from_base64(key))
        .transpose()
        .map_err(|_| MigrationError::Configuration)?;
    let mut database = PgConnection::connect(&database_url)
        .await
        .map_err(|_| MigrationError::Database)?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(93017, 4)")
        .fetch_one(&mut database)
        .await
        .map_err(|_| MigrationError::Database)?;
    if !locked {
        return Err(MigrationError::ConcurrentMigration);
    }

    let mut cursor: Option<String> = None;
    let mut migrated = 0_u64;
    let mut verified = 0_u64;
    loop {
        let rows = page(&mut database, cursor.as_deref()).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = Some(row.id.clone());
            if is_remote_envelope(&row.ciphertext) {
                verify(&remote, &row, &row.ciphertext).await?;
                verified += 1;
                continue;
            }
            let cipher = legacy.as_ref().ok_or(MigrationError::LegacyCiphertext)?;
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(&row.ciphertext)
                    .map_err(|_| MigrationError::LegacyCiphertext)?,
            );
            let envelope = remote
                .encrypt(
                    &row.organization_id,
                    &row.id,
                    &row.provider,
                    &row.purpose,
                    &plaintext,
                )
                .await
                .map_err(|_| MigrationError::RemoteEnvelope)?;
            let recovered = Zeroizing::new(
                remote
                    .decrypt(
                        &row.organization_id,
                        &row.id,
                        &row.provider,
                        &row.purpose,
                        &envelope,
                    )
                    .await
                    .map_err(|_| MigrationError::RemoteEnvelope)?,
            );
            let matches = recovered.as_str() == plaintext.as_str();
            if !matches {
                return Err(MigrationError::RemoteEnvelope);
            }
            let changed = sqlx::query(
                "UPDATE issuance_service.organization_integration_secrets
                 SET encrypted_secret_value = $1
                 WHERE id = $2 AND organization_id = $3 AND provider = $4
                   AND purpose = $5 AND encrypted_secret_value = $6",
            )
            .bind(&envelope)
            .bind(&row.id)
            .bind(&row.organization_id)
            .bind(&row.provider)
            .bind(&row.purpose)
            .bind(&row.ciphertext)
            .execute(&mut database)
            .await
            .map_err(|_| MigrationError::Database)?;
            if changed.rows_affected() != 1 {
                return Err(MigrationError::ConcurrentWrite);
            }
            migrated += 1;
        }
    }
    // Audit every row again after changes, including rows already migrated by
    // a previous run. No plaintext or row identifier is written to stdout.
    if operation == Operation::Migrate {
        verified = audit_all(&mut database, &remote).await?;
    }
    println!("integration-secret migration: migrated={migrated} verified={verified}");
    Ok(ExitCode::SUCCESS)
}

fn secret_value(name: &str) -> Result<String, MigrationError> {
    let value = match env::var(format!("{name}_FILE")) {
        Ok(path) => fs::read_to_string(path).map_err(|_| MigrationError::Configuration)?,
        Err(_) => env::var(name).map_err(|_| MigrationError::Configuration)?,
    };
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(MigrationError::Configuration);
    }
    Ok(value)
}

async fn page(
    database: &mut PgConnection,
    cursor: Option<&str>,
) -> Result<Vec<SecretRow>, MigrationError> {
    let rows = sqlx::query(
        "SELECT id, organization_id, provider, purpose, encrypted_secret_value
         FROM issuance_service.organization_integration_secrets
         WHERE ($1::text IS NULL OR id > $1)
         ORDER BY id LIMIT $2",
    )
    .bind(cursor)
    .bind(PAGE_SIZE)
    .fetch_all(database)
    .await
    .map_err(|_| MigrationError::Database)?;
    rows.into_iter()
        .map(|row| {
            Ok(SecretRow {
                id: row.try_get("id").map_err(|_| MigrationError::Database)?,
                organization_id: row
                    .try_get("organization_id")
                    .map_err(|_| MigrationError::Database)?,
                provider: row
                    .try_get("provider")
                    .map_err(|_| MigrationError::Database)?,
                purpose: row
                    .try_get("purpose")
                    .map_err(|_| MigrationError::Database)?,
                ciphertext: row
                    .try_get("encrypted_secret_value")
                    .map_err(|_| MigrationError::Database)?,
            })
        })
        .collect()
}

fn is_remote_envelope(ciphertext: &str) -> bool {
    serde_json::from_str::<Value>(ciphertext)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|schema| schema == ENVELOPE_SCHEMA)
}

async fn verify(
    remote: &KmsIntegrationSecretCipher,
    row: &SecretRow,
    ciphertext: &str,
) -> Result<(), MigrationError> {
    let _plaintext = Zeroizing::new(
        remote
            .decrypt(
                &row.organization_id,
                &row.id,
                &row.provider,
                &row.purpose,
                ciphertext,
            )
            .await
            .map_err(|_| MigrationError::RemoteEnvelope)?,
    );
    Ok(())
}

async fn audit_all(
    database: &mut PgConnection,
    remote: &KmsIntegrationSecretCipher,
) -> Result<u64, MigrationError> {
    let mut cursor: Option<String> = None;
    let mut verified = 0_u64;
    loop {
        let rows = page(database, cursor.as_deref()).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor = Some(row.id.clone());
            if !is_remote_envelope(&row.ciphertext) {
                return Err(MigrationError::LegacyCiphertext);
            }
            verify(remote, &row, &row.ciphertext).await?;
            verified += 1;
        }
    }
    Ok(verified)
}
