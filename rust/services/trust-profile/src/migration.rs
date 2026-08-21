use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::{sanitize_private_custody_metadata, TRUST_PROFILE_MIGRATION};

const MIGRATION_VERSION: &str = "trust-profile-rust-v1";
const ADVISORY_LOCK_ID: i64 = 800_420_260_821;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustProfileMigrationSummary {
    pub metadata_rows_sanitized: u64,
    pub verification_key_rows_sanitized: u64,
}

#[derive(Debug, Error)]
pub enum TrustProfileMigrationError {
    #[error("TRUST_PROFILE.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("TRUST_PROFILE.MIGRATION_INVALID_JSON: {0}")]
    InvalidJson(&'static str),
}

pub async fn run_migrations(
    pool: &PgPool,
) -> Result<TrustProfileMigrationSummary, TrustProfileMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(TRUST_PROFILE_MIGRATION)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "ALTER TABLE trust_profile_service.trust_profiles
         ADD COLUMN IF NOT EXISTS revocation_profile_id TEXT",
    )
    .execute(&mut *transaction)
    .await?;

    let mut summary = TrustProfileMigrationSummary::default();
    for (select, update, field) in [
        (
            "SELECT id,metadata FROM trust_profile_service.organization_trust_profiles WHERE metadata IS NOT NULL",
            "UPDATE trust_profile_service.organization_trust_profiles SET metadata=$1,updated_at=now() WHERE id=$2",
            "organization_trust_profiles.metadata",
        ),
        (
            "SELECT id,metadata FROM trust_profile_service.issuer_entities WHERE metadata IS NOT NULL",
            "UPDATE trust_profile_service.issuer_entities SET metadata=$1,updated_at=now() WHERE id=$2",
            "issuer_entities.metadata",
        ),
        (
            "SELECT id,metadata FROM trust_profile_service.trust_profile_issuers WHERE metadata IS NOT NULL",
            "UPDATE trust_profile_service.trust_profile_issuers SET metadata=$1,updated_at=now() WHERE id=$2",
            "trust_profile_issuers.metadata",
        ),
        (
            "SELECT id,metadata FROM trust_profile_service.trust_registry_sources WHERE metadata IS NOT NULL",
            "UPDATE trust_profile_service.trust_registry_sources SET metadata=$1,updated_at=now() WHERE id=$2",
            "trust_registry_sources.metadata",
        ),
        (
            "SELECT id,validation_rules AS metadata FROM trust_profile_service.trust_profiles WHERE validation_rules IS NOT NULL",
            "UPDATE trust_profile_service.trust_profiles SET validation_rules=$1,updated_at=now() WHERE id=$2",
            "trust_profiles.validation_rules",
        ),
    ] {
        summary.metadata_rows_sanitized +=
            sanitize_json_column(&mut transaction, select, update, field).await?;
    }
    summary.verification_key_rows_sanitized += sanitize_json_column(
        &mut transaction,
        "SELECT id,verification_keys AS metadata FROM trust_profile_service.trust_registry_issuers WHERE verification_keys IS NOT NULL",
        "UPDATE trust_profile_service.trust_registry_issuers SET verification_keys=$1,updated_at=now() WHERE id=$2",
        "trust_registry_issuers.verification_keys",
    )
    .await?;

    sqlx::query(
        "INSERT INTO trust_profile_service.native_migrations(version)
         VALUES($1) ON CONFLICT(version) DO NOTHING",
    )
    .bind(MIGRATION_VERSION)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(summary)
}

async fn sanitize_json_column(
    transaction: &mut Transaction<'_, Postgres>,
    select: &'static str,
    update: &'static str,
    field: &'static str,
) -> Result<u64, TrustProfileMigrationError> {
    let rows = sqlx::query(select).fetch_all(&mut **transaction).await?;
    let mut changed = 0;
    for row in rows {
        let id: String = row.try_get("id")?;
        let value: Value = row
            .try_get("metadata")
            .map_err(|_| TrustProfileMigrationError::InvalidJson(field))?;
        let sanitized = sanitize_private_custody_metadata(&value);
        if sanitized != value {
            sqlx::query(update)
                .bind(sanitized)
                .bind(id)
                .execute(&mut **transaction)
                .await?;
            changed += 1;
        }
    }
    Ok(changed)
}
