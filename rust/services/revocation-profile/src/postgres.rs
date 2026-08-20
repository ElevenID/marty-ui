use crate::{
    domain::{RevocationProfile, RevocationProfileStatus},
    repository::{ProfileRepository, RepositoryError, StatusIndexReservation},
    status::StatusListFormat,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[derive(Debug, Clone)]
pub struct PgProfileRepository {
    pool: PgPool,
}

impl PgProfileRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, RepositoryError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(repository_error)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl ProfileRepository for PgProfileRepository {
    async fn save(&self, profile: RevocationProfile) -> Result<(), RepositoryError> {
        let issuer_config =
            serde_json::to_value(&profile.issuer_config).map_err(repository_error)?;
        let verifier_config =
            serde_json::to_value(&profile.verifier_config).map_err(repository_error)?;
        let automation_config =
            serde_json::to_value(&profile.automation_config).map_err(repository_error)?;
        let supported_formats =
            serde_json::to_value(&profile.supported_formats).map_err(repository_error)?;

        sqlx::query(
            r#"
            INSERT INTO revocation_profile_service.revocation_profiles (
                id, organization_id, name, status, issuer_config, verifier_config,
                automation_config, supported_formats, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                name = EXCLUDED.name,
                status = EXCLUDED.status,
                issuer_config = EXCLUDED.issuer_config,
                verifier_config = EXCLUDED.verifier_config,
                automation_config = EXCLUDED.automation_config,
                supported_formats = EXCLUDED.supported_formats,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&profile.id)
        .bind(&profile.organization_id)
        .bind(&profile.name)
        .bind(profile.status.as_str())
        .bind(issuer_config)
        .bind(verifier_config)
        .bind(automation_config)
        .bind(supported_formats)
        .bind(profile.created_at)
        .bind(profile.updated_at)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }

    async fn get(&self, profile_id: &str) -> Result<Option<RevocationProfile>, RepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, name, status, issuer_config, verifier_config,
                   automation_config, supported_formats, created_at, updated_at
            FROM revocation_profile_service.revocation_profiles
            WHERE id = $1
            "#,
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)?;
        row.map(row_to_profile).transpose()
    }

    async fn list(&self, organization_id: &str) -> Result<Vec<RevocationProfile>, RepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, name, status, issuer_config, verifier_config,
                   automation_config, supported_formats, created_at, updated_at
            FROM revocation_profile_service.revocation_profiles
            WHERE organization_id = $1
            ORDER BY created_at ASC, id ASC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await
        .map_err(repository_error)?;
        rows.into_iter().map(row_to_profile).collect()
    }

    async fn delete(&self, profile_id: &str) -> Result<bool, RepositoryError> {
        let result =
            sqlx::query("DELETE FROM revocation_profile_service.revocation_profiles WHERE id = $1")
                .bind(profile_id)
                .execute(&self.pool)
                .await
                .map_err(repository_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn reserve_status_index(
        &self,
        reservation: StatusIndexReservation,
    ) -> Result<usize, RepositoryError> {
        let format = persisted_status_format(reservation.format);
        let size = i64::try_from(reservation.size).map_err(repository_error)?;
        let legacy_floor = i64::try_from(reservation.legacy_floor).map_err(repository_error)?;
        let mut transaction = self.pool.begin().await.map_err(repository_error)?;

        // The credential lock prevents the same globally stable credential ID
        // from racing across different tenant/profile scopes. The profile row
        // lock serializes distinct credentials within one status-list scope.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&reservation.credential_id)
            .execute(&mut *transaction)
            .await
            .map_err(repository_error)?;

        if let Some(row) = sqlx::query(
            r#"
            SELECT organization_id, profile_id, status_list_format, status_list_index
            FROM revocation_profile_service.status_list_allocations
            WHERE credential_id = $1
            "#,
        )
        .bind(&reservation.credential_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?
        {
            let organization_id: String =
                row.try_get("organization_id").map_err(repository_error)?;
            let profile_id: String = row.try_get("profile_id").map_err(repository_error)?;
            let persisted_format: String = row
                .try_get("status_list_format")
                .map_err(repository_error)?;
            if organization_id != reservation.organization_id
                || profile_id != reservation.profile_id
                || persisted_format != format
            {
                return Err(RepositoryError::AllocationScopeConflict {
                    credential_id: reservation.credential_id,
                });
            }
            let index: i64 = row.try_get("status_list_index").map_err(repository_error)?;
            transaction.commit().await.map_err(repository_error)?;
            return usize::try_from(index).map_err(repository_error);
        }

        let profile_exists = sqlx::query_scalar::<_, String>(
            r#"
            SELECT id
            FROM revocation_profile_service.revocation_profiles
            WHERE id = $1 AND organization_id = $2
            FOR UPDATE
            "#,
        )
        .bind(&reservation.profile_id)
        .bind(&reservation.organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if profile_exists.is_none() {
            return Err(RepositoryError::AllocationScopeConflict {
                credential_id: reservation.credential_id,
            });
        }

        sqlx::query(
            r#"
            INSERT INTO revocation_profile_service.status_list_allocation_counters (
                organization_id, profile_id, status_list_format, next_index
            ) VALUES ($1, $2, $3, $4)
            ON CONFLICT (organization_id, profile_id, status_list_format)
            DO UPDATE SET next_index = GREATEST(
                revocation_profile_service.status_list_allocation_counters.next_index,
                EXCLUDED.next_index
            )
            "#,
        )
        .bind(&reservation.organization_id)
        .bind(&reservation.profile_id)
        .bind(format)
        .bind(legacy_floor)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;

        let index = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT next_index
            FROM revocation_profile_service.status_list_allocation_counters
            WHERE organization_id = $1 AND profile_id = $2 AND status_list_format = $3
            FOR UPDATE
            "#,
        )
        .bind(&reservation.organization_id)
        .bind(&reservation.profile_id)
        .bind(format)
        .fetch_one(&mut *transaction)
        .await
        .map_err(repository_error)?;
        if index >= size {
            return Err(RepositoryError::AllocationFull(format!(
                "{}:{}",
                reservation.organization_id, reservation.profile_id
            )));
        }

        sqlx::query(
            r#"
            INSERT INTO revocation_profile_service.status_list_allocations (
                credential_id, organization_id, profile_id, status_list_format,
                status_list_index, created_at
            ) VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind(&reservation.credential_id)
        .bind(&reservation.organization_id)
        .bind(&reservation.profile_id)
        .bind(format)
        .bind(index)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        sqlx::query(
            r#"
            UPDATE revocation_profile_service.status_list_allocation_counters
            SET next_index = $4
            WHERE organization_id = $1 AND profile_id = $2 AND status_list_format = $3
            "#,
        )
        .bind(&reservation.organization_id)
        .bind(&reservation.profile_id)
        .bind(format)
        .bind(index + 1)
        .execute(&mut *transaction)
        .await
        .map_err(repository_error)?;
        transaction.commit().await.map_err(repository_error)?;
        usize::try_from(index).map_err(repository_error)
    }
}

fn persisted_status_format(format: StatusListFormat) -> &'static str {
    match format {
        StatusListFormat::Bitstring => "bitstring",
        StatusListFormat::TokenStatusList => "token_status_list",
    }
}

fn row_to_profile(row: sqlx::postgres::PgRow) -> Result<RevocationProfile, RepositoryError> {
    let status: String = row.try_get("status").map_err(repository_error)?;
    Ok(RevocationProfile {
        id: row.try_get("id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        name: row.try_get("name").map_err(repository_error)?,
        // The released schema does not persist descriptions. Preserve the existing
        // Python adapter's read behavior until a versioned schema change is approved.
        description: None,
        status: parse_status(&status)?,
        issuer_config: parse_json(row.try_get("issuer_config").map_err(repository_error)?)?,
        verifier_config: parse_json(row.try_get("verifier_config").map_err(repository_error)?)?,
        automation_config: parse_json(row.try_get("automation_config").map_err(repository_error)?)?,
        supported_formats: parse_json(row.try_get("supported_formats").map_err(repository_error)?)?,
        created_at: row
            .try_get::<DateTime<Utc>, _>("created_at")
            .map_err(repository_error)?,
        updated_at: row
            .try_get::<DateTime<Utc>, _>("updated_at")
            .map_err(repository_error)?,
    })
}

fn parse_status(value: &str) -> Result<RevocationProfileStatus, RepositoryError> {
    match value {
        "draft" => Ok(RevocationProfileStatus::Draft),
        "active" => Ok(RevocationProfileStatus::Active),
        "suspended" => Ok(RevocationProfileStatus::Suspended),
        _ => Err(RepositoryError::Operation(format!(
            "unknown persisted revocation profile status: {value}"
        ))),
    }
}

fn parse_json<T: DeserializeOwned>(value: Value) -> Result<T, RepositoryError> {
    serde_json::from_value(value).map_err(repository_error)
}

fn repository_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::Operation(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        CredentialFormat, IssuerRevocationConfig, RevocationAutomationConfig,
        VerifierRevocationConfig,
    };

    #[test]
    fn persisted_status_values_fail_closed() {
        assert_eq!(
            parse_status("draft").unwrap(),
            RevocationProfileStatus::Draft
        );
        assert!(parse_status("enabled").is_err());
    }

    #[test]
    fn released_json_shapes_roundtrip() {
        let issuer = serde_json::to_value(IssuerRevocationConfig::default()).unwrap();
        let verifier = serde_json::to_value(VerifierRevocationConfig::default()).unwrap();
        let automation = serde_json::to_value(RevocationAutomationConfig::default()).unwrap();
        let formats = serde_json::to_value([
            CredentialFormat::SdJwtVc,
            CredentialFormat::Mdoc,
            CredentialFormat::VcJwt,
        ])
        .unwrap();
        assert_eq!(
            parse_json::<IssuerRevocationConfig>(issuer).unwrap(),
            IssuerRevocationConfig::default()
        );
        assert_eq!(
            parse_json::<VerifierRevocationConfig>(verifier).unwrap(),
            VerifierRevocationConfig::default()
        );
        assert_eq!(
            parse_json::<RevocationAutomationConfig>(automation).unwrap(),
            RevocationAutomationConfig::default()
        );
        assert_eq!(
            parse_json::<Vec<CredentialFormat>>(formats).unwrap().len(),
            3
        );
    }
}
