use crate::{
    domain::{RevocationProfile, RevocationProfileStatus},
    repository::{ProfileRepository, RepositoryError},
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
