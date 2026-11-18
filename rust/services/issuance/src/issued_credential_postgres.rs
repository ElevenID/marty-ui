use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::issued_credential_records::{
    IssuedCredentialProjectionSource, IssuedCredentialRecordRepository,
    IssuedCredentialRepositoryError, IssuedCredentialTransactionProjection,
};

macro_rules! projection_sql {
    ($predicate:literal) => {
        concat!(
            r#"
SELECT c.id, c.transaction_id, c.organization_id, c.credential_template_id,
       c.applicant_id, c.subject_did, c.issuer_did, c.revocation_profile_id,
       c.renewed_from_credential_id, c.renewed_to_credential_id,
       c.status_list_entries, c.credential_hash, c.status, c.status_updated_at,
       c.revoked_at, c.revocation_reason, c.issued_at, c.expires_at,
       t.id AS joined_transaction_id, t.applicant_id AS transaction_applicant_id,
       t.application_id, t.subject_did AS transaction_subject_did,
       t.issuer_did_override, t.claims, t.credential_type,
       t.credential_payload_format, t.renewable, t.renewal_window_days
FROM issuance_service.issued_credentials c
LEFT JOIN issuance_service.issuance_transactions t ON t.id = c.transaction_id
"#,
            $predicate
        )
    };
}

const GET_PROJECTION: &str = projection_sql!(" WHERE c.id = $1");
const LIST_PROJECTION: &str = projection_sql!(" WHERE c.organization_id = $1");

#[derive(Clone, Debug)]
pub struct PostgresIssuedCredentialRecordRepository {
    pool: PgPool,
}

impl PostgresIssuedCredentialRecordRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IssuedCredentialRecordRepository for PostgresIssuedCredentialRecordRepository {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        sqlx::query(GET_PROJECTION)
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(|row| projection(&row))
            .transpose()
    }

    async fn list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        sqlx::query(LIST_PROJECTION)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .iter()
            .map(projection)
            .collect()
    }
}

fn projection(
    row: &sqlx::postgres::PgRow,
) -> Result<IssuedCredentialProjectionSource, IssuedCredentialRepositoryError> {
    let status_list_entries = row
        .try_get::<Value, _>("status_list_entries")
        .map_err(repository_error)?
        .as_array()
        .cloned()
        .ok_or(IssuedCredentialRepositoryError)?;
    let transaction = row
        .try_get::<Option<String>, _>("joined_transaction_id")
        .map_err(repository_error)?
        .map(|_| {
            Ok(IssuedCredentialTransactionProjection {
                applicant_id: row
                    .try_get("transaction_applicant_id")
                    .map_err(repository_error)?,
                application_id: row.try_get("application_id").map_err(repository_error)?,
                subject_did: row
                    .try_get("transaction_subject_did")
                    .map_err(repository_error)?,
                issuer_did_override: row
                    .try_get("issuer_did_override")
                    .map_err(repository_error)?,
                claims: row.try_get("claims").map_err(repository_error)?,
                credential_type: row.try_get("credential_type").map_err(repository_error)?,
                credential_payload_format: row
                    .try_get("credential_payload_format")
                    .map_err(repository_error)?,
                renewable: row.try_get("renewable").map_err(repository_error)?,
                renewal_window_days: i64::from(
                    row.try_get::<i32, _>("renewal_window_days")
                        .map_err(repository_error)?,
                ),
            })
        })
        .transpose()?;
    Ok(IssuedCredentialProjectionSource {
        id: row.try_get("id").map_err(repository_error)?,
        transaction_id: row.try_get("transaction_id").map_err(repository_error)?,
        organization_id: row.try_get("organization_id").map_err(repository_error)?,
        credential_template_id: row
            .try_get("credential_template_id")
            .map_err(repository_error)?,
        applicant_id: row.try_get("applicant_id").map_err(repository_error)?,
        subject_did: row.try_get("subject_did").map_err(repository_error)?,
        issuer_did: row.try_get("issuer_did").map_err(repository_error)?,
        revocation_profile_id: row
            .try_get("revocation_profile_id")
            .map_err(repository_error)?,
        renewed_from_credential_id: row
            .try_get("renewed_from_credential_id")
            .map_err(repository_error)?,
        renewed_to_credential_id: row
            .try_get("renewed_to_credential_id")
            .map_err(repository_error)?,
        status_list_entries,
        credential_hash: row.try_get("credential_hash").map_err(repository_error)?,
        status: row.try_get("status").map_err(repository_error)?,
        status_updated_at: row.try_get("status_updated_at").map_err(repository_error)?,
        revoked_at: row.try_get("revoked_at").map_err(repository_error)?,
        revocation_reason: row.try_get("revocation_reason").map_err(repository_error)?,
        issued_at: row.try_get("issued_at").map_err(repository_error)?,
        expires_at: row.try_get("expires_at").map_err(repository_error)?,
        transaction,
    })
}

fn repository_error(error: impl std::fmt::Display) -> IssuedCredentialRepositoryError {
    tracing::error!(error = %error, "issued-credential repository operation failed");
    IssuedCredentialRepositoryError
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_is_one_join_and_never_reads_private_credential_material() {
        assert!(GET_PROJECTION.contains("LEFT JOIN issuance_service.issuance_transactions"));
        assert!(LIST_PROJECTION.contains("WHERE c.organization_id = $1"));
        assert!(!GET_PROJECTION.contains("credential_jwt"));
        assert!(!GET_PROJECTION.contains("access_token"));
        assert!(!GET_PROJECTION.contains("pre_auth_code"));
    }
}
