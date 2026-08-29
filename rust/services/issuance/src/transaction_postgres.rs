use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{postgres::PgRow, PgPool, Row};
use tracing::error;

use crate::transaction_reads::{
    IssuanceTransactionRecord, TransactionReadError, TransactionReadRepository, TransactionStatus,
};

macro_rules! transaction_query {
    ($predicate:literal) => {
        concat!(
            "SELECT id, organization_id, credential_template_id, applicant_id, application_id,
                    subject_did, status, pre_auth_code, credential_type, created_at, expires_at,
                    issued_at, revoked_at, revocation_reason
             FROM issuance_service.issuance_transactions ",
            $predicate
        )
    };
}

const GET_TRANSACTION: &str = transaction_query!("WHERE id = $1");
const LIST_TRANSACTIONS: &str = transaction_query!("WHERE organization_id = $1");

#[derive(Clone)]
pub struct PostgresTransactionReadRepository {
    pool: PgPool,
}

impl std::fmt::Debug for PostgresTransactionReadRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresTransactionReadRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresTransactionReadRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TransactionReadRepository for PostgresTransactionReadRepository {
    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<IssuanceTransactionRecord>, TransactionReadError> {
        sqlx::query(GET_TRANSACTION)
            .bind(transaction_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
    }

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuanceTransactionRecord>, TransactionReadError> {
        sqlx::query(LIST_TRANSACTIONS)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?
            .into_iter()
            .map(transaction_row)
            .collect()
    }
}

fn transaction_row(row: PgRow) -> Result<IssuanceTransactionRecord, TransactionReadError> {
    let status: String = row.try_get("status").map_err(row_error)?;
    Ok(IssuanceTransactionRecord {
        id: get(&row, "id")?,
        organization_id: get(&row, "organization_id")?,
        credential_template_id: get(&row, "credential_template_id")?,
        applicant_id: get(&row, "applicant_id")?,
        application_id: get(&row, "application_id")?,
        subject_did: get(&row, "subject_did")?,
        status: TransactionStatus::try_from(status.as_str())?,
        pre_auth_code: get(&row, "pre_auth_code")?,
        credential_type: get(&row, "credential_type")?,
        created_at: get::<DateTime<Utc>>(&row, "created_at")?,
        expires_at: get::<DateTime<Utc>>(&row, "expires_at")?,
        issued_at: get::<Option<DateTime<Utc>>>(&row, "issued_at")?,
        revoked_at: get::<Option<DateTime<Utc>>>(&row, "revoked_at")?,
        revocation_reason: get(&row, "revocation_reason")?,
    })
}

fn get<'row, T>(row: &'row PgRow, name: &str) -> Result<T, TransactionReadError>
where
    T: sqlx::Decode<'row, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name).map_err(row_error)
}

fn repository_error(cause: sqlx::Error) -> TransactionReadError {
    error!(%cause, "issuance transaction repository query failed");
    TransactionReadError::RepositoryUnavailable
}

fn row_error(cause: sqlx::Error) -> TransactionReadError {
    error!(%cause, "issuance transaction repository row is invalid");
    TransactionReadError::RepositoryUnavailable
}
