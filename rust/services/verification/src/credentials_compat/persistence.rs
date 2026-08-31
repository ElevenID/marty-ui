use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime};
use serde_json::Value;
use sqlx::{postgres::PgRow, AssertSqlSafe, PgPool, Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::session::TerminalDecisionKind;
use super::{
    ClaimState, PersistedEvidence, PersistedEvidenceError, ProcessingLease, ProcessingToken,
    SessionDraft, SessionDurationSeconds, SessionRecord, SessionStatus, Sha256Digest,
    SubmissionClaim, TerminalDecision, VerificationMethod, VerifierNonce,
};

// All SQL assembled with this fragment interpolates only this compile-time
// column allowlist. Every runtime value is still passed as a bind parameter.
const SESSION_COLUMNS: &str = "id, organization_id, verifier_did, presentation_definition, status, required_credential_types, trusted_issuers, required_claims, verified_claims, verification_evidence, verification_method, verified_at, created_at, updated_at, expires_at, error_message, request_uri, nonce, submission_sha256, processing_token_sha256, processing_started_at, processing_expires_at";

#[derive(Debug, Error)]
pub enum SessionPersistenceError {
    #[error("VERIFICATION.SESSION_DATABASE: persistence operation failed")]
    Database(#[source] sqlx::Error),
    #[error("VERIFICATION.SESSION_CORRUPT: {0}")]
    Corrupt(&'static str),
    #[error("VERIFICATION.SESSION_EVIDENCE: terminal evidence is invalid")]
    InvalidEvidence(#[source] PersistedEvidenceError),
}

impl From<sqlx::Error> for SessionPersistenceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(
        &self,
        draft: SessionDraft,
        duration: SessionDurationSeconds,
    ) -> Result<SessionRecord, SessionPersistenceError>;

    async fn claim(
        &self,
        session_id: &str,
        presentation_digest: &Sha256Digest,
        processing_token: &ProcessingToken,
        lease: ProcessingLease,
    ) -> Result<SubmissionClaim, SessionPersistenceError>;

    async fn finalize(
        &self,
        session_id: &str,
        presentation_digest: &Sha256Digest,
        processing_token: &ProcessingToken,
        decision: TerminalDecision,
    ) -> Result<SubmissionClaim, SessionPersistenceError>;

    async fn get(&self, session_id: &str)
        -> Result<Option<SessionRecord>, SessionPersistenceError>;

    async fn list_by_organization(
        &self,
        organization_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionRecord>, SessionPersistenceError>;
}

#[derive(Clone, Debug)]
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create(
        &self,
        draft: SessionDraft,
        duration: SessionDurationSeconds,
    ) -> Result<SessionRecord, SessionPersistenceError> {
        let duration = i64::try_from(duration.get())
            .map_err(|_| SessionPersistenceError::Corrupt("session duration exceeds i64"))?;
        let mut transaction = self.pool.begin().await?;
        let now = database_now(&mut transaction).await?;
        let expires_at = now + Duration::seconds(duration);
        let row = sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO public.verification_sessions (
                id, organization_id, verifier_did, presentation_definition, status,
                required_credential_types, trusted_issuers, required_claims,
                presentation_data, verified_claims, verification_evidence,
                verification_method, verified_at, created_at, updated_at, expires_at,
                error_message, request_uri, nonce, submission_sha256,
                processing_token_sha256, processing_started_at, processing_expires_at
             ) VALUES (
                $1,$2,$3,$4,'PENDING',$5,$6,$7,NULL,NULL,$8,NULL,NULL,$9,$9,$10,
                NULL,$11,$12,NULL,NULL,NULL,NULL
             ) RETURNING {SESSION_COLUMNS}"
        )))
        .bind(&draft.id)
        .bind(&draft.organization_id)
        .bind(&draft.verifier_did)
        .bind(&draft.presentation_definition)
        .bind(Value::Array(
            draft
                .required_credential_types
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ))
        .bind(Value::Array(
            draft
                .trusted_issuers
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ))
        .bind(Value::Array(
            draft
                .required_claims
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ))
        .bind(draft.verification_evidence.as_value())
        .bind(now)
        .bind(expires_at)
        .bind(&draft.request_uri)
        .bind(draft.nonce.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let record = record(row)?;
        transaction.commit().await?;
        Ok(record)
    }

    async fn claim(
        &self,
        session_id: &str,
        presentation_digest: &Sha256Digest,
        processing_token: &ProcessingToken,
        lease: ProcessingLease,
    ) -> Result<SubmissionClaim, SessionPersistenceError> {
        let mut transaction = self.pool.begin().await?;
        let Some(row) = locked_row(&mut transaction, session_id).await? else {
            transaction.rollback().await?;
            return Ok(SubmissionClaim::state(ClaimState::NotFound));
        };
        let current_token: Option<String> = row.try_get("processing_token_sha256")?;
        let current = record(row)?;
        let now = database_now(&mut transaction).await?;

        if matches!(
            current.status,
            SessionStatus::Verified | SessionStatus::Failed
        ) {
            let state = if current.submission_sha256.as_ref() == Some(presentation_digest) {
                ClaimState::Terminal
            } else {
                ClaimState::Conflict
            };
            transaction.rollback().await?;
            return Ok(SubmissionClaim::session(state, current));
        }

        if current.expires_at.is_some_and(|deadline| deadline <= now) {
            let expired = expire(&mut transaction, session_id, now).await?;
            transaction.commit().await?;
            return Ok(SubmissionClaim::session(ClaimState::Expired, expired));
        }

        if current.status == SessionStatus::Expired {
            transaction.rollback().await?;
            return Ok(SubmissionClaim::session(ClaimState::Expired, current));
        }

        match current.status {
            SessionStatus::InProgress => {
                if current.submission_sha256.as_ref() != Some(presentation_digest) {
                    transaction.rollback().await?;
                    return Ok(SubmissionClaim::state(ClaimState::Conflict));
                }
                if current.processing_expires_at.is_none()
                    || current.nonce.is_none()
                    || current_token.is_none()
                {
                    let expired = expire(&mut transaction, session_id, now).await?;
                    transaction.commit().await?;
                    return Ok(SubmissionClaim::session(ClaimState::Expired, expired));
                }
                if current
                    .processing_expires_at
                    .is_some_and(|deadline| deadline > now)
                {
                    transaction.rollback().await?;
                    return Ok(SubmissionClaim::session(ClaimState::Busy, current));
                }
            }
            SessionStatus::Pending => {
                if current.nonce.is_none() {
                    let expired = expire(&mut transaction, session_id, now).await?;
                    transaction.commit().await?;
                    return Ok(SubmissionClaim::session(ClaimState::Expired, expired));
                }
            }
            SessionStatus::Verified | SessionStatus::Failed | SessionStatus::Expired => {
                transaction.rollback().await?;
                return Ok(SubmissionClaim::state(ClaimState::Conflict));
            }
        }

        let lease_seconds = i64::try_from(lease.seconds())
            .map_err(|_| SessionPersistenceError::Corrupt("processing lease exceeds i64"))?;
        let mut lease_deadline = now + Duration::seconds(lease_seconds);
        if let Some(session_deadline) = current.expires_at {
            lease_deadline = lease_deadline.min(session_deadline);
        }
        let token_digest = processing_token.digest();
        let row = sqlx::query(AssertSqlSafe(format!(
            "UPDATE public.verification_sessions
             SET status='IN_PROGRESS', submission_sha256=$2,
                 processing_token_sha256=$3, processing_started_at=$4,
                 processing_expires_at=$5, updated_at=$4
             WHERE id=$1 RETURNING {SESSION_COLUMNS}"
        )))
        .bind(session_id)
        .bind(presentation_digest.as_str())
        .bind(token_digest.as_str())
        .bind(now)
        .bind(lease_deadline)
        .fetch_one(&mut *transaction)
        .await?;
        let claimed = record(row)?;
        let nonce = claimed
            .nonce
            .clone()
            .ok_or(SessionPersistenceError::Corrupt(
                "claimed session omitted verifier nonce",
            ))?;
        transaction.commit().await?;
        Ok(SubmissionClaim::claimed(claimed, nonce))
    }

    async fn finalize(
        &self,
        session_id: &str,
        presentation_digest: &Sha256Digest,
        processing_token: &ProcessingToken,
        decision: TerminalDecision,
    ) -> Result<SubmissionClaim, SessionPersistenceError> {
        decision
            .validate_binding(session_id, presentation_digest)
            .map_err(SessionPersistenceError::InvalidEvidence)?;
        let mut transaction = self.pool.begin().await?;
        let Some(row) = locked_row(&mut transaction, session_id).await? else {
            transaction.rollback().await?;
            return Ok(SubmissionClaim::state(ClaimState::NotFound));
        };
        let current_token: Option<String> = row.try_get("processing_token_sha256")?;
        let current = record(row)?;
        let now = database_now(&mut transaction).await?;

        if matches!(
            current.status,
            SessionStatus::Verified | SessionStatus::Failed
        ) {
            let state = if current.submission_sha256.as_ref() == Some(presentation_digest) {
                ClaimState::Terminal
            } else {
                ClaimState::Conflict
            };
            transaction.rollback().await?;
            return Ok(SubmissionClaim::session(state, current));
        }

        if current.expires_at.is_some_and(|deadline| deadline <= now) {
            let expired = expire(&mut transaction, session_id, now).await?;
            transaction.commit().await?;
            return Ok(SubmissionClaim::session(ClaimState::Expired, expired));
        }

        if current.status != SessionStatus::InProgress
            || current.submission_sha256.as_ref() != Some(presentation_digest)
        {
            transaction.rollback().await?;
            return Ok(SubmissionClaim::state(ClaimState::Conflict));
        }

        let expected_token = processing_token.digest();
        let token_matches = current_token.as_deref().is_some_and(|actual| {
            actual
                .as_bytes()
                .ct_eq(expected_token.as_str().as_bytes())
                .into()
        });
        if !token_matches
            || current
                .processing_expires_at
                .is_none_or(|deadline| deadline <= now)
        {
            transaction.rollback().await?;
            return Ok(SubmissionClaim::state(ClaimState::Stale));
        }

        let status = decision.status();
        let (verified_claims, evidence, method, error_message, verified_at) =
            match decision.into_kind() {
                TerminalDecisionKind::Verified {
                    verification_evidence,
                    method,
                } => (
                    Some(Value::Object(Default::default())),
                    verification_evidence,
                    Some(method.as_database_str()),
                    None,
                    Some(now),
                ),
                TerminalDecisionKind::Failed {
                    verification_evidence,
                    method,
                    error_message,
                } => (
                    None,
                    verification_evidence,
                    method.map(VerificationMethod::as_database_str),
                    Some(error_message),
                    None,
                ),
            };
        let row = sqlx::query(AssertSqlSafe(format!(
            "UPDATE public.verification_sessions
             SET status=$2, presentation_data=NULL, verified_claims=$3,
                 verification_evidence=$4, verification_method=$5, verified_at=$6,
                 updated_at=$7, error_message=$8, nonce=NULL,
                 processing_token_sha256=NULL, processing_started_at=NULL,
                 processing_expires_at=NULL
             WHERE id=$1 RETURNING {SESSION_COLUMNS}"
        )))
        .bind(session_id)
        .bind(status.as_database_str())
        .bind(verified_claims)
        .bind(evidence.as_value())
        .bind(method)
        .bind(verified_at)
        .bind(now)
        .bind(error_message)
        .fetch_one(&mut *transaction)
        .await?;
        let finalized = record(row)?;
        transaction.commit().await?;
        Ok(SubmissionClaim::session(ClaimState::Finalized, finalized))
    }

    async fn get(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionRecord>, SessionPersistenceError> {
        sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLUMNS} FROM public.verification_sessions WHERE id=$1"
        )))
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?
        .map(record)
        .transpose()
    }

    async fn list_by_organization(
        &self,
        organization_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SessionRecord>, SessionPersistenceError> {
        let rows = sqlx::query(AssertSqlSafe(format!(
            "SELECT {SESSION_COLUMNS} FROM public.verification_sessions
             WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )))
        .bind(organization_id)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(record).collect()
    }
}

async fn database_now(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<NaiveDateTime, sqlx::Error> {
    sqlx::query_scalar("SELECT clock_timestamp() AT TIME ZONE 'UTC'")
        .fetch_one(&mut **transaction)
        .await
}

async fn locked_row(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: &str,
) -> Result<Option<PgRow>, sqlx::Error> {
    sqlx::query(AssertSqlSafe(format!(
        "SELECT {SESSION_COLUMNS} FROM public.verification_sessions WHERE id=$1 FOR UPDATE"
    )))
    .bind(session_id)
    .fetch_optional(&mut **transaction)
    .await
}

async fn expire(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: &str,
    now: NaiveDateTime,
) -> Result<SessionRecord, SessionPersistenceError> {
    let row = sqlx::query(AssertSqlSafe(format!(
        "UPDATE public.verification_sessions
         SET status='EXPIRED', nonce=NULL, updated_at=$2,
             error_message='Verification session expired',
             processing_token_sha256=NULL, processing_started_at=NULL,
             processing_expires_at=NULL
         WHERE id=$1 RETURNING {SESSION_COLUMNS}"
    )))
    .bind(session_id)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await?;
    record(row)
}

fn record(row: PgRow) -> Result<SessionRecord, SessionPersistenceError> {
    let status = SessionStatus::parse_database(row.try_get("status")?)
        .ok_or(SessionPersistenceError::Corrupt("unknown session status"))?;
    let verification_method = row
        .try_get::<Option<String>, _>("verification_method")?
        .map(|value| {
            VerificationMethod::parse_database(&value).ok_or(SessionPersistenceError::Corrupt(
                "unknown verification method",
            ))
        })
        .transpose()?;
    let nonce = row
        .try_get::<Option<String>, _>("nonce")?
        .map(VerifierNonce::parse)
        .transpose()
        .map_err(|_| SessionPersistenceError::Corrupt("invalid verifier nonce"))?;
    let submission_sha256 = row
        .try_get::<Option<String>, _>("submission_sha256")?
        .map(Sha256Digest::parse)
        .transpose()
        .map_err(|_| SessionPersistenceError::Corrupt("invalid presentation digest"))?;
    Ok(SessionRecord {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        verifier_did: row.try_get("verifier_did")?,
        presentation_definition: row.try_get("presentation_definition")?,
        status,
        required_credential_types: string_array(row.try_get("required_credential_types")?)?,
        trusted_issuers: string_array(row.try_get("trusted_issuers")?)?,
        required_claims: string_array(row.try_get("required_claims")?)?,
        verification_evidence: PersistedEvidence::from_database(
            row.try_get("verification_evidence")?,
        ),
        verification_method,
        verified_at: row.try_get("verified_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        expires_at: row.try_get("expires_at")?,
        error_message: row.try_get("error_message")?,
        request_uri: row.try_get("request_uri")?,
        nonce,
        submission_sha256,
        processing_started_at: row.try_get("processing_started_at")?,
        processing_expires_at: row.try_get("processing_expires_at")?,
    })
}

fn string_array(value: Option<Value>) -> Result<Vec<String>, SessionPersistenceError> {
    value.map_or_else(
        || Ok(Vec::new()),
        |value| {
            value
                .as_array()
                .ok_or(SessionPersistenceError::Corrupt(
                    "constraint list is not an array",
                ))?
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or(SessionPersistenceError::Corrupt(
                            "constraint list contains a non-string",
                        ))
                })
                .collect()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_error_display_does_not_leak_query_or_bind_values() {
        let error = SessionPersistenceError::Database(sqlx::Error::RowNotFound);
        assert_eq!(
            error.to_string(),
            "VERIFICATION.SESSION_DATABASE: persistence operation failed"
        );
    }
}
