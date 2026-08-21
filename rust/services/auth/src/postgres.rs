use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use crate::{
    ApplicantProfile, ApplicantProvisioningStore, ApplicantUpsert, AuthAuditSink, PortError,
    Session, SessionStatus, UserType,
};

const SELECT_APPLICANT: &str = "
    SELECT id::text AS id, account_id, email, surname, given_names, date_of_birth,
           nationality, identity_proofing_completed, identity_proofing_date, active,
           suspended, COALESCE(extra_data::jsonb, '{}'::jsonb) AS extra_data,
           created_at, updated_at
    FROM public.applicants
    WHERE deleted_at IS NULL AND (account_id=$1 OR email=$2)
    ORDER BY CASE WHEN account_id=$1 THEN 0 ELSE 1 END FOR UPDATE";

const UPDATE_APPLICANT: &str = "
    UPDATE public.applicants
    SET account_id=$2, email=$3, given_names=$4, surname=$5,
        extra_data=$6::json, updated_at=$7
    WHERE id::text=$1
    RETURNING id::text AS id, account_id, email, surname, given_names, date_of_birth,
              nationality, identity_proofing_completed, identity_proofing_date, active,
              suspended, COALESCE(extra_data::jsonb, '{}'::jsonb) AS extra_data,
              created_at, updated_at";

const INSERT_APPLICANT: &str = "
    INSERT INTO public.applicants (
        id, account_id, email, surname, given_names, date_of_birth, nationality,
        identity_proofing_completed, identity_proofing_date, active, suspended,
        extra_data, created_at, updated_at, deleted_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NULL, TRUE, FALSE,
              $8::json, $9, $9, NULL)
    RETURNING id::text AS id, account_id, email, surname, given_names, date_of_birth,
              nationality, identity_proofing_completed, identity_proofing_date, active,
              suspended, COALESCE(extra_data::jsonb, '{}'::jsonb) AS extra_data,
              created_at, updated_at";

#[derive(Clone)]
pub struct PostgresAuthRepository {
    pool: PgPool,
}

impl PostgresAuthRepository {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn get_audit_logs(
        &self,
        filter: &AuditLogFilter,
    ) -> Result<Vec<AuditLogRecord>, PortError> {
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT id, event_type, user_id, email, organization_id, session_id, \
             authentication_method, success, host(ip_address) AS ip_address, user_agent, \
             COALESCE(event_metadata, '{}'::jsonb) AS event_metadata, created_at \
             FROM auth_service.audit_logs WHERE TRUE",
        );
        if let Some(user_id) = &filter.user_id {
            query.push(" AND user_id = ").push_bind(user_id);
        }
        if let Some(organization_id) = &filter.organization_id {
            query
                .push(" AND organization_id = ")
                .push_bind(organization_id);
        }
        if let Some(event_type) = &filter.event_type {
            query.push(" AND event_type = ").push_bind(event_type);
        }
        query
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(normalized_limit(filter.limit));
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.iter().map(audit_log_from_row).collect())
            .map_err(database_error)
    }

    pub async fn get_session_history(
        &self,
        filter: &SessionHistoryFilter,
    ) -> Result<Vec<SessionHistoryRecord>, PortError> {
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT id, session_id, user_id, email, organization_id, user_type, created_at, \
             expires_at, expired_at, revoked_at, revocation_reason, \
             host(ip_address) AS ip_address, user_agent, device_info, last_activity \
             FROM auth_service.session_history WHERE TRUE",
        );
        if let Some(user_id) = &filter.user_id {
            query.push(" AND user_id = ").push_bind(user_id);
        }
        if let Some(organization_id) = &filter.organization_id {
            query
                .push(" AND organization_id = ")
                .push_bind(organization_id);
        }
        query
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(normalized_limit(filter.limit));
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.iter().map(session_history_from_row).collect())
            .map_err(database_error)
    }

    pub async fn mark_session_expired(
        &self,
        session_id: &str,
        expired_at: DateTime<Utc>,
    ) -> Result<bool, PortError> {
        sqlx::query(
            "UPDATE auth_service.session_history
             SET expired_at=$2, last_activity=GREATEST(last_activity, $2)
             WHERE session_id=$1",
        )
        .bind(session_id)
        .bind(expired_at)
        .execute(&self.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(database_error)
    }
}

#[async_trait]
impl ApplicantProvisioningStore for PostgresAuthRepository {
    async fn upsert(&self, plan: &ApplicantUpsert) -> Result<ApplicantProfile, PortError> {
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        // Acquire both locks in a stable order so either natural key serializes first login.
        let mut lock_keys = [
            format!("auth-applicant-account:{}", plan.account_id),
            format!("auth-applicant-email:{}", plan.email),
        ];
        lock_keys.sort();
        for lock_key in lock_keys {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(lock_key)
                .execute(&mut *transaction)
                .await
                .map_err(database_error)?;
        }

        let rows = sqlx::query(SELECT_APPLICANT)
            .bind(&plan.account_id)
            .bind(&plan.email)
            .fetch_all(&mut *transaction)
            .await
            .map_err(database_error)?;
        if rows.len() > 1 {
            return Err(PortError::new(
                "applicant_identity_conflict",
                "OIDC account and email resolve to different applicant records",
            ));
        }

        let profile = if let Some(row) = rows.first() {
            let mut extra_data: Value = row.get("extra_data");
            merge_json_object(&mut extra_data, &plan.extra_data_patch);
            let current_given: String = row.get("given_names");
            let current_surname: String = row.get("surname");
            let given_names = plan.given_names.as_ref().unwrap_or(&current_given);
            let surname = plan.surname.as_ref().unwrap_or(&current_surname);
            let id: String = row.get("id");
            let row = sqlx::query(UPDATE_APPLICANT)
                .bind(id)
                .bind(&plan.account_id)
                .bind(&plan.email)
                .bind(given_names)
                .bind(surname)
                .bind(extra_data)
                .bind(plan.now)
                .fetch_one(&mut *transaction)
                .await
                .map_err(database_error)?;
            applicant_from_row(&row)
        } else {
            let row = sqlx::query(INSERT_APPLICANT)
                .bind(&plan.new_id)
                .bind(&plan.account_id)
                .bind(&plan.email)
                .bind(plan.surname.as_ref().unwrap_or(&plan.fallback_surname))
                .bind(
                    plan.given_names
                        .as_ref()
                        .unwrap_or(&plan.fallback_given_names),
                )
                .bind(plan.date_of_birth)
                .bind(&plan.nationality)
                .bind(&plan.extra_data_patch)
                .bind(plan.now)
                .fetch_one(&mut *transaction)
                .await
                .map_err(database_error)?;
            applicant_from_row(&row)
        };
        transaction.commit().await.map_err(database_error)?;
        Ok(profile)
    }
}

#[async_trait]
impl AuthAuditSink for PostgresAuthRepository {
    async fn record_authentication(
        &self,
        session: &Session,
        authentication_method: &str,
    ) -> Result<(), PortError> {
        let now = Utc::now();
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        insert_audit(
            &mut transaction,
            "user_authenticated",
            session,
            Some(authentication_method),
            json!({}),
            now,
        )
        .await?;
        insert_audit(
            &mut transaction,
            "session_created",
            session,
            None,
            json!({
                "expires_at": session.expires_at.to_rfc3339(),
                "user_type": user_type_name(session.user.user_type),
            }),
            now,
        )
        .await?;
        upsert_session_history(&mut transaction, session).await?;
        transaction.commit().await.map_err(database_error)
    }

    async fn record_logout(&self, session: &Session) -> Result<(), PortError> {
        let now = Utc::now();
        let mut transaction = self.pool.begin().await.map_err(database_error)?;
        insert_audit(
            &mut transaction,
            "logout",
            session,
            None,
            json!({"logout_type": "user_initiated"}),
            now,
        )
        .await?;
        insert_audit(
            &mut transaction,
            "session_revoked",
            session,
            None,
            json!({"revoked_by": "user", "reason": "logout"}),
            now,
        )
        .await?;
        upsert_session_history(&mut transaction, session).await?;
        transaction.commit().await.map_err(database_error)
    }
}

async fn insert_audit(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    event_type: &str,
    session: &Session,
    authentication_method: Option<&str>,
    metadata: Value,
    created_at: DateTime<Utc>,
) -> Result<(), PortError> {
    sqlx::query(
        "INSERT INTO auth_service.audit_logs (
            id, event_type, user_id, email, organization_id, session_id,
            authentication_method, success, ip_address, user_agent, event_metadata, created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8::inet, $9, $10, $11)",
    )
    .bind(Uuid::new_v4())
    .bind(event_type)
    .bind(&session.user.user_id)
    .bind(&session.user.email)
    .bind(&session.user.organization_id)
    .bind(&session.session_id)
    .bind(authentication_method)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .bind(metadata)
    .bind(created_at)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(database_error)
}

async fn upsert_session_history(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    session: &Session,
) -> Result<(), PortError> {
    let revoked_at = (session.status == SessionStatus::Revoked).then(Utc::now);
    sqlx::query(
        "INSERT INTO auth_service.session_history (
            id, session_id, user_id, email, organization_id, user_type, created_at, expires_at,
            revoked_at, revocation_reason, ip_address, user_agent, last_activity
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet, $12, $13)
         ON CONFLICT (session_id) DO UPDATE SET
            last_activity=EXCLUDED.last_activity,
            revoked_at=COALESCE(EXCLUDED.revoked_at, auth_service.session_history.revoked_at),
            revocation_reason=COALESCE(EXCLUDED.revocation_reason,
                                       auth_service.session_history.revocation_reason)",
    )
    .bind(Uuid::new_v4())
    .bind(&session.session_id)
    .bind(&session.user.user_id)
    .bind(&session.user.email)
    .bind(&session.user.organization_id)
    .bind(user_type_name(session.user.user_type))
    .bind(session.created_at)
    .bind(session.expires_at)
    .bind(revoked_at)
    .bind(revoked_at.map(|_| "logout"))
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .bind(session.last_activity)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(database_error)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditLogFilter {
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub event_type: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub event_type: String,
    pub user_id: String,
    pub email: Option<String>,
    pub organization_id: Option<String>,
    pub session_id: Option<String>,
    pub authentication_method: Option<String>,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub event_metadata: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionHistoryFilter {
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionHistoryRecord {
    pub id: Uuid,
    pub session_id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub organization_id: Option<String>,
    pub user_type: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub expired_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<Value>,
    pub last_activity: Option<DateTime<Utc>>,
}

fn applicant_from_row(row: &PgRow) -> ApplicantProfile {
    ApplicantProfile {
        id: row.get("id"),
        account_id: row.get("account_id"),
        email: row.get("email"),
        surname: row.get("surname"),
        given_names: row.get("given_names"),
        date_of_birth: row.get::<NaiveDate, _>("date_of_birth"),
        nationality: row.get("nationality"),
        identity_proofing_completed: row.get("identity_proofing_completed"),
        identity_proofing_date: row.get("identity_proofing_date"),
        active: row.get("active"),
        suspended: row.get("suspended"),
        extra_data: row.get("extra_data"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn audit_log_from_row(row: &PgRow) -> AuditLogRecord {
    AuditLogRecord {
        id: row.get("id"),
        event_type: row.get("event_type"),
        user_id: row.get("user_id"),
        email: row.get("email"),
        organization_id: row.get("organization_id"),
        session_id: row.get("session_id"),
        authentication_method: row.get("authentication_method"),
        success: row.get("success"),
        ip_address: row.get("ip_address"),
        user_agent: row.get("user_agent"),
        event_metadata: row.get("event_metadata"),
        created_at: row.get("created_at"),
    }
}

fn session_history_from_row(row: &PgRow) -> SessionHistoryRecord {
    SessionHistoryRecord {
        id: row.get("id"),
        session_id: row.get("session_id"),
        user_id: row.get("user_id"),
        email: row.get("email"),
        organization_id: row.get("organization_id"),
        user_type: row.get("user_type"),
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        expired_at: row.get("expired_at"),
        revoked_at: row.get("revoked_at"),
        revocation_reason: row.get("revocation_reason"),
        ip_address: row.get("ip_address"),
        user_agent: row.get("user_agent"),
        device_info: row.get("device_info"),
        last_activity: row.get("last_activity"),
    }
}

fn merge_json_object(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            target.insert(key.clone(), value.clone());
        }
    }
}

const fn normalized_limit(limit: usize) -> i64 {
    if limit == 0 {
        100
    } else if limit > 1_000 {
        1_000
    } else {
        limit as i64
    }
}

const fn user_type_name(user_type: UserType) -> &'static str {
    match user_type {
        UserType::Applicant => "applicant",
        UserType::Vendor => "vendor",
        UserType::Administrator => "administrator",
    }
}

fn database_error(error: sqlx::Error) -> PortError {
    PortError::new("auth_database_unavailable", error.to_string())
}
