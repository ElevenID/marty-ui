use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use crate::{AuthAuditSink, PortError, Session, SessionStatus};

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
                "user_type": session.user.user_type.as_str(),
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
    .bind(session.user.user_type.as_str())
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

const fn normalized_limit(limit: usize) -> i64 {
    if limit == 0 {
        100
    } else if limit > 1_000 {
        1_000
    } else {
        limit as i64
    }
}

fn database_error(error: sqlx::Error) -> PortError {
    PortError::new("auth_database_unavailable", error.to_string())
}
