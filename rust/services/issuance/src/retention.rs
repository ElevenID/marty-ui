//! Tenant-scoped issuance retention, matching the frozen Credentials boundary.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};

use crate::{management_security::ManagementSecurity, transaction_reads::TransactionReadError};

pub const TRACKED_SCOPE: [&str; 6] = [
    "applications",
    "submitted_evidence",
    "issuance_transactions",
    "issued_credentials",
    "authorization_sessions",
    "issuance_events",
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RetentionRecordCounts {
    pub issuance_transactions: u64,
    pub applications: u64,
    pub authorization_sessions: u64,
    pub issuance_events: u64,
    pub issued_credentials: u64,
    pub total: u64,
}

impl RetentionRecordCounts {
    fn from_parts(
        issuance_transactions: u64,
        applications: u64,
        authorization_sessions: u64,
        issuance_events: u64,
        issued_credentials: u64,
    ) -> Self {
        Self {
            issuance_transactions,
            applications,
            authorization_sessions,
            issuance_events,
            issued_credentials,
            total: issuance_transactions
                + applications
                + authorization_sessions
                + issuance_events
                + issued_credentials,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionSnapshot {
    pub eligible_for_purge: RetentionRecordCounts,
    pub oldest_retained_record_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetentionSummary {
    pub organization_id: String,
    pub retention_days: u16,
    pub cutoff_at: String,
    pub oldest_retained_record_at: Option<String>,
    pub next_expiry_at: Option<String>,
    pub eligible_for_purge: RetentionRecordCounts,
    pub tracked_scope: [&'static str; 6],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetentionPurge {
    pub organization_id: String,
    pub retention_days: u16,
    pub cutoff_at: String,
    pub purged_at: String,
    pub purged_records: RetentionRecordCounts,
    pub oldest_retained_record_at: Option<String>,
    pub next_expiry_at: Option<String>,
    pub tracked_scope: [&'static str; 6],
}

#[async_trait]
pub trait RetentionRepository: Send + Sync {
    async fn summary(
        &self,
        organization_id: &str,
        cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionSnapshot, sqlx::Error>;

    async fn purge(
        &self,
        organization_id: &str,
        cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionRecordCounts, sqlx::Error>;
}

pub trait RetentionClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug)]
pub struct SystemRetentionClock;

impl RetentionClock for SystemRetentionClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct RetentionService {
    repository: Arc<dyn RetentionRepository>,
    security: ManagementSecurity,
    clock: Arc<dyn RetentionClock>,
}

impl RetentionService {
    #[must_use]
    pub fn new(repository: Arc<dyn RetentionRepository>, api_key: Option<&str>) -> Self {
        Self {
            repository,
            security: ManagementSecurity::new(api_key),
            clock: Arc::new(SystemRetentionClock),
        }
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn RetentionClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn authorize(
        &self,
        api_key: Option<&str>,
        trusted_organization: Option<&str>,
        organization_id: &str,
    ) -> Result<(), TransactionReadError> {
        self.security.authorize(api_key)?;
        self.security
            .require_organization(trusted_organization, organization_id, false)
    }

    pub async fn summary(
        &self,
        organization_id: &str,
        retention_days: u16,
    ) -> Result<RetentionSummary, sqlx::Error> {
        let cutoff = self.clock.now() - Duration::days(i64::from(retention_days));
        let snapshot = self.repository.summary(organization_id, cutoff).await?;
        Ok(RetentionSummary {
            organization_id: organization_id.to_owned(),
            retention_days,
            cutoff_at: iso(cutoff),
            oldest_retained_record_at: snapshot.oldest_retained_record_at.map(iso),
            next_expiry_at: snapshot
                .oldest_retained_record_at
                .map(|oldest| iso(oldest + Duration::days(i64::from(retention_days)))),
            eligible_for_purge: snapshot.eligible_for_purge,
            tracked_scope: TRACKED_SCOPE,
        })
    }

    pub async fn purge(
        &self,
        organization_id: &str,
        retention_days: u16,
    ) -> Result<RetentionPurge, sqlx::Error> {
        let cutoff = self.clock.now() - Duration::days(i64::from(retention_days));
        let purged_records = self.repository.purge(organization_id, cutoff).await?;
        let after = self.repository.summary(organization_id, cutoff).await?;
        Ok(RetentionPurge {
            organization_id: organization_id.to_owned(),
            retention_days,
            cutoff_at: iso(cutoff),
            purged_at: iso(self.clock.now()),
            purged_records,
            oldest_retained_record_at: after.oldest_retained_record_at.map(iso),
            next_expiry_at: after
                .oldest_retained_record_at
                .map(|oldest| iso(oldest + Duration::days(i64::from(retention_days)))),
            tracked_scope: TRACKED_SCOPE,
        })
    }
}

fn iso(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

#[derive(Clone)]
pub struct PostgresRetentionRepository {
    pool: PgPool,
}

impl PostgresRetentionRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const SNAPSHOT_SQL: &str = r#"
WITH transaction_records AS (
    SELECT COUNT(*) FILTER (WHERE created_at < $2)::bigint AS expired,
           MIN(created_at) FILTER (WHERE created_at >= $2) AS retained
    FROM issuance_service.issuance_transactions WHERE organization_id = $1
), application_records AS (
    SELECT COUNT(*) FILTER (WHERE created_at < $2)::bigint AS expired,
           MIN(created_at) FILTER (WHERE created_at >= $2) AS retained
    FROM issuance_service.applications WHERE organization_id = $1
), authorization_records AS (
    SELECT COUNT(*) FILTER (WHERE created_at < $2)::bigint AS expired,
           MIN(created_at) FILTER (WHERE created_at >= $2) AS retained
    FROM issuance_service.authorization_sessions WHERE organization_id = $1
), event_records AS (
    SELECT COUNT(*) FILTER (WHERE e.created_at < $2)::bigint AS expired,
           MIN(e.created_at) FILTER (WHERE e.created_at >= $2) AS retained
    FROM issuance_service.issuance_events e
    WHERE e.organization_id = $1 OR (e.organization_id IS NULL AND (
        EXISTS (SELECT 1 FROM issuance_service.issuance_transactions t
                WHERE t.id = e.transaction_id AND t.organization_id = $1)
        OR EXISTS (SELECT 1 FROM issuance_service.applications a
                   WHERE a.id = e.application_id AND a.organization_id = $1)
    ))
), credential_records AS (
    SELECT COUNT(*)::bigint AS expired
    FROM issuance_service.issued_credentials c
    JOIN issuance_service.issuance_transactions t ON t.id = c.transaction_id
    WHERE c.organization_id = $1 AND t.organization_id = $1 AND t.created_at < $2
)
SELECT t.expired AS issuance_transactions,
       a.expired AS applications,
       s.expired AS authorization_sessions,
       e.expired AS issuance_events,
       c.expired AS issued_credentials,
       (SELECT MIN(value) FROM (VALUES (t.retained), (a.retained), (s.retained), (e.retained))
            AS candidates(value)) AS oldest_retained_record_at
FROM transaction_records t, application_records a, authorization_records s,
     event_records e, credential_records c
"#;

#[async_trait]
impl RetentionRepository for PostgresRetentionRepository {
    async fn summary(
        &self,
        organization_id: &str,
        cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionSnapshot, sqlx::Error> {
        let row = sqlx::query(SNAPSHOT_SQL)
            .bind(organization_id)
            .bind(cutoff_at)
            .fetch_one(&self.pool)
            .await?;
        let count = |name: &str| -> Result<u64, sqlx::Error> {
            let value: i64 = row.try_get(name)?;
            Ok(value as u64)
        };
        Ok(RetentionSnapshot {
            eligible_for_purge: RetentionRecordCounts::from_parts(
                count("issuance_transactions")?,
                count("applications")?,
                count("authorization_sessions")?,
                count("issuance_events")?,
                count("issued_credentials")?,
            ),
            oldest_retained_record_at: row.try_get("oldest_retained_record_at")?,
        })
    }

    async fn purge(
        &self,
        organization_id: &str,
        cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionRecordCounts, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        // Persist ownership before deleting a parent whose FK uses SET NULL.
        sqlx::query(
            r#"UPDATE issuance_service.issuance_events e SET organization_id = $1
               WHERE e.organization_id IS NULL AND e.created_at >= $2 AND (
                   EXISTS (SELECT 1 FROM issuance_service.issuance_transactions t
                           WHERE t.id = e.transaction_id AND t.organization_id = $1)
                   OR EXISTS (SELECT 1 FROM issuance_service.applications a
                              WHERE a.id = e.application_id AND a.organization_id = $1))"#,
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?;
        let events = sqlx::query(
            r#"DELETE FROM issuance_service.issuance_events e
               WHERE e.created_at < $2 AND (e.organization_id = $1 OR
                   (e.organization_id IS NULL AND (
                       EXISTS (SELECT 1 FROM issuance_service.issuance_transactions t
                               WHERE t.id = e.transaction_id AND t.organization_id = $1)
                       OR EXISTS (SELECT 1 FROM issuance_service.applications a
                                  WHERE a.id = e.application_id AND a.organization_id = $1))))"#,
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let sessions = sqlx::query(
            "DELETE FROM issuance_service.authorization_sessions \
             WHERE organization_id = $1 AND created_at < $2",
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let applications = sqlx::query(
            "DELETE FROM issuance_service.applications \
             WHERE organization_id = $1 AND created_at < $2",
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        // The migrated schema does not cascade issued credentials from a
        // transaction, so count and delete them explicitly before the parent.
        let credentials = sqlx::query(
            r#"DELETE FROM issuance_service.issued_credentials c
               USING issuance_service.issuance_transactions t
               WHERE c.transaction_id = t.id AND c.organization_id = $1
                 AND t.organization_id = $1 AND t.created_at < $2"#,
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let transactions = sqlx::query(
            "DELETE FROM issuance_service.issuance_transactions \
             WHERE organization_id = $1 AND created_at < $2",
        )
        .bind(organization_id)
        .bind(cutoff_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        transaction.commit().await?;
        Ok(RetentionRecordCounts::from_parts(
            transactions,
            applications,
            sessions,
            events,
            credentials,
        ))
    }
}
