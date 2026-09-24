//! PostgreSQL Canvas mirror repository with tenant-qualified mutable writes.

use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};
use tracing::error;

use crate::{
    canvas_mirror_domain::{CanvasMirrorAlertEvent, CanvasMirrorDeliveryRecord},
    canvas_mirror_repository::{
        CanvasMirrorDeliveryQuery, CanvasMirrorRepository, CanvasMirrorRepositoryError,
    },
    credential::CredentialTransaction,
    credential_postgres::transaction_row,
};

const CLAIM_ID_KEY: &str = "_canvas_mirror_claim_id";
const CLAIM_EXPIRES_AT_KEY: &str = "_canvas_mirror_claim_expires_at";
const EFFECT_STARTED_AT_KEY: &str = "_canvas_mirror_effect_started_at";
const STATUS_SYNC_FAILURE_SQL: &str = "(metadata ? 'last_status_sync_error' AND metadata->'last_status_sync_error' NOT IN ('null'::jsonb,'false'::jsonb,'0'::jsonb,'\"\"'::jsonb,'[]'::jsonb,'{}'::jsonb))";

#[derive(Clone)]
pub struct PostgresCanvasMirrorRepository {
    pool: PgPool,
}

impl PostgresCanvasMirrorRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn records(
        &self,
        sql: &'static str,
        values: impl FnOnce(
            sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
        )
            -> sqlx::query::Query<'_, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        let rows = values(sqlx::query(sql))
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?;
        rows.into_iter().map(decode_record).collect()
    }
}

#[async_trait]
impl CanvasMirrorRepository for PostgresCanvasMirrorRepository {
    async fn delivery_record(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        sqlx::query("SELECT to_jsonb(d) AS value FROM issuance_service.credential_delivery_records d WHERE id=$1 AND organization_id=$2 AND delivery_target='canvas_credentials'")
            .bind(id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(decode_record)
            .transpose()
    }

    async fn delivery_by_external_credential(
        &self,
        external_credential_id: &str,
        canvas_account_id: Option<&str>,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        sqlx::query("SELECT to_jsonb(d) AS value FROM issuance_service.credential_delivery_records d WHERE delivery_target='canvas_credentials' AND external_credential_id=$1 AND organization_id=$2 AND ($3::text IS NULL OR canvas_account_id=$3) ORDER BY created_at,delivery_target,id LIMIT 1")
            .bind(external_credential_id)
            .bind(organization_id)
            .bind(canvas_account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(decode_record)
            .transpose()
    }

    async fn deliveries_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.records(
            "SELECT to_jsonb(d) AS value FROM issuance_service.credential_delivery_records d WHERE credential_id=$1 AND organization_id=$2 AND delivery_target='canvas_credentials' ORDER BY created_at,delivery_target,id",
            |query| query.bind(credential_id).bind(organization_id),
        )
        .await
    }

    async fn canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        let statuses = query
            .statuses
            .into_iter()
            .map(|status| status.as_str().to_owned())
            .collect::<Vec<_>>();
        let limit = query.limit.map(i64::from);
        let sql = format!(
            "SELECT to_jsonb(d) AS value FROM issuance_service.credential_delivery_records d WHERE delivery_target='canvas_credentials' AND ($1::text IS NULL OR organization_id=$1) AND (cardinality($2::text[])=0 OR status=ANY($2)) AND (NOT $4 OR {STATUS_SYNC_FAILURE_SQL}) ORDER BY created_at,delivery_target,id LIMIT $3"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(query.organization_id)
            .bind(statuses)
            .bind(limit)
            .bind(query.status_sync_failures_only)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?;
        rows.into_iter().map(decode_record).collect()
    }

    async fn claim_canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
        claim_id: &str,
        claim_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        let statuses = query
            .statuses
            .into_iter()
            .map(|status| status.as_str().to_owned())
            .collect::<Vec<_>>();
        let limit = query.limit.map(i64::from);
        let sql = format!(
            "WITH candidates AS (SELECT d.id FROM issuance_service.credential_delivery_records d WHERE delivery_target='canvas_credentials' AND ($1::text IS NULL OR organization_id=$1) AND (cardinality($2::text[])=0 OR status=ANY($2)) AND (NOT $4 OR {STATUS_SYNC_FAILURE_SQL}) AND NOT (metadata ? '{EFFECT_STARTED_AT_KEY}') AND (NOT (metadata ? '{CLAIM_ID_KEY}') OR NULLIF(metadata->>'{CLAIM_EXPIRES_AT_KEY}','')::timestamptz <= transaction_timestamp()) ORDER BY created_at,delivery_target,id FOR UPDATE SKIP LOCKED LIMIT $3) UPDATE issuance_service.credential_delivery_records d SET metadata=COALESCE(d.metadata,'{{}}'::jsonb) || jsonb_build_object('{CLAIM_ID_KEY}',$5,'{CLAIM_EXPIRES_AT_KEY}',$6::text) FROM candidates c WHERE d.id=c.id RETURNING to_jsonb(d) AS value"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(query.organization_id)
            .bind(statuses)
            .bind(limit)
            .bind(query.status_sync_failures_only)
            .bind(claim_id)
            .bind(claim_expires_at)
            .fetch_all(&self.pool)
            .await
            .map_err(repository_error)?;
        rows.into_iter().map(decode_claimed_record).collect()
    }

    async fn claim_delivery_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
        claim_id: &str,
        claim_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        let sql = format!(
            "WITH candidate AS (SELECT d.id FROM issuance_service.credential_delivery_records d WHERE credential_id=$1 AND organization_id=$2 AND delivery_target='canvas_credentials' AND status<>'delivered' AND NOT (metadata ? '{EFFECT_STARTED_AT_KEY}') AND (NOT (metadata ? '{CLAIM_ID_KEY}') OR NULLIF(metadata->>'{CLAIM_EXPIRES_AT_KEY}','')::timestamptz <= transaction_timestamp()) ORDER BY created_at,delivery_target,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE issuance_service.credential_delivery_records d SET metadata=COALESCE(d.metadata,'{{}}'::jsonb) || jsonb_build_object('{CLAIM_ID_KEY}',$3,'{CLAIM_EXPIRES_AT_KEY}',$4::text) FROM candidate c WHERE d.id=c.id RETURNING to_jsonb(d) AS value"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(credential_id)
            .bind(organization_id)
            .bind(claim_id)
            .bind(claim_expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(decode_claimed_record)
            .transpose()
    }

    async fn credential(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM issuance_service.issued_credentials c WHERE id=$1 AND organization_id=$2",
        )
        .bind(id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)
    }

    async fn credential_unscoped(
        &self,
        id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar(
            "SELECT to_jsonb(c) FROM issuance_service.issued_credentials c WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)
    }

    async fn transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar(
            "SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1 AND organization_id=$2",
        )
        .bind(id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(repository_error)
    }

    async fn publication_transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, CanvasMirrorRepositoryError> {
        sqlx::query("SELECT * FROM issuance_service.issuance_transactions WHERE id=$1 AND organization_id=$2")
            .bind(id)
            .bind(organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(repository_error)?
            .map(transaction_row)
            .transpose()
            .map_err(|cause| {
                error!(%cause, "Canvas mirror transaction row could not be decoded");
                CanvasMirrorRepositoryError
            })
    }

    async fn application(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar("SELECT to_jsonb(a) FROM issuance_service.applications a WHERE id=$1 AND organization_id=$2")
            .bind(id).bind(organization_id).fetch_optional(&self.pool).await.map_err(repository_error)
    }

    async fn canvas_program_binding(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar("SELECT to_jsonb(b) FROM issuance_service.canvas_program_bindings b WHERE id=$1 AND organization_id=$2")
            .bind(id).bind(organization_id).fetch_optional(&self.pool).await.map_err(repository_error)
    }

    async fn canvas_platform(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        sqlx::query_scalar("SELECT to_jsonb(p) FROM issuance_service.canvas_platforms p WHERE id=$1 AND organization_id=$2")
            .bind(id).bind(organization_id).fetch_optional(&self.pool).await.map_err(repository_error)
    }

    async fn save_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        let affected = sqlx::query("UPDATE issuance_service.credential_delivery_records SET status=$3,canvas_account_id=$4,external_credential_id=$5,external_issuer_id=$6,last_error=$7,metadata=$8,updated_at=$9::timestamptz WHERE id=$1 AND organization_id=$2 AND credential_id=$10 AND transaction_id=$11 AND delivery_target='canvas_credentials'")
            .bind(&record.id)
            .bind(&record.organization_id)
            .bind(&record.status)
            .bind(&record.canvas_account_id)
            .bind(&record.external_credential_id)
            .bind(&record.external_issuer_id)
            .bind(&record.last_error)
            .bind(Value::Object(record.metadata.clone()))
            .bind(&record.updated_at)
            .bind(&record.credential_id)
            .bind(&record.transaction_id)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(CanvasMirrorRepositoryError)
        }
    }

    async fn save_claimed_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
        claim_id: &str,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        let sql = format!("UPDATE issuance_service.credential_delivery_records SET status=$3,canvas_account_id=$4,external_credential_id=$5,external_issuer_id=$6,last_error=$7,metadata=$8,updated_at=$9::timestamptz WHERE id=$1 AND organization_id=$2 AND credential_id=$10 AND transaction_id=$11 AND delivery_target='canvas_credentials' AND metadata->>'{CLAIM_ID_KEY}'=$12");
        let affected = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&record.id)
            .bind(&record.organization_id)
            .bind(&record.status)
            .bind(&record.canvas_account_id)
            .bind(&record.external_credential_id)
            .bind(&record.external_issuer_id)
            .bind(&record.last_error)
            .bind(Value::Object(record.metadata.clone()))
            .bind(&record.updated_at)
            .bind(&record.credential_id)
            .bind(&record.transaction_id)
            .bind(claim_id)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(CanvasMirrorRepositoryError)
        }
    }

    async fn mark_claim_effect_started(
        &self,
        record: &CanvasMirrorDeliveryRecord,
        claim_id: &str,
        started_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        let sql = format!("UPDATE issuance_service.credential_delivery_records SET metadata=COALESCE(metadata,'{{}}'::jsonb) || jsonb_build_object('{EFFECT_STARTED_AT_KEY}',$4::text) WHERE id=$1 AND organization_id=$2 AND delivery_target='canvas_credentials' AND metadata->>'{CLAIM_ID_KEY}'=$3");
        let affected = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(&record.id)
            .bind(&record.organization_id)
            .bind(claim_id)
            .bind(started_at)
            .execute(&self.pool)
            .await
            .map_err(repository_error)?
            .rows_affected();
        if affected == 1 {
            Ok(())
        } else {
            Err(CanvasMirrorRepositoryError)
        }
    }

    async fn save_alert_event(
        &self,
        event: &CanvasMirrorAlertEvent,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_events (id,transaction_id,application_id,event_type,metadata,created_at) VALUES ($1,$2,$3,$4,$5,$6::timestamptz)",
        )
        .bind(&event.id)
        .bind(&event.transaction_id)
        .bind(&event.application_id)
        .bind(&event.event_type)
        .bind(&event.metadata)
        .bind(&event.created_at)
        .execute(&self.pool)
        .await
        .map_err(repository_error)?;
        Ok(())
    }
}

fn decode_record(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorRepositoryError> {
    let value: Value = row.try_get("value").map_err(repository_error)?;
    serde_json::from_value(value).map_err(|cause| {
        error!(%cause, "Canvas mirror delivery row could not be decoded");
        CanvasMirrorRepositoryError
    })
}

fn decode_claimed_record(
    row: sqlx::postgres::PgRow,
) -> Result<CanvasMirrorDeliveryRecord, CanvasMirrorRepositoryError> {
    let mut record = decode_record(row)?;
    record.metadata.remove(CLAIM_ID_KEY);
    record.metadata.remove(CLAIM_EXPIRES_AT_KEY);
    record.metadata.remove(EFFECT_STARTED_AT_KEY);
    Ok(record)
}

fn repository_error(cause: sqlx::Error) -> CanvasMirrorRepositoryError {
    error!(%cause, "Canvas mirror repository query failed");
    CanvasMirrorRepositoryError
}
