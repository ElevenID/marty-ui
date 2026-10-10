//! Transactional reference-only holder key ledger.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{
    holder_credential::eligible,
    holder_key::HolderKeyRecord,
    postgres::{persistence, registration},
    DeviceError,
};
use marty_holder_key_reference::belongs_to;

#[derive(Clone)]
pub struct PostgresHolderKeyRepository {
    pool: PgPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHolderKeyDeletion {
    pub provider_reference: String,
    pub registration_id: String,
    pub organization_id: String,
    pub purpose: String,
}

pub(crate) async fn revoke_and_queue(
    transaction: &mut Transaction<'_, Postgres>,
    registration_id: &str,
    purpose: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    sqlx::query("WITH retired AS (UPDATE device_registration_service.device_holder_keys SET revoked_at=GREATEST($2, created_at) WHERE registration_id=$1 AND ($3::text IS NULL OR purpose=$3) AND revoked_at IS NULL RETURNING provider_reference) INSERT INTO device_registration_service.device_holder_key_deletions (provider_reference,queued_at,retry_after) SELECT provider_reference,$2,$2 FROM retired WHERE true ON CONFLICT DO NOTHING")
        .bind(registration_id)
        .bind(now)
        .bind(purpose)
        .execute(&mut **transaction)
        .await
        .map_err(persistence)?;
    Ok(())
}

impl PostgresHolderKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reserve the exact remote name before creating a key. An interrupted
    /// create is reconciled by the stale-provision cleanup worker.
    pub async fn reserve(
        &self,
        registration_id: &str,
        purpose: &str,
        algorithm: &str,
        provider_reference: &str,
    ) -> Result<(), DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?;
        let registration =
            row.as_ref().map(registration).transpose()?.ok_or_else(|| {
                DeviceError::Forbidden("managed holder key scope is invalid".into())
            })?;
        let organization_id = registration
            .organization_id
            .as_deref()
            .ok_or_else(|| DeviceError::Forbidden("managed holder key scope is invalid".into()))?;
        if !eligible(&registration)
            || !matches!(algorithm, "EdDSA" | "ES256")
            || !belongs_to(
                provider_reference,
                organization_id,
                registration_id,
                purpose,
            )
        {
            return Err(DeviceError::Forbidden(
                "managed holder key scope is invalid".into(),
            ));
        }
        sqlx::query("INSERT INTO device_registration_service.device_holder_key_provisions (provider_reference,registration_id,user_id,organization_id,purpose,algorithm,reserved_at,cleanup_after,retry_after) VALUES ($1,$2,$3,$4,$5,$6,now(),now()+interval '1 minute',now()+interval '1 minute')")
            .bind(provider_reference)
            .bind(registration_id)
            .bind(&registration.user_id)
            .bind(organization_id)
            .bind(purpose)
            .bind(algorithm)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    /// Bind a provider-created key only to a live, keyless registration.
    /// The caller must compensate in OpenBao if this transaction fails.
    pub async fn bind(&self, key: HolderKeyRecord, now: DateTime<Utc>) -> Result<(), DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(&key.registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?;
        let registration =
            row.as_ref().map(registration).transpose()?.ok_or_else(|| {
                DeviceError::Forbidden("managed holder key scope is invalid".into())
            })?;
        if !key.valid_for(&registration) || key.created_at > now {
            return Err(DeviceError::Forbidden(
                "managed holder key scope is invalid".into(),
            ));
        }
        let reserved = sqlx::query("SELECT 1 FROM device_registration_service.device_holder_key_provisions WHERE provider_reference=$1 AND registration_id=$2 AND user_id=$3 AND organization_id=$4 AND purpose=$5 AND algorithm=$6 AND bound_at IS NULL AND cleaned_at IS NULL AND cleanup_after > now() FOR UPDATE")
            .bind(&key.provider_reference)
            .bind(&key.registration_id)
            .bind(&key.user_id)
            .bind(&key.organization_id)
            .bind(&key.purpose)
            .bind(&key.algorithm)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?;
        if reserved.is_none() {
            return Err(DeviceError::Forbidden(
                "managed holder key reservation is invalid".into(),
            ));
        }
        revoke_and_queue(
            &mut transaction,
            &key.registration_id,
            Some(&key.purpose),
            now,
        )
        .await?;
        sqlx::query("INSERT INTO device_registration_service.device_holder_keys (id,registration_id,user_id,organization_id,purpose,algorithm,provider_reference,remote_version,public_x,public_y,created_at,revoked_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL)")
            .bind(&key.id)
            .bind(&key.registration_id)
            .bind(&key.user_id)
            .bind(&key.organization_id)
            .bind(&key.purpose)
            .bind(&key.algorithm)
            .bind(&key.provider_reference)
            .bind(key.remote_version)
            .bind(&key.public_x)
            .bind(&key.public_y)
            .bind(key.created_at)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
        sqlx::query("UPDATE device_registration_service.device_holder_key_provisions SET bound_at=now() WHERE provider_reference=$1 AND bound_at IS NULL AND cleaned_at IS NULL")
            .bind(&key.provider_reference)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }

    pub async fn current(
        &self,
        registration_id: &str,
        purpose: &str,
    ) -> Result<Option<HolderKeyRecord>, DeviceError> {
        let key = sqlx::query("SELECT * FROM device_registration_service.device_holder_keys WHERE registration_id=$1 AND purpose=$2 AND revoked_at IS NULL")
            .bind(registration_id)
            .bind(purpose)
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .as_ref()
            .map(stored)
            .transpose()?;
        let Some(key) = key else { return Ok(None) };
        let registration = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1",
        )
        .bind(registration_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(persistence)?
        .as_ref()
        .map(registration)
        .transpose()?;
        if !registration
            .as_ref()
            .is_some_and(|value| key.valid_for(value))
        {
            return Err(DeviceError::Forbidden(
                "managed holder key scope is invalid".into(),
            ));
        }
        Ok(Some(key))
    }

    pub async fn revoke(
        &self,
        registration_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        sqlx::query("SELECT id FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE")
            .bind(registration_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?;
        revoke_and_queue(&mut transaction, registration_id, None, now).await?;
        transaction.commit().await.map_err(persistence)
    }

    /// Retired keys stay queued until the remote KMS confirms deletion.
    pub async fn pending_deletions(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingHolderKeyDeletion>, DeviceError> {
        if !(1..=100).contains(&limit) {
            return Err(DeviceError::BadRequest(
                "invalid holder deletion batch size".into(),
            ));
        }
        let rows = sqlx::query("SELECT k.provider_reference,k.registration_id,k.organization_id,k.purpose FROM device_registration_service.device_holder_key_deletions d JOIN device_registration_service.device_holder_keys k USING (provider_reference) WHERE d.deleted_at IS NULL AND d.retry_after <= now() AND k.revoked_at IS NOT NULL ORDER BY d.retry_after,d.provider_reference LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(persistence)?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingHolderKeyDeletion {
                    provider_reference: row.try_get("provider_reference").map_err(persistence)?,
                    registration_id: row.try_get("registration_id").map_err(persistence)?,
                    organization_id: row.try_get("organization_id").map_err(persistence)?,
                    purpose: row.try_get("purpose").map_err(persistence)?,
                })
            })
            .collect()
    }

    pub async fn mark_deleted(
        &self,
        provider_reference: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        let result = sqlx::query("UPDATE device_registration_service.device_holder_key_deletions SET deleted_at=GREATEST($2, queued_at) WHERE provider_reference=$1 AND deleted_at IS NULL")
            .bind(provider_reference)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            let already_deleted: Option<bool> = sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM device_registration_service.device_holder_key_deletions WHERE provider_reference=$1")
                .bind(provider_reference)
                .fetch_optional(&self.pool)
                .await
                .map_err(persistence)?;
            if already_deleted != Some(true) {
                return Err(DeviceError::Conflict(
                    "holder deletion is not pending".into(),
                ));
            }
        }
        Ok(())
    }

    pub async fn postpone_deletion(
        &self,
        provider_reference: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        sqlx::query("UPDATE device_registration_service.device_holder_key_deletions SET attempts=attempts+1,retry_after=GREATEST($2, queued_at)+interval '30 seconds' WHERE provider_reference=$1 AND deleted_at IS NULL")
            .bind(provider_reference)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    pub async fn expired_provisions(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingHolderKeyDeletion>, DeviceError> {
        if !(1..=100).contains(&limit) {
            return Err(DeviceError::BadRequest(
                "invalid holder cleanup batch size".into(),
            ));
        }
        let rows = sqlx::query("SELECT provider_reference,registration_id,organization_id,purpose FROM device_registration_service.device_holder_key_provisions WHERE bound_at IS NULL AND cleaned_at IS NULL AND cleanup_after <= now() AND retry_after <= now() ORDER BY retry_after,provider_reference LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(persistence)?;
        rows.into_iter()
            .map(|row| {
                Ok(PendingHolderKeyDeletion {
                    provider_reference: row.try_get("provider_reference").map_err(persistence)?,
                    registration_id: row.try_get("registration_id").map_err(persistence)?,
                    organization_id: row.try_get("organization_id").map_err(persistence)?,
                    purpose: row.try_get("purpose").map_err(persistence)?,
                })
            })
            .collect()
    }

    pub async fn abandon_provision(&self, provider_reference: &str) -> Result<(), DeviceError> {
        sqlx::query("UPDATE device_registration_service.device_holder_key_provisions SET cleanup_after=GREATEST(reserved_at+interval '1 second',now()),retry_after=GREATEST(reserved_at+interval '1 second',now()) WHERE provider_reference=$1 AND bound_at IS NULL AND cleaned_at IS NULL")
            .bind(provider_reference)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    pub async fn mark_provision_cleaned(
        &self,
        provider_reference: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        let result = sqlx::query("UPDATE device_registration_service.device_holder_key_provisions SET cleaned_at=GREATEST($2,cleanup_after) WHERE provider_reference=$1 AND bound_at IS NULL AND cleaned_at IS NULL AND cleanup_after <= now()")
            .bind(provider_reference)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        if result.rows_affected() != 1 {
            let cleaned: Option<bool> = sqlx::query_scalar("SELECT cleaned_at IS NOT NULL FROM device_registration_service.device_holder_key_provisions WHERE provider_reference=$1 AND bound_at IS NULL")
                .bind(provider_reference)
                .fetch_optional(&self.pool)
                .await
                .map_err(persistence)?;
            if cleaned != Some(true) {
                return Err(DeviceError::Conflict(
                    "holder provision is not pending cleanup".into(),
                ));
            }
        }
        Ok(())
    }

    pub async fn postpone_provision(
        &self,
        provider_reference: &str,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        sqlx::query("UPDATE device_registration_service.device_holder_key_provisions SET retry_after=GREATEST($2,cleanup_after)+interval '30 seconds' WHERE provider_reference=$1 AND bound_at IS NULL AND cleaned_at IS NULL AND cleanup_after <= now()")
            .bind(provider_reference)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }
}

pub(crate) fn stored(row: &sqlx::postgres::PgRow) -> Result<HolderKeyRecord, DeviceError> {
    Ok(HolderKeyRecord {
        id: row.try_get("id").map_err(persistence)?,
        registration_id: row.try_get("registration_id").map_err(persistence)?,
        user_id: row.try_get("user_id").map_err(persistence)?,
        organization_id: row.try_get("organization_id").map_err(persistence)?,
        purpose: row.try_get("purpose").map_err(persistence)?,
        algorithm: row.try_get("algorithm").map_err(persistence)?,
        provider_reference: row.try_get("provider_reference").map_err(persistence)?,
        remote_version: row.try_get("remote_version").map_err(persistence)?,
        public_x: row.try_get("public_x").map_err(persistence)?,
        public_y: row.try_get("public_y").map_err(persistence)?,
        created_at: row.try_get("created_at").map_err(persistence)?,
        revoked_at: row.try_get("revoked_at").map_err(persistence)?,
    })
}
