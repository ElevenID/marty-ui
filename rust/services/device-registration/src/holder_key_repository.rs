//! Transactional reference-only holder key ledger.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use crate::{
    holder_key::HolderKeyRecord,
    postgres::{persistence, registration},
    DeviceError,
};

#[derive(Clone)]
pub struct PostgresHolderKeyRepository {
    pool: PgPool,
}

impl PostgresHolderKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
        sqlx::query("UPDATE device_registration_service.device_holder_keys SET revoked_at=GREATEST($3, created_at) WHERE registration_id=$1 AND purpose=$2 AND revoked_at IS NULL")
            .bind(&key.registration_id)
            .bind(&key.purpose)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
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
        sqlx::query("UPDATE device_registration_service.device_holder_keys SET revoked_at=GREATEST($2, created_at) WHERE registration_id=$1 AND revoked_at IS NULL")
            .bind(registration_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }
}

fn stored(row: &sqlx::postgres::PgRow) -> Result<HolderKeyRecord, DeviceError> {
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
