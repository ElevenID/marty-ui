//! Durable digest-only storage for device bearer credentials.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::{
    holder_credential::{
        authorize, issue, valid_record_for, HolderCredentialRecord, IssuedHolderCredential,
    },
    postgres::{persistence, registration},
    DeviceError, DeviceRepository,
};

#[async_trait]
pub trait HolderCredentialRepository: Send + Sync {
    /// Atomically revoke the former current credential and store this digest.
    async fn replace(
        &self,
        record: HolderCredentialRecord,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError>;
    async fn find_by_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<HolderCredentialRecord>, DeviceError>;
    async fn revoke(&self, registration_id: &str, now: DateTime<Utc>) -> Result<(), DeviceError>;
}

/// Resolve a bearer through the digest-only store and recheck live device scope.
pub async fn authorize_bearer(
    holders: &dyn HolderCredentialRepository,
    devices: &dyn DeviceRepository,
    bearer: &str,
    user_id: &str,
    organization_id: &str,
    now: DateTime<Utc>,
) -> Result<HolderCredentialRecord, DeviceError> {
    let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
    let record = holders
        .find_by_digest(&digest)
        .await?
        .ok_or_else(|| DeviceError::Forbidden("holder device credential is invalid".into()))?;
    let registration = devices
        .get(&record.registration_id)
        .await?
        .ok_or_else(|| DeviceError::Forbidden("holder device credential is invalid".into()))?;
    authorize(
        &record,
        bearer,
        &registration,
        user_id,
        organization_id,
        now,
    )?;
    Ok(record)
}

pub struct MemoryHolderCredentialRepository {
    devices: Arc<dyn DeviceRepository>,
    records: Mutex<HashMap<String, HolderCredentialRecord>>,
}

impl MemoryHolderCredentialRepository {
    pub fn new(devices: Arc<dyn DeviceRepository>) -> Self {
        Self {
            devices,
            records: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl HolderCredentialRepository for MemoryHolderCredentialRepository {
    async fn replace(
        &self,
        record: HolderCredentialRecord,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        let device = self
            .devices
            .get(&record.registration_id)
            .await?
            .ok_or_else(|| DeviceError::Forbidden("holder device credential is invalid".into()))?;
        if !valid_record_for(&record, &device, now) {
            return Err(DeviceError::Forbidden(
                "holder device credential is invalid".into(),
            ));
        }
        let mut records = self.records.lock().await;
        if records.contains_key(&record.id)
            || records
                .values()
                .any(|existing| existing.token_sha256 == record.token_sha256)
        {
            return Err(DeviceError::Conflict(
                "holder device credential already exists".into(),
            ));
        }
        for current in records.values_mut() {
            if current.registration_id == record.registration_id && current.revoked_at.is_none() {
                current.revoked_at = Some(now);
            }
        }
        records.insert(record.id.clone(), record);
        Ok(())
    }

    async fn find_by_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<HolderCredentialRecord>, DeviceError> {
        Ok(self
            .records
            .lock()
            .await
            .values()
            .find(|record| &record.token_sha256 == digest)
            .cloned())
    }

    async fn revoke(&self, registration_id: &str, now: DateTime<Utc>) -> Result<(), DeviceError> {
        for record in self.records.lock().await.values_mut() {
            if record.registration_id == registration_id && record.revoked_at.is_none() {
                record.revoked_at = Some(now);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PostgresHolderCredentialRepository {
    pool: PgPool,
}

impl PostgresHolderCredentialRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Internal issuance boundary. The caller must separately prove enrollment
    /// authority before receiving this one-time bearer; no public route calls it.
    pub async fn issue_for_registration(
        &self,
        registration_id: &str,
        user_id: &str,
        organization_id: &str,
        lifetime: Duration,
    ) -> Result<IssuedHolderCredential, DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        .ok_or_else(|| DeviceError::Forbidden("holder device credential is invalid".into()))?;
        let device = registration(&row)?;
        if device.user_id != user_id || device.organization_id.as_deref() != Some(organization_id) {
            return Err(DeviceError::Forbidden(
                "holder device credential is invalid".into(),
            ));
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        let issued = issue(&device, now, lifetime)?;
        replace_locked(&mut transaction, &issued.record, now).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(issued)
    }
}

pub(crate) async fn replace_locked(
    transaction: &mut Transaction<'_, Postgres>,
    record: &HolderCredentialRecord,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    sqlx::query("UPDATE device_registration_service.device_holder_credentials SET revoked_at=GREATEST($2,issued_at) WHERE registration_id=$1 AND revoked_at IS NULL")
        .bind(&record.registration_id)
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(persistence)?;
    sqlx::query("INSERT INTO device_registration_service.device_holder_credentials (id, registration_id, user_id, organization_id, token_sha256, issued_at, expires_at, revoked_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL)")
        .bind(&record.id)
        .bind(&record.registration_id)
        .bind(&record.user_id)
        .bind(&record.organization_id)
        .bind(record.token_sha256.as_slice())
        .bind(record.issued_at)
        .bind(record.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(persistence)?;
    Ok(())
}

pub(crate) fn stored(row: &sqlx::postgres::PgRow) -> Result<HolderCredentialRecord, DeviceError> {
    let raw: Vec<u8> = row.try_get("token_sha256").map_err(persistence)?;
    let token_sha256 = raw
        .try_into()
        .map_err(|_| DeviceError::Persistence("stored holder digest is invalid".into()))?;
    Ok(HolderCredentialRecord {
        id: row.try_get("id").map_err(persistence)?,
        registration_id: row.try_get("registration_id").map_err(persistence)?,
        user_id: row.try_get("user_id").map_err(persistence)?,
        organization_id: row.try_get("organization_id").map_err(persistence)?,
        token_sha256,
        issued_at: row.try_get("issued_at").map_err(persistence)?,
        expires_at: row.try_get("expires_at").map_err(persistence)?,
        revoked_at: row.try_get("revoked_at").map_err(persistence)?,
    })
}

#[async_trait]
impl HolderCredentialRepository for PostgresHolderCredentialRepository {
    async fn replace(
        &self,
        record: HolderCredentialRecord,
        now: DateTime<Utc>,
    ) -> Result<(), DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(&record.registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?;
        let device =
            row.as_ref().map(registration).transpose()?.ok_or_else(|| {
                DeviceError::Forbidden("holder device credential is invalid".into())
            })?;
        if !valid_record_for(&record, &device, now) {
            return Err(DeviceError::Forbidden(
                "holder device credential is invalid".into(),
            ));
        }
        replace_locked(&mut transaction, &record, now).await?;
        transaction.commit().await.map_err(persistence)
    }

    async fn find_by_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<Option<HolderCredentialRecord>, DeviceError> {
        sqlx::query("SELECT * FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .as_ref()
            .map(stored)
            .transpose()
    }

    async fn revoke(&self, registration_id: &str, now: DateTime<Utc>) -> Result<(), DeviceError> {
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        sqlx::query("SELECT id FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE")
            .bind(registration_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?;
        sqlx::query("UPDATE device_registration_service.device_holder_credentials SET revoked_at=GREATEST($2, issued_at) WHERE registration_id=$1 AND revoked_at IS NULL")
            .bind(registration_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(persistence)?;
        transaction.commit().await.map_err(persistence)
    }
}
