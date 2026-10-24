//! Durable, ticket-scoped browser confirmation; no bearer or key is persisted.

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{sync::Arc, time::Duration as StdDuration};

use crate::{
    holder_credential::canonical_bearer, pairing_ticket::PairingScope, postgres::persistence,
    DeviceError, DeviceRepository,
};

const INVALID: &str = "wallet pairing confirmation is invalid";
const CONFIRM_GRACE: Duration = Duration::minutes(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingConfirmationStatus {
    pub organization_id: String,
    pub state: &'static str,
    pub registration_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundWalletTrustProfile {
    pub user_id: String,
    pub organization_id: String,
    pub trust_profile_id: String,
}

#[derive(Clone)]
pub struct PostgresPairingConfirmations {
    pool: PgPool,
}

impl PostgresPairingConfirmations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Profile selection is fixed by the browser ticket, not a mobile query parameter.
    pub async fn profile_for_bearer(
        &self,
        bearer: &str,
    ) -> Result<BoundWalletTrustProfile, DeviceError> {
        if !canonical_bearer(bearer) {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let row = sqlx::query("SELECT p.user_id,p.organization_id,p.trust_profile_id FROM device_registration_service.device_holder_credentials c JOIN device_registration_service.device_pairing_confirmations p ON p.registration_id=c.registration_id JOIN device_registration_service.device_registrations d ON d.id=c.registration_id WHERE c.token_sha256=$1 AND c.revoked_at IS NULL AND c.issued_at<=clock_timestamp() AND c.expires_at>clock_timestamp() AND p.confirmed_at IS NOT NULL AND p.expired_at IS NULL AND c.user_id=p.user_id AND c.organization_id=p.organization_id AND d.user_id=p.user_id AND d.organization_id=p.organization_id AND d.is_active=true")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        Ok(BoundWalletTrustProfile {
            user_id: row.try_get("user_id").map_err(persistence)?,
            organization_id: row.try_get("organization_id").map_err(persistence)?,
            trust_profile_id: row.try_get("trust_profile_id").map_err(persistence)?,
        })
    }

    pub async fn record_issued(&self, scope: &PairingScope) -> Result<(), DeviceError> {
        let expires_at = scope
            .expires_at
            .checked_add_signed(CONFIRM_GRACE)
            .ok_or_else(|| DeviceError::Persistence("pairing status expiry is invalid".into()))?;
        sqlx::query("INSERT INTO device_registration_service.device_pairing_confirmations (pairing_id,user_id,organization_id,trust_profile_id,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(&scope.pairing_id)
            .bind(&scope.user_id)
            .bind(&scope.organization_id)
            .bind(&scope.trust_profile_id)
            .bind(scope.issued_at)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    pub async fn record_redeemed(
        &self,
        scope: &PairingScope,
        registration_id: &str,
    ) -> Result<(), DeviceError> {
        let updated = sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET registration_id=$2 WHERE pairing_id=$1 AND user_id=$3 AND organization_id=$4 AND registration_id IS NULL AND confirmed_at IS NULL AND expired_at IS NULL AND expires_at>clock_timestamp()")
            .bind(&scope.pairing_id)
            .bind(registration_id)
            .bind(&scope.user_id)
            .bind(&scope.organization_id)
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        Ok(())
    }

    /// Called only after the remote holder key has signed a confirmation
    /// challenge. The current bearer, registration and pairing row must still
    /// agree at the database clock; rotation or deactivation fails closed.
    pub async fn confirm(&self, pairing_id: &str, bearer: &str) -> Result<(), DeviceError> {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let updated = sqlx::query("UPDATE device_registration_service.device_pairing_confirmations p SET confirmed_at=clock_timestamp() FROM device_registration_service.device_holder_credentials c, device_registration_service.device_registrations d WHERE p.pairing_id=$1 AND p.registration_id=c.registration_id AND c.token_sha256=$2 AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() AND c.user_id=p.user_id AND c.organization_id=p.organization_id AND d.id=p.registration_id AND d.user_id=p.user_id AND d.organization_id=p.organization_id AND d.is_active=true AND p.confirmed_at IS NULL AND p.expired_at IS NULL AND p.expires_at>clock_timestamp()")
            .bind(pairing_id)
            .bind(digest.as_slice())
            .execute(&self.pool)
            .await
            .map_err(persistence)?;
        if updated.rows_affected() != 1 {
            let already_confirmed: Option<i64> = sqlx::query_scalar("SELECT 1::bigint FROM device_registration_service.device_pairing_confirmations p JOIN device_registration_service.device_holder_credentials c ON c.registration_id=p.registration_id JOIN device_registration_service.device_registrations d ON d.id=p.registration_id WHERE p.pairing_id=$1 AND p.confirmed_at IS NOT NULL AND p.expired_at IS NULL AND c.token_sha256=$2 AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp() AND c.user_id=p.user_id AND c.organization_id=p.organization_id AND d.user_id=p.user_id AND d.organization_id=p.organization_id AND d.is_active=true")
                .bind(pairing_id)
                .bind(digest.as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(persistence)?;
            if already_confirmed.is_none() {
                return Err(DeviceError::Forbidden(INVALID.into()));
            }
        }
        Ok(())
    }

    pub async fn status(
        &self,
        pairing_id: &str,
        user_id: &str,
    ) -> Result<PairingConfirmationStatus, DeviceError> {
        let row = sqlx::query("SELECT p.organization_id,p.registration_id,p.confirmed_at,p.expired_at,p.expires_at<=clock_timestamp() AS timed_out,COALESCE(d.is_active,false) AS registration_active FROM device_registration_service.device_pairing_confirmations p LEFT JOIN device_registration_service.device_registrations d ON d.id=p.registration_id WHERE p.pairing_id=$1 AND p.user_id=$2")
            .bind(pairing_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::NotFound("Wallet pairing was not found".into()))?;
        let confirmed: Option<chrono::DateTime<Utc>> =
            row.try_get("confirmed_at").map_err(persistence)?;
        let expired: Option<chrono::DateTime<Utc>> =
            row.try_get("expired_at").map_err(persistence)?;
        let timed_out: bool = row.try_get("timed_out").map_err(persistence)?;
        let registration_id: Option<String> =
            row.try_get("registration_id").map_err(persistence)?;
        let active: bool = row.try_get("registration_active").map_err(persistence)?;
        let state = if confirmed.is_some() && active {
            "paired"
        } else if expired.is_some() || timed_out || confirmed.is_some() {
            "expired"
        } else {
            "pending"
        };
        Ok(PairingConfirmationStatus {
            organization_id: row.try_get("organization_id").map_err(persistence)?,
            state,
            registration_id: (state == "paired").then_some(registration_id).flatten(),
        })
    }

    /// Expired, unconfirmed enrollments never become usable. Deactivation
    /// revokes their bearer and queues the bound KMS keys for durable deletion.
    pub async fn expire_once(
        &self,
        devices: &Arc<dyn DeviceRepository>,
    ) -> Result<usize, DeviceError> {
        let rows = sqlx::query("SELECT pairing_id,registration_id FROM device_registration_service.device_pairing_confirmations WHERE confirmed_at IS NULL AND expired_at IS NULL AND expires_at<=clock_timestamp() ORDER BY expires_at LIMIT 100")
            .fetch_all(&self.pool)
            .await
            .map_err(persistence)?;
        for row in &rows {
            let registration_id: Option<String> =
                row.try_get("registration_id").map_err(persistence)?;
            if let Some(registration_id) = registration_id {
                devices.deactivate(&registration_id).await?;
            }
            let pairing_id: String = row.try_get("pairing_id").map_err(persistence)?;
            sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET expired_at=clock_timestamp() WHERE pairing_id=$1 AND confirmed_at IS NULL AND expired_at IS NULL AND expires_at<=clock_timestamp()")
                .bind(pairing_id)
                .execute(&self.pool)
                .await
                .map_err(persistence)?;
        }
        Ok(rows.len())
    }

    pub async fn expire_forever(self, devices: Arc<dyn DeviceRepository>) {
        let mut interval = tokio::time::interval(StdDuration::from_secs(5));
        loop {
            interval.tick().await;
            match self.expire_once(&devices).await {
                Ok(count) if count > 0 => {
                    tracing::info!(count, "expired unconfirmed wallet pairings")
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("wallet pairing expiry pass could not complete"),
            }
        }
    }
}
