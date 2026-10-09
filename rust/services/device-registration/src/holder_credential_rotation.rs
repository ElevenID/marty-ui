//! Recoverable digest-only bearer renewal for an already confirmed mobile device.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    control_plane::MembershipAuthorizer,
    holder_credential::{
        authorize, canonical_bearer, issue_with_bearer, valid_record_for, CREDENTIAL_LIFETIME,
    },
    holder_credential_repository::{replace_locked, stored},
    postgres::{persistence, registration},
    DeviceError,
};

const INVALID: &str = "holder credential rotation is invalid";

#[derive(Debug, Serialize)]
pub struct RotatedHolderCredential {
    pub registration_id: String,
    pub credential_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct HolderCredentialRotator {
    pool: PgPool,
    memberships: Arc<dyn MembershipAuthorizer>,
}

impl HolderCredentialRotator {
    pub fn new(pool: PgPool, memberships: Arc<dyn MembershipAuthorizer>) -> Self {
        Self { pool, memberships }
    }

    /// The mobile client persists the replacement in a pending secure-storage
    /// slot before calling this endpoint. Repeating the same old/new pair
    /// after a lost response returns the current expiry without rotating twice.
    pub async fn rotate(
        &self,
        current_bearer: &str,
        replacement_bearer: &str,
    ) -> Result<RotatedHolderCredential, DeviceError> {
        if !canonical_bearer(current_bearer)
            || !canonical_bearer(replacement_bearer)
            || current_bearer == replacement_bearer
        {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        let current_digest: [u8; 32] = Sha256::digest(current_bearer.as_bytes()).into();
        let replacement_digest: [u8; 32] = Sha256::digest(replacement_bearer.as_bytes()).into();
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let registration_id: String = sqlx::query_scalar("SELECT registration_id FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1")
            .bind(current_digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let device_row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(&registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let device = registration(&device_row)?;
        let current_row = sqlx::query("SELECT * FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1 FOR UPDATE")
            .bind(current_digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let current = stored(&current_row)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        if !device.is_active
            || current.user_id != device.user_id
            || device.organization_id.as_deref() != Some(current.organization_id.as_str())
            || current.registration_id != registration_id
        {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        let paired: Option<i64> = sqlx::query_scalar("SELECT 1::bigint FROM device_registration_service.device_pairing_confirmations WHERE registration_id=$1 AND confirmed_at IS NOT NULL AND expired_at IS NULL")
            .bind(&registration_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?;
        if paired.is_none() {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        self.memberships
            .require_active(&current.user_id, &current.organization_id)
            .await?;
        if let Some(revoked_at) = current.revoked_at {
            let replacement_row = sqlx::query("SELECT * FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1 AND registration_id=$2 FOR UPDATE")
                .bind(replacement_digest.as_slice())
                .bind(&registration_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(persistence)?
                .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
            let replacement = stored(&replacement_row)?;
            if !valid_record_for(&replacement, &device, now) || replacement.issued_at < revoked_at {
                return Err(DeviceError::Forbidden(INVALID.into()));
            }
            return Ok(RotatedHolderCredential {
                registration_id,
                credential_expires_at: replacement.expires_at,
            });
        }
        authorize(
            &current,
            current_bearer,
            &device,
            &current.user_id,
            &current.organization_id,
            now,
        )?;
        let issued = issue_with_bearer(
            &device,
            now,
            CREDENTIAL_LIFETIME,
            replacement_bearer.to_owned(),
        )?;
        replace_locked(&mut transaction, &issued.record, now).await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(RotatedHolderCredential {
            registration_id,
            credential_expires_at: issued.record.expires_at,
        })
    }
}
