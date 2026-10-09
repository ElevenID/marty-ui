//! Authorize a device bearer and hold the registration lock through remote signing.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use marty_holder_key_reference::{HolderKeyScope, HolderSignature, SignHolderKeyRequest};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    holder_credential::{authorize, HolderCredentialRecord},
    holder_credential_repository,
    holder_key_client::HolderKeyClient,
    holder_key_repository,
    postgres::{persistence, registration},
    DeviceError,
};

const INVALID: &str = "holder signing authorization is invalid";
const MAX_SIGNING_INPUT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct HolderSigner {
    pool: PgPool,
    client: HolderKeyClient,
}

impl HolderSigner {
    pub fn new(pool: PgPool, client: HolderKeyClient) -> Self {
        Self { pool, client }
    }

    /// Internal only. A public caller must separately establish device enrollment
    /// and user/session authorization before issuing the bearer.
    pub async fn sign(
        &self,
        bearer: &str,
        user_id: &str,
        organization_id: &str,
        purpose: &str,
        payload: &[u8],
    ) -> Result<HolderSignature, DeviceError> {
        if !matches!(purpose, "holder_binding" | "presentation_signing")
            || payload.is_empty()
            || payload.len() > MAX_SIGNING_INPUT_BYTES
        {
            return Err(DeviceError::BadRequest(
                "holder signing input is invalid".into(),
            ));
        }
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let mut transaction = self.pool.begin().await.map_err(persistence)?;
        let registration_id: Option<String> = sqlx::query_scalar("SELECT registration_id FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1")
            .bind(digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?;
        let registration_id =
            registration_id.ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        // Replacement and deactivation acquire this lock first. Keep it until
        // the bounded remote call returns, so neither can revoke mid-signature.
        let device_row = sqlx::query(
            "SELECT * FROM device_registration_service.device_registrations WHERE id=$1 FOR UPDATE",
        )
        .bind(&registration_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let device = registration(&device_row)?;
        let credential_row = sqlx::query("SELECT * FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1 FOR UPDATE")
            .bind(digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let credential: HolderCredentialRecord =
            holder_credential_repository::stored(&credential_row)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(persistence)?;
        authorize(&credential, bearer, &device, user_id, organization_id, now)?;
        let key_row = sqlx::query("SELECT * FROM device_registration_service.device_holder_keys WHERE registration_id=$1 AND purpose=$2 AND revoked_at IS NULL FOR UPDATE")
            .bind(&registration_id)
            .bind(purpose)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let key = holder_key_repository::stored(&key_row)?;
        if !key.valid_for(&device) {
            return Err(DeviceError::Forbidden(INVALID.into()));
        }
        let result = self
            .client
            .sign(&SignHolderKeyRequest {
                scope: HolderKeyScope {
                    organization_id: key.organization_id.clone(),
                    registration_id: key.registration_id.clone(),
                    purpose: key.purpose.clone(),
                    provider_reference: key.provider_reference.clone(),
                },
                algorithm: key.algorithm.clone(),
                key_version: key.remote_version as u64,
                public_jwk: key.public_jwk(),
                payload_b64: URL_SAFE_NO_PAD.encode(payload),
            })
            .await?;
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }
}
