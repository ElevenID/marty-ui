//! Authorize a device bearer and hold the registration lock through remote signing.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use marty_holder_key_reference::{HolderKeyScope, HolderSignature, SignHolderKeyRequest};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::{
    control_plane::MembershipAuthorizer,
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
    memberships: Arc<dyn MembershipAuthorizer>,
}

impl HolderSigner {
    pub fn new(
        pool: PgPool,
        client: HolderKeyClient,
        memberships: Arc<dyn MembershipAuthorizer>,
    ) -> Self {
        Self {
            pool,
            client,
            memberships,
        }
    }

    /// Resolve scope from the digest-only bearer record. No public caller may
    /// select a user or organization for holder signing.
    pub async fn sign_from_bearer(
        &self,
        bearer: &str,
        purpose: &str,
        payload: &[u8],
    ) -> Result<HolderSignature, DeviceError> {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let row = sqlx::query("SELECT * FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let credential = holder_credential_repository::stored(&row)?;
        self.sign_inner(
            bearer,
            &credential.user_id,
            &credential.organization_id,
            purpose,
            payload,
            None,
        )
        .await
    }

    /// The pending device can prove its remote key only for this fixed,
    /// ticket-bound challenge. General signing remains unavailable until ack.
    pub async fn sign_pairing_confirmation(
        &self,
        bearer: &str,
        pairing_id: &str,
    ) -> Result<HolderSignature, DeviceError> {
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        let row = sqlx::query("SELECT user_id,organization_id FROM device_registration_service.device_holder_credentials WHERE token_sha256=$1")
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let user_id: String = row.try_get("user_id").map_err(persistence)?;
        let organization_id: String = row.try_get("organization_id").map_err(persistence)?;
        self.sign_inner(
            bearer,
            &user_id,
            &organization_id,
            "holder_binding",
            format!("marty-pairing-confirm:{pairing_id}").as_bytes(),
            Some(pairing_id),
        )
        .await
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
        self.sign_inner(bearer, user_id, organization_id, purpose, payload, None)
            .await
    }

    async fn sign_inner(
        &self,
        bearer: &str,
        user_id: &str,
        organization_id: &str,
        purpose: &str,
        payload: &[u8],
        pending_pairing_id: Option<&str>,
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
        let pairing = sqlx::query("SELECT pairing_id,confirmed_at,expires_at,expired_at FROM device_registration_service.device_pairing_confirmations WHERE registration_id=$1 FOR UPDATE")
            .bind(&registration_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(persistence)?
            .ok_or_else(|| DeviceError::Forbidden(INVALID.into()))?;
        let confirmed: Option<DateTime<Utc>> =
            pairing.try_get("confirmed_at").map_err(persistence)?;
        let expires_at: DateTime<Utc> = pairing.try_get("expires_at").map_err(persistence)?;
        let expired: Option<DateTime<Utc>> = pairing.try_get("expired_at").map_err(persistence)?;
        let stored_pairing_id: String = pairing.try_get("pairing_id").map_err(persistence)?;
        match pending_pairing_id {
            Some(id)
                if id == stored_pairing_id
                    && expired.is_none()
                    && (confirmed.is_some() || expires_at > now) => {}
            None if confirmed.is_some() && expired.is_none() => {}
            _ => return Err(DeviceError::Forbidden(INVALID.into())),
        }
        self.memberships
            .require_active(&credential.user_id, &credential.organization_id)
            .await?;
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
        if pending_pairing_id.is_some() {
            let public: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&key.public_x)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    DeviceError::Persistence("remote pairing public key is invalid".into())
                })?;
            let signature = URL_SAFE_NO_PAD
                .decode(&result.signature_b64)
                .ok()
                .and_then(|bytes| Signature::from_slice(&bytes).ok())
                .ok_or_else(|| {
                    DeviceError::Persistence("remote pairing signature is invalid".into())
                })?;
            if result.signature_encoding != "raw"
                || VerifyingKey::from_bytes(&public)
                    .and_then(|key| key.verify_strict(payload, &signature))
                    .is_err()
            {
                return Err(DeviceError::Persistence(
                    "remote pairing signature is invalid".into(),
                ));
            }
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(result)
    }
}
