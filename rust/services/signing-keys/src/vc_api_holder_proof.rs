//! One-request OID4VCI holder proofs for the Gateway VC-API bridge.
//!
//! Transit creates and signs with a non-exportable Ed25519 key. The key is
//! deleted before a proof is returned, preserving the bridge's ephemeral
//! holder identity without placing private material in Gateway or this service.

use std::{env, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    config::Config,
    kms::{self, ProviderRequest, SignRequest},
};

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NONCE_BYTES: usize = 1024;
const STALE_KEY_AGE_SECONDS: i64 = 60 * 60;
const KEY_PREFIX: &str = "vcapi-holder-";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderProofRequest {
    pub organization_id: String,
    pub issuer_url: String,
    pub nonce: String,
}

#[derive(Debug, Serialize)]
pub struct HolderProofResponse {
    pub proof_jwt: String,
}

#[derive(Clone)]
pub struct OpenBaoHolderProofProvider {
    endpoint: String,
    token: String,
    issuer_base_url: String,
}

#[derive(Debug, Error)]
pub enum HolderProofError {
    #[error("VC-API holder proof provider is unavailable")]
    Unavailable,
    #[error("VC-API holder proof request is invalid")]
    InvalidRequest,
    #[error("VC-API holder proof operation failed")]
    Provider,
}

impl OpenBaoHolderProofProvider {
    pub fn from_environment() -> Result<Self, HolderProofError> {
        let config = Config::from_env().map_err(|_| HolderProofError::Unavailable)?;
        let endpoint = config.bao_addr.ok_or(HolderProofError::Unavailable)?;
        let token = config.bao_token.ok_or(HolderProofError::Unavailable)?;
        let issuer_base_url =
            env::var("ISSUER_BASE_URL").map_err(|_| HolderProofError::Unavailable)?;
        Self::new(endpoint, token, issuer_base_url)
    }

    pub fn new(
        endpoint: String,
        token: String,
        issuer_base_url: String,
    ) -> Result<Self, HolderProofError> {
        let endpoint_url = Url::parse(&endpoint).map_err(|_| HolderProofError::Unavailable)?;
        let issuer_url = Url::parse(&issuer_base_url).map_err(|_| HolderProofError::Unavailable)?;
        if !matches!(endpoint_url.scheme(), "https" | "http") {
            return Err(HolderProofError::Unavailable);
        }
        if !matches!(issuer_url.scheme(), "https" | "http")
            || !endpoint_url.username().is_empty()
            || endpoint_url.password().is_some()
            || !issuer_url.username().is_empty()
            || issuer_url.password().is_some()
            || endpoint_url.path() != "/"
            || issuer_url.path() != "/"
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
            || issuer_url.query().is_some()
            || issuer_url.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err(HolderProofError::Unavailable);
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            token,
            issuer_base_url: issuer_base_url.trim_end_matches('/').to_owned(),
        })
    }

    fn validate(&self, request: &HolderProofRequest) -> Result<(), HolderProofError> {
        if request.organization_id.is_empty()
            || request.organization_id.len() > 128
            || !request
                .organization_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || request.issuer_url
                != format!("{}/org/{}", self.issuer_base_url, request.organization_id)
            || request.nonce.is_empty()
            || request.nonce.len() > MAX_NONCE_BYTES
            || request.nonce.chars().any(char::is_control)
        {
            return Err(HolderProofError::InvalidRequest);
        }
        Ok(())
    }

    pub async fn issue(
        &self,
        request: HolderProofRequest,
    ) -> Result<HolderProofResponse, HolderProofError> {
        self.validate(&request)?;
        let tenant_digest = Sha256::digest(request.organization_id.as_bytes());
        let key_name = format!(
            "{KEY_PREFIX}{}-{}-{}",
            Utc::now().timestamp(),
            hex::encode(&tenant_digest[..8]),
            Uuid::new_v4().simple()
        );
        let config = self.service_config(&key_name);
        let metadata = match kms::create_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        {
            Ok(metadata) => metadata,
            Err(_) => {
                // A timed-out create may have succeeded remotely. Try to delete it.
                let _ = self.delete_key(&key_name).await;
                return Err(HolderProofError::Provider);
            }
        };

        let result = self.issue_with_key(config, metadata, &request).await;
        let cleanup = self.delete_key(&key_name).await;
        if cleanup.is_err() {
            tracing::error!(key_reference = %key_name, "ephemeral VC-API holder key cleanup failed");
            return Err(HolderProofError::Provider);
        }
        result.map(|proof_jwt| HolderProofResponse { proof_jwt })
    }

    /// Reconcile keys left by process death or an uncertain create/delete result.
    /// Keys younger than one hour may still belong to an in-flight request.
    pub async fn reap_stale_keys(&self) -> Result<usize, HolderProofError> {
        let client = Client::new();
        let response = client
            .get(format!("{}/v1/transit/keys?list=true", self.endpoint))
            .timeout(TIMEOUT)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|_| HolderProofError::Provider)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(0);
        }
        let response = response
            .error_for_status()
            .map_err(|_| HolderProofError::Provider)?;
        let body: Value = response
            .json()
            .await
            .map_err(|_| HolderProofError::Provider)?;
        let keys = body["data"]["keys"]
            .as_array()
            .ok_or(HolderProofError::Provider)?;
        let cutoff = Utc::now().timestamp() - STALE_KEY_AGE_SECONDS;
        let mut deleted = 0;
        for key in keys {
            let Some(name) = key.as_str() else { continue };
            let Some(timestamp) = name
                .strip_prefix(KEY_PREFIX)
                .and_then(|suffix| suffix.split('-').next())
                .and_then(|timestamp| timestamp.parse::<i64>().ok())
            else {
                continue;
            };
            if timestamp > cutoff || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                continue;
            }
            self.delete_key(name).await?;
            deleted += 1;
        }
        Ok(deleted)
    }

    fn service_config(&self, key_name: &str) -> Value {
        json!({
            "id":"managed-openbao-transit",
            "service_type":"openbao-transit",
            "endpoint":self.endpoint,
            "mount":"transit",
            "key_reference":key_name,
            "algorithm":"EdDSA",
            "auth_reference":self.token,
        })
    }

    async fn delete_key(&self, key_name: &str) -> Result<(), HolderProofError> {
        kms::delete_managed_openbao(ProviderRequest {
            service_config: self.service_config(key_name),
        })
        .await
        .map_err(|_| HolderProofError::Provider)
    }

    async fn issue_with_key(
        &self,
        config: Value,
        metadata: Value,
        request: &HolderProofRequest,
    ) -> Result<String, HolderProofError> {
        if metadata["status"] != "active"
            || metadata["type"] != "ed25519"
            || metadata["exportable"] != false
            || metadata["allow_plaintext_backup"] != false
            || metadata["deletion_allowed"] != false
        {
            return Err(HolderProofError::Provider);
        }
        let public = metadata
            .get("public_jwk")
            .ok_or(HolderProofError::Provider)?;
        let public_bytes = ed25519_public_bytes(public)?;
        let mut multicodec = Vec::with_capacity(34);
        multicodec.extend_from_slice(&[0xed, 0x01]);
        multicodec.extend_from_slice(&public_bytes);
        let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
        let header = json!({
            "alg":"EdDSA", "typ":"openid4vci-proof+jwt",
            "kid":format!("{did}#{did}"),
        });
        let claims = json!({
            "iss":did, "aud":request.issuer_url,
            "iat":Utc::now().timestamp(), "nonce":request.nonce,
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&header).map_err(|_| HolderProofError::Provider)?),
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&claims).map_err(|_| HolderProofError::Provider)?),
        );
        let signed = kms::sign(SignRequest {
            service_config: config,
            payload_b64: URL_SAFE_NO_PAD.encode(signing_input.as_bytes()),
        })
        .await
        .map_err(|_| HolderProofError::Provider)?;
        if signed.signature_encoding != "raw" {
            return Err(HolderProofError::Provider);
        }
        let proof = format!("{signing_input}.{}", signed.signature_b64);
        marty_oid4vci::proof::verify_jwt_proof(
            &proof,
            &request.issuer_url,
            Some(&request.nonce),
            300,
        )
        .map_err(|_| HolderProofError::Provider)?;
        Ok(proof)
    }
}

fn ed25519_public_bytes(public: &Value) -> Result<[u8; 32], HolderProofError> {
    let object = public.as_object().ok_or(HolderProofError::Provider)?;
    if object.get("kty").and_then(Value::as_str) != Some("OKP")
        || object.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || object
            .keys()
            .any(|key| matches!(key.as_str(), "d" | "p" | "q" | "dp" | "dq" | "qi" | "k"))
    {
        return Err(HolderProofError::Provider);
    }
    let encoded = object
        .get("x")
        .and_then(Value::as_str)
        .ok_or(HolderProofError::Provider)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| HolderProofError::Provider)?;
    decoded.try_into().map_err(|_| HolderProofError::Provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_scope_rejects_foreign_issuer_and_unbounded_nonce() {
        let provider = OpenBaoHolderProofProvider::new(
            "http://127.0.0.1:8200".into(),
            "disposable".into(),
            "https://issuer.example".into(),
        )
        .unwrap();
        let mut request = HolderProofRequest {
            organization_id: "org-1".into(),
            issuer_url: "https://issuer.example/org/org-1".into(),
            nonce: "nonce-1".into(),
        };
        assert!(provider.validate(&request).is_ok());
        request.issuer_url = "https://foreign.example/org/org-1".into();
        assert!(provider.validate(&request).is_err());
        request.issuer_url = "https://issuer.example/org/org-1".into();
        request.nonce = "x".repeat(MAX_NONCE_BYTES + 1);
        assert!(provider.validate(&request).is_err());
        request.nonce = "nonce-1".into();
        request.organization_id = "../org-2".into();
        assert!(provider.validate(&request).is_err());
    }

    #[test]
    fn provider_rejects_url_credentials_and_paths() {
        assert!(OpenBaoHolderProofProvider::new(
            "https://user:password@bao.example".into(),
            "token".into(),
            "https://issuer.example".into(),
        )
        .is_err());
        assert!(OpenBaoHolderProofProvider::new(
            "https://bao.example/v1".into(),
            "token".into(),
            "https://issuer.example".into(),
        )
        .is_err());
        assert!(OpenBaoHolderProofProvider::new(
            "https://bao.example".into(),
            "token".into(),
            "https://issuer.example/other".into(),
        )
        .is_err());
    }
}
