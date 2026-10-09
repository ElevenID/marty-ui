//! Purpose-scoped, non-exportable OpenBao holder operations.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub use marty_holder_key_reference::{
    CreateHolderKeyRequest, HolderKeyScope, SignHolderKeyRequest,
};
use marty_key_material_policy::contains_private_key;
use reqwest::Url;
use serde_json::{json, Value};
use thiserror::Error;

use crate::kms::{self, ProviderRequest, SignRequest, SignResponse};

const MAX_SIGNING_INPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum HolderKeyError {
    #[error("managed holder key request is invalid")]
    Invalid,
    #[error("managed holder KMS is unavailable")]
    Unavailable,
    #[error("managed holder KMS operation failed")]
    Provider,
}

#[derive(Clone)]
pub struct OpenBaoManagedHolderKeys {
    endpoint: String,
    token: String,
}

impl OpenBaoManagedHolderKeys {
    pub fn new(endpoint: String, token: String) -> Result<Self, HolderKeyError> {
        let url = Url::parse(&endpoint).map_err(|_| HolderKeyError::Unavailable)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || token.is_empty()
        {
            return Err(HolderKeyError::Unavailable);
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').into(),
            token,
        })
    }

    fn validate_scope(scope: &HolderKeyScope) -> Result<(), HolderKeyError> {
        if !scope.valid() {
            return Err(HolderKeyError::Invalid);
        }
        Ok(())
    }

    fn config(&self, scope: &HolderKeyScope, algorithm: &str, version: Option<u64>) -> Value {
        let mut config = json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "endpoint":self.endpoint, "mount":"transit",
            "key_reference":scope.provider_reference,
            "algorithm":algorithm, "auth_reference":self.token,
        });
        if let Some(version) = version {
            config["key_version"] = json!(version);
        }
        config
    }

    pub async fn create(&self, request: CreateHolderKeyRequest) -> Result<Value, HolderKeyError> {
        Self::validate_scope(&request.scope)?;
        if !matches!(request.algorithm.as_str(), "EdDSA" | "ES256") {
            return Err(HolderKeyError::Invalid);
        }
        kms::create_managed_openbao(ProviderRequest {
            service_config: self.config(&request.scope, &request.algorithm, None),
        })
        .await
        .map_err(|_| HolderKeyError::Provider)
    }

    pub async fn sign(
        &self,
        request: SignHolderKeyRequest,
    ) -> Result<SignResponse, HolderKeyError> {
        Self::validate_scope(&request.scope)?;
        if !matches!(request.algorithm.as_str(), "EdDSA" | "ES256")
            || request.key_version == 0
            || contains_private_key(&request.public_jwk)
        {
            return Err(HolderKeyError::Invalid);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(&request.payload_b64)
            .map_err(|_| HolderKeyError::Invalid)?;
        if payload.is_empty()
            || payload.len() > MAX_SIGNING_INPUT_BYTES
            || URL_SAFE_NO_PAD.encode(payload) != request.payload_b64
        {
            return Err(HolderKeyError::Invalid);
        }
        let config = self.config(
            &request.scope,
            &request.algorithm,
            Some(request.key_version),
        );
        let metadata = kms::read_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        .map_err(|_| HolderKeyError::Provider)?;
        if metadata["status"] != "active"
            || metadata["selected_version"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                != Some(request.key_version)
            || metadata["public_jwk"] != request.public_jwk
        {
            return Err(HolderKeyError::Provider);
        }
        kms::sign(SignRequest {
            service_config: config,
            payload_b64: request.payload_b64,
        })
        .await
        .map_err(|_| HolderKeyError::Provider)
    }

    pub async fn revoke(&self, scope: HolderKeyScope) -> Result<(), HolderKeyError> {
        Self::validate_scope(&scope)?;
        let config = self.config(&scope, "EdDSA", None);
        let _deletion = kms::delete_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await;
        match kms::read_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        {
            Err(error)
                if kms::missing_managed_openbao_key(&config, &error)
                    .await
                    .unwrap_or(false) =>
            {
                Ok(())
            }
            _ => Err(HolderKeyError::Provider),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_holder_key_reference::new_reference;

    #[tokio::test]
    async fn invalid_version_or_cross_registration_requests_fail_before_provider_access() {
        let provider = OpenBaoManagedHolderKeys::new(
            "http://127.0.0.1:1".into(),
            "disposable-provider-token-longer-than-32".into(),
        )
        .unwrap();
        let reference = new_reference("org-a", "registration-a", "holder_binding").unwrap();
        let scope = || HolderKeyScope {
            organization_id: "org-a".into(),
            registration_id: "registration-a".into(),
            purpose: "holder_binding".into(),
            provider_reference: reference.clone(),
        };
        let invalid_version = SignHolderKeyRequest {
            scope: scope(),
            algorithm: "EdDSA".into(),
            key_version: 0,
            public_jwk: json!({"kty":"OKP","crv":"Ed25519","x":"public"}),
            payload_b64: URL_SAFE_NO_PAD.encode(b"proof"),
        };
        assert!(matches!(
            provider.sign(invalid_version).await,
            Err(HolderKeyError::Invalid)
        ));
        let mut wrong_scope = scope();
        wrong_scope.registration_id = "registration-b".into();
        let wrong = SignHolderKeyRequest {
            scope: wrong_scope,
            algorithm: "EdDSA".into(),
            key_version: 1,
            public_jwk: json!({"kty":"OKP","crv":"Ed25519","x":"public"}),
            payload_b64: URL_SAFE_NO_PAD.encode(b"proof"),
        };
        assert!(matches!(
            provider.sign(wrong).await,
            Err(HolderKeyError::Invalid)
        ));
    }
}
