//! Dedicated Device Registration client for remote holder-key operations.

use marty_holder_key_reference::{
    CreateHolderKeyRequest, HolderKeyScope, HolderSignature, SignHolderKeyRequest,
};
use marty_key_material_policy::contains_private_key;
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration;

use crate::DeviceError;

const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const REMOTE_ERROR: &str = "holder KMS operation failed";

#[derive(Clone)]
pub struct HolderKeyClient {
    client: Client,
    endpoint: String,
    service_key: String,
}

impl HolderKeyClient {
    pub fn new(endpoint: &str, service_key: String) -> Result<Self, DeviceError> {
        let parsed = Url::parse(endpoint)
            .map_err(|_| DeviceError::BadRequest("Signing Keys holder origin is invalid".into()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || service_key.len() < 32
        {
            return Err(DeviceError::BadRequest(
                "Signing Keys holder client configuration is invalid".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| DeviceError::Persistence("holder KMS client unavailable".into()))?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').into(),
            service_key,
        })
    }

    async fn post<B: serde::Serialize>(
        &self,
        operation: &str,
        body: &B,
    ) -> Result<reqwest::Response, DeviceError> {
        let response = self
            .client
            .post(format!(
                "{}/internal/device-registration/holder-keys/{operation}",
                self.endpoint
            ))
            .header("x-device-registration-key", &self.service_key)
            .json(body)
            .send()
            .await
            .map_err(|_| DeviceError::Persistence(REMOTE_ERROR.into()))?;
        if !response.status().is_success() {
            return Err(DeviceError::Persistence(REMOTE_ERROR.into()));
        }
        Ok(response)
    }

    async fn parse<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, DeviceError> {
        let bytes = response
            .bytes()
            .await
            .map_err(|_| DeviceError::Persistence(REMOTE_ERROR.into()))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(DeviceError::Persistence(REMOTE_ERROR.into()));
        }
        serde_json::from_slice(&bytes).map_err(|_| DeviceError::Persistence(REMOTE_ERROR.into()))
    }

    pub async fn create(&self, request: &CreateHolderKeyRequest) -> Result<Value, DeviceError> {
        if !request.scope.valid() || !matches!(request.algorithm.as_str(), "EdDSA" | "ES256") {
            return Err(DeviceError::BadRequest(
                "managed holder key scope is invalid".into(),
            ));
        }
        let metadata: Value = Self::parse(self.post("create", request).await?).await?;
        if contains_private_key(&metadata) {
            return Err(DeviceError::Persistence(
                "holder KMS returned private material".into(),
            ));
        }
        Ok(metadata)
    }

    pub async fn sign(
        &self,
        request: &SignHolderKeyRequest,
    ) -> Result<HolderSignature, DeviceError> {
        if !request.scope.valid()
            || request.key_version == 0
            || contains_private_key(&request.public_jwk)
        {
            return Err(DeviceError::BadRequest(
                "managed holder key scope is invalid".into(),
            ));
        }
        Self::parse(self.post("sign", request).await?).await
    }

    pub async fn revoke(&self, scope: &HolderKeyScope) -> Result<(), DeviceError> {
        if !scope.valid() {
            return Err(DeviceError::BadRequest(
                "managed holder key scope is invalid".into(),
            ));
        }
        self.post("revoke", scope).await?;
        Ok(())
    }
}
