//! Provider-native signing, public-key discovery, and connectivity probes.

use std::{env, fs, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_kms::config::Region;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use marty_crypto::jwk::{public_key_der_to_jwk, public_key_pem_to_jwk, PublicJwk};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROVIDER_ERROR_BYTES: usize = 2_048;

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub service_config: Value,
    pub payload_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub signature_b64: String,
    pub signature_encoding: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcoded_signature_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProviderRequest {
    pub service_config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityResult {
    pub ok: bool,
    pub checks: Vec<CapabilityCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CapabilityResult {
    fn ok() -> Self {
        Self {
            ok: true,
            checks: Vec::new(),
            error: None,
        }
    }

    fn fail(name: &str, detail: impl Into<String>) -> Self {
        let mut result = Self::ok();
        result.add_check(name, "fail", detail);
        result
    }

    fn add_check(&mut self, name: &str, status: &str, detail: impl Into<String>) {
        if status == "fail" {
            self.ok = false;
        }
        self.checks.push(CapabilityCheck {
            name: name.to_string(),
            status: status.to_string(),
            detail: detail.into(),
            source: "adapter".to_string(),
        });
    }
}

#[derive(Debug, Error)]
pub enum KmsError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("{0}")]
    InvalidConfig(String),
    #[error("No adapter found for service type '{0}'.")]
    UnsupportedProvider(String),
    #[error("Provider returned HTTP {status}: {detail}")]
    ProviderStatus { status: StatusCode, detail: String },
    #[error("{0}")]
    InvalidResponse(String),
    #[error("{0}")]
    Provider(String),
}

impl IntoResponse for KmsError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidConfig(_) | Self::UnsupportedProvider(_) => StatusCode::BAD_REQUEST,
            Self::ProviderStatus { status, .. } => *status,
            Self::InvalidResponse(_) | Self::Provider(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    OpenBao,
    Aws,
    Azure,
    Gcp,
}

impl Provider {
    fn from_config(config: &Value) -> Result<Self, KmsError> {
        match string(config, "service_type").unwrap_or_default() {
            "openbao-transit" | "hashicorp-vault-transit" | "custom-transit-compatible" => {
                Ok(Self::OpenBao)
            }
            "aws-kms" => Ok(Self::Aws),
            "azure-key-vault" => Ok(Self::Azure),
            "gcp-cloud-kms" => Ok(Self::Gcp),
            other => Err(KmsError::UnsupportedProvider(other.to_string())),
        }
    }

    fn signature_encoding(self, algorithm: &str) -> &'static str {
        if self == Self::OpenBao && algorithm == "EdDSA" {
            "raw"
        } else {
            "der"
        }
    }
}

pub async fn sign(request: SignRequest) -> Result<SignResponse, KmsError> {
    let provider = Provider::from_config(&request.service_config)?;
    let payload = decode_urlsafe(&request.payload_b64, "payload_b64")?;
    let algorithm = string(&request.service_config, "algorithm").unwrap_or("ES256");
    let signature = match provider {
        Provider::OpenBao => match sign_openbao(&request.service_config, &payload).await {
            Err(KmsError::ProviderStatus { status, .. })
                if status == StatusCode::NOT_FOUND
                    && string(&request.service_config, "id") == Some("managed-openbao-transit") =>
            {
                create_managed_openbao_key(&request.service_config).await?;
                sign_openbao(&request.service_config, &payload).await?
            }
            result => result?,
        },
        Provider::Aws => sign_aws(&request.service_config, &payload).await?,
        Provider::Azure => sign_azure(&request.service_config, &payload).await?,
        Provider::Gcp => sign_gcp(&request.service_config, &payload).await?,
    };
    let transcoded_signature_b64 = match algorithm {
        "ES256" | "ES384" => marty_crypto::ecdsa::normalize_signature(&signature, algorithm)
            .ok()
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes)),
        _ => None,
    };

    Ok(SignResponse {
        signature_b64: URL_SAFE_NO_PAD.encode(signature),
        signature_encoding: provider.signature_encoding(algorithm),
        transcoded_signature_b64,
    })
}

pub async fn public_key(request: ProviderRequest) -> Result<Value, KmsError> {
    match Provider::from_config(&request.service_config)? {
        Provider::OpenBao => match public_key_openbao(&request.service_config).await {
            Err(KmsError::ProviderStatus { status, .. })
                if status == StatusCode::NOT_FOUND
                    && string(&request.service_config, "id") == Some("managed-openbao-transit") =>
            {
                create_managed_openbao_key(&request.service_config).await?;
                public_key_openbao(&request.service_config).await
            }
            result => result,
        },
        Provider::Aws => public_key_aws(&request.service_config).await,
        Provider::Azure => public_key_azure(&request.service_config).await,
        Provider::Gcp => public_key_gcp(&request.service_config).await,
    }
}

pub async fn verify(request: ProviderRequest) -> Result<CapabilityResult, KmsError> {
    Ok(match Provider::from_config(&request.service_config)? {
        Provider::OpenBao => verify_openbao(&request.service_config).await,
        Provider::Aws => verify_aws(&request.service_config).await,
        Provider::Azure => verify_azure(&request.service_config).await,
        Provider::Gcp => verify_gcp(&request.service_config).await,
    })
}

async fn sign_openbao(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "OpenBao adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "OpenBao adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let algorithm = string(config, "algorithm").unwrap_or("ES256");
    let (input, prehashed) = if algorithm == "EdDSA" {
        (STANDARD.encode(payload), false)
    } else {
        (STANDARD.encode(Sha256::digest(payload)), true)
    };
    let url = format!(
        "{}/v1/{mount}/sign/{key_reference}",
        endpoint.trim_end_matches('/')
    );
    let response = send_json(
        Client::new()
            .post(url)
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config))
            .json(&json!({"input": input, "prehashed": prehashed})),
    )
    .await?;
    let encoded = response
        .pointer("/data/signature")
        .and_then(Value::as_str)
        .and_then(|value| value.rsplit(':').next())
        .ok_or_else(|| {
            KmsError::InvalidResponse("OpenBao sign response did not include signature".to_string())
        })?;
    decode_standard(encoded, "OpenBao signature")
}

async fn public_key_openbao(config: &Value) -> Result<Value, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "OpenBao adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "OpenBao adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let response = send_json(
        Client::new()
            .get(format!(
                "{}/v1/{mount}/keys/{key_reference}",
                endpoint.trim_end_matches('/')
            ))
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config)),
    )
    .await?;
    let data = response
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            KmsError::InvalidResponse("OpenBao key response did not include data".to_string())
        })?;
    let latest = data
        .get("latest_version")
        .map(|value| match value {
            Value::String(value) => value.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| "1".to_string());
    let metadata = data
        .get("keys")
        .and_then(Value::as_object)
        .and_then(|keys| keys.get(&latest))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned no public key material"
            ))
        })?;
    let material = metadata
        .get("public_key")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned no public key material"
            ))
        })?;
    let key_type = metadata
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| data.get("type").and_then(Value::as_str))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let jwk = if key_type == "ed25519" && !material.trim_start().starts_with("-----BEGIN ") {
        let raw = decode_standard(material, "OpenBao Ed25519 public key").map_err(|_| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned an invalid public key"
            ))
        })?;
        if raw.len() != 32 {
            return Err(KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned an invalid public key"
            )));
        }
        PublicJwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(raw)),
            ..PublicJwk::default()
        }
    } else {
        public_key_pem_to_jwk(material).map_err(|_| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned an invalid public key"
            ))
        })?
    };
    jwk_value(jwk, key_reference)
}

async fn create_managed_openbao_key(config: &Value) -> Result<(), KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "Managed OpenBao key creation requires 'endpoint' and 'key_reference'",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "Managed OpenBao key creation requires 'endpoint' and 'key_reference'",
    )?;
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let algorithm = string(config, "algorithm").unwrap_or("ES256");
    let key_type = match algorithm {
        "ES256" => "ecdsa-p256",
        "ES384" => "ecdsa-p384",
        "RS256" => "rsa-2048",
        "EdDSA" => "ed25519",
        other => {
            return Err(KmsError::InvalidConfig(format!(
                "Unsupported signing algorithm '{other}'."
            )))
        }
    };
    let token = transit_token(config);
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao access is not configured for the signing service.".into(),
        ));
    }
    let create = || {
        send_json_or_empty(
            Client::new()
                .post(format!(
                    "{}/v1/{mount}/keys/{key_reference}",
                    endpoint.trim_end_matches('/')
                ))
                .timeout(HTTP_TIMEOUT)
                .header("X-Vault-Token", &token)
                .json(&json!({"type": key_type})),
        )
    };
    match create().await {
        Ok(_) => Ok(()),
        Err(KmsError::ProviderStatus { status, detail })
            if status == StatusCode::BAD_REQUEST && existing_key_detail(&detail) =>
        {
            Ok(())
        }
        Err(KmsError::ProviderStatus { status, detail })
            if status == StatusCode::NOT_FOUND && missing_route_detail(&detail) =>
        {
            match send_json_or_empty(
                Client::new()
                    .post(format!(
                        "{}/v1/sys/mounts/{mount}",
                        endpoint.trim_end_matches('/')
                    ))
                    .timeout(HTTP_TIMEOUT)
                    .header("X-Vault-Token", &token)
                    .json(&json!({"type": "transit"})),
            )
            .await
            {
                Ok(_) => {}
                Err(KmsError::ProviderStatus { status, detail })
                    if status == StatusCode::BAD_REQUEST && mount_exists_detail(&detail) => {}
                Err(error) => return Err(error),
            }
            match create().await {
                Ok(_) => Ok(()),
                Err(KmsError::ProviderStatus { status, detail })
                    if status == StatusCode::BAD_REQUEST && existing_key_detail(&detail) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn verify_openbao(config: &Value) -> CapabilityResult {
    let endpoint = match string(config, "endpoint").filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => return CapabilityResult::fail("Endpoint", "endpoint is required"),
    };
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let key_reference = string(config, "key_reference").unwrap_or_default();
    let request = Client::new()
        .get(format!(
            "{}/v1/{mount}/keys/{key_reference}",
            endpoint.trim_end_matches('/')
        ))
        .timeout(PROBE_TIMEOUT)
        .header("X-Vault-Token", transit_token(config));
    let mut result = CapabilityResult::ok();
    match request.send().await {
        Ok(response) if response.status() == StatusCode::OK => {
            let supports = response
                .json::<Value>()
                .await
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/data/supports_signing")
                        .and_then(Value::as_bool)
                })
                .unwrap_or(false);
            result.add_check(
                "Key exists",
                if supports { "pass" } else { "warning" },
                format!("Key '{key_reference}' found; supports_signing={supports}."),
            );
        }
        Ok(response) if response.status() == StatusCode::FORBIDDEN => result.add_check(
            "Authentication",
            "fail",
            "Token is invalid or lacks read permissions.",
        ),
        Ok(response) if response.status() == StatusCode::NOT_FOUND => result.add_check(
            "Key exists",
            "fail",
            format!("Key '{key_reference}' was not found in mount '{mount}'."),
        ),
        Ok(response) => result.add_check(
            "Connectivity",
            "fail",
            format!(
                "Unexpected HTTP {} from transit endpoint.",
                response.status().as_u16()
            ),
        ),
        Err(error) => result.add_check(
            "Connectivity",
            "fail",
            format!("Cannot reach endpoint: {error}"),
        ),
    }
    result
}

async fn sign_azure(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_path = key_path(key_reference, string(config, "key_version"));
    let response = send_json(
        bearer(
            Client::new().post(format!(
                "{}/keys/{key_path}/sign?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(HTTP_TIMEOUT)
        .json(&json!({
            "alg": string(config, "azure_signing_algorithm").unwrap_or("ES256"),
            "value": URL_SAFE_NO_PAD.encode(Sha256::digest(payload)),
        })),
    )
    .await?;
    let value = response
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "Azure Key Vault sign response did not include signature value".to_string(),
            )
        })?;
    decode_urlsafe(value, "Azure signature")
}

async fn public_key_azure(config: &Value) -> Result<Value, KmsError> {
    let endpoint = required(
        config,
        "endpoint",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "azure-key-vault adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let key_path = key_path(key_reference, string(config, "key_version"));
    let response = send_json(
        bearer(
            Client::new().get(format!(
                "{}/keys/{key_path}?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(HTTP_TIMEOUT),
    )
    .await?;
    let jwk = response
        .get("key")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let public_jwk = canonical_provider_jwk(jwk, key_reference)?;
    let mut output = public_jwk.as_object().cloned().unwrap_or_default();
    output.insert("provider".to_string(), Value::String("azure".to_string()));
    output.insert(
        "key_reference".to_string(),
        Value::String(key_reference.to_string()),
    );
    Ok(Value::Object(output))
}

async fn verify_azure(config: &Value) -> CapabilityResult {
    let endpoint = match string(config, "endpoint").filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => return CapabilityResult::fail("Endpoint", "endpoint is required"),
    };
    verify_http_status(
        bearer(
            Client::new().get(format!(
                "{}/keys?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(PROBE_TIMEOUT),
        "Azure Key Vault",
        |status| match status {
            StatusCode::OK => (
                "Connectivity",
                "pass",
                "Azure Key Vault endpoint is reachable.".to_string(),
            ),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                "Authentication",
                "fail",
                "Azure token is invalid or unauthorized.".to_string(),
            ),
            other => (
                "Connectivity",
                "fail",
                format!("Azure returned HTTP {}.", other.as_u16()),
            ),
        },
    )
    .await
}

async fn sign_gcp(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = string(config, "endpoint").unwrap_or("https://cloudkms.googleapis.com");
    let key_reference = required(
        config,
        "key_reference",
        "gcp-cloud-kms adapter requires 'key_reference' in service_config",
    )?;
    let response = send_json(
        bearer(
            Client::new().post(format!(
                "{}/v1/{key_reference}:asymmetricSign",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(HTTP_TIMEOUT)
        .json(&json!({"digest": {"sha256": STANDARD.encode(Sha256::digest(payload))}})),
    )
    .await?;
    let signature = response
        .get("signature")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "GCP Cloud KMS sign response did not include signature".to_string(),
            )
        })?;
    decode_standard(signature, "GCP signature")
}

async fn public_key_gcp(config: &Value) -> Result<Value, KmsError> {
    let endpoint = string(config, "endpoint").unwrap_or("https://cloudkms.googleapis.com");
    let key_reference = required(
        config,
        "key_reference",
        "gcp-cloud-kms adapter requires 'key_reference' in service_config",
    )?;
    let response = send_json(
        bearer(
            Client::new().get(format!(
                "{}/v1/{key_reference}/publicKey",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(HTTP_TIMEOUT),
    )
    .await?;
    let pem = response.get("pem").and_then(Value::as_str).ok_or_else(|| {
        KmsError::InvalidResponse(
            "GCP Cloud KMS public key response did not include pem".to_string(),
        )
    })?;
    let public_jwk = jwk_value(
        public_key_pem_to_jwk(pem).map_err(|error| {
            KmsError::InvalidResponse(format!("GCP returned an invalid public key: {error}"))
        })?,
        key_reference,
    )?;
    Ok(json!({
        "provider": "gcp",
        "key_reference": key_reference,
        "public_key_pem": pem,
        "algorithm": response.get("algorithm").cloned().unwrap_or(Value::Null),
        "protection_level": response.get("protectionLevel").cloned().unwrap_or(Value::Null),
        "public_jwk": public_jwk,
    }))
}

async fn verify_gcp(config: &Value) -> CapabilityResult {
    let endpoint = string(config, "endpoint").unwrap_or("https://cloudkms.googleapis.com");
    let key_reference = match string(config, "key_reference").filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => return CapabilityResult::fail("Key reference", "key_reference is required"),
    };
    verify_http_status(
        bearer(
            Client::new().get(format!(
                "{}/v1/{key_reference}",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .timeout(PROBE_TIMEOUT),
        "GCP Cloud KMS",
        |status| match status {
            StatusCode::OK => (
                "Key exists",
                "pass",
                format!("GCP KMS key '{key_reference}' is reachable."),
            ),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                "Authentication",
                "fail",
                "GCP token is invalid or unauthorized.".to_string(),
            ),
            StatusCode::NOT_FOUND => (
                "Key exists",
                "fail",
                "Configured GCP key reference was not found.".to_string(),
            ),
            other => (
                "Connectivity",
                "fail",
                format!("GCP returned HTTP {}.", other.as_u16()),
            ),
        },
    )
    .await
}

async fn aws_client(config: &Value) -> aws_sdk_kms::Client {
    let region = string(config, "region").unwrap_or("us-east-1").to_string();
    let mut loader = aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region));
    if let Some(endpoint) = string(config, "endpoint").filter(|value| !value.is_empty()) {
        loader = loader.endpoint_url(endpoint);
        if endpoint.starts_with("http://") {
            loader = loader.http_client(aws_smithy_http_client::Builder::new().build_http());
        }
    }
    aws_sdk_kms::Client::new(&loader.load().await)
}

async fn sign_aws(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let key_id = required(
        config,
        "key_reference",
        "aws-kms adapter requires 'key_reference' in service_config",
    )?;
    let algorithm = string(config, "aws_signing_algorithm").unwrap_or("ECDSA_SHA_256");
    let output = aws_client(config)
        .await
        .sign()
        .key_id(key_id)
        .message(Blob::new(payload))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::from(algorithm))
        .send()
        .await
        .map_err(|error| KmsError::Provider(format!("AWS KMS sign failed: {error}")))?;
    output
        .signature()
        .map(|signature| signature.as_ref().to_vec())
        .ok_or_else(|| {
            KmsError::InvalidResponse(
                "AWS KMS sign response did not include binary Signature".to_string(),
            )
        })
}

async fn public_key_aws(config: &Value) -> Result<Value, KmsError> {
    let key_id = required(
        config,
        "key_reference",
        "aws-kms adapter requires 'key_reference' in service_config",
    )?;
    let output = aws_client(config)
        .await
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|error| KmsError::Provider(format!("AWS KMS get public key failed: {error}")))?;
    let der = output
        .public_key()
        .map(|value| value.as_ref())
        .unwrap_or_default();
    let public_jwk = jwk_value(
        public_key_der_to_jwk(der).map_err(|error| {
            KmsError::InvalidResponse(format!("AWS returned an invalid public key: {error}"))
        })?,
        key_id,
    )?;
    Ok(json!({
        "provider": "aws",
        "key_reference": key_id,
        "public_key_der_b64": STANDARD.encode(der),
        "signing_algorithms": output.signing_algorithms().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "key_spec": output.key_spec().map(|value| value.as_str()),
        "key_usage": output.key_usage().map(|value| value.as_str()),
        "public_jwk": public_jwk,
    }))
}

async fn verify_aws(config: &Value) -> CapabilityResult {
    let key_id = match string(config, "key_reference").filter(|value| !value.is_empty()) {
        Some(value) => value,
        None => return CapabilityResult::fail("Key reference", "key_reference is required"),
    };
    let mut result = CapabilityResult::ok();
    match aws_client(config)
        .await
        .describe_key()
        .key_id(key_id)
        .send()
        .await
    {
        Ok(_) => result.add_check(
            "Key exists",
            "pass",
            format!("AWS KMS key '{key_id}' is reachable."),
        ),
        Err(error) => result.add_check(
            "Connectivity",
            "fail",
            format!("AWS KMS verification failed: {error}"),
        ),
    }
    result
}

fn string<'a>(config: &'a Value, name: &str) -> Option<&'a str> {
    config.get(name).and_then(Value::as_str)
}

fn required<'a>(config: &'a Value, name: &str, message: &str) -> Result<&'a str, KmsError> {
    string(config, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| KmsError::InvalidConfig(message.to_string()))
}

fn key_path<'a>(key_reference: &'a str, version: Option<&'a str>) -> String {
    version
        .filter(|value| !value.is_empty())
        .map(|version| format!("{key_reference}/{version}"))
        .unwrap_or_else(|| key_reference.to_string())
}

fn bearer(builder: reqwest::RequestBuilder, config: &Value) -> reqwest::RequestBuilder {
    match string(config, "auth_reference").filter(|value| !value.is_empty()) {
        Some(token) => builder.bearer_auth(token),
        None => builder,
    }
}

fn transit_token(config: &Value) -> String {
    if string(config, "auth_mode") == Some("service_token") {
        return secret_value("BAO_TOKEN")
            .or_else(|| secret_value("OPENBAO_SERVICE_TOKEN"))
            .unwrap_or_default();
    }
    string(config, "auth_reference")
        .unwrap_or_default()
        .to_owned()
}

fn secret_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let path = env::var(format!("{name}_FILE")).ok()?;
            fs::read_to_string(path)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
}

async fn send_json(builder: reqwest::RequestBuilder) -> Result<Value, KmsError> {
    let response = builder
        .send()
        .await
        .map_err(|error| KmsError::Provider(format!("Provider request failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(KmsError::ProviderStatus {
            status,
            detail: bounded(&detail),
        });
    }
    response.json().await.map_err(|error| {
        KmsError::InvalidResponse(format!("Provider returned invalid JSON: {error}"))
    })
}

async fn send_json_or_empty(builder: reqwest::RequestBuilder) -> Result<Value, KmsError> {
    let response = builder
        .send()
        .await
        .map_err(|error| KmsError::Provider(format!("Provider request failed: {error}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| KmsError::Provider(format!("Provider response failed: {error}")))?;
    if !status.is_success() {
        return Err(KmsError::ProviderStatus {
            status,
            detail: bounded(&String::from_utf8_lossy(&body)),
        });
    }
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&body).map_err(|error| {
            KmsError::InvalidResponse(format!("Provider returned invalid JSON: {error}"))
        })
    }
}

fn existing_key_detail(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("already exists") || detail.contains("existing key")
}

fn missing_route_detail(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("no handler for route")
        || detail.contains("unsupported path")
        || detail.contains("route not found")
}

fn mount_exists_detail(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("path is already in use") || detail.contains("already exists")
}

async fn verify_http_status<F>(
    builder: reqwest::RequestBuilder,
    provider: &str,
    classify: F,
) -> CapabilityResult
where
    F: FnOnce(StatusCode) -> (&'static str, &'static str, String),
{
    let mut result = CapabilityResult::ok();
    match builder.send().await {
        Ok(response) => {
            let (name, status, detail) = classify(response.status());
            result.add_check(name, status, detail);
        }
        Err(error) => result.add_check(
            "Connectivity",
            "fail",
            format!("{provider} verification failed: {error}"),
        ),
    }
    result
}

fn canonical_provider_jwk(
    mut object: Map<String, Value>,
    key_reference: &str,
) -> Result<Value, KmsError> {
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        object.remove(private);
    }
    object
        .entry("kid".to_string())
        .or_insert_with(|| Value::String(key_reference.to_string()));
    let jwk: PublicJwk = serde_json::from_value(Value::Object(object)).map_err(|error| {
        KmsError::InvalidResponse(format!("Provider returned an invalid JWK: {error}"))
    })?;
    if jwk.kty.is_empty() {
        return Err(KmsError::InvalidResponse(
            "Provider returned a non-public or incomplete JWK".to_string(),
        ));
    }
    serde_json::to_value(jwk)
        .map_err(|error| KmsError::InvalidResponse(format!("JWK serialization failed: {error}")))
}

fn jwk_value(mut jwk: PublicJwk, key_reference: &str) -> Result<Value, KmsError> {
    jwk.kid = Some(key_reference.to_string());
    serde_json::to_value(jwk)
        .map_err(|error| KmsError::InvalidResponse(format!("JWK serialization failed: {error}")))
}

fn decode_standard(value: &str, label: &str) -> Result<Vec<u8>, KmsError> {
    let padding = "=".repeat((4 - value.len() % 4) % 4);
    STANDARD
        .decode(format!("{value}{padding}"))
        .map_err(|error| KmsError::InvalidResponse(format!("{label} is not valid base64: {error}")))
}

fn decode_urlsafe(value: &str, label: &str) -> Result<Vec<u8>, KmsError> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|error| {
            KmsError::InvalidConfig(format!("{label} is not valid base64url: {error}"))
        })
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_PROVIDER_ERROR_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_factory_preserves_supported_aliases_and_rejects_unknowns() {
        for service_type in [
            "openbao-transit",
            "hashicorp-vault-transit",
            "custom-transit-compatible",
            "aws-kms",
            "azure-key-vault",
            "gcp-cloud-kms",
        ] {
            assert!(Provider::from_config(&json!({"service_type": service_type})).is_ok());
        }
        assert!(Provider::from_config(&json!({"service_type": "unknown"})).is_err());
    }

    #[test]
    fn provider_jwks_remove_private_material() {
        let value = canonical_provider_jwk(
            serde_json::from_value::<Map<String, Value>>(json!({
                "kty": "OKP", "crv": "Ed25519", "x": "AQ", "d": "secret"
            }))
            .expect("object"),
            "key-1",
        )
        .expect("public JWK");
        assert_eq!(value["kid"], "key-1");
        assert!(value.get("d").is_none());
    }

    #[test]
    fn invalid_payload_base64_fails_closed() {
        assert!(decode_urlsafe("***", "payload_b64").is_err());
    }
}
