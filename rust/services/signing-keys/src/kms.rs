//! Provider-native signing, public-key discovery, and connectivity probes.

use std::{env, fs, path::Path, time::Duration};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use marty_crypto::jwk::{public_key_der_to_jwk, public_key_pem_to_jwk, PublicJwk};
use marty_openbao_http::OpenBaoHttp;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

#[path = "kms_azure.rs"]
mod azure;
use azure::*;

#[path = "kms_gcp.rs"]
mod gcp;
use gcp::*;

#[path = "kms_aws.rs"]
mod aws;
use aws::*;
pub(crate) use aws::{aws_key_arn, aws_signing_algorithm};
pub(crate) use gcp::gcp_key_version_reference;

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
    #[error("Provider returned HTTP {status}.")]
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
        if crate::private_material::contains_private_key(config) {
            return Err(KmsError::InvalidConfig(
                "Provider configuration must not contain private key material.".into(),
            ));
        }
        let provider = match string(config, "service_type").unwrap_or_default() {
            "openbao-transit" | "hashicorp-vault-transit" | "custom-transit-compatible" => {
                Self::OpenBao
            }
            "aws-kms" => Self::Aws,
            "azure-key-vault" => Self::Azure,
            "gcp-cloud-kms" => Self::Gcp,
            other => return Err(KmsError::UnsupportedProvider(other.to_string())),
        };
        validate_service_auth_config(config)?;
        Ok(provider)
    }

    fn signature_encoding(self, algorithm: &str) -> &'static str {
        if matches!(algorithm, "ES256" | "ES384" | "ES512") {
            "der"
        } else {
            "raw"
        }
    }
}

pub(crate) fn validate_service_auth_config(config: &Value) -> Result<(), KmsError> {
    match string(config, "service_type").unwrap_or_default() {
        "openbao-transit" | "hashicorp-vault-transit" | "custom-transit-compatible" => {
            validate_transit_auth_config(config)
        }
        "aws-kms" => {
            validate_cloud_endpoint(config, "aws")?;
            aws_region(config)?;
            validate_aws_auth_config(config)?;
            if string(config, "key_reference").is_some_and(|value| !value.is_empty()) {
                aws_key_arn(config)?;
            }
            Ok(())
        }
        "azure-key-vault" => {
            validate_cloud_endpoint(config, "azure")?;
            validate_azure_auth_config(config)?;
            if string(config, "key_reference").is_some_and(|value| !value.is_empty()) {
                azure_key_path(config)?;
            }
            Ok(())
        }
        "gcp-cloud-kms" => {
            validate_cloud_endpoint(config, "gcp")?;
            validate_gcp_auth_config(config)?;
            if string(config, "key_reference").is_some_and(|value| !value.is_empty()) {
                gcp_key_version_reference(config)?;
            }
            Ok(())
        }
        other => Err(KmsError::UnsupportedProvider(other.to_string())),
    }
}

fn validate_cloud_endpoint(config: &Value, provider: &str) -> Result<(), KmsError> {
    let endpoint = string(config, "endpoint").filter(|value| !value.is_empty());
    let Some(endpoint) = endpoint else {
        return if provider == "azure" {
            Err(KmsError::InvalidConfig(
                "Azure Key Vault endpoint is required.".into(),
            ))
        } else {
            Ok(())
        };
    };
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|_| KmsError::InvalidConfig("KMS endpoint is invalid.".into()))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(KmsError::InvalidConfig("KMS endpoint is invalid.".into()));
    }
    let host = parsed.host_str().unwrap_or_default();
    // Local HTTP stubs are confined to debug builds. Release artifacts can
    // never redirect a workload token or managed identity to a tenant URL.
    if cfg!(debug_assertions)
        && matches!(parsed.scheme(), "http" | "https")
        && matches!(host, "127.0.0.1" | "localhost" | "::1")
    {
        return Ok(());
    }
    let official = parsed.scheme() == "https"
        && parsed.port().is_none()
        && match provider {
            "aws" => false,
            "azure" => [".vault.azure.net", ".managedhsm.azure.net"]
                .iter()
                .any(|suffix| host.ends_with(suffix) && host.len() > suffix.len()),
            "gcp" => host == "cloudkms.googleapis.com",
            _ => false,
        };
    if !official {
        return Err(KmsError::InvalidConfig(
            "KMS endpoint is not a supported provider endpoint.".into(),
        ));
    }
    Ok(())
}

pub(crate) fn provider_http_client() -> Result<Client, KmsError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| KmsError::Provider("KMS HTTP client is unavailable.".into()))
}

pub(crate) fn transit_http_client(config: &Value) -> Result<Client, KmsError> {
    let endpoint = string(config, "endpoint")
        .ok_or_else(|| KmsError::InvalidConfig("Transit endpoint is required".into()))?;
    #[cfg(test)]
    if reqwest::Url::parse(endpoint)
        .ok()
        .is_some_and(|url| test_loopback_http(&url))
    {
        // Unit tests exercise response handling with an in-process Axum mock.
        // This branch is absent from production and integration-test builds.
        return provider_http_client();
    }
    let ca_file = if string(config, "auth_mode") == Some("service_token") {
        env::var("BAO_CACERT").ok()
    } else {
        string(config, "ca_cert_file").map(str::to_owned)
    };
    OpenBaoHttp::connect(endpoint, ca_file.as_deref().map(Path::new), HTTP_TIMEOUT)
        .map(|transport| transport.client().clone())
        .map_err(|_| KmsError::InvalidConfig("Transit HTTPS client is unavailable".into()))
}

fn cloud_http_client() -> Result<Client, KmsError> {
    provider_http_client()
}

pub(crate) fn validate_transit_auth_config(config: &Value) -> Result<(), KmsError> {
    match string(config, "auth_mode") {
        Some("token") => {
            validate_external_transit_endpoint(config)?;
            let token = string(config, "auth_reference").unwrap_or_default();
            if token.trim().is_empty() || token.len() > 16_384 {
                return Err(KmsError::InvalidConfig(
                    "A transit token is required for external KMS access.".into(),
                ));
            }
        }
        Some("service_token") => {
            let configured = env::var("BAO_ADDR").map_err(|_| {
                KmsError::InvalidConfig("Managed OpenBao endpoint is unavailable.".into())
            })?;
            let endpoint = string(config, "endpoint").unwrap_or_default();
            validate_external_transit_endpoint(config)?;
            if string(config, "id") != Some("managed-openbao-transit")
                || string(config, "service_type") != Some("openbao-transit")
                || configured.trim_end_matches('/') != endpoint.trim_end_matches('/')
                || string(config, "auth_reference").is_some_and(|reference| !reference.is_empty())
            {
                return Err(KmsError::InvalidConfig(
                    "Mounted OpenBao service token is restricted to the managed endpoint.".into(),
                ));
            }
        }
        _ => {
            return Err(KmsError::InvalidConfig(
                "Transit authentication mode is unsupported.".into(),
            ));
        }
    }
    Ok(())
}

fn validate_external_transit_endpoint(config: &Value) -> Result<(), KmsError> {
    let endpoint = string(config, "endpoint")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| KmsError::InvalidConfig("External Transit endpoint is required.".into()))?;
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| KmsError::InvalidConfig("External Transit endpoint is invalid.".into()))?;
    let host = url.host_str().unwrap_or_default();
    #[cfg(test)]
    let test_http = test_loopback_http(&url);
    #[cfg(not(test))]
    let test_http = false;
    if !(url.scheme() == "https" || test_http)
        || host.is_empty()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(KmsError::InvalidConfig(
            "External Transit endpoint must be a root HTTPS origin.".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn test_loopback_http(url: &reqwest::Url) -> bool {
    url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

pub async fn sign(request: SignRequest) -> Result<SignResponse, KmsError> {
    let provider = Provider::from_config(&request.service_config)?;
    let payload = decode_urlsafe(&request.payload_b64, "payload_b64")?;
    let algorithm = string(&request.service_config, "algorithm").unwrap_or("ES256");
    let signature = match provider {
        Provider::OpenBao => sign_openbao(&request.service_config, &payload).await?,
        Provider::Aws => sign_aws(&request.service_config, &payload).await?,
        Provider::Azure => sign_azure(&request.service_config, &payload).await?,
        Provider::Gcp => sign_gcp(&request.service_config, &payload).await?,
    };
    let transcoded_signature_b64 = normalize_provider_signature(&signature, algorithm)?;

    Ok(SignResponse {
        signature_b64: URL_SAFE_NO_PAD.encode(signature),
        signature_encoding: provider.signature_encoding(algorithm),
        transcoded_signature_b64,
    })
}

fn normalize_provider_signature(
    signature: &[u8],
    algorithm: &str,
) -> Result<Option<String>, KmsError> {
    if signature.is_empty() {
        return Err(KmsError::InvalidResponse(
            "Remote signer returned an empty signature.".into(),
        ));
    }
    match algorithm {
        "ES256" | "ES384" | "ES512" => {
            marty_crypto::ecdsa::normalize_signature(signature, algorithm)
                .map(|bytes| Some(URL_SAFE_NO_PAD.encode(bytes)))
                .map_err(|_| {
                    KmsError::InvalidResponse(
                        "Remote signer returned an invalid ECDSA signature.".into(),
                    )
                })
        }
        "EdDSA" if signature.len() != 64 => Err(KmsError::InvalidResponse(
            "Remote signer returned an invalid Ed25519 signature length.".into(),
        )),
        _ => Ok(None),
    }
}

pub async fn public_key(request: ProviderRequest) -> Result<Value, KmsError> {
    // Runtime reads must never replace a missing managed key under an old
    // reference. Provisioning is an explicit issuer-profile operation.
    public_key_existing(request).await
}

/// Read existing public key material without provisioning a missing managed key.
pub async fn public_key_existing(request: ProviderRequest) -> Result<Value, KmsError> {
    match Provider::from_config(&request.service_config)? {
        Provider::OpenBao => public_key_openbao(&request.service_config).await,
        Provider::Aws => public_key_aws(&request.service_config).await,
        Provider::Azure => public_key_azure(&request.service_config).await,
        Provider::Gcp => public_key_gcp(&request.service_config).await,
    }
}

/// Read an existing managed key's custody and public metadata. Inventory must
/// never provision a missing key or admit an importable/exportable key.
pub async fn managed_openbao_metadata_existing(
    endpoint: &str,
    key_reference: &str,
) -> Result<Value, KmsError> {
    read_managed_openbao(ProviderRequest {
        service_config: json!({
            "id": "managed-openbao-transit",
            "service_type": "openbao-transit",
            "endpoint": endpoint,
            "mount": "transit",
            "auth_mode": "service_token",
            "key_reference": key_reference,
        }),
    })
    .await
}

/// List public Transit key names without creating or exporting key material.
/// Callers must tenant-filter the names before reading individual keys.
pub async fn list_managed_openbao_key_names(endpoint: &str) -> Result<Vec<String>, KmsError> {
    let token = transit_token(&json!({
        "id": "managed-openbao-transit",
        "service_type": "openbao-transit",
        "auth_mode": "service_token",
        "endpoint": endpoint,
    }))?;
    list_managed_openbao_key_names_with_token(endpoint, &token).await
}

async fn list_managed_openbao_key_names_with_token(
    endpoint: &str,
    token: &str,
) -> Result<Vec<String>, KmsError> {
    let transport_config = json!({"endpoint": endpoint, "auth_mode": "service_token"});
    let response = match send_json(
        transit_http_client(&transport_config)?
            .get(format!(
                "{}/v1/transit/keys",
                endpoint.trim_end_matches('/')
            ))
            .query(&[("list", "true")])
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", token),
    )
    .await
    {
        Ok(response) => response,
        Err(KmsError::ProviderStatus { status, detail })
            if status == reqwest::StatusCode::NOT_FOUND && empty_transit_list_response(&detail) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let names = response
        .pointer("/data/keys")
        .and_then(Value::as_array)
        .ok_or_else(|| KmsError::InvalidResponse("OpenBao key list is malformed".into()))?;
    names
        .iter()
        .map(|name| {
            name.as_str()
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| KmsError::InvalidResponse("OpenBao key name is malformed".into()))
        })
        .collect()
}

fn empty_transit_list_response(detail: &str) -> bool {
    serde_json::from_str::<Value>(detail)
        .ok()
        .and_then(|response| response.get("errors").and_then(Value::as_array).cloned())
        .is_some_and(|errors| errors.is_empty())
}

/// Rotate one existing Transit key inside KMS and return its new public version.
/// No private key material crosses this boundary.
pub async fn openbao_latest_version(request: ProviderRequest) -> Result<u64, KmsError> {
    if Provider::from_config(&request.service_config)? != Provider::OpenBao {
        return Err(KmsError::InvalidConfig(
            "No provider rotation adapter available.".into(),
        ));
    }
    let config = &request.service_config;
    let endpoint = required(
        config,
        "endpoint",
        "Transit endpoint is required for rotation",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "A registered KMS key reference is required for rotation",
    )?;
    let token = transit_token(config)?;
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Transit access is not configured for rotation.".into(),
        ));
    }
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let mut read = transit_http_client(config)?
        .get(format!(
            "{}/v1/{mount}/keys/{key_reference}",
            endpoint.trim_end_matches('/')
        ))
        .timeout(HTTP_TIMEOUT)
        .header("X-Vault-Token", token);
    if let Some(namespace) = string(config, "namespace")
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        read = read.header("X-Vault-Namespace", namespace);
    }
    let response = send_json(read).await?;
    response
        .pointer("/data/latest_version")
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
        .filter(|version| *version > 0)
        .ok_or_else(|| KmsError::InvalidResponse("OpenBao key version is unavailable".into()))
}

pub async fn rotate_openbao(request: ProviderRequest) -> Result<Value, KmsError> {
    if Provider::from_config(&request.service_config)? != Provider::OpenBao {
        return Err(KmsError::InvalidConfig(
            "No provider rotation adapter available.".into(),
        ));
    }
    let config = &request.service_config;
    let endpoint = required(
        config,
        "endpoint",
        "Transit endpoint is required for rotation",
    )?;
    let key_reference = required(
        config,
        "key_reference",
        "A registered KMS key reference is required for rotation",
    )?;
    let token = transit_token(config)?;
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Transit access is not configured for rotation.".into(),
        ));
    }
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let namespace = string(config, "namespace")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let url = format!(
        "{}/v1/{mount}/keys/{key_reference}",
        endpoint.trim_end_matches('/')
    );
    let rotate = transit_http_client(config)?
        .post(format!("{url}/rotate"))
        .timeout(HTTP_TIMEOUT)
        .header("X-Vault-Token", &token);
    let rotate = if let Some(namespace) = namespace {
        rotate.header("X-Vault-Namespace", namespace)
    } else {
        rotate
    };
    send_json_or_empty(rotate).await?;
    let read = transit_http_client(config)?
        .get(url)
        .timeout(HTTP_TIMEOUT)
        .header("X-Vault-Token", &token);
    let read = if let Some(namespace) = namespace {
        read.header("X-Vault-Namespace", namespace)
    } else {
        read
    };
    let latest_version = match send_json(read).await {
        Ok(response) => response
            .get("data")
            .and_then(|data| data.get("latest_version"))
            .cloned()
            .unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    Ok(json!({"ok": true, "version": latest_version}))
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
    let key_version = requested_openbao_key_version(config)?;
    if string(config, "id") == Some("managed-openbao-transit") {
        let metadata = read_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await?;
        if metadata.get("status").and_then(Value::as_str) != Some("active") {
            return Err(KmsError::InvalidResponse(
                "Managed OpenBao key is not under active non-exportable custody".into(),
            ));
        }
        if metadata
            .get("public_jwk")
            .and_then(managed_public_key_algorithm)
            != Some(string(config, "algorithm").unwrap_or("ES256"))
        {
            return Err(KmsError::InvalidResponse(
                "Managed OpenBao key does not match the requested signing algorithm".into(),
            ));
        }
    }
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
    let (input, prehashed, hash_algorithm) = if algorithm == "EdDSA" {
        (STANDARD.encode(payload), false, None)
    } else {
        let (name, digest) = signing_digest(algorithm, payload)?;
        let vault_name = match name {
            "sha256" => "sha2-256",
            "sha384" => "sha2-384",
            "sha512" => "sha2-512",
            _ => unreachable!("signing_digest returns a supported SHA-2 name"),
        };
        (STANDARD.encode(digest), true, Some(vault_name))
    };
    let mut body = json!({"input": input, "prehashed": prehashed});
    if let Some(key_version) = key_version {
        body["key_version"] = json!(key_version);
    }
    if let Some(hash_algorithm) = hash_algorithm {
        body["hash_algorithm"] = Value::String(hash_algorithm.to_string());
    }
    match algorithm {
        "RS256" | "RS384" | "RS512" => {
            body["signature_algorithm"] = json!("pkcs1v15");
        }
        "PS256" | "PS384" | "PS512" => {
            body["signature_algorithm"] = json!("pss");
            // JOSE PS* requires a hash-length salt; Transit defaults to maximum.
            body["salt_length"] = json!("hash");
        }
        _ => {}
    }
    let url = format!(
        "{}/v1/{mount}/sign/{key_reference}",
        endpoint.trim_end_matches('/')
    );
    let response = send_json(
        transit_http_client(config)?
            .post(url)
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config)?)
            .json(&body),
    )
    .await?;
    let signature = response
        .pointer("/data/signature")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            KmsError::InvalidResponse("OpenBao sign response did not include signature".to_string())
        })?;
    if let Some(expected_version) = key_version {
        let expected_prefix = format!("vault:v{expected_version}:");
        if !signature.starts_with(&expected_prefix) {
            return Err(KmsError::InvalidResponse(
                "OpenBao signed with a different key version".into(),
            ));
        }
    }
    let encoded = signature.rsplit(':').next().ok_or_else(|| {
        KmsError::InvalidResponse("OpenBao sign response did not include signature".to_string())
    })?;
    decode_standard(encoded, "OpenBao signature")
}

async fn public_key_openbao(config: &Value) -> Result<Value, KmsError> {
    let data = openbao_key_data(config).await?;
    openbao_jwk_from_data(config, &data)
}

async fn openbao_key_data(config: &Value) -> Result<Value, KmsError> {
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
        transit_http_client(config)?
            .get(format!(
                "{}/v1/{mount}/keys/{key_reference}",
                endpoint.trim_end_matches('/')
            ))
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config)?),
    )
    .await?;
    response
        .get("data")
        .filter(|data| data.is_object())
        .cloned()
        .ok_or_else(|| {
            KmsError::InvalidResponse("OpenBao key response did not include data".to_string())
        })
}

fn openbao_jwk_from_data(config: &Value, data: &Value) -> Result<Value, KmsError> {
    let key_reference = required(
        config,
        "key_reference",
        "OpenBao adapter requires 'endpoint' and 'key_reference' in service_config",
    )?;
    let latest = openbao_selected_version(config, data)?;
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
        PublicJwk::from_json(
            &serde_json::json!({"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(raw)})
                .to_string(),
        )
        .map_err(|_| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned an invalid public key"
            ))
        })?
    } else {
        public_key_pem_to_jwk(material).map_err(|_| {
            KmsError::InvalidResponse(format!(
                "OpenBao key '{key_reference}' returned an invalid public key"
            ))
        })?
    };
    jwk_value(jwk, key_reference)
}

fn requested_openbao_key_version(config: &Value) -> Result<Option<u64>, KmsError> {
    let Some(value) = config.get("key_version").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let version = match value {
        Value::String(value) => value.parse::<u64>().ok(),
        Value::Number(value) => value.as_u64(),
        _ => None,
    }
    .filter(|version| *version > 0)
    .ok_or_else(|| KmsError::InvalidConfig("OpenBao key_version must be positive".into()))?;
    Ok(Some(version))
}

fn openbao_selected_version(config: &Value, data: &Value) -> Result<String, KmsError> {
    Ok(requested_openbao_key_version(config)?
        .map(|version| version.to_string())
        .unwrap_or_else(|| openbao_latest_version_from_data(data)))
}

fn openbao_latest_version_from_data(data: &Value) -> String {
    data.get("latest_version")
        .map(|value| match value {
            Value::String(value) => value.clone(),
            other => other.to_string(),
        })
        .unwrap_or_else(|| "1".to_string())
}

fn validate_managed_openbao(config: &Value) -> Result<(), KmsError> {
    if string(config, "id") != Some("managed-openbao-transit")
        || string(config, "service_type") != Some("openbao-transit")
    {
        return Err(KmsError::InvalidConfig(
            "Only the managed OpenBao Transit service can create signing keys.".into(),
        ));
    }
    Ok(())
}

fn managed_openbao_key_active(data: &Value) -> bool {
    data.get("supports_signing").and_then(Value::as_bool) == Some(true)
        && data.get("soft_deleted").and_then(Value::as_bool) == Some(false)
        && data.get("exportable").and_then(Value::as_bool) == Some(false)
        && data.get("allow_plaintext_backup").and_then(Value::as_bool) == Some(false)
        && data.get("deletion_allowed").and_then(Value::as_bool) == Some(false)
        && data.get("imported_key").and_then(Value::as_bool) == Some(false)
}

pub(crate) fn managed_public_key_algorithm(jwk: &Value) -> Option<&'static str> {
    match (
        jwk.get("kty").and_then(Value::as_str),
        jwk.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => Some("ES256"),
        (Some("EC"), Some("P-384")) => Some("ES384"),
        (Some("EC"), Some("P-521")) => Some("ES512"),
        (Some("RSA"), _) => Some("RS256"),
        (Some("OKP"), Some("Ed25519")) => Some("EdDSA"),
        _ => None,
    }
}

/// Read only public metadata for an existing managed Transit key.
pub async fn read_managed_openbao(request: ProviderRequest) -> Result<Value, KmsError> {
    let config = &request.service_config;
    validate_managed_openbao(config)?;
    let data = openbao_key_data(config).await?;
    let public_jwk = openbao_jwk_from_data(config, &data)?;
    let latest_version = data.get("latest_version").cloned().unwrap_or(Value::Null);
    let selected_version = openbao_selected_version(config, &data)?;
    let selected_key = data
        .get("keys")
        .and_then(Value::as_object)
        .and_then(|keys| keys.get(&selected_version));
    Ok(json!({
        "public_jwk": public_jwk,
        "latest_version": latest_version,
        "selected_version": selected_version,
        "created_at": selected_key.and_then(|key| key.get("creation_time")).cloned().unwrap_or(Value::Null),
        "type": data.get("type").cloned().unwrap_or(Value::Null),
        "exportable": data.get("exportable").cloned().unwrap_or(Value::Null),
        "allow_plaintext_backup": data.get("allow_plaintext_backup").cloned().unwrap_or(Value::Null),
        "deletion_allowed": data.get("deletion_allowed").cloned().unwrap_or(Value::Null),
        "status": if managed_openbao_key_active(&data) {"active"} else {"invalid"},
    }))
}

/// Explicitly create or retrieve one managed Transit key and return public metadata only.
/// The provider retains all private key material; callers must independently authorize
/// and tenant-scope the key reference before reaching this operation.
pub async fn create_managed_openbao(request: ProviderRequest) -> Result<Value, KmsError> {
    validate_managed_openbao(&request.service_config)?;
    create_managed_openbao_key(&request.service_config).await?;
    read_managed_openbao(request).await
}

/// Revoke a managed Transit key after the caller has authorized its scoped
/// reference. A failed delete leaves `deletion_allowed=true`, which makes all
/// managed signing and metadata checks fail closed until deletion is retried.
pub async fn delete_managed_openbao(request: ProviderRequest) -> Result<(), KmsError> {
    let config = &request.service_config;
    validate_managed_openbao(config)?;
    let endpoint = required(config, "endpoint", "Managed OpenBao endpoint is required")?;
    let endpoint_url = reqwest::Url::parse(endpoint)
        .map_err(|_| KmsError::InvalidConfig("Managed OpenBao endpoint is invalid".into()))?;
    if !matches!(endpoint_url.scheme(), "http" | "https")
        || !endpoint_url.username().is_empty()
        || endpoint_url.password().is_some()
        || endpoint_url.path() != "/"
        || endpoint_url.query().is_some()
        || endpoint_url.fragment().is_some()
    {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao endpoint must be an origin URL".into(),
        ));
    }
    let mount = string(config, "mount").unwrap_or("transit");
    let key_reference = required(config, "key_reference", "Managed key reference is required")?;
    if ![mount, key_reference].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 200
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    }) {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao mount or key reference is invalid".into(),
        ));
    }
    let token = transit_token(config)?;
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao access is not configured for the signing service".into(),
        ));
    }
    let key_url = format!(
        "{}/v1/{mount}/keys/{key_reference}",
        endpoint.trim_end_matches('/')
    );
    let client = transit_http_client(config)?;
    send_json_or_empty(
        client
            .post(format!("{key_url}/config"))
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", &token)
            .json(&json!({"deletion_allowed": true})),
    )
    .await?;
    send_json_or_empty(
        client
            .delete(&key_url)
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", &token),
    )
    .await?;
    Ok(())
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
    let key_type = openbao_key_type(algorithm)?;
    let token = transit_token(config)?;
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao access is not configured for the signing service.".into(),
        ));
    }
    let client = transit_http_client(config)?;
    let create = || {
        send_json_or_empty(
            client
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
                client
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

fn openbao_key_type(algorithm: &str) -> Result<&'static str, KmsError> {
    Ok(match algorithm {
        "ES256" => "ecdsa-p256",
        "ES384" => "ecdsa-p384",
        "ES512" => "ecdsa-p521",
        "RS256" => "rsa-2048",
        "EdDSA" => "ed25519",
        other => {
            return Err(KmsError::InvalidConfig(format!(
                "Unsupported signing algorithm '{other}'."
            )))
        }
    })
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
    let client = match transit_http_client(config) {
        Ok(client) => client,
        Err(_) => return CapabilityResult::fail("Connectivity", "KMS HTTP client is unavailable"),
    };
    let token = match transit_token(config) {
        Ok(token) => token,
        Err(_) => {
            return CapabilityResult::fail("Authentication", "KMS authentication is unavailable")
        }
    };
    let request = client
        .get(format!(
            "{}/v1/{mount}/keys/{key_reference}",
            endpoint.trim_end_matches('/')
        ))
        .timeout(PROBE_TIMEOUT)
        .header("X-Vault-Token", token);
    let mut result = CapabilityResult::ok();
    match request.send().await {
        Ok(response) if response.status() == StatusCode::OK => {
            let supports = bounded_provider_json(response, MAX_PROVIDER_JSON_BYTES)
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
        Err(_) => result.add_check("Connectivity", "fail", "Cannot reach Transit endpoint."),
    }
    result
}

fn string<'a>(config: &'a Value, name: &str) -> Option<&'a str> {
    config.get(name).and_then(Value::as_str)
}

fn signing_digest(algorithm: &str, payload: &[u8]) -> Result<(&'static str, Vec<u8>), KmsError> {
    match algorithm {
        "ES256"
        | "RS256"
        | "PS256"
        | "ECDSA_SHA_256"
        | "RSASSA_PKCS1_V1_5_SHA_256"
        | "RSASSA_PSS_SHA_256" => Ok(("sha256", Sha256::digest(payload).to_vec())),
        "ES384"
        | "RS384"
        | "PS384"
        | "ECDSA_SHA_384"
        | "RSASSA_PKCS1_V1_5_SHA_384"
        | "RSASSA_PSS_SHA_384" => Ok(("sha384", Sha384::digest(payload).to_vec())),
        "ES512"
        | "RS512"
        | "PS512"
        | "ECDSA_SHA_512"
        | "RSASSA_PKCS1_V1_5_SHA_512"
        | "RSASSA_PSS_SHA_512" => Ok(("sha512", Sha512::digest(payload).to_vec())),
        other => Err(KmsError::InvalidConfig(format!(
            "Unsupported signing algorithm '{other}'."
        ))),
    }
}

fn gcp_sign_body(algorithm: &str, payload: &[u8]) -> Result<Value, KmsError> {
    if algorithm == "EdDSA" {
        return Ok(json!({"data": STANDARD.encode(payload)}));
    }
    let (digest_name, digest) = signing_digest(algorithm, payload)?;
    Ok(json!({
        "digest": {digest_name: STANDARD.encode(digest)}
    }))
}

fn required<'a>(config: &'a Value, name: &str, message: &str) -> Result<&'a str, KmsError> {
    string(config, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| KmsError::InvalidConfig(message.to_string()))
}

pub(crate) fn azure_key_path(config: &Value) -> Result<String, KmsError> {
    let endpoint = required(config, "endpoint", "Azure Key Vault endpoint is required.")?;
    let reference = required(config, "key_reference", "Azure key reference is required.")?;
    let key_identifier = if reference.contains("://") {
        if reference.contains('%')
            || reference.contains("/./")
            || reference.contains("/../")
            || reference.ends_with("/.")
            || reference.ends_with("/..")
        {
            return Err(KmsError::InvalidConfig(
                "Azure key reference is invalid.".into(),
            ));
        }
        let base = reqwest::Url::parse(endpoint)
            .map_err(|_| KmsError::InvalidConfig("Azure Key Vault endpoint is invalid.".into()))?;
        let key = reqwest::Url::parse(reference)
            .map_err(|_| KmsError::InvalidConfig("Azure key reference is invalid.".into()))?;
        if key.origin() != base.origin()
            || !key.username().is_empty()
            || key.password().is_some()
            || key.query().is_some()
            || key.fragment().is_some()
        {
            return Err(KmsError::InvalidConfig(
                "Azure key reference must belong to its configured vault.".into(),
            ));
        }
        key.path()
            .strip_prefix("/keys/")
            .ok_or_else(|| KmsError::InvalidConfig("Azure key reference is invalid.".into()))?
            .to_string()
    } else {
        reference.to_string()
    };
    let mut parts = key_identifier.split('/');
    let name = parts.next().unwrap_or_default();
    let embedded_version = parts.next();
    if parts.next().is_some()
        || !valid_azure_key_segment(name)
        || embedded_version.is_some_and(|value| !valid_azure_key_segment(value))
    {
        return Err(KmsError::InvalidConfig(
            "Azure key reference is invalid.".into(),
        ));
    }
    if config
        .get("key_version")
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(KmsError::InvalidConfig(
            "Azure key version is invalid.".into(),
        ));
    }
    let version = string(config, "key_version").filter(|value| !value.is_empty());
    if version.is_some_and(|value| !valid_azure_key_segment(value))
        || matches!((embedded_version, version), (Some(a), Some(b)) if a != b)
    {
        return Err(KmsError::InvalidConfig(
            "Azure key version is invalid.".into(),
        ));
    }
    let version = embedded_version.or(version).ok_or_else(|| {
        KmsError::InvalidConfig("Azure signing key reference must pin a key version.".into())
    })?;
    Ok(format!("{name}/{version}"))
}

fn valid_azure_key_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn transit_token(config: &Value) -> Result<String, KmsError> {
    if string(config, "auth_mode") == Some("service_token") {
        validate_transit_auth_config(config)?;
        return secret_value("BAO_TOKEN")
            .or_else(|| secret_value("OPENBAO_SERVICE_TOKEN"))
            .ok_or_else(|| {
                KmsError::InvalidConfig("Managed OpenBao access is unavailable.".into())
            });
    }
    Ok(string(config, "auth_reference")
        .unwrap_or_default()
        .to_owned())
}

pub(crate) fn secret_value(name: &str) -> Option<String> {
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

pub(crate) const MAX_PROVIDER_JSON_BYTES: usize = 4 * 1024 * 1024;

async fn bounded_response_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, KmsError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| KmsError::Provider("Provider response failed.".into()))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(KmsError::InvalidResponse(
                "Provider response exceeds the size limit.".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) async fn bounded_provider_json(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Value, KmsError> {
    let body = bounded_response_body(response, max_bytes).await?;
    serde_json::from_slice(&body)
        .map_err(|_| KmsError::InvalidResponse("Provider returned invalid JSON.".into()))
}

async fn send_json(builder: reqwest::RequestBuilder) -> Result<Value, KmsError> {
    send_provider_json(builder, false).await
}

async fn send_json_or_empty(builder: reqwest::RequestBuilder) -> Result<Value, KmsError> {
    send_provider_json(builder, true).await
}

/// Provider status, size bounds and redacted errors have one execution path.
/// Empty-success admission remains explicit for lifecycle endpoints only.
async fn send_provider_json(
    builder: reqwest::RequestBuilder,
    allow_empty: bool,
) -> Result<Value, KmsError> {
    let response = builder
        .send()
        .await
        .map_err(|_| KmsError::Provider("Provider request failed.".into()))?;
    let status = response.status();
    let max_bytes = if status.is_success() {
        MAX_PROVIDER_JSON_BYTES
    } else {
        MAX_PROVIDER_ERROR_BYTES
    };
    let body = bounded_response_body(response, max_bytes).await?;
    if !status.is_success() {
        return Err(KmsError::ProviderStatus {
            status,
            detail: safe_provider_detail(&body),
        });
    }
    if allow_empty && body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| KmsError::InvalidResponse("Provider returned invalid JSON.".into()))
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

/// Confirm the Transit collection is readable and omits this key before
/// provisioning after a 404. Error bodies vary across OpenBao and proxies;
/// a denied list or missing mount must fail closed.
pub(crate) async fn missing_managed_openbao_key(
    config: &Value,
    error: &KmsError,
) -> Result<bool, KmsError> {
    let KmsError::ProviderStatus { status, detail } = error else {
        return Ok(false);
    };
    if *status != StatusCode::NOT_FOUND || missing_route_detail(detail) {
        return Ok(false);
    }
    let endpoint = required(
        config,
        "endpoint",
        "Managed OpenBao key lookup requires 'endpoint' and 'key_reference'",
    )?;
    let reference = required(
        config,
        "key_reference",
        "Managed OpenBao key lookup requires 'endpoint' and 'key_reference'",
    )?;
    if string(config, "mount").unwrap_or("transit") != "transit" {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao key lookup requires the transit mount".into(),
        ));
    }
    let token = transit_token(config)?;
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao access is unavailable.".into(),
        ));
    }
    Ok(!list_managed_openbao_key_names_with_token(endpoint, &token)
        .await?
        .iter()
        .any(|name| name == reference))
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
        Err(_) => result.add_check(
            "Connectivity",
            "fail",
            format!("{provider} verification failed."),
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
    // Azure Key Vault extends JWK `kty` with custody-specific HSM values.
    // Public DID/JWK consumers require the standard asymmetric key type.
    match object.get("kty").and_then(Value::as_str) {
        Some("EC-HSM") => {
            object.insert("kty".to_string(), Value::String("EC".to_string()));
        }
        Some("RSA-HSM") => {
            object.insert("kty".to_string(), Value::String("RSA".to_string()));
        }
        _ => {}
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

fn safe_provider_detail(body: &[u8]) -> String {
    let raw = String::from_utf8_lossy(body);
    if empty_transit_list_response(&raw) {
        return r#"{"errors":[]}"#.into();
    }
    let lower = raw.to_ascii_lowercase();
    for signal in [
        "already exists",
        "existing key",
        "no handler for route",
        "unsupported path",
        "route not found",
        "permission denied",
    ] {
        if lower.contains(signal) {
            return signal.into();
        }
    }
    "Provider rejected the request.".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provider_http_does_not_forward_vault_token_to_redirect_target() {
        let (tx, mut received) = tokio::sync::mpsc::unbounded_channel();
        let target = axum::Router::new().route(
            "/leak",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(headers.get("X-Vault-Token").cloned());
                    StatusCode::OK
                }
            }),
        );
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/leak", target_listener.local_addr().unwrap());
        let target_server =
            tokio::spawn(async move { axum::serve(target_listener, target).await.unwrap() });
        let redirect = axum::Router::new().route(
            "/transit",
            axum::routing::get(move || {
                let target_url = target_url.clone();
                async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, target_url)],
                    )
                }
            }),
        );
        let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/transit", redirect_listener.local_addr().unwrap());
        let redirect_server =
            tokio::spawn(async move { axum::serve(redirect_listener, redirect).await.unwrap() });
        let response = provider_http_client()
            .unwrap()
            .get(endpoint)
            .header("X-Vault-Token", "tenant-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(received.try_recv().is_err());
        redirect_server.abort();
        target_server.abort();
    }

    #[tokio::test]
    async fn empty_success_requires_explicit_lifecycle_admission() {
        let app = axum::Router::new().route(
            "/empty",
            axum::routing::get(|| async { StatusCode::NO_CONTENT }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/empty", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::new();
        assert!(matches!(
            send_json(client.get(&endpoint)).await,
            Err(KmsError::InvalidResponse(_))
        ));
        assert_eq!(
            send_json_or_empty(client.get(&endpoint)).await.unwrap(),
            Value::Null
        );
        server.abort();
    }

    #[tokio::test]
    async fn provider_http_rejects_oversized_success_and_error_bodies() {
        let app = axum::Router::new()
            .route(
                "/success",
                axum::routing::get(|| async {
                    axum::Json(json!({"padding": "x".repeat(MAX_PROVIDER_JSON_BYTES)}))
                }),
            )
            .route(
                "/error",
                axum::routing::get(|| async {
                    (
                        StatusCode::BAD_GATEWAY,
                        "x".repeat(MAX_PROVIDER_ERROR_BYTES + 1),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::new();
        assert!(matches!(
            send_json(client.get(format!("{endpoint}/success"))).await,
            Err(KmsError::InvalidResponse(_))
        ));
        assert!(matches!(
            send_json_or_empty(client.get(format!("{endpoint}/error"))).await,
            Err(KmsError::InvalidResponse(_))
        ));
        server.abort();
    }

    #[tokio::test]
    async fn provider_error_body_cannot_reappear_in_public_error() {
        let secret = "provider-echoed-secret-must-stay-private";
        let app = axum::Router::new().route(
            "/error",
            axum::routing::get(move || async move { (StatusCode::BAD_REQUEST, secret) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let error = send_json(Client::new().get(format!("{endpoint}/error")))
            .await
            .unwrap_err();
        assert!(matches!(error, KmsError::ProviderStatus { .. }));
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
        let response = error.into_response();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(secret));
        server.abort();
    }

    #[test]
    fn provider_error_signals_keep_state_without_echoing_response() {
        let secret = "provider-echoed-secret-must-stay-private";
        assert_eq!(
            safe_provider_detail(
                format!("{{\"errors\":[\"key already exists {secret}\"]}}").as_bytes()
            ),
            "already exists"
        );
        assert_eq!(
            safe_provider_detail(br#"{"errors":[]}"#),
            r#"{"errors":[]}"#
        );
        assert_eq!(
            safe_provider_detail(format!("permission denied {secret}").as_bytes()),
            "permission denied"
        );
        assert_eq!(
            safe_provider_detail(secret.as_bytes()),
            "Provider rejected the request."
        );
    }

    #[test]
    fn external_transit_token_requires_https_origin() {
        let config = |endpoint: &str| {
            json!({
                "service_type": "custom-transit-compatible",
                "endpoint": endpoint,
                "auth_mode": "token",
                "auth_reference": "fixture-token"
            })
        };
        assert!(validate_transit_auth_config(&config("https://kms.example")).is_ok());
        for endpoint in [
            "http://kms.example",
            "https://user:pass@kms.example",
            "https://kms.example/v1/transit",
            "https://kms.example?token=secret",
            "https://kms.example#fragment",
        ] {
            assert!(
                validate_transit_auth_config(&config(endpoint)).is_err(),
                "accepted {endpoint}"
            );
        }
        assert!(validate_transit_auth_config(&config("http://127.0.0.1:8200")).is_ok());
    }

    #[test]
    fn azure_client_secret_never_posts_to_an_unapproved_origin() {
        let credential = AzureClientSecret {
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            client_id: "22222222-2222-2222-2222-222222222222".into(),
            client_secret: "must-not-send".into(),
        };
        for endpoint in [
            "http://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token",
            "https://login.microsoftonline.com.attacker.example/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token",
            "https://login.microsoftonline.com/other/oauth2/v2.0/token",
            "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token?redirect=1",
        ] {
            assert!(
                azure_client_secret_request(
                    cloud_http_client().unwrap(), endpoint, &credential, "https://vault.azure.net"
                ).is_err(),
                "accepted {endpoint}"
            );
        }
    }

    #[test]
    fn cloud_provider_endpoints_cannot_route_credentials_to_tenant_hosts() {
        for (service_type, auth_mode, endpoint) in [
            ("aws-kms", "iam_role", "https://attacker.example"),
            (
                "azure-key-vault",
                "managed_identity",
                "https://attacker.example",
            ),
            (
                "gcp-cloud-kms",
                "workload_identity",
                "https://attacker.example",
            ),
            (
                "azure-key-vault",
                "managed_identity",
                "https://vault.azure.net.attacker.example",
            ),
            (
                "gcp-cloud-kms",
                "workload_identity",
                "https://cloudkms.googleapis.com.attacker.example",
            ),
            (
                "azure-key-vault",
                "managed_identity",
                "https://vault.vault.azure.net:444",
            ),
            (
                "azure-key-vault",
                "managed_identity",
                "https://vault.vault.azure.net/other",
            ),
            (
                "azure-key-vault",
                "managed_identity",
                "https://user@vault.vault.azure.net",
            ),
        ] {
            let config =
                json!({"service_type": service_type, "auth_mode": auth_mode, "endpoint": endpoint});
            assert!(validate_service_auth_config(&config).is_err(), "{endpoint}");
        }
        for (service_type, auth_mode, endpoint) in [
            (
                "azure-key-vault",
                "managed_identity",
                "https://vault.vault.azure.net",
            ),
            (
                "azure-key-vault",
                "managed_identity",
                "https://vault.managedhsm.azure.net",
            ),
            (
                "gcp-cloud-kms",
                "workload_identity",
                "https://cloudkms.googleapis.com",
            ),
        ] {
            let config =
                json!({"service_type": service_type, "auth_mode": auth_mode, "endpoint": endpoint});
            assert!(validate_service_auth_config(&config).is_ok(), "{endpoint}");
        }
        assert_eq!(
            gcp_endpoint(&json!({"endpoint": ""})),
            "https://cloudkms.googleapis.com"
        );
        assert_eq!(aws_region(&json!({"region": ""})).unwrap(), "us-east-1");
        for region in ["us-east-1.attacker.example", "us-east-1/path", "US-EAST-1"] {
            assert!(validate_service_auth_config(&json!({
                "service_type": "aws-kms", "auth_mode": "iam_role", "region": region
            }))
            .is_err());
        }
    }

    #[test]
    fn azure_key_identifier_resolves_only_within_its_configured_vault() {
        let base = json!({
            "service_type": "azure-key-vault",
            "endpoint": "https://issuer.vault.azure.net",
            "auth_mode": "managed_identity",
            "key_reference": "https://issuer.vault.azure.net/keys/signing-key/version-1"
        });
        assert_eq!(azure_key_path(&base).unwrap(), "signing-key/version-1");
        assert!(validate_service_auth_config(&base).is_ok());
        assert_eq!(
            azure_token_resource(&base).unwrap(),
            "https://vault.azure.net"
        );
        let mut hsm = base.clone();
        hsm["endpoint"] = json!("https://westus.issuer.managedhsm.azure.net");
        hsm["key_reference"] =
            json!("https://westus.issuer.managedhsm.azure.net/keys/signing-key/version-1");
        assert_eq!(azure_key_path(&hsm).unwrap(), "signing-key/version-1");
        assert_eq!(
            azure_token_resource(&hsm).unwrap(),
            "https://managedhsm.azure.net"
        );
        for reference in [
            "https://other.vault.azure.net/keys/signing-key/version-1",
            "https://issuer.vault.azure.net/keys/signing-key/extra/path",
            "https://issuer.vault.azure.net/keys/signing-key%2Fother",
            "https://issuer.vault.azure.net/keys/old/../signing-key",
            "https://issuer.vault.azure.net/keys/signing-key?version=1",
            "https://issuer.vault.azure.net/keys/signing-key#fragment",
        ] {
            let mut config = base.clone();
            config["key_reference"] = json!(reference);
            assert!(
                validate_service_auth_config(&config).is_err(),
                "{reference}"
            );
        }
        let mut mismatched_version = base.clone();
        mismatched_version["key_version"] = json!("version-2");
        assert!(azure_key_path(&mismatched_version).is_err());
        let mut bare = base.clone();
        bare["key_reference"] = json!("signing-key");
        bare["key_version"] = json!("version-1");
        assert_eq!(azure_key_path(&bare).unwrap(), "signing-key/version-1");
        bare.as_object_mut().unwrap().remove("key_version");
        assert!(azure_key_path(&bare).is_err());
    }

    #[test]
    fn gcp_key_reference_requires_a_versioned_resource_path() {
        let reference = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        assert_eq!(
            gcp_key_version_reference(&json!({"key_reference": reference})).unwrap(),
            reference
        );
        for invalid in [
            "projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/0",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/+1",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1?alt=json",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1/../2",
        ] {
            assert!(gcp_key_version_reference(&json!({"key_reference": invalid})).is_err());
        }
    }

    #[test]
    fn aws_signing_requires_a_region_bound_key_arn() {
        let reference = "arn:aws:kms:us-east-1:111122223333:key/test";
        assert_eq!(
            aws_key_arn(&json!({"key_reference": reference})).unwrap(),
            reference
        );
        for invalid in [
            "alias/movable",
            "arn:aws:kms:us-east-1:111122223333:alias/movable",
            "arn:aws:kms:us-west-2:111122223333:key/test",
            "arn:aws:kms:us-east-1:111122223333:key/test/other",
        ] {
            assert!(aws_key_arn(&json!({"key_reference": invalid})).is_err());
        }
    }

    #[tokio::test]
    async fn aws_signing_rejects_alias_before_network_io() {
        let result = sign(SignRequest {
            service_config: json!({
                "service_type": "aws-kms",
                "auth_mode": "iam_role",
                "key_reference": "alias/movable",
                "algorithm": "ES256"
            }),
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        assert!(matches!(result, Err(KmsError::InvalidConfig(_))));
    }

    #[test]
    fn gcp_signing_response_must_name_the_requested_key_version() {
        let reference = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
        assert!(require_gcp_response_name(&json!({"name": reference}), reference, true).is_ok());
        for response in [
            json!({}),
            json!({"name": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/2"}),
            json!({"name": null}),
        ] {
            assert!(matches!(
                require_gcp_response_name(&response, reference, true),
                Err(KmsError::InvalidResponse(_))
            ));
        }
        assert!(require_gcp_response_name(&json!({}), reference, false).is_ok());
        assert!(require_gcp_response_name(&json!({"name": null}), reference, false).is_err());
    }

    #[tokio::test]
    async fn gcp_signing_rejects_versionless_key_before_network_io() {
        let result = sign(SignRequest {
            service_config: json!({
                "service_type": "gcp-cloud-kms",
                "auth_mode": "workload_identity",
                "key_reference": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                "algorithm": "ES256"
            }),
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        assert!(
            matches!(result, Err(KmsError::InvalidConfig(message)) if message.contains("CryptoKeyVersion"))
        );
    }

    #[tokio::test]
    async fn gcp_impersonation_uses_short_lived_cloud_scope_without_a_key() {
        async fn token(request: axum::extract::Request) -> axum::Json<Value> {
            assert_eq!(request.method(), reqwest::Method::POST);
            assert!(request.uri().path().contains("serviceAccounts/"));
            assert!(request.uri().path().contains("%40"));
            assert_eq!(
                request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer source-token")
            );
            let body = axum::body::to_bytes(request.into_body(), 4096)
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body["scope"],
                json!(["https://www.googleapis.com/auth/cloud-platform"])
            );
            axum::Json(json!({"accessToken": "impersonated-token"}))
        }
        let app = axum::Router::new().fallback(axum::routing::post(token));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let account = GcpServiceAccount {
            email: "signer@project.iam.gserviceaccount.com".into(),
        };
        assert_eq!(
            gcp_service_account_token_at(&endpoint, &account, "source-token")
                .await
                .unwrap(),
            "impersonated-token"
        );
        server.abort();
    }

    #[test]
    fn mounted_token_cannot_be_routed_to_an_external_transit_endpoint() {
        let config = json!({
            "id": "external-signer", "service_type": "openbao-transit",
            "auth_mode": "service_token", "endpoint": "https://external.example"
        });
        assert!(Provider::from_config(&config).is_err());
    }

    #[tokio::test]
    async fn mounted_token_is_origin_bound_for_managed_lifecycle_and_inventory() {
        let endpoint = "https://unmounted.example.invalid";
        let config = json!({
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "auth_mode": "service_token", "endpoint": endpoint, "mount": "transit",
            "key_reference": "issuer-key", "algorithm": "ES256"
        });
        let rejects = |error: KmsError| {
            matches!(error, KmsError::InvalidConfig(detail)
                if detail.contains("Mounted OpenBao service token")
                    || detail.contains("Managed OpenBao endpoint is unavailable"))
        };
        assert!(rejects(
            read_managed_openbao(ProviderRequest {
                service_config: config.clone(),
            })
            .await
            .unwrap_err()
        ));
        assert!(rejects(
            create_managed_openbao(ProviderRequest {
                service_config: config.clone(),
            })
            .await
            .unwrap_err()
        ));
        assert!(rejects(
            delete_managed_openbao(ProviderRequest {
                service_config: config.clone(),
            })
            .await
            .unwrap_err()
        ));
        assert!(rejects(
            list_managed_openbao_key_names(endpoint).await.unwrap_err()
        ));
        assert!(rejects(
            missing_managed_openbao_key(
                &config,
                &KmsError::ProviderStatus {
                    status: StatusCode::NOT_FOUND,
                    detail: r#"{"errors":[]}"#.into(),
                },
            )
            .await
            .unwrap_err()
        ));
    }

    #[test]
    fn transit_adapter_rejects_missing_token_and_unimplemented_auth_modes() {
        for mode in ["approle", "mtls", "api_key", "custom", ""] {
            let config = json!({
                "service_type": "openbao-transit",
                "auth_mode": mode,
                "auth_reference": "fixture-token"
            });
            assert!(Provider::from_config(&config).is_err(), "{mode}");
        }
        assert!(Provider::from_config(&json!({
            "service_type": "openbao-transit",
            "auth_mode": "token",
            "auth_reference": " "
        }))
        .is_err());
    }

    #[test]
    fn provider_operations_reject_nested_private_material() {
        for config in [
            json!({"service_type": "aws-kms", "auth_reference": "{\"private_key\":\"test\"}"}),
            json!({"service_type": "azure-key-vault", "auth_reference": "-----BEGIN PRIVATE KEY-----\\ntest"}),
            json!({"service_type": "gcp-cloud-kms", "metadata": {"privateKeyJwk": "test"}}),
        ] {
            assert!(matches!(
                Provider::from_config(&config),
                Err(KmsError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn azure_client_secret_uses_scoped_oauth_form() {
        let config = json!({
            "auth_mode": "client_secret",
            "auth_reference": r#"{"tenant_id":"11111111-1111-1111-1111-111111111111","client_id":"22222222-2222-2222-2222-222222222222","client_secret":"fixture-secret"}"#
        });
        assert!(validate_azure_auth_config(&config).is_ok());
        let AzureAuth::ClientSecret(credential) = parse_azure_auth(&config).unwrap() else {
            panic!("client-secret mode was not selected")
        };
        let endpoint = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token";
        for (resource, expected_scope) in [
            (
                "https://vault.azure.net",
                "scope=https%3A%2F%2Fvault.azure.net%2F.default",
            ),
            (
                "https://managedhsm.azure.net",
                "scope=https%3A%2F%2Fmanagedhsm.azure.net%2F.default",
            ),
        ] {
            let request = azure_client_secret_request(
                cloud_http_client().unwrap(),
                endpoint,
                &credential,
                resource,
            )
            .unwrap()
            .build()
            .unwrap();
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(request.url().as_str(), endpoint);
            let form = std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap();
            assert!(form.contains("grant_type=client_credentials"));
            assert!(form.contains("client_id=22222222-2222-2222-2222-222222222222"));
            assert!(form.contains("client_secret=fixture-secret"));
            assert!(form.contains(expected_scope));
        }
    }

    #[tokio::test]
    async fn pinned_openbao_version_selects_matching_public_key_and_signing_version() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        };

        let first = STANDARD.encode([1_u8; 32]);
        let second = STANDARD.encode([2_u8; 32]);
        let data = json!({
            "latest_version": 2, "type": "ed25519",
            "supports_signing": true, "soft_deleted": false,
            "exportable": false, "allow_plaintext_backup": false,
            "deletion_allowed": false, "imported_key": false,
            "keys": {"1": {"public_key": first}, "2": {"public_key": second}}
        });
        let signed_body = Arc::new(Mutex::new(None::<Value>));
        let returned_version = Arc::new(AtomicUsize::new(1));
        let app = axum::Router::new()
            .route(
                "/v1/transit/keys/holder-key",
                axum::routing::get(move || {
                    let data = data.clone();
                    async move { axum::Json(json!({"data": data})) }
                }),
            )
            .route(
                "/v1/transit/sign/holder-key",
                axum::routing::post({
                    let signed_body = Arc::clone(&signed_body);
                    let returned_version = Arc::clone(&returned_version);
                    move |axum::Json(body): axum::Json<Value>| {
                        let signed_body = Arc::clone(&signed_body);
                        let returned_version = Arc::clone(&returned_version);
                        async move {
                            *signed_body.lock().unwrap() = Some(body);
                            let version = returned_version.load(Ordering::SeqCst);
                            axum::Json(json!({"data":{"signature":format!(
                                "vault:v{version}:{}", STANDARD.encode([1_u8; 64])
                            )}}))
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "endpoint":endpoint, "mount":"transit", "key_reference":"holder-key",
            "algorithm":"EdDSA", "auth_mode":"token", "auth_reference":"fixture-token", "key_version":1
        });
        let metadata = read_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        .unwrap();
        assert_eq!(
            metadata["public_jwk"]["x"],
            URL_SAFE_NO_PAD.encode([1_u8; 32])
        );
        assert_eq!(metadata["selected_version"], "1");
        let response = sign(SignRequest {
            service_config: config.clone(),
            payload_b64: URL_SAFE_NO_PAD.encode(b"holder-payload"),
        })
        .await
        .unwrap();
        assert_eq!(response.signature_b64, URL_SAFE_NO_PAD.encode([1_u8; 64]));
        assert_eq!(
            signed_body.lock().unwrap().as_ref().unwrap()["key_version"],
            1
        );
        returned_version.store(2, Ordering::SeqCst);
        assert!(matches!(
            sign(SignRequest {
                service_config: config,
                payload_b64: URL_SAFE_NO_PAD.encode(b"holder-payload"),
            })
            .await,
            Err(KmsError::InvalidResponse(_))
        ));
        server.abort();
        assert!(requested_openbao_key_version(&json!({"key_version":0})).is_err());
        assert!(requested_openbao_key_version(&json!({"key_version":"bad"})).is_err());
    }

    #[test]
    fn managed_signing_key_requires_provider_generated_non_exportable_custody() {
        let valid = json!({
            "supports_signing": true,
            "soft_deleted": false,
            "exportable": false,
            "allow_plaintext_backup": false,
            "deletion_allowed": false,
            "imported_key": false
        });
        assert!(managed_openbao_key_active(&valid));
        for (field, unsafe_value) in [
            ("supports_signing", json!(false)),
            ("soft_deleted", json!(true)),
            ("exportable", json!(true)),
            ("allow_plaintext_backup", json!(true)),
            ("deletion_allowed", json!(true)),
            ("imported_key", json!(true)),
        ] {
            let mut changed = valid.clone();
            changed[field] = unsafe_value;
            assert!(!managed_openbao_key_active(&changed), "{field}");
            changed.as_object_mut().unwrap().remove(field);
            assert!(!managed_openbao_key_active(&changed), "missing {field}");
        }
    }

    #[tokio::test]
    async fn managed_sign_refuses_unsafe_custody_and_wrong_algorithm_before_transit_sign() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };

        const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n";
        let signs = Arc::new(AtomicUsize::new(0));
        let exportable = Arc::new(AtomicBool::new(true));
        let app = axum::Router::new()
            .route(
                "/v1/transit/keys/issuer-key",
                axum::routing::get({
                    let exportable = Arc::clone(&exportable);
                    move || {
                        let exportable = Arc::clone(&exportable);
                        async move {
                            axum::Json(json!({"data": {
                                "latest_version": 1, "type": "ecdsa-p256",
                                "supports_signing": true, "soft_deleted": false,
                                "exportable": exportable.load(Ordering::SeqCst),
                                "allow_plaintext_backup": false,
                                "deletion_allowed": false, "imported_key": false,
                                "keys": {"1": {"public_key": PUBLIC_KEY}}
                            }}))
                        }
                    }
                }),
            )
            .route(
                "/v1/transit/sign/issuer-key",
                axum::routing::post({
                    let signs = Arc::clone(&signs);
                    move || {
                        let signs = Arc::clone(&signs);
                        async move {
                            signs.fetch_add(1, Ordering::SeqCst);
                            StatusCode::OK
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = json!({
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "endpoint": endpoint, "mount": "transit", "key_reference": "issuer-key",
            "algorithm": "ES256", "auth_mode": "token", "auth_reference": "test-token"
        });
        let result = sign(SignRequest {
            service_config: config.clone(),
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        assert!(matches!(result, Err(KmsError::InvalidResponse(_))));
        exportable.store(false, Ordering::SeqCst);
        config["algorithm"] = json!("EdDSA");
        let result = sign(SignRequest {
            service_config: config,
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        server.abort();
        assert!(matches!(result, Err(KmsError::InvalidResponse(_))));
        assert_eq!(signs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn transit_rotation_stays_in_kms_and_reports_public_version() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let rotations = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/v1/transit/keys/signing-key",
                axum::routing::get(|| async { axum::Json(json!({"data": {"latest_version": 2}})) }),
            )
            .route(
                "/v1/transit/keys/signing-key/rotate",
                axum::routing::post({
                    let rotations = Arc::clone(&rotations);
                    move || {
                        let rotations = Arc::clone(&rotations);
                        async move {
                            rotations.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local KMS fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let rotated = rotate_openbao(ProviderRequest {
            service_config: json!({
                "service_type": "openbao-transit", "endpoint": endpoint,
                "mount": "transit", "auth_mode": "token", "auth_reference": "fixture-token",
                "key_reference": "signing-key"
            }),
        })
        .await
        .unwrap();
        server.abort();
        assert_eq!(rotated, json!({"ok": true, "version": 2}));
        assert_eq!(rotations.load(Ordering::SeqCst), 1);
        assert!(rotate_openbao(ProviderRequest {
            service_config: json!({"service_type": "aws-kms"}),
        })
        .await
        .is_err());
    }

    #[tokio::test]
    async fn managed_delete_enables_revocation_before_removing_the_remote_key() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };

        let enabled = Arc::new(AtomicBool::new(false));
        let allow_config = Arc::new(AtomicBool::new(true));
        let deleted = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route(
                "/v1/transit/keys/holder-key/config",
                axum::routing::post({
                    let enabled = Arc::clone(&enabled);
                    let allow_config = Arc::clone(&allow_config);
                    move |axum::Json(body): axum::Json<Value>| {
                        let enabled = Arc::clone(&enabled);
                        let allow_config = Arc::clone(&allow_config);
                        async move {
                            if body["deletion_allowed"] != true
                                || !allow_config.load(Ordering::SeqCst)
                            {
                                return StatusCode::BAD_REQUEST;
                            }
                            enabled.store(true, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    }
                }),
            )
            .route(
                "/v1/transit/keys/holder-key",
                axum::routing::delete({
                    let enabled = Arc::clone(&enabled);
                    let deleted = Arc::clone(&deleted);
                    move || {
                        let enabled = Arc::clone(&enabled);
                        let deleted = Arc::clone(&deleted);
                        async move {
                            if !enabled.load(Ordering::SeqCst) {
                                return StatusCode::CONFLICT;
                            }
                            deleted.fetch_add(1, Ordering::SeqCst);
                            StatusCode::NO_CONTENT
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local KMS fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = json!({
            "id": "managed-openbao-transit", "service_type": "openbao-transit",
            "endpoint": endpoint, "mount": "transit", "key_reference": "holder-key",
            "auth_reference": "fixture-token"
        });
        let mut invalid_reference = config.clone();
        invalid_reference["key_reference"] = json!("../issuer-key");
        assert!(delete_managed_openbao(ProviderRequest {
            service_config: invalid_reference,
        })
        .await
        .is_err());
        assert!(!enabled.load(Ordering::SeqCst));
        delete_managed_openbao(ProviderRequest {
            service_config: config.clone(),
        })
        .await
        .expect("authorized managed key must be revoked in Transit");
        assert_eq!(deleted.load(Ordering::SeqCst), 1);
        allow_config.store(false, Ordering::SeqCst);
        assert!(delete_managed_openbao(ProviderRequest {
            service_config: config,
        })
        .await
        .is_err());
        assert_eq!(deleted.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn existing_public_key_discovery_never_creates_a_managed_key() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let creates = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/v1/transit/keys/missing-key",
            axum::routing::get(|| async { StatusCode::NOT_FOUND }).post({
                let creates = Arc::clone(&creates);
                move || {
                    let creates = Arc::clone(&creates);
                    async move {
                        creates.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local KMS fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result = public_key_existing(ProviderRequest {
            service_config: json!({
                "id": "managed-openbao-transit",
                "service_type": "openbao-transit",
                "endpoint": endpoint,
                "mount": "transit",
                "auth_mode": "token",
                "auth_reference": "fixture-token",
                "key_reference": "missing-key"
            }),
        })
        .await;
        server.abort();
        assert!(matches!(
            result,
            Err(KmsError::ProviderStatus {
                status: StatusCode::NOT_FOUND,
                ..
            })
        ));
        assert_eq!(creates.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_transit_list_is_distinct_from_missing_mount_and_denied_access() {
        assert!(empty_transit_list_response("{\"errors\":[]}"));
        assert!(!empty_transit_list_response(
            "{\"errors\":[\"no handler for route \\\"transit/keys/\\\"\"]}"
        ));
        assert!(!empty_transit_list_response("permission denied"));
    }

    #[tokio::test]
    async fn managed_key_missing_signal_requires_404_before_collection_lookup() {
        let config = json!({"endpoint": "http://127.0.0.1:1", "key_reference": "key"});
        let missing = |detail: &str| KmsError::ProviderStatus {
            status: StatusCode::NOT_FOUND,
            detail: detail.into(),
        };
        assert!(!missing_managed_openbao_key(
            &config,
            &missing(r#"{"errors":["no handler for route transit/keys/key"]}"#)
        )
        .await
        .unwrap());
        assert!(!missing_managed_openbao_key(
            &config,
            &KmsError::ProviderStatus {
                status: StatusCode::FORBIDDEN,
                detail: "permission denied".into()
            }
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn managed_key_missing_lookup_uses_the_same_scoped_token() {
        let app = axum::Router::new().route(
            "/v1/transit/keys",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                if headers
                    .get("x-vault-token")
                    .and_then(|value| value.to_str().ok())
                    == Some("scoped-token")
                {
                    (StatusCode::OK, axum::Json(json!({"data":{"keys":[]}})))
                } else {
                    (
                        StatusCode::FORBIDDEN,
                        axum::Json(json!({"errors":["permission denied"]})),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local KMS fixture");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = json!({
            "endpoint": endpoint,
            "mount": "transit",
            "key_reference": "missing-key",
            "auth_reference": "scoped-token"
        });
        let missing = KmsError::ProviderStatus {
            status: StatusCode::NOT_FOUND,
            detail: r#"{"errors":[]}"#.into(),
        };
        assert!(missing_managed_openbao_key(&config, &missing)
            .await
            .expect("scoped collection lookup"));
        server.abort();
    }

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
            let (auth_mode, auth_reference) = match service_type {
                "aws-kms" => ("iam_role", ""),
                "azure-key-vault" => ("managed_identity", ""),
                "gcp-cloud-kms" => ("workload_identity", ""),
                _ => ("token", "fixture-token"),
            };
            let endpoint = if service_type == "azure-key-vault" {
                "https://fixture.vault.azure.net"
            } else if matches!(
                service_type,
                "openbao-transit" | "hashicorp-vault-transit" | "custom-transit-compatible"
            ) {
                "https://kms.example"
            } else {
                ""
            };
            assert!(Provider::from_config(&json!({
                "service_type": service_type,
                "auth_mode": auth_mode,
                "auth_reference": auth_reference,
                "endpoint": endpoint
            }))
            .is_ok());
        }
        assert!(Provider::from_config(&json!({"service_type": "unknown"})).is_err());
    }

    #[test]
    fn azure_hsm_public_jwks_use_standard_types_without_private_material() {
        let value = canonical_provider_jwk(
            serde_json::from_value::<Map<String, Value>>(json!({
                "kty": "EC-HSM", "crv": "P-256", "x": "AQ", "y": "Ag", "d": "secret"
            }))
            .expect("object"),
            "key-1",
        )
        .expect("public JWK");
        assert_eq!(value["kty"], "EC");
        assert_eq!(value["kid"], "key-1");
        assert!(value.get("d").is_none());

        let rsa = canonical_provider_jwk(
            serde_json::from_value::<Map<String, Value>>(json!({
                "kty": "RSA-HSM", "n": "AQ", "e": "AQAB", "p": "secret"
            }))
            .expect("object"),
            "key-2",
        )
        .expect("public RSA JWK");
        assert_eq!(rsa["kty"], "RSA");
        assert!(rsa.get("p").is_none());
    }

    #[test]
    fn invalid_payload_base64_fails_closed() {
        assert!(decode_urlsafe("***", "payload_b64").is_err());
    }

    #[test]
    fn invalid_remote_signature_shapes_fail_closed() {
        for algorithm in ["ES256", "ES384", "ES512"] {
            assert!(matches!(
                normalize_provider_signature(&[0, 1, 2], algorithm),
                Err(KmsError::InvalidResponse(_))
            ));
        }
        let valid_der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        assert!(normalize_provider_signature(&valid_der, "ES256")
            .unwrap()
            .is_some());
        assert_eq!(
            normalize_provider_signature(&[0, 1, 2], "RS256").unwrap(),
            None
        );
        assert!(matches!(
            normalize_provider_signature(&[1; 63], "EdDSA"),
            Err(KmsError::InvalidResponse(_))
        ));
        assert_eq!(
            normalize_provider_signature(&[1; 64], "EdDSA").unwrap(),
            None
        );
        for algorithm in ["ES256", "RS256", "EdDSA"] {
            assert!(matches!(
                normalize_provider_signature(&[], algorithm),
                Err(KmsError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn provider_digest_and_managed_key_mappings_cover_all_csca_curves() {
        for (algorithm, digest_name, digest_len, key_type) in [
            ("ES256", "sha256", 32, "ecdsa-p256"),
            ("ES384", "sha384", 48, "ecdsa-p384"),
            ("ES512", "sha512", 64, "ecdsa-p521"),
        ] {
            let (actual_name, digest) = signing_digest(algorithm, b"CSCA parity vector").unwrap();
            assert_eq!(actual_name, digest_name);
            assert_eq!(digest.len(), digest_len);
            assert_eq!(openbao_key_type(algorithm).unwrap(), key_type);
        }
        assert!(signing_digest("unsupported", b"payload").is_err());
        assert!(openbao_key_type("unsupported").is_err());
        assert_eq!(aws_signing_algorithm("ES384").unwrap(), "ECDSA_SHA_384");
        assert_eq!(
            aws_signing_algorithm("RS256").unwrap(),
            "RSASSA_PKCS1_V1_5_SHA_256"
        );
        assert!(aws_signing_algorithm("EdDSA").is_err());
        assert_eq!(signing_digest("ES256", &[42; 8192]).unwrap().1.len(), 32);
    }

    #[tokio::test]
    async fn aws_signing_rejects_conflicting_provider_algorithm_before_network_io() {
        let result = sign(SignRequest {
            service_config: json!({
                "service_type": "aws-kms",
                "key_reference": "arn:aws:kms:us-east-1:111122223333:key/test",
                "algorithm": "RS256",
                "aws_signing_algorithm": "ECDSA_SHA_256"
            }),
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        assert!(matches!(result, Err(KmsError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn azure_signing_rejects_conflicting_provider_algorithm_before_network_io() {
        let result = sign(SignRequest {
            service_config: json!({
                "service_type": "azure-key-vault",
                "endpoint": "https://issuer.vault.azure.net",
                "key_reference": "https://issuer.vault.azure.net/keys/issuer/version-1",
                "auth_mode": "managed_identity",
                "algorithm": "RS256",
                "azure_signing_algorithm": "ES256"
            }),
            payload_b64: "cGF5bG9hZA".into(),
        })
        .await;
        assert!(matches!(result, Err(KmsError::InvalidConfig(_))));
    }

    #[test]
    fn azure_signing_requires_the_requested_key_version_in_the_response() {
        let endpoint = "https://issuer.vault.azure.net";
        let requested = "issuer/version-1";
        assert!(require_azure_response_key(
            &json!({"kid": "https://issuer.vault.azure.net/keys/issuer/version-1"}),
            endpoint,
            requested,
        )
        .is_ok());
        assert!(require_azure_response_key(
            &json!({"kid": "https://issuer.vault.azure.net/keys/issuer/version-1"}),
            "https://ISSUER.VAULT.AZURE.NET/",
            requested,
        )
        .is_ok());
        for response in [
            json!({}),
            json!({"kid": "https://issuer.vault.azure.net/keys/issuer/version-2"}),
            json!({"kid": "https://other.vault.azure.net/keys/issuer/version-1"}),
            json!({"kid": "https://issuer.vault.azure.net/keys/issuer/version-1?latest=true"}),
        ] {
            assert!(matches!(
                require_azure_response_key(&response, endpoint, requested),
                Err(KmsError::InvalidResponse(_))
            ));
        }
    }

    #[test]
    fn gcp_ed25519_signing_sends_data_instead_of_a_digest() {
        assert_eq!(
            gcp_sign_body("EdDSA", b"payload").unwrap(),
            json!({"data": "cGF5bG9hZA=="})
        );
        assert_eq!(
            gcp_sign_body("ES256", b"payload").unwrap(),
            json!({
                "digest": {"sha256": "I59Z7VXnN8dxR89VrQwbAwttfudIp0JpUvm4UtWpNeU="}
            })
        );
    }
}
