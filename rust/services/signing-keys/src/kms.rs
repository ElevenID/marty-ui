//! Provider-native signing, public-key discovery, and connectivity probes.

use std::{env, fs, time::Duration};

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
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
use sha2::{Digest, Sha256, Sha384, Sha512};
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
        if crate::private_material::contains_private_key(config) {
            return Err(KmsError::InvalidConfig(
                "Provider configuration must not contain private key material.".into(),
            ));
        }
        validate_transit_auth_config(config)?;
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
        if matches!(algorithm, "ES256" | "ES384" | "ES512") {
            "der"
        } else {
            "raw"
        }
    }
}

pub(crate) fn validate_transit_auth_config(config: &Value) -> Result<(), KmsError> {
    if string(config, "auth_mode") != Some("service_token") {
        return Ok(());
    }
    let configured = env::var("BAO_ADDR")
        .map_err(|_| KmsError::InvalidConfig("Managed OpenBao endpoint is unavailable.".into()))?;
    let endpoint = string(config, "endpoint").unwrap_or_default();
    if string(config, "id") != Some("managed-openbao-transit")
        || string(config, "service_type") != Some("openbao-transit")
        || configured.trim_end_matches('/') != endpoint.trim_end_matches('/')
    {
        return Err(KmsError::InvalidConfig(
            "Mounted OpenBao service token is restricted to the managed endpoint.".into(),
        ));
    }
    Ok(())
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
    let transcoded_signature_b64 = match algorithm {
        "ES256" | "ES384" | "ES512" => {
            marty_crypto::ecdsa::normalize_signature(&signature, algorithm)
                .ok()
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        }
        _ => None,
    };

    Ok(SignResponse {
        signature_b64: URL_SAFE_NO_PAD.encode(signature),
        signature_encoding: provider.signature_encoding(algorithm),
        transcoded_signature_b64,
    })
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
    let token = secret_value("BAO_TOKEN")
        .or_else(|| secret_value("OPENBAO_SERVICE_TOKEN"))
        .ok_or_else(|| KmsError::InvalidConfig("Managed OpenBao access is unavailable.".into()))?;
    list_managed_openbao_key_names_with_token(endpoint, &token).await
}

async fn list_managed_openbao_key_names_with_token(
    endpoint: &str,
    token: &str,
) -> Result<Vec<String>, KmsError> {
    let response = match send_json(
        Client::new()
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
    let token = transit_token(config);
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Transit access is not configured for rotation.".into(),
        ));
    }
    let mount = string(config, "mount")
        .unwrap_or("transit")
        .trim_matches('/');
    let mut read = Client::new()
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
    let token = transit_token(config);
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
    let rotate = Client::new()
        .post(format!("{url}/rotate"))
        .timeout(HTTP_TIMEOUT)
        .header("X-Vault-Token", &token);
    let rotate = if let Some(namespace) = namespace {
        rotate.header("X-Vault-Namespace", namespace)
    } else {
        rotate
    };
    send_json_or_empty(rotate).await?;
    let read = Client::new()
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
        Client::new()
            .post(url)
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config))
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
        Client::new()
            .get(format!(
                "{}/v1/{mount}/keys/{key_reference}",
                endpoint.trim_end_matches('/')
            ))
            .timeout(HTTP_TIMEOUT)
            .header("X-Vault-Token", transit_token(config)),
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
    let token = transit_token(config);
    if token.is_empty() {
        return Err(KmsError::InvalidConfig(
            "Managed OpenBao access is not configured for the signing service".into(),
        ));
    }
    let key_url = format!(
        "{}/v1/{mount}/keys/{key_reference}",
        endpoint.trim_end_matches('/')
    );
    let client = Client::new();
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AzureManagedIdentity {
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AzureClientSecret {
    tenant_id: String,
    client_id: String,
    client_secret: String,
}

enum AzureAuth {
    ManagedIdentity(Option<String>),
    ClientSecret(AzureClientSecret),
}

fn valid_azure_tenant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn parse_azure_auth(config: &Value) -> Result<AzureAuth, KmsError> {
    let reference = string(config, "auth_reference").unwrap_or_default();
    match string(config, "auth_mode").unwrap_or("managed_identity") {
        "managed_identity" => {
            if reference.is_empty() {
                return Ok(AzureAuth::ManagedIdentity(None));
            }
            let identity: AzureManagedIdentity = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("Azure managed identity reference is invalid.".into())
            })?;
            if uuid::Uuid::parse_str(&identity.client_id).is_err() {
                return Err(KmsError::InvalidConfig(
                    "Azure managed identity client ID is invalid.".into(),
                ));
            }
            Ok(AzureAuth::ManagedIdentity(Some(identity.client_id)))
        }
        "client_secret" => {
            if reference.len() > 16_384 {
                return Err(KmsError::InvalidConfig(
                    "Azure client credential is invalid.".into(),
                ));
            }
            let credential: AzureClientSecret = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("Azure client credential is invalid.".into())
            })?;
            if !valid_azure_tenant(&credential.tenant_id)
                || uuid::Uuid::parse_str(&credential.client_id).is_err()
                || credential.client_secret.is_empty()
            {
                return Err(KmsError::InvalidConfig(
                    "Azure client credential is invalid.".into(),
                ));
            }
            Ok(AzureAuth::ClientSecret(credential))
        }
        "certificate" => Err(KmsError::InvalidConfig(
            "Azure certificate authentication requires a remote client-assertion signer.".into(),
        )),
        _ => Err(KmsError::InvalidConfig(
            "Azure authentication mode is unsupported.".into(),
        )),
    }
}

pub(crate) fn validate_azure_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_azure_auth(config).map(|_| ())
}

async fn azure_access_token(config: &Value) -> Result<String, KmsError> {
    match parse_azure_auth(config)? {
        AzureAuth::ManagedIdentity(client_id) => {
            let endpoint = env::var("IDENTITY_ENDPOINT")
                .ok()
                .filter(|value| !value.is_empty());
            let header = env::var("IDENTITY_HEADER")
                .ok()
                .filter(|value| !value.is_empty());
            match (endpoint, header) {
                (Some(endpoint), Some(header)) => {
                    let parsed = reqwest::Url::parse(&endpoint).map_err(|_| {
                        KmsError::InvalidConfig(
                            "Azure managed identity endpoint is invalid.".into(),
                        )
                    })?;
                    if parsed.scheme() != "http"
                        || !matches!(
                            parsed.host_str(),
                            Some("127.0.0.1" | "localhost" | "::1" | "169.254.169.254")
                        )
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                        || parsed.query().is_some()
                        || parsed.fragment().is_some()
                    {
                        return Err(KmsError::InvalidConfig(
                            "Azure managed identity endpoint is invalid.".into(),
                        ));
                    }
                    azure_managed_token(&endpoint, Some(&header), client_id.as_deref()).await
                }
                (None, None) => {
                    azure_managed_token(
                        "http://169.254.169.254/metadata/identity/oauth2/token",
                        None,
                        client_id.as_deref(),
                    )
                    .await
                }
                _ => Err(KmsError::InvalidConfig(
                    "Azure managed identity environment is incomplete.".into(),
                )),
            }
        }
        AzureAuth::ClientSecret(credential) => {
            let endpoint = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                credential.tenant_id
            );
            azure_client_secret_token(&endpoint, &credential).await
        }
    }
}

async fn azure_managed_token(
    endpoint: &str,
    header: Option<&str>,
    client_id: Option<&str>,
) -> Result<String, KmsError> {
    let client = Client::builder()
        .no_proxy()
        .build()
        .map_err(|_| KmsError::Provider("Azure identity HTTP client is unavailable.".into()))?;
    let version = if header.is_some() {
        "2019-08-01"
    } else {
        "2018-02-01"
    };
    let mut request = client.get(endpoint).timeout(HTTP_TIMEOUT).query(&[
        ("api-version", version),
        ("resource", "https://vault.azure.net"),
    ]);
    if let Some(header) = header {
        request = request.header("X-IDENTITY-HEADER", header);
    } else {
        request = request.header("Metadata", "true");
    }
    if let Some(client_id) = client_id {
        request = request.query(&[("client_id", client_id)]);
    }
    azure_token_value(send_json(request).await.map_err(|_| {
        KmsError::Provider("Azure managed identity token acquisition failed.".into())
    })?)
}

async fn azure_client_secret_token(
    endpoint: &str,
    credential: &AzureClientSecret,
) -> Result<String, KmsError> {
    let response = send_json(Client::new().post(endpoint).timeout(HTTP_TIMEOUT).form(&[
        ("grant_type", "client_credentials"),
        ("client_id", credential.client_id.as_str()),
        ("client_secret", credential.client_secret.as_str()),
        ("scope", "https://vault.azure.net/.default"),
    ]))
    .await
    .map_err(|_| KmsError::Provider("Azure client token acquisition failed.".into()))?;
    azure_token_value(response)
}

fn azure_token_value(response: Value) -> Result<String, KmsError> {
    response
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            KmsError::InvalidResponse("Azure identity response omitted access token.".into())
        })
}

async fn azure_bearer(
    builder: reqwest::RequestBuilder,
    config: &Value,
) -> Result<reqwest::RequestBuilder, KmsError> {
    Ok(builder.bearer_auth(azure_access_token(config).await?))
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
    let algorithm = string(config, "azure_signing_algorithm")
        .or_else(|| string(config, "algorithm"))
        .unwrap_or("ES256");
    let (_, digest) = signing_digest(algorithm, payload)?;
    let response = send_json(
        azure_bearer(
            Client::new().post(format!(
                "{}/keys/{key_path}/sign?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT)
        .json(&json!({
            "alg": algorithm,
            "value": URL_SAFE_NO_PAD.encode(digest),
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
        azure_bearer(
            Client::new().get(format!(
                "{}/keys/{key_path}?api-version=7.4",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
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
    let builder = match azure_bearer(
        Client::new().get(format!(
            "{}/keys?api-version=7.4",
            endpoint.trim_end_matches('/')
        )),
        config,
    )
    .await
    {
        Ok(builder) => builder,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    verify_http_status(
        builder.timeout(PROBE_TIMEOUT),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GcpServiceAccount {
    email: String,
}

enum GcpAuth {
    WorkloadIdentity,
    ServiceAccount(GcpServiceAccount),
}

fn parse_gcp_auth(config: &Value) -> Result<GcpAuth, KmsError> {
    let reference = string(config, "auth_reference").unwrap_or_default();
    match string(config, "auth_mode").unwrap_or("workload_identity") {
        "workload_identity" => {
            if !reference.is_empty() {
                return Err(KmsError::InvalidConfig(
                    "GCP workload identity does not accept a bearer token.".into(),
                ));
            }
            Ok(GcpAuth::WorkloadIdentity)
        }
        "service_account" => {
            if reference.len() > 4096 {
                return Err(KmsError::InvalidConfig(
                    "GCP service account reference is invalid.".into(),
                ));
            }
            let account: GcpServiceAccount = serde_json::from_str(reference).map_err(|_| {
                KmsError::InvalidConfig("GCP service account reference is invalid.".into())
            })?;
            if !valid_gcp_service_account(&account.email) {
                return Err(KmsError::InvalidConfig(
                    "GCP service account reference is invalid.".into(),
                ));
            }
            Ok(GcpAuth::ServiceAccount(account))
        }
        _ => Err(KmsError::InvalidConfig(
            "GCP authentication mode is unsupported.".into(),
        )),
    }
}

fn valid_gcp_service_account(email: &str) -> bool {
    email.len() <= 256
        && email.ends_with(".gserviceaccount.com")
        && email.split_once('@').is_some_and(|(name, domain)| {
            !name.is_empty()
                && !domain.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                && domain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        })
}

pub(crate) fn validate_gcp_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_gcp_auth(config).map(|_| ())
}

async fn gcp_metadata_token() -> Result<String, KmsError> {
    let host = env::var("GCE_METADATA_HOST")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "metadata.google.internal".into());
    if host
        .chars()
        .any(|character| matches!(character, '/' | '?' | '#' | '@') || character.is_whitespace())
    {
        return Err(KmsError::InvalidConfig(
            "GCP metadata endpoint is invalid.".into(),
        ));
    }
    let endpoint =
        format!("http://{host}/computeMetadata/v1/instance/service-accounts/default/token");
    let parsed = reqwest::Url::parse(&endpoint)
        .map_err(|_| KmsError::InvalidConfig("GCP metadata endpoint is invalid.".into()))?;
    if !matches!(
        parsed.host_str(),
        Some("metadata.google.internal" | "169.254.169.254" | "127.0.0.1" | "localhost" | "::1")
    ) || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some_and(|port| {
            port != 80 && !matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"))
        })
    {
        return Err(KmsError::InvalidConfig(
            "GCP metadata endpoint is invalid.".into(),
        ));
    }
    let client = Client::builder()
        .no_proxy()
        .build()
        .map_err(|_| KmsError::Provider("GCP metadata HTTP client is unavailable.".into()))?;
    let response = send_json(
        client
            .get(endpoint)
            .timeout(HTTP_TIMEOUT)
            .header("Metadata-Flavor", "Google"),
    )
    .await
    .map_err(|_| KmsError::Provider("GCP workload token acquisition failed.".into()))?;
    gcp_token_value(response, "access_token")
}

async fn gcp_service_account_token_at(
    endpoint: &str,
    account: &GcpServiceAccount,
    source_token: &str,
) -> Result<String, KmsError> {
    let email =
        percent_encoding::utf8_percent_encode(&account.email, percent_encoding::NON_ALPHANUMERIC);
    let response = send_json(
        Client::new()
            .post(format!(
                "{}/v1/projects/-/serviceAccounts/{email}:generateAccessToken",
                endpoint.trim_end_matches('/')
            ))
            .timeout(HTTP_TIMEOUT)
            .bearer_auth(source_token)
            .json(&json!({"scope": ["https://www.googleapis.com/auth/cloud-platform"]})),
    )
    .await
    .map_err(|_| KmsError::Provider("GCP service account token acquisition failed.".into()))?;
    gcp_token_value(response, "accessToken")
}

fn gcp_token_value(response: Value, field: &str) -> Result<String, KmsError> {
    response
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            KmsError::InvalidResponse("GCP identity response omitted access token.".into())
        })
}

async fn gcp_access_token(config: &Value) -> Result<String, KmsError> {
    match parse_gcp_auth(config)? {
        GcpAuth::WorkloadIdentity => gcp_metadata_token().await,
        GcpAuth::ServiceAccount(account) => {
            let source_token = gcp_metadata_token().await?;
            gcp_service_account_token_at(
                "https://iamcredentials.googleapis.com",
                &account,
                &source_token,
            )
            .await
        }
    }
}

async fn gcp_bearer(
    builder: reqwest::RequestBuilder,
    config: &Value,
) -> Result<reqwest::RequestBuilder, KmsError> {
    Ok(builder.bearer_auth(gcp_access_token(config).await?))
}

async fn sign_gcp(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let endpoint = string(config, "endpoint").unwrap_or("https://cloudkms.googleapis.com");
    let key_reference = required(
        config,
        "key_reference",
        "gcp-cloud-kms adapter requires 'key_reference' in service_config",
    )?;
    let algorithm = string(config, "algorithm").unwrap_or("ES256");
    let body = gcp_sign_body(algorithm, payload)?;
    let response = send_json(
        gcp_bearer(
            Client::new().post(format!(
                "{}/v1/{key_reference}:asymmetricSign",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
        .timeout(HTTP_TIMEOUT)
        .json(&body),
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
        gcp_bearer(
            Client::new().get(format!(
                "{}/v1/{key_reference}/publicKey",
                endpoint.trim_end_matches('/')
            )),
            config,
        )
        .await?
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
    let builder = match gcp_bearer(
        Client::new().get(format!(
            "{}/v1/{key_reference}",
            endpoint.trim_end_matches('/')
        )),
        config,
    )
    .await
    {
        Ok(builder) => builder,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    verify_http_status(
        builder.timeout(PROBE_TIMEOUT),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsAccessKey {
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsAssumeRole {
    role_arn: String,
    #[serde(default)]
    external_id: Option<String>,
}

enum AwsAuth {
    IamRole,
    AccessKey(AwsAccessKey),
    AssumeRole(AwsAssumeRole),
}

fn parse_aws_auth(config: &Value) -> Result<AwsAuth, KmsError> {
    match string(config, "auth_mode").unwrap_or("iam_role") {
        "iam_role" => {
            if string(config, "auth_reference").is_some_and(|reference| !reference.is_empty()) {
                return Err(KmsError::InvalidConfig(
                    "AWS IAM role mode does not accept a credential reference.".into(),
                ));
            }
            Ok(AwsAuth::IamRole)
        }
        "access_key" => {
            let encoded = required(
                config,
                "auth_reference",
                "AWS access key credential is required",
            )?;
            if encoded.len() > 16_384 {
                return Err(KmsError::InvalidConfig(
                    "AWS access key credential is invalid.".into(),
                ));
            }
            let credential: AwsAccessKey = serde_json::from_str(encoded).map_err(|_| {
                KmsError::InvalidConfig("AWS access key credential is invalid.".into())
            })?;
            if credential.access_key_id.trim().is_empty()
                || credential.secret_access_key.trim().is_empty()
            {
                return Err(KmsError::InvalidConfig(
                    "AWS access key credential is invalid.".into(),
                ));
            }
            Ok(AwsAuth::AccessKey(credential))
        }
        "assume_role" => {
            let encoded = required(config, "auth_reference", "AWS role reference is required")?;
            if encoded.len() > 4096 {
                return Err(KmsError::InvalidConfig(
                    "AWS role reference is invalid.".into(),
                ));
            }
            let role: AwsAssumeRole = serde_json::from_str(encoded)
                .map_err(|_| KmsError::InvalidConfig("AWS role reference is invalid.".into()))?;
            if !valid_aws_role_arn(&role.role_arn) {
                return Err(KmsError::InvalidConfig("AWS role ARN is invalid.".into()));
            }
            Ok(AwsAuth::AssumeRole(role))
        }
        _ => Err(KmsError::InvalidConfig(
            "AWS authentication mode is unsupported.".into(),
        )),
    }
}

pub(crate) fn validate_aws_auth_config(config: &Value) -> Result<(), KmsError> {
    parse_aws_auth(config).map(|_| ())
}

fn aws_role_source(loader: aws_config::ConfigLoader) -> Result<aws_config::ConfigLoader, KmsError> {
    let present = |name: &str| env::var(name).is_ok_and(|value| !value.trim().is_empty());
    let web_identity = present("AWS_WEB_IDENTITY_TOKEN_FILE") || present("AWS_ROLE_ARN");
    if web_identity {
        if !present("AWS_WEB_IDENTITY_TOKEN_FILE") || !present("AWS_ROLE_ARN") {
            return Err(KmsError::InvalidConfig(
                "AWS workload role identity is incomplete.".into(),
            ));
        }
        return Ok(loader.credentials_provider(
            aws_config::web_identity_token::WebIdentityTokenCredentialsProvider::builder().build(),
        ));
    }
    if present("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        || present("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    {
        return Ok(
            loader.credentials_provider(aws_config::ecs::EcsCredentialsProvider::builder().build())
        );
    }
    if env::var("AWS_EC2_METADATA_DISABLED").is_ok_and(|value| value.eq_ignore_ascii_case("true")) {
        return Err(KmsError::InvalidConfig(
            "AWS IAM role identity is unavailable.".into(),
        ));
    }
    Ok(loader.credentials_provider(
        aws_config::imds::credentials::ImdsCredentialsProvider::builder().build(),
    ))
}

async fn aws_client(config: &Value) -> Result<aws_sdk_kms::Client, KmsError> {
    let region = string(config, "region").unwrap_or("us-east-1").to_string();
    let mut loader = aws_config::defaults(BehaviorVersion::latest()).region(Region::new(region));
    if let Some(endpoint) = string(config, "endpoint").filter(|value| !value.is_empty()) {
        loader = loader.endpoint_url(endpoint);
        if endpoint.starts_with("http://") {
            loader = loader.http_client(aws_smithy_http_client::Builder::new().build_http());
        }
    }
    let sdk_config = match parse_aws_auth(config)? {
        AwsAuth::IamRole => aws_role_source(loader)?.load().await,
        AwsAuth::AccessKey(credential) => {
            loader
                .credentials_provider(Credentials::new(
                    credential.access_key_id,
                    credential.secret_access_key,
                    credential.session_token,
                    None,
                    "marty-tenant-credential",
                ))
                .load()
                .await
        }
        AwsAuth::AssumeRole(role) => {
            let source = aws_role_source(aws_config::defaults(BehaviorVersion::latest()).region(
                Region::new(string(config, "region").unwrap_or("us-east-1").to_string()),
            ))?
            .load()
            .await;
            let mut builder = aws_config::sts::AssumeRoleProvider::builder(role.role_arn)
                .session_name("marty-signing-keys")
                .configure(&source);
            if let Some(external_id) = role.external_id.filter(|value| !value.is_empty()) {
                builder = builder.external_id(external_id);
            }
            loader
                .credentials_provider(builder.build().await)
                .load()
                .await
        }
    };
    Ok(aws_sdk_kms::Client::new(&sdk_config))
}

fn valid_aws_role_arn(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && matches!(parts[1], "aws" | "aws-us-gov" | "aws-cn")
        && parts[2] == "iam"
        && parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("role/")
        && parts[5].len() > 5
        && !value.chars().any(char::is_whitespace)
}

async fn sign_aws(config: &Value, payload: &[u8]) -> Result<Vec<u8>, KmsError> {
    let key_id = required(
        config,
        "key_reference",
        "aws-kms adapter requires 'key_reference' in service_config",
    )?;
    let jose_algorithm = string(config, "algorithm").unwrap_or("ES256");
    let algorithm = aws_signing_algorithm(jose_algorithm)?;
    if string(config, "aws_signing_algorithm").is_some_and(|configured| configured != algorithm) {
        return Err(KmsError::InvalidConfig(format!(
            "AWS signing algorithm must be {algorithm} for {jose_algorithm}."
        )));
    }
    // AWS KMS caps RAW messages at 4096 bytes. Its DIGEST mode signs the
    // pre-hashed input without hashing it a second time.
    let (_, digest) = signing_digest(jose_algorithm, payload)?;
    let output = aws_client(config)
        .await?
        .sign()
        .key_id(key_id)
        .message(Blob::new(digest))
        .message_type(MessageType::Digest)
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

pub(crate) fn aws_signing_algorithm(algorithm: &str) -> Result<&'static str, KmsError> {
    match algorithm {
        "ES256" => Ok("ECDSA_SHA_256"),
        "ES384" => Ok("ECDSA_SHA_384"),
        "ES512" => Ok("ECDSA_SHA_512"),
        "RS256" => Ok("RSASSA_PKCS1_V1_5_SHA_256"),
        "RS384" => Ok("RSASSA_PKCS1_V1_5_SHA_384"),
        "RS512" => Ok("RSASSA_PKCS1_V1_5_SHA_512"),
        "PS256" => Ok("RSASSA_PSS_SHA_256"),
        "PS384" => Ok("RSASSA_PSS_SHA_384"),
        "PS512" => Ok("RSASSA_PSS_SHA_512"),
        other => Err(KmsError::InvalidConfig(format!(
            "Unsupported AWS signing algorithm '{other}'."
        ))),
    }
}

async fn public_key_aws(config: &Value) -> Result<Value, KmsError> {
    let key_id = required(
        config,
        "key_reference",
        "aws-kms adapter requires 'key_reference' in service_config",
    )?;
    let output = aws_client(config)
        .await?
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
    let client = match aws_client(config).await {
        Ok(client) => client,
        Err(error) => return CapabilityResult::fail("Authentication", error.to_string()),
    };
    match client.describe_key().key_id(key_id).send().await {
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

fn key_path<'a>(key_reference: &'a str, version: Option<&'a str>) -> String {
    version
        .filter(|value| !value.is_empty())
        .map(|version| format!("{key_reference}/{version}"))
        .unwrap_or_else(|| key_reference.to_string())
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
    let token = transit_token(config);
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

fn bounded(value: &str) -> String {
    value.chars().take(MAX_PROVIDER_ERROR_BYTES).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn azure_client_secret_uses_scoped_oauth_form() {
        async fn token(request: axum::extract::Request) -> axum::Json<Value> {
            assert_eq!(request.method(), reqwest::Method::POST);
            let body = axum::body::to_bytes(request.into_body(), 4096)
                .await
                .unwrap();
            let form = String::from_utf8(body.to_vec()).unwrap();
            assert!(form.contains("grant_type=client_credentials"));
            assert!(form.contains("scope=https%3A%2F%2Fvault.azure.net%2F.default"));
            assert!(form.contains("client_secret=fixture-secret"));
            axum::Json(json!({"access_token": "scoped-azure-token"}))
        }
        let app = axum::Router::new().route("/token", axum::routing::post(token));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = json!({
            "auth_mode": "client_secret",
            "auth_reference": r#"{"tenant_id":"11111111-1111-1111-1111-111111111111","client_id":"22222222-2222-2222-2222-222222222222","client_secret":"fixture-secret"}"#
        });
        assert!(validate_azure_auth_config(&config).is_ok());
        let AzureAuth::ClientSecret(credential) = parse_azure_auth(&config).unwrap() else {
            panic!("client-secret mode was not selected")
        };
        assert_eq!(
            azure_client_secret_token(&endpoint, &credential)
                .await
                .unwrap(),
            "scoped-azure-token"
        );
        server.abort();
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
                            axum::Json(
                                json!({"data":{"signature":format!("vault:v{version}:AQID")}}),
                            )
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
            "algorithm":"EdDSA", "auth_reference":"fixture-token", "key_version":1
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
        assert_eq!(response.signature_b64, "AQID");
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
            "algorithm": "ES256", "auth_reference": "test-token"
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
            assert!(Provider::from_config(&json!({"service_type": service_type})).is_ok());
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
