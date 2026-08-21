use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    env, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::Duration,
};
use thiserror::Error;
use tokio::net::lookup_host;
use url::{Host, Url};

pub const WEBHOOK_SECRET_ENVELOPE_KEY_ID: &str = "notification-webhook-envelope-marty-aes256";
pub const WEBHOOK_SECRET_ENVELOPE_SCHEMA: &str = "marty.notification-webhook-secret/v1";
pub const WEBHOOK_SECRET_ENVELOPE_PURPOSE: &str = "webhook_hmac_signing";
const MIN_SECRET_LENGTH: usize = 32;
const MAX_SECRET_LENGTH: usize = 128;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WebhookError {
    #[error("{code}")]
    Destination { code: &'static str, retryable: bool },
    #[error("{0}")]
    EnvelopeUnavailable(String),
    #[error("{0}")]
    InvalidEnvelope(String),
}

impl WebhookError {
    pub const fn destination(code: &'static str, retryable: bool) -> Self {
        Self::Destination { code, retryable }
    }

    pub const fn code(&self) -> &'static str {
        match self {
            Self::Destination { code, .. } => code,
            Self::EnvelopeUnavailable(_) => "WEBHOOK_SECRET_KMS_UNAVAILABLE",
            Self::InvalidEnvelope(_) => "WEBHOOK_SECRET_ENVELOPE_INVALID",
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Destination {
                retryable: true,
                ..
            } | Self::EnvelopeUnavailable(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWebhookUrl {
    pub original: Url,
    pub hostname: String,
    pub port: u16,
}

pub fn valid_webhook_signing_secret(secret: &str) -> bool {
    let normalized = secret.trim();
    let lowered = normalized.to_ascii_lowercase();
    (MIN_SECRET_LENGTH..=MAX_SECRET_LENGTH).contains(&normalized.len())
        && !["change-me", "change_me", "changeme"]
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
}

pub fn generate_webhook_secret() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn read_secret_value(name: &str) -> Result<String, WebhookError> {
    let direct = env::var(name).unwrap_or_default().trim().to_owned();
    if !direct.is_empty() {
        return Ok(direct);
    }
    let file_name = env::var(format!("{name}_FILE"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    if file_name.is_empty() {
        return Ok(String::new());
    }
    fs::read_to_string(Path::new(&file_name))
        .map(|value| value.trim().to_owned())
        .map_err(|_| WebhookError::EnvelopeUnavailable("secret file is unavailable".into()))
}

pub fn load_direct_webhook_signing_secret() -> Option<String> {
    let inline = env::var("NOTIFICATION_WEBHOOK_SECRET")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let file_name = env::var("NOTIFICATION_WEBHOOK_SECRET_FILE")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if !inline.is_empty() && !file_name.is_empty() {
        return None;
    }
    let candidate = if file_name.is_empty() {
        inline
    } else {
        fs::read_to_string(file_name).ok()?.trim().to_owned()
    };
    valid_webhook_signing_secret(&candidate).then_some(candidate)
}

pub fn validate_webhook_url_structure(url: &str) -> Result<ValidatedWebhookUrl, WebhookError> {
    if url.is_empty() || url.trim() != url {
        return Err(WebhookError::destination(
            "WEBHOOK_DESTINATION_REJECTED",
            false,
        ));
    }
    let parsed = Url::parse(url)
        .map_err(|_| WebhookError::destination("WEBHOOK_DESTINATION_REJECTED", false))?;
    if parsed.scheme() != "https" {
        return Err(WebhookError::destination("WEBHOOK_HTTPS_REQUIRED", false));
    }
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(WebhookError::destination(
            "WEBHOOK_DESTINATION_REJECTED",
            false,
        ));
    }
    let hostname = parsed
        .host_str()
        .ok_or_else(|| WebhookError::destination("WEBHOOK_DESTINATION_REJECTED", false))?
        .to_owned();
    if let Some(address) = match parsed.host() {
        Some(Host::Ipv4(value)) => Some(IpAddr::V4(value)),
        Some(Host::Ipv6(value)) => Some(IpAddr::V6(value)),
        _ => None,
    } {
        require_global(address)?;
    }
    Ok(ValidatedWebhookUrl {
        original: parsed,
        hostname,
        port: Url::parse(url)
            .ok()
            .and_then(|value| value.port())
            .unwrap_or(443),
    })
}

fn require_global(address: IpAddr) -> Result<(), WebhookError> {
    if is_global_address(address) {
        Ok(())
    } else {
        Err(WebhookError::destination(
            "WEBHOOK_DESTINATION_REJECTED",
            false,
        ))
    }
}

fn is_global_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            let blocked = [
                ("0.0.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 8),
                ("10.0.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 8),
                ("100.64.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 10),
                ("127.0.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 8),
                (
                    "169.254.0.0".parse::<Ipv4Addr>().expect("constant IPv4"),
                    16,
                ),
                ("172.16.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 12),
                ("192.0.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 24),
                ("192.0.2.0".parse::<Ipv4Addr>().expect("constant IPv4"), 24),
                (
                    "192.88.99.0".parse::<Ipv4Addr>().expect("constant IPv4"),
                    24,
                ),
                (
                    "192.168.0.0".parse::<Ipv4Addr>().expect("constant IPv4"),
                    16,
                ),
                ("198.18.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 15),
                (
                    "198.51.100.0".parse::<Ipv4Addr>().expect("constant IPv4"),
                    24,
                ),
                (
                    "203.0.113.0".parse::<Ipv4Addr>().expect("constant IPv4"),
                    24,
                ),
                ("224.0.0.0".parse::<Ipv4Addr>().expect("constant IPv4"), 3),
            ];
            !blocked.into_iter().any(|(network, prefix)| {
                let mask = u32::MAX << (32 - prefix);
                value & mask == u32::from(network) & mask
            })
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_global_address(IpAddr::V4(mapped));
            }
            let value = u128::from(address);
            let blocked = [
                ("::".parse::<Ipv6Addr>().expect("constant IPv6"), 128),
                ("::1".parse::<Ipv6Addr>().expect("constant IPv6"), 128),
                ("100::".parse::<Ipv6Addr>().expect("constant IPv6"), 64),
                ("2001:2::".parse::<Ipv6Addr>().expect("constant IPv6"), 48),
                ("2001:db8::".parse::<Ipv6Addr>().expect("constant IPv6"), 32),
                ("fc00::".parse::<Ipv6Addr>().expect("constant IPv6"), 7),
                ("fe80::".parse::<Ipv6Addr>().expect("constant IPv6"), 10),
                ("ff00::".parse::<Ipv6Addr>().expect("constant IPv6"), 8),
            ];
            !blocked.into_iter().any(|(network, prefix)| {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                value & mask == u128::from(network) & mask
            })
        }
    }
}

pub async fn resolve_webhook_destination(
    url: &str,
) -> Result<(ValidatedWebhookUrl, Vec<SocketAddr>), WebhookError> {
    let validated = validate_webhook_url_structure(url)?;
    let addresses = lookup_host((validated.hostname.as_str(), validated.port))
        .await
        .map_err(|_| WebhookError::destination("WEBHOOK_DESTINATION_UNAVAILABLE", true))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(WebhookError::destination(
            "WEBHOOK_DESTINATION_UNAVAILABLE",
            true,
        ));
    }
    for address in &addresses {
        require_global(address.ip())?;
    }
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    Ok((validated, addresses))
}

pub fn canonical_signature(secret: &str, payload: &Map<String, Value>) -> String {
    let canonical = serde_json::to_vec(&canonical_json(&Value::Object(payload.clone())))
        .expect("JSON map serialization cannot fail");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key sizes");
    mac.update(&canonical);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(name, _)| *name);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(name, value)| (name.clone(), canonical_json(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

pub fn encode_bound_webhook_secret(
    organization_id: &str,
    webhook_id: &str,
    secret: &str,
) -> Result<String, WebhookError> {
    if organization_id.is_empty() || webhook_id.is_empty() {
        return Err(WebhookError::InvalidEnvelope(
            "Webhook secret binding is incomplete".into(),
        ));
    }
    if !valid_webhook_signing_secret(secret) {
        return Err(WebhookError::InvalidEnvelope(
            "Webhook signing secret is invalid".into(),
        ));
    }
    let document = BTreeMap::from([
        ("organization_id", organization_id),
        ("purpose", WEBHOOK_SECRET_ENVELOPE_PURPOSE),
        ("schema", WEBHOOK_SECRET_ENVELOPE_SCHEMA),
        ("secret", secret),
        ("webhook_id", webhook_id),
    ]);
    let encoded = serde_json::to_vec(&document)
        .map_err(|error| WebhookError::InvalidEnvelope(error.to_string()))?;
    Ok(STANDARD.encode(encoded))
}

pub fn decode_bound_webhook_secret(
    plaintext: &str,
    organization_id: &str,
    webhook_id: &str,
) -> Result<String, WebhookError> {
    let decoded = STANDARD.decode(plaintext).map_err(|_| {
        WebhookError::InvalidEnvelope("Webhook secret envelope plaintext is malformed".into())
    })?;
    let document: BTreeMap<String, Value> = serde_json::from_slice(&decoded).map_err(|_| {
        WebhookError::InvalidEnvelope("Webhook secret envelope plaintext is malformed".into())
    })?;
    let expected = [
        ("schema", WEBHOOK_SECRET_ENVELOPE_SCHEMA),
        ("organization_id", organization_id),
        ("webhook_id", webhook_id),
        ("purpose", WEBHOOK_SECRET_ENVELOPE_PURPOSE),
    ];
    if expected
        .iter()
        .any(|(key, value)| document.get(*key).and_then(Value::as_str) != Some(*value))
    {
        return Err(WebhookError::InvalidEnvelope(
            "Webhook secret envelope binding mismatch".into(),
        ));
    }
    if document.len() != 5 {
        return Err(WebhookError::InvalidEnvelope(
            "Webhook secret envelope contains unexpected fields".into(),
        ));
    }
    let secret = document
        .get("secret")
        .and_then(Value::as_str)
        .filter(|value| valid_webhook_signing_secret(value))
        .ok_or_else(|| {
            WebhookError::InvalidEnvelope(
                "Webhook secret envelope contains an invalid signing secret".into(),
            )
        })?;
    Ok(secret.to_owned())
}

#[derive(Debug, Clone)]
pub struct WebhookSecretEnvelope {
    bao_addr: String,
    bao_token: String,
    key_id: String,
    client: Client,
}

impl WebhookSecretEnvelope {
    pub fn from_environment() -> Result<Self, WebhookError> {
        let bao_addr = env::var("BAO_ADDR")
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_owned();
        let dedicated = read_secret_value("NOTIFICATION_OPENBAO_TOKEN")?;
        let environment = env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".into())
            .to_ascii_lowercase();
        if matches!(environment.as_str(), "production" | "prod") && dedicated.is_empty() {
            return Err(WebhookError::EnvelopeUnavailable(
                "Dedicated Notification OpenBao identity is not configured".into(),
            ));
        }
        let token = if dedicated.is_empty() {
            let shared = read_secret_value("OPENBAO_SERVICE_TOKEN")?;
            if shared.is_empty() {
                read_secret_value("BAO_TOKEN")?
            } else {
                shared
            }
        } else {
            dedicated
        };
        if bao_addr.is_empty() || token.is_empty() || Url::parse(&bao_addr).is_err() {
            return Err(WebhookError::EnvelopeUnavailable(
                "OpenBao webhook secret protection is not configured".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|error| WebhookError::EnvelopeUnavailable(error.to_string()))?;
        Ok(Self {
            bao_addr,
            bao_token: token,
            key_id: WEBHOOK_SECRET_ENVELOPE_KEY_ID.into(),
            client,
        })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        invalid_ciphertext_status: bool,
    ) -> Result<Value, WebhookError> {
        let mut request = self
            .client
            .request(
                method,
                format!("{}/v1/{}", self.bao_addr, path.trim_start_matches('/')),
            )
            .header("X-Vault-Token", &self.bao_token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|_| {
            WebhookError::EnvelopeUnavailable(
                "OpenBao webhook secret operation is unavailable".into(),
            )
        })?;
        if invalid_ciphertext_status && response.status() == StatusCode::BAD_REQUEST {
            return Err(WebhookError::InvalidEnvelope(
                "Webhook secret ciphertext was rejected".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(WebhookError::EnvelopeUnavailable(format!(
                "OpenBao webhook secret operation failed with HTTP {}",
                response.status().as_u16()
            )));
        }
        response.json().await.map_err(|_| {
            WebhookError::EnvelopeUnavailable("OpenBao webhook secret response is invalid".into())
        })
    }

    pub async fn check_ready(&self) -> Result<(), WebhookError> {
        let payload = self
            .request(
                reqwest::Method::GET,
                &format!("transit/keys/{}", self.key_id),
                None,
                false,
            )
            .await?;
        let data = payload
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                WebhookError::EnvelopeUnavailable(
                    "OpenBao webhook secret key metadata is invalid".into(),
                )
            })?;
        if data.get("type").and_then(Value::as_str) != Some("aes256-gcm96")
            || data.get("exportable").and_then(Value::as_bool) != Some(false)
        {
            return Err(WebhookError::EnvelopeUnavailable(
                "OpenBao webhook secret key has unsafe attributes".into(),
            ));
        }
        Ok(())
    }

    pub async fn wrap(
        &self,
        organization_id: &str,
        webhook_id: &str,
        secret: &str,
    ) -> Result<String, WebhookError> {
        let plaintext = encode_bound_webhook_secret(organization_id, webhook_id, secret)?;
        let body = serde_json::json!({"plaintext": plaintext});
        let payload = self
            .request(
                reqwest::Method::POST,
                &format!("transit/encrypt/{}", self.key_id),
                Some(&body),
                false,
            )
            .await?;
        payload
            .pointer("/data/ciphertext")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("vault:"))
            .map(str::to_owned)
            .ok_or_else(|| {
                WebhookError::EnvelopeUnavailable(
                    "OpenBao did not return a webhook secret ciphertext".into(),
                )
            })
    }

    pub async fn unwrap(
        &self,
        organization_id: &str,
        webhook_id: &str,
        ciphertext: &str,
    ) -> Result<String, WebhookError> {
        if !ciphertext.starts_with("vault:") {
            return Err(WebhookError::InvalidEnvelope(
                "Webhook secret ciphertext is invalid".into(),
            ));
        }
        let body = serde_json::json!({"ciphertext": ciphertext});
        let payload = self
            .request(
                reqwest::Method::POST,
                &format!("transit/decrypt/{}", self.key_id),
                Some(&body),
                true,
            )
            .await?;
        let plaintext = payload
            .pointer("/data/plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WebhookError::EnvelopeUnavailable(
                    "OpenBao did not return webhook secret plaintext".into(),
                )
            })?;
        decode_bound_webhook_secret(plaintext, organization_id, webhook_id)
    }
}

pub fn pinned_client(hostname: &str, addresses: &[SocketAddr]) -> Result<Client, WebhookError> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .resolve_to_addrs(hostname, addresses)
        .build()
        .map_err(|_| WebhookError::destination("WEBHOOK_DESTINATION_UNAVAILABLE", true))
}
