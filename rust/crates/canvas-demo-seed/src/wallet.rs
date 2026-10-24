use crate::GatewaySeedConfig;
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WalletOperation {
    pub method: &'static str,
    pub url: String,
    pub json: Option<Value>,
    pub form: Option<Vec<(String, String)>>,
    pub bearer: Option<String>,
    pub timeout_seconds: u64,
}

#[async_trait]
pub trait WalletTransport {
    async fn request(&self, operation: WalletOperation) -> Result<Value, String>;
}

pub struct WalletHttp {
    client: reqwest::Client,
}

impl WalletHttp {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for WalletHttp {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WalletTransport for WalletHttp {
    async fn request(&self, operation: WalletOperation) -> Result<Value, String> {
        let method =
            reqwest::Method::from_bytes(operation.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut request = self
            .client
            .request(method, &operation.url)
            .header("Accept", "application/json")
            .timeout(Duration::from_secs(operation.timeout_seconds));
        if let Some(bearer) = operation.bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(payload) = operation.json {
            request = request.json(&payload);
        }
        if let Some(form) = operation.form {
            request = request.form(&form);
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("wallet issuance request failed ({status})"));
        }
        let body = response.text().await.map_err(|e| e.to_string())?;
        if body.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&body).map_err(|e| e.to_string())
        }
    }
}

#[async_trait]
pub trait WalletProof {
    async fn create_proof_jwt(&self, audience: &str, nonce: &str) -> Result<String, String>;
}

/// Uses the same KMS-backed holder proof provider as the Gateway VC-API bridge.
pub struct CanonicalWalletProof {
    url: String,
    api_key: String,
    organization_id: String,
    client: reqwest::Client,
}

impl CanonicalWalletProof {
    pub fn new(
        signing_keys_internal_base_url: &str,
        api_key: &str,
        organization_id: &str,
    ) -> Result<Self, String> {
        let service = reqwest::Url::parse(signing_keys_internal_base_url)
            .map_err(|_| "Signing keys holder proof URL is invalid")?;
        if !matches!(service.scheme(), "http" | "https")
            || service.host_str().is_none()
            || !service.username().is_empty()
            || service.password().is_some()
            || service.path().trim_end_matches('/') != "/internal/signing-keys"
            || service.query().is_some()
            || service.fragment().is_some()
            || api_key.trim().is_empty()
            || organization_id.trim().is_empty()
        {
            return Err("Signing keys holder proof configuration is incomplete".into());
        }
        Ok(Self {
            url: format!(
                "{}/internal/vc-api/holder-proof",
                service.origin().ascii_serialization()
            ),
            api_key: api_key.into(),
            organization_id: organization_id.into(),
            client: reqwest::Client::new(),
        })
    }
}

#[async_trait]
impl WalletProof for CanonicalWalletProof {
    async fn create_proof_jwt(&self, audience: &str, nonce: &str) -> Result<String, String> {
        let response = self
            .client
            .post(&self.url)
            .header("x-api-key", &self.api_key)
            .json(&json!({
                "organization_id": self.organization_id,
                "issuer_url": audience,
                "nonce": nonce,
            }))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("KMS holder proof request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "KMS holder proof request failed ({})",
                response.status()
            ));
        }
        let body: Value = response.json().await.map_err(|e| e.to_string())?;
        body["proof_jwt"]
            .as_str()
            .filter(|proof| !proof.is_empty())
            .map(str::to_owned)
            .ok_or("KMS holder proof response did not include proof_jwt".into())
    }
}

fn pre_authorized_code(offer: &Value) -> Option<&str> {
    let grant = &offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
    for candidate in [grant, offer] {
        for key in ["pre-authorized_code", "pre_authorized_code"] {
            if let Some(code) = candidate[key]
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Some(code);
            }
        }
    }
    None
}

fn compact_credential(response: &Value) -> Option<&str> {
    response["credential"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            response["credentials"]
                .as_array()
                .and_then(|items| items.first())
                .and_then(|first| first.as_str().or_else(|| first["credential"].as_str()))
                .filter(|value| !value.trim().is_empty())
        })
}

/// Claims one demo credential through the public pre-authorized OID4VCI path.
pub async fn claim_wallet_credential<T: WalletTransport + Sync, P: WalletProof + Sync>(
    transport: &T,
    proof: &P,
    cfg: &GatewaySeedConfig,
    public_api_url: &str,
    transaction_id: &str,
) -> Result<Value, String> {
    let base = cfg.base_url.trim_end_matches('/');
    let offer = transport
        .request(WalletOperation {
            method: "GET",
            url: format!("{base}/v1/issuance/offers/{transaction_id}"),
            json: None,
            form: None,
            bearer: None,
            timeout_seconds: 20,
        })
        .await?;
    if !offer.is_object() {
        return Err("Credential offer endpoint did not return an object".into());
    }
    let code = pre_authorized_code(&offer)
        .ok_or("Credential offer did not include a pre-authorized code")?;
    let token = transport
        .request(WalletOperation {
            method: "POST",
            url: format!("{base}/v1/issuance/token"),
            json: None,
            form: Some(vec![
                (
                    "grant_type".into(),
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code".into(),
                ),
                ("pre-authorized_code".into(), code.into()),
            ]),
            bearer: None,
            timeout_seconds: 20,
        })
        .await?;
    let access_token = token["access_token"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("Token endpoint did not return an access token")?;
    // The current issuer returns proof nonces from the dedicated endpoint,
    // independently of the token exchange. Do not reuse a legacy token nonce.
    let nonce_response = transport
        .request(WalletOperation {
            method: "POST",
            url: format!("{base}/v1/issuance/nonce"),
            json: None,
            form: None,
            bearer: None,
            timeout_seconds: 20,
        })
        .await?;
    let nonce = nonce_response["c_nonce"]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or("Nonce endpoint did not return a c_nonce")?;
    let audience_base = if public_api_url.trim().is_empty() {
        base
    } else {
        public_api_url.trim_end_matches('/')
    };
    let audience = format!("{audience_base}/org/{}", cfg.organization_id);
    let proof_jwt = proof.create_proof_jwt(&audience, nonce).await?;
    let response = transport
        .request(WalletOperation {
            method: "POST",
            url: format!("{base}/v1/issuance/credential"),
            json: Some(json!({
                "credential_configuration_id": "OpenBadgeCredential#sd-jwt",
                "proofs": {"jwt": [proof_jwt]}
            })),
            form: None,
            bearer: Some(access_token.into()),
            timeout_seconds: 60,
        })
        .await?;
    if !response.is_object() {
        return Err("Credential endpoint did not return an object".into());
    }
    let compact =
        compact_credential(&response).ok_or("Credential endpoint did not return a credential")?;
    Ok(json!({
        "transaction_id": transaction_id,
        "credential_format": "vc+sd-jwt",
        "credential_size": compact.len(),
        "credential_hash": hex::encode(Sha256::digest(compact.as_bytes())),
        "notification_id": response.get("notification_id")
    }))
}
