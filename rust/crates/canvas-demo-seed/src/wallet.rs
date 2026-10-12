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
        let body = response.text().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("wallet issuance request failed ({status}): {body}"));
        }
        if body.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&body).map_err(|e| e.to_string())
        }
    }
}

pub trait WalletProof {
    fn create_proof_jwt(&self, audience: &str, nonce: &str) -> Result<String, String>;
}

pub struct CanonicalWalletProof;

impl WalletProof for CanonicalWalletProof {
    fn create_proof_jwt(&self, audience: &str, nonce: &str) -> Result<String, String> {
        marty_oid4vci::proof::create_proof_jwt(audience, nonce).map_err(|e| e.to_string())
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
pub async fn claim_wallet_credential<T: WalletTransport + Sync, P: WalletProof>(
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
    let nonce = token["c_nonce"]
        .as_str()
        .filter(|value| !value.is_empty())
        .or_else(|| token["nonce"].as_str().filter(|value| !value.is_empty()))
        .ok_or("Token endpoint did not return a c_nonce")?;
    let audience_base = if public_api_url.trim().is_empty() {
        base
    } else {
        public_api_url.trim_end_matches('/')
    };
    let audience = format!("{audience_base}/org/{}", cfg.organization_id);
    let proof_jwt = proof.create_proof_jwt(&audience, nonce)?;
    let response = transport
        .request(WalletOperation {
            method: "POST",
            url: format!("{base}/v1/issuance/credential"),
            json: Some(json!({
                "format": "vc+sd-jwt",
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
