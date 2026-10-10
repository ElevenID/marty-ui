//! Scoped remote HAIP response-key operations backed by OpenBao.

use std::{path::PathBuf, time::Duration};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use marty_oid4vp_contract::haip_key::{matches_public_jwk, valid_version as valid_haip_version};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

use crate::kms::{self, KmsError};

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct OpenBaoEnvelopeProvider {
    endpoint: String,
    token: String,
    haip_token_file: Option<PathBuf>,
    client: Client,
}

#[derive(Debug, Deserialize)]
pub struct CreateHaipKeyRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ResolveHaipKeyRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptHaipResponseRequest {
    pub organization_id: String,
    pub flow_instance_id: String,
    pub version: String,
    pub jwe: String,
}

#[derive(Debug, Error)]
pub enum FlowEnvelopeError {
    #[error("Invalid internal signing API key.")]
    Unauthorized,
    #[error("KMS flow-key provider is unavailable.")]
    Unavailable,
    #[error("Invalid HAIP response-key scope or version.")]
    InvalidHaipScope,
    #[error("Remote HAIP response-key operation failed.")]
    HaipFailed,
}

impl IntoResponse for FlowEnvelopeError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::InvalidHaipScope => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unavailable | Self::HaipFailed => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"detail": self.to_string()}))).into_response()
    }
}

impl OpenBaoEnvelopeProvider {
    pub fn new(endpoint: impl Into<String>, token: impl Into<String>) -> Result<Self, String> {
        let endpoint = endpoint.into().trim_end_matches('/').to_owned();
        let token = token.into();
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|error| format!("BAO_ADDR is invalid: {error}"))?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || token.trim().is_empty()
        {
            return Err("OpenBao envelope provider configuration is invalid".into());
        }
        Ok(Self {
            endpoint,
            token,
            haip_token_file: None,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "OpenBao envelope HTTP client is unavailable")?,
        })
    }

    pub fn with_haip_token_file(mut self, path: PathBuf) -> Result<Self, String> {
        if path.as_os_str().is_empty() || !path.is_file() {
            return Err("HAIP_KMS_TOKEN_FILE must be a readable file".into());
        }
        self.haip_token_file = Some(path);
        Ok(self)
    }

    pub async fn create_haip_key(
        &self,
        request: CreateHaipKeyRequest,
    ) -> Result<Value, FlowEnvelopeError> {
        let (tenant, flow) = haip_scope(&request.organization_id, &request.flow_instance_id)?;
        let response = self
            .post_haip(&format!("/v1/didcomm/haip/keys/{tenant}/{flow}"), json!({}))
            .await?;
        haip_public_key_response(&response, tenant, flow, None)
    }

    pub async fn resolve_haip_key(
        &self,
        request: ResolveHaipKeyRequest,
    ) -> Result<Value, FlowEnvelopeError> {
        let (tenant, flow) = haip_scope(&request.organization_id, &request.flow_instance_id)?;
        if !valid_haip_version(&request.version) {
            return Err(FlowEnvelopeError::InvalidHaipScope);
        }
        let response = self
            .get_haip(&format!(
                "/v1/didcomm/haip/keys/{tenant}/{flow}/versions/{}",
                request.version
            ))
            .await?;
        haip_public_key_response(&response, tenant, flow, Some(&request.version))
    }

    pub async fn decrypt_haip_response(
        &self,
        request: DecryptHaipResponseRequest,
    ) -> Result<Value, FlowEnvelopeError> {
        let (tenant, flow) = haip_scope(&request.organization_id, &request.flow_instance_id)?;
        if !valid_haip_version(&request.version)
            || request.jwe.is_empty()
            || request.jwe.len() > 2 << 20
        {
            return Err(FlowEnvelopeError::InvalidHaipScope);
        }
        let response = self
            .post_haip(
                &format!(
                    "/v1/didcomm/haip/decrypt/{tenant}/{flow}/{}",
                    request.version
                ),
                json!({"jwe": request.jwe}),
            )
            .await?;
        let data = response.get("data").ok_or(FlowEnvelopeError::HaipFailed)?;
        if haip_version(data, tenant, flow)? != request.version {
            return Err(FlowEnvelopeError::HaipFailed);
        }
        let encoded = data
            .get("plaintext_base64")
            .and_then(Value::as_str)
            .ok_or(FlowEnvelopeError::HaipFailed)?;
        if encoded.len() > 4 * ((1 << 20) / 3 + 2) {
            return Err(FlowEnvelopeError::HaipFailed);
        }
        let plaintext = STANDARD
            .decode(encoded)
            .map_err(|_| FlowEnvelopeError::HaipFailed)?;
        if plaintext.is_empty() || plaintext.len() > 1 << 20 {
            return Err(FlowEnvelopeError::HaipFailed);
        }
        Ok(json!({
            "organization_id": tenant,
            "flow_instance_id": flow,
            "version": request.version,
            "plaintext_b64": URL_SAFE_NO_PAD.encode(plaintext),
        }))
    }

    pub(crate) async fn post(&self, path: &str, body: Value) -> Result<Value, KmsError> {
        self.post_with_token(path, body, &self.token).await
    }

    async fn post_haip(&self, path: &str, body: Value) -> Result<Value, FlowEnvelopeError> {
        let token = self.haip_token()?;
        self.post_with_token(path, body, &token)
            .await
            .map_err(|_| FlowEnvelopeError::HaipFailed)
    }

    async fn get_haip(&self, path: &str) -> Result<Value, FlowEnvelopeError> {
        let token = self.haip_token()?;
        let url = self
            .provider_url(path)
            .map_err(|_| FlowEnvelopeError::HaipFailed)?;
        let response = self
            .client
            .get(url)
            .timeout(TIMEOUT)
            .header("X-Vault-Token", token)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| FlowEnvelopeError::HaipFailed)?
            .error_for_status()
            .map_err(|_| FlowEnvelopeError::HaipFailed)?;
        kms::bounded_provider_json(response, kms::MAX_PROVIDER_JSON_BYTES)
            .await
            .map_err(|_| FlowEnvelopeError::HaipFailed)
    }

    fn haip_token(&self) -> Result<String, FlowEnvelopeError> {
        let path_to_token = self
            .haip_token_file
            .as_ref()
            .ok_or(FlowEnvelopeError::Unavailable)?;
        let metadata =
            std::fs::metadata(path_to_token).map_err(|_| FlowEnvelopeError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(FlowEnvelopeError::Unavailable);
        }
        let token =
            std::fs::read_to_string(path_to_token).map_err(|_| FlowEnvelopeError::Unavailable)?;
        let token = token.trim();
        if token.is_empty() || token.len() > 4096 || token.contains(['\r', '\n']) {
            return Err(FlowEnvelopeError::Unavailable);
        }
        Ok(token.to_owned())
    }

    async fn post_with_token(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> Result<Value, KmsError> {
        let url = self.provider_url(path)?;
        let response = self
            .client
            .post(url)
            .timeout(TIMEOUT)
            .header("X-Vault-Token", token)
            .header("accept", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| KmsError::Provider("OpenBao request failed".into()))?
            .error_for_status()
            .map_err(|_| KmsError::Provider("OpenBao request failed".into()))?;
        kms::bounded_provider_json(response, kms::MAX_PROVIDER_JSON_BYTES).await
    }

    pub(crate) async fn get(&self, path: &str) -> Result<Value, KmsError> {
        let url = self.provider_url(path)?;
        let response = self
            .client
            .get(url)
            .timeout(TIMEOUT)
            .header("X-Vault-Token", &self.token)
            .header("accept", "application/json")
            .send()
            .await
            .map_err(|_| KmsError::Provider("OpenBao request failed".into()))?
            .error_for_status()
            .map_err(|_| KmsError::Provider("OpenBao request failed".into()))?;
        kms::bounded_provider_json(response, kms::MAX_PROVIDER_JSON_BYTES).await
    }

    fn provider_url(&self, path: &str) -> Result<reqwest::Url, KmsError> {
        if !path.starts_with("/v1/")
            || path.len() > 512
            || path.split('/').any(|part| part == "." || part == "..")
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
        {
            return Err(KmsError::InvalidConfig(
                "OpenBao request path is invalid.".into(),
            ));
        }
        let mut url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| KmsError::InvalidConfig("OpenBao endpoint is invalid.".into()))?;
        url.set_path(path);
        Ok(url)
    }
}

fn haip_scope<'a>(tenant: &'a str, flow: &'a str) -> Result<(&'a str, &'a str), FlowEnvelopeError> {
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 64
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    };
    if !valid(tenant) || !valid(flow) {
        return Err(FlowEnvelopeError::InvalidHaipScope);
    }
    Ok((tenant, flow))
}

fn haip_version<'a>(
    data: &'a Value,
    tenant: &str,
    flow: &str,
) -> Result<&'a str, FlowEnvelopeError> {
    if data.get("tenant").and_then(Value::as_str) != Some(tenant)
        || data.get("flow").and_then(Value::as_str) != Some(flow)
    {
        return Err(FlowEnvelopeError::HaipFailed);
    }
    data.get("version")
        .and_then(Value::as_str)
        .filter(|version| valid_haip_version(version))
        .ok_or(FlowEnvelopeError::HaipFailed)
}

fn haip_public_key_response(
    response: &Value,
    tenant: &str,
    flow: &str,
    expected_version: Option<&str>,
) -> Result<Value, FlowEnvelopeError> {
    let data = response.get("data").ok_or(FlowEnvelopeError::HaipFailed)?;
    let version = haip_version(data, tenant, flow)?;
    if expected_version.is_some_and(|expected| expected != version) {
        return Err(FlowEnvelopeError::HaipFailed);
    }
    let public = data
        .get("public_jwk")
        .ok_or(FlowEnvelopeError::HaipFailed)?;
    if !matches_public_jwk(public, version) {
        return Err(FlowEnvelopeError::HaipFailed);
    }
    Ok(json!({
        "organization_id": tenant,
        "flow_instance_id": flow,
        "version": version,
        "key_reference": format!("didcomm/haip/keys/{tenant}/{flow}/versions/{version}"),
        "public_jwk": public,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use axum::{extract::State, http::HeaderMap, routing::post, Router};

    #[tokio::test]
    async fn openbao_json_reader_rejects_oversized_responses() {
        let app = Router::new().route(
            "/response",
            axum::routing::get(|| async { Json(json!({"data": "x".repeat(64)})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/response", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::new();
        let response = client.get(&url).send().await.unwrap();
        assert!(matches!(
            kms::bounded_provider_json(response, 16).await,
            Err(KmsError::InvalidResponse(_))
        ));
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(
            kms::bounded_provider_json(response, 128).await.unwrap()["data"],
            "x".repeat(64)
        );
        server.abort();
    }

    #[test]
    fn openbao_path_cannot_change_provider_origin_or_add_query() {
        let provider = OpenBaoEnvelopeProvider::new("http://127.0.0.1:8200", "test-token")
            .expect("test provider");
        let url = provider
            .provider_url("/v1/didcomm/haip/keys/org-1/flow-1")
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8200/v1/didcomm/haip/keys/org-1/flow-1"
        );
        for path in [
            "//attacker.example/v1/transit/keys",
            "/v1/../sys/health",
            "/v1/transit/keys?list=true",
            "/v1/transit/keys#fragment",
            "/v1/transit/%2e%2e/sys/health",
        ] {
            assert!(provider.provider_url(path).is_err(), "accepted {path}");
        }
        assert!(
            OpenBaoEnvelopeProvider::new("http://127.0.0.1:8200/v1/transit", "test-token").is_err()
        );
    }

    #[test]
    fn haip_scope_and_public_jwk_require_exact_public_p256_binding() {
        assert!(haip_scope("org-1", "flow_1").is_ok());
        let too_long = "x".repeat(65);
        for bad in ["", "tenant/other", "tenant.other", &too_long] {
            assert!(haip_scope(bad, "flow_1").is_err());
        }
        assert!(valid_haip_version("0123456789abcdef0123456789abcdef"));
        assert!(!valid_haip_version("0123456789ABCDEF0123456789ABCDEF"));

        let x = hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
            .unwrap();
        let y = hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
            .unwrap();
        let version = "0123456789abcdef0123456789abcdef";
        let public = json!({
            "kty":"EC", "crv":"P-256", "alg":"ECDH-ES", "use":"enc",
            "kid":format!("oid4vp-haip-{version}"),
            "x":URL_SAFE_NO_PAD.encode(x),
            "y":URL_SAFE_NO_PAD.encode(y),
        });
        assert!(matches_public_jwk(&public, version));
        let mut private = public.clone();
        private["d"] = json!("private-must-not-cross-boundary");
        assert!(!matches_public_jwk(&private, version));
        let mut wrong_kid = public.clone();
        wrong_kid["kid"] = json!("other");
        assert!(!matches_public_jwk(&wrong_kid, version));
    }

    #[tokio::test]
    async fn haip_uses_only_the_dedicated_token_file_and_reads_rotation() {
        async fn respond(
            State(seen): State<Arc<Mutex<Vec<String>>>>,
            headers: HeaderMap,
        ) -> Json<Value> {
            seen.lock().unwrap().push(
                headers
                    .get("x-vault-token")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            );
            let version = "0123456789abcdef0123456789abcdef";
            Json(json!({"data":{
                "tenant":"org-1", "flow":"flow-1", "version":version,
                "public_jwk":{
                    "kty":"EC", "crv":"P-256", "alg":"ECDH-ES", "use":"enc",
                    "kid":format!("oid4vp-haip-{version}"),
                    "x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
                    "y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
                }
            }}))
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let router = Router::new()
            .route("/v1/didcomm/haip/keys/org-1/flow-1", post(respond))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base = OpenBaoEnvelopeProvider::new(format!("http://{address}"), "broad-transit-token")
            .unwrap();
        assert!(matches!(
            base.create_haip_key(CreateHaipKeyRequest {
                organization_id: "org-1".into(),
                flow_instance_id: "flow-1".into(),
            })
            .await,
            Err(FlowEnvelopeError::Unavailable)
        ));
        let directory = tempfile::tempdir().unwrap();
        let token_file = directory.path().join("haip-token");
        std::fs::write(&token_file, "scoped-token-one\n").unwrap();
        let provider = base.with_haip_token_file(token_file.clone()).unwrap();
        for token in ["scoped-token-one", "scoped-token-two"] {
            std::fs::write(&token_file, format!("{token}\n")).unwrap();
            provider
                .create_haip_key(CreateHaipKeyRequest {
                    organization_id: "org-1".into(),
                    flow_instance_id: "flow-1".into(),
                })
                .await
                .unwrap();
        }
        assert_eq!(
            *seen.lock().unwrap(),
            ["scoped-token-one", "scoped-token-two"]
        );
        server.abort();
    }
}
