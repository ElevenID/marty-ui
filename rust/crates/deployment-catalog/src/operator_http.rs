//! Bounded JSON and denial-proof mechanics shared by native operator profiles.
use crate::operator::{Result, REFUSAL};
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) fn builder(
    bao: &OpenBaoHttp,
    method: Method,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = bao
        .client()
        .request(method, format!("{}/v1/{path}", bao.origin()))
        .timeout(Duration::from_secs(10));
    if let Some(body) = body {
        request = request.json(body);
    }
    if let Some(token) = token {
        request = request.header("X-Vault-Token", token);
    }
    request
}
pub(crate) async fn request(
    bao: &OpenBaoHttp,
    method: Method,
    path: &str,
    body: Option<&Value>,
    token: Option<&str>,
) -> Result<Value> {
    let mut response = builder(bao, method, path, body, token)
        .send()
        .await
        .map_err(|_| REFUSAL)?;
    if !response.status().is_success() {
        return Err(REFUSAL);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| REFUSAL)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(REFUSAL);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        Ok(json!({}))
    } else {
        serde_json::from_slice(&bytes).map_err(|_| REFUSAL)
    }
}
pub(crate) async fn denial(
    bao: &OpenBaoHttp,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<()> {
    if builder(bao, method, path, body.as_ref(), Some(token))
        .send()
        .await
        .map_err(|_| REFUSAL)?
        .status()
        != StatusCode::FORBIDDEN
    {
        return Err(REFUSAL);
    }
    Ok(())
}
