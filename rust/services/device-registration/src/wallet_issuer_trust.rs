//! Bounded, service-authenticated projection of operator-governed wallet issuer keys.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use marty_key_material_policy::contains_private_key;
use reqwest::{Client, Url};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

use crate::DeviceError;

const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const UNAVAILABLE: &str = "wallet issuer trust is unavailable";

#[derive(Clone)]
pub struct WalletIssuerTrustClient {
    client: Client,
    origin: String,
    service_token: String,
}

impl WalletIssuerTrustClient {
    pub fn new(origin: &str, service_token: String) -> Result<Self, DeviceError> {
        let parsed = Url::parse(origin)
            .map_err(|_| DeviceError::BadRequest("Trust Profile origin is invalid".into()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || service_token.len() < 32
        {
            return Err(DeviceError::BadRequest(
                "Trust Profile client configuration is invalid".into(),
            ));
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| DeviceError::AuthorizationUnavailable)?;
        Ok(Self {
            client,
            origin: origin.trim_end_matches('/').into(),
            service_token,
        })
    }

    pub async fn fetch(
        &self,
        profile_id: &str,
        organization_id: &str,
    ) -> Result<Value, DeviceError> {
        if Uuid::parse_str(profile_id).is_err() || organization_id.is_empty() {
            return Err(DeviceError::BadRequest(
                "wallet issuer trust scope is invalid".into(),
            ));
        }
        let mut response = self
            .client
            .get(format!(
                "{}/internal/v1/trust-profiles/{profile_id}/wallet-issuer-keys",
                self.origin
            ))
            .header("x-service-token", &self.service_token)
            .send()
            .await
            .map_err(|_| DeviceError::AuthorizationUnavailable)?;
        if response.status() == reqwest::StatusCode::FORBIDDEN
            || response.status() == reqwest::StatusCode::NOT_FOUND
        {
            return Err(DeviceError::Forbidden(UNAVAILABLE.into()));
        }
        if !response.status().is_success() {
            return Err(DeviceError::AuthorizationUnavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| DeviceError::AuthorizationUnavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(DeviceError::AuthorizationUnavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let snapshot: Value =
            serde_json::from_slice(&body).map_err(|_| DeviceError::AuthorizationUnavailable)?;
        validate_snapshot(&snapshot, profile_id, organization_id, Utc::now())?;
        Ok(snapshot)
    }
}

fn validate_snapshot(
    snapshot: &Value,
    profile_id: &str,
    organization_id: &str,
    now: DateTime<Utc>,
) -> Result<(), DeviceError> {
    let invalid = || DeviceError::AuthorizationUnavailable;
    if snapshot.get("organization_id").and_then(Value::as_str) != Some(organization_id)
        || snapshot.get("trust_profile_id").and_then(Value::as_str) != Some(profile_id)
        || contains_private_key(snapshot)
    {
        return Err(invalid());
    }
    let generated = snapshot
        .get("generated_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(invalid)?;
    let expires = snapshot
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(invalid)?;
    if generated > now + ChronoDuration::seconds(5)
        || expires <= now
        || expires <= generated
        || expires > generated + ChronoDuration::minutes(1)
    {
        return Err(invalid());
    }
    let keys = snapshot
        .get("issuer_keys")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if keys.is_empty()
        || keys.len() > 256
        || keys.iter().any(|key| {
            key.get("issuer")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || key
                    .get("algorithm")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || !key.get("public_jwk").is_some_and(Value::is_object)
        })
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Path,
        http::{HeaderMap, StatusCode},
        routing::get,
        Json, Router,
    };
    use serde_json::json;

    const PROFILE_ID: &str = "11111111-2222-4333-8444-555555555555";

    async fn snapshot(
        headers: HeaderMap,
        Path(profile_id): Path<String>,
    ) -> Result<Json<Value>, StatusCode> {
        if headers
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            != Some("service-token-with-at-least-32-bytes")
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let now = Utc::now();
        Ok(Json(json!({
            "organization_id": "org-a", "trust_profile_id": profile_id,
            "generated_at": now, "expires_at": now + ChronoDuration::seconds(30),
            "issuer_keys": [{"issuer":"did:example:issuer","algorithm":"EdDSA","public_jwk":{"kty":"OKP","crv":"Ed25519","x":"public"}}]
        })))
    }

    #[tokio::test]
    async fn fetch_uses_service_auth_and_rejects_wrong_organization() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/internal/v1/trust-profiles/{profile_id}/wallet-issuer-keys",
                    get(snapshot),
                ),
            )
            .await
        });
        let client =
            WalletIssuerTrustClient::new(&origin, "service-token-with-at-least-32-bytes".into())
                .unwrap();
        assert!(client.fetch(PROFILE_ID, "org-a").await.is_ok());
        assert!(client.fetch(PROFILE_ID, "org-b").await.is_err());
        server.abort();
    }

    #[test]
    fn rejects_wrong_tenant_stale_and_private_key_snapshots() {
        let now = Utc::now();
        let profile = Uuid::new_v4().to_string();
        let mut snapshot = json!({
            "organization_id": "org-a", "trust_profile_id": profile,
            "generated_at": now, "expires_at": now + ChronoDuration::seconds(30),
            "issuer_keys": [{"issuer":"did:example:issuer","algorithm":"EdDSA","public_jwk":{"kty":"OKP","crv":"Ed25519","x":"public"}}]
        });
        assert!(validate_snapshot(&snapshot, &profile, "org-a", now).is_ok());
        assert!(validate_snapshot(&snapshot, &profile, "org-b", now).is_err());
        snapshot["expires_at"] = json!(now - ChronoDuration::seconds(1));
        assert!(validate_snapshot(&snapshot, &profile, "org-a", now).is_err());
        snapshot["expires_at"] = json!(now + ChronoDuration::seconds(30));
        snapshot["issuer_keys"][0]["public_jwk"]["d"] = json!("private");
        assert!(validate_snapshot(&snapshot, &profile, "org-a", now).is_err());
    }
}
