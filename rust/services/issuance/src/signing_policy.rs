use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use marty_oid4vci::discovery::{KeyAttestationRequirements, ProofPolicyRequest};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tracing::error;
use url::Url;

use crate::tenant_discovery::{ProofPolicyResolver, TenantDiscoveryError};

#[derive(Clone)]
pub struct HttpProofPolicyResolver {
    client: Client,
    base_url: Url,
    api_key: Option<Arc<str>>,
}

impl std::fmt::Debug for HttpProofPolicyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpProofPolicyResolver")
            .field("base_url", &self.base_url)
            .field("api_key_configured", &self.api_key.is_some())
            .finish()
    }
}

impl HttpProofPolicyResolver {
    pub fn new(
        base_url: Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, TenantDiscoveryError> {
        if timeout.is_zero() {
            return Err(TenantDiscoveryError::ProofPolicyUnavailable);
        }
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|cause| {
                error!(%cause, "proof policy HTTP client configuration failed");
                TenantDiscoveryError::ProofPolicyUnavailable
            })?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.map(Arc::<str>::from),
        })
    }
}

#[async_trait]
impl ProofPolicyResolver for HttpProofPolicyResolver {
    async fn resolve(
        &self,
        request: &ProofPolicyRequest,
    ) -> Result<KeyAttestationRequirements, TenantDiscoveryError> {
        let operation = if request.issuer_did.is_some() {
            "resolve-issuer-did"
        } else {
            "issuer-context"
        };
        let mut endpoint = self.base_url.join(operation).map_err(|cause| {
            error!(%cause, "proof policy endpoint construction failed");
            TenantDiscoveryError::ProofPolicyUnavailable
        })?;
        {
            let mut query = endpoint.query_pairs_mut();
            query.append_pair("organization_id", &request.organization_id);
            if let Some(issuer_did) = &request.issuer_did {
                query.append_pair("issuer_did", issuer_did);
            }
            query.append_pair("credential_format", &request.credential_format);
            query.append_pair("key_purpose", &request.key_purpose);
        }
        let mut outbound = self.client.get(endpoint);
        if let Some(api_key) = &self.api_key {
            outbound = outbound.header("X-API-Key", api_key.as_ref());
        }
        let response = outbound.send().await.map_err(|cause| {
            error!(%cause, "proof policy request failed");
            TenantDiscoveryError::ProofPolicyUnavailable
        })?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(KeyAttestationRequirements::default());
        }
        if !response.status().is_success() {
            error!(status = %response.status(), "proof policy request was rejected");
            return Err(TenantDiscoveryError::ProofPolicyUnavailable);
        }
        let payload: Value = response.json().await.map_err(|cause| {
            error!(%cause, "proof policy response was invalid JSON");
            TenantDiscoveryError::ProofPolicyUnavailable
        })?;
        let Some(payload) = payload.as_object() else {
            return Ok(KeyAttestationRequirements::default());
        };
        if payload.get("ok").and_then(Value::as_bool) != Some(true) {
            return Ok(KeyAttestationRequirements::default());
        }
        let profile = payload.get("issuer_profile").and_then(Value::as_object);
        if request.issuer_did.is_some()
            && profile
                .and_then(|profile| profile.get("id"))
                .is_none_or(|value| !python_truthy(value))
        {
            error!("DID-selected proof policy response has no issuer profile");
            return Err(TenantDiscoveryError::ProofPolicyUnavailable);
        }
        let Some(policy) = profile
            .and_then(|profile| profile.get("key_attestation_policy"))
            .and_then(Value::as_object)
        else {
            return Ok(KeyAttestationRequirements::default());
        };
        if policy.get("mode").and_then(Value::as_str) != Some("required") {
            return Ok(KeyAttestationRequirements::default());
        }
        Ok(KeyAttestationRequirements {
            key_storage: string_list(policy.get("required_key_storage")),
            user_authentication: string_list(policy.get("required_user_authentication")),
        })
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(python_string)
        .collect()
}

fn python_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(value) => if *value { "True" } else { "False" }.to_owned(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use axum::{
        extract::Query,
        http::{HeaderMap, StatusCode},
        routing::get,
        Json, Router,
    };
    use marty_oid4vci::discovery::ProofPolicyRequest;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    use crate::tenant_discovery::{ProofPolicyResolver, TenantDiscoveryError};

    use super::HttpProofPolicyResolver;

    async fn resolved(
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
    ) -> Json<Value> {
        assert_eq!(query["organization_id"], "org-a");
        assert_eq!(query["issuer_did"], "did:web:issuer.example");
        assert_eq!(query["credential_format"], "dc+sd-jwt");
        assert_eq!(query["key_purpose"], "vc_jwt_issuer");
        assert_eq!(headers["x-api-key"], "service-secret");
        Json(json!({
            "ok": true,
            "issuer_profile": {
                "id": "profile-a",
                "key_attestation_policy": {
                    "mode": "required",
                    "required_key_storage": ["iso_18045_high"],
                    "required_user_authentication": ["biometric"]
                }
            }
        }))
    }

    async fn spawn(app: Router) -> (url::Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        (
            url::Url::parse(&format!("http://{address}/internal/signing-keys/")).expect("base URL"),
            task,
        )
    }

    fn request() -> ProofPolicyRequest {
        serde_json::from_value(json!({
            "organization_id": "org-a",
            "issuer_did": "did:web:issuer.example",
            "credential_format": "dc+sd-jwt",
            "key_purpose": "vc_jwt_issuer"
        }))
        .expect("request")
    }

    #[tokio::test]
    async fn resolves_did_selected_key_attestation_policy() {
        let (base_url, task) =
            spawn(Router::new().route("/internal/signing-keys/resolve-issuer-did", get(resolved)))
                .await;
        let resolver =
            HttpProofPolicyResolver::new(base_url, Some("service-secret"), Duration::from_secs(1))
                .expect("resolver");
        let requirements = resolver.resolve(&request()).await.expect("policy");
        assert_eq!(requirements.key_storage, ["iso_18045_high"]);
        assert_eq!(requirements.user_authentication, ["biometric"]);
        task.abort();
    }

    #[tokio::test]
    async fn treats_not_found_as_no_additional_constraint_and_other_errors_as_unavailable() {
        let (base_url, task) = spawn(Router::new()).await;
        let resolver =
            HttpProofPolicyResolver::new(base_url, None, Duration::from_secs(1)).expect("resolver");
        assert_eq!(
            resolver.resolve(&request()).await.expect("empty policy"),
            Default::default()
        );
        task.abort();

        let (base_url, task) =
            spawn(Router::new().fallback(|| async { StatusCode::SERVICE_UNAVAILABLE })).await;
        let resolver =
            HttpProofPolicyResolver::new(base_url, None, Duration::from_secs(1)).expect("resolver");
        assert_eq!(
            resolver.resolve(&request()).await,
            Err(TenantDiscoveryError::ProofPolicyUnavailable)
        );
        task.abort();
    }
}
