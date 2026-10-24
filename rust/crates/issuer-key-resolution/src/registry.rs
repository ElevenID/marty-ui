//! Authenticated adapter for the internal signing identity registry.
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{header::HeaderValue, redirect::Policy, Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    governed::{IssuerResolutionRequest, OrganizationIssuerResolver, RegistryIssuerResolution},
    policy::validate_source_controls,
    IssuerKeyResolutionError,
};

pub struct HttpOrganizationIssuerResolver {
    client: Client,
    endpoint: Url,
    credential: HeaderValue,
}

impl std::fmt::Debug for HttpOrganizationIssuerResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOrganizationIssuerResolver")
            .finish_non_exhaustive()
    }
}

impl HttpOrganizationIssuerResolver {
    pub fn new(
        base_url: &str,
        internal_api_key: &str,
        timeout: Duration,
    ) -> Result<Self, IssuerKeyResolutionError> {
        let mut endpoint = Url::parse(base_url).map_err(|_| IssuerKeyResolutionError::Invalid)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || internal_api_key.trim().is_empty()
            || timeout.is_zero()
        {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        endpoint.set_path("/internal/compat/resolve-issuer-did");
        let mut credential = HeaderValue::from_str(internal_api_key)
            .map_err(|_| IssuerKeyResolutionError::Invalid)?;
        credential.set_sensitive(true);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?;
        Ok(Self {
            client,
            endpoint,
            credential,
        })
    }
}

#[async_trait]
impl OrganizationIssuerResolver for HttpOrganizationIssuerResolver {
    async fn resolve(
        &self,
        request: &IssuerResolutionRequest,
    ) -> Result<RegistryIssuerResolution, IssuerKeyResolutionError> {
        let organization = request
            .organization_id
            .as_deref()
            .ok_or(IssuerKeyResolutionError::Invalid)?;
        validate_source_controls(
            &request.issuer_did,
            Some(organization),
            &request.verification_method_ids,
        )?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header("x-api-key", self.credential.clone())
            .json(&json!({
                "organization_id":organization, "issuer_did":request.issuer_did,
                "credential_format":request.credential_format, "key_purpose":request.key_purpose,
                "algorithm":request.algorithm,
            }))
            .send()
            .await
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?;
        // 4xx includes absent, ambiguous or incompatible identities and denied
        // authentication. None of these authorize fallback to public resolution.
        if response.status().is_server_error() {
            return Err(IssuerKeyResolutionError::Unavailable);
        }
        if !response.status().is_success() {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > 1_048_576 {
                return Err(IssuerKeyResolutionError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| IssuerKeyResolutionError::Invalid)?;
        decode_binding(request, &value)
    }
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, IssuerKeyResolutionError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or(IssuerKeyResolutionError::Invalid)
}

fn decode_binding(
    request: &IssuerResolutionRequest,
    value: &Value,
) -> Result<RegistryIssuerResolution, IssuerKeyResolutionError> {
    let profile = value
        .get("issuer_profile")
        .ok_or(IssuerKeyResolutionError::Invalid)?;
    let organization = text(value, "organization_id")?;
    let did = text(value, "issuer_did")?;
    let algorithm = text(value, "algorithm")?;
    let purpose = text(value, "key_purpose")?;
    if value.get("ok") != Some(&Value::Bool(true))
        || request.organization_id.as_deref() != Some(organization)
        || did != request.issuer_did
        || text(profile, "organization_id")? != organization
        || text(profile, "issuer_did")? != did
        || text(profile, "status")? != "active"
        || text(profile, "credential_format")? != request.credential_format
        || text(profile, "key_purpose")? != purpose
        || purpose != request.key_purpose
        || text(profile, "algorithm")? != algorithm
        || algorithm != request.algorithm
    {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    let document = value
        .get("did_document")
        .ok_or(IssuerKeyResolutionError::Invalid)?;
    let encoded = serde_json::to_vec(document).map_err(|_| IssuerKeyResolutionError::Invalid)?;
    let resolver = value
        .get("resolver")
        .ok_or(IssuerKeyResolutionError::Invalid)?;
    if resolver.get("public_fallback_used") != Some(&Value::Bool(false)) {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    Ok(RegistryIssuerResolution {
        organization_id: organization.into(),
        issuer_did: did.into(),
        active: true,
        credential_format: request.credential_format.clone(),
        key_purpose: purpose.into(),
        algorithm: algorithm.into(),
        verification_method_id: text(value, "verification_method_id")?.into(),
        document: serde_json::from_value(document.clone())
            .map_err(|_| IssuerKeyResolutionError::Invalid)?,
        source: "organization_signing_registry".into(),
        retrieved_at: text(resolver, "resolved_at")?.into(),
        content_sha256: format!("{:x}", Sha256::digest(encoded)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        governed::resolve_governed_issuer, policy::DidResolutionPolicy, IssuerKeyResolution,
        IssuerKeyResolver,
    };
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };

    struct NoPublic;
    #[async_trait]
    impl IssuerKeyResolver for NoPublic {
        async fn resolve(&self, _: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
            panic!("registry validation must not downgrade to public resolution")
        }
    }
    fn request() -> IssuerResolutionRequest {
        IssuerResolutionRequest {
            organization_id: Some("org-1".into()),
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "VC_JWT".into(),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: "ES256".into(),
            verification_method_ids: vec!["did:web:issuer.example#key".into()],
            policy: DidResolutionPolicy::default(),
        }
    }
    fn payload() -> Value {
        json!({"ok":true, "organization_id":"org-1", "issuer_did":"did:web:issuer.example",
            "algorithm":"ES256", "key_purpose":"vc_jwt_issuer", "verification_method_id":"did:web:issuer.example#key",
            "issuer_profile":{"organization_id":"org-1", "issuer_did":"did:web:issuer.example", "status":"active", "algorithm":"ES256", "credential_format":"VC_JWT", "key_purpose":"vc_jwt_issuer", "signing_key_reference":"private-coordinate"},
            "did_document":{"id":"did:web:issuer.example", "verificationMethod":[{"id":"did:web:issuer.example#key", "controller":"did:web:issuer.example", "type":"JsonWebKey2020", "publicKeyJwk":{"kty":"EC", "crv":"P-256", "x":"x", "y":"y"}}], "assertionMethod":["did:web:issuer.example#key"]},
            "resolver":{"public_fallback_used":false,"resolved_at":"2026-10-23T00:00:00Z"}
        })
    }
    async fn server(status: StatusCode, payload: Value) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().route("/internal/compat/resolve-issuer-did", post(move |headers:HeaderMap, Json(body):Json<Value>| {
            let payload = payload.clone();
            async move {
                assert_eq!(headers["x-api-key"], "test-internal-credential");
                assert_eq!(body, json!({"organization_id":"org-1", "issuer_did":"did:web:issuer.example", "credential_format":"VC_JWT", "key_purpose":"vc_jwt_issuer", "algorithm":"ES256"}));
                (status, Json(payload))
            }
        }));
        (
            base,
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }),
        )
    }
    #[tokio::test]
    async fn authenticated_registry_response_yields_only_document_authorized_public_material() {
        let (base, server) = server(StatusCode::OK, payload()).await;
        let adapter = HttpOrganizationIssuerResolver::new(
            &base,
            "test-internal-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        let result = resolve_governed_issuer(&request(), &adapter, &NoPublic)
            .await
            .unwrap();
        assert_eq!(result.source, "organization_signing_registry");
        assert_eq!(result.content_sha256.len(), 64);
        assert_eq!(
            result.verification_keys[0]["kid"],
            "did:web:issuer.example#key"
        );
        assert!(!format!("{result:?} {adapter:?}").contains("private-coordinate"));
        assert!(!format!("{adapter:?}").contains("test-internal-credential"));
        server.abort();
    }
    #[tokio::test]
    async fn status_failures_and_bad_registry_context_fail_closed() {
        for (status, expected) in [
            (StatusCode::NOT_FOUND, IssuerKeyResolutionError::Invalid),
            (StatusCode::CONFLICT, IssuerKeyResolutionError::Invalid),
            (StatusCode::UNAUTHORIZED, IssuerKeyResolutionError::Invalid),
            (StatusCode::FOUND, IssuerKeyResolutionError::Invalid),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                IssuerKeyResolutionError::Unavailable,
            ),
        ] {
            let (base, server) = server(status, payload()).await;
            let adapter = HttpOrganizationIssuerResolver::new(
                &base,
                "test-internal-credential",
                Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(
                resolve_governed_issuer(&request(), &adapter, &NoPublic).await,
                Err(expected)
            );
            server.abort();
        }
        let mut invalid = payload();
        invalid["issuer_profile"]["organization_id"] = json!("org-2");
        let (base, server) = server(StatusCode::OK, invalid).await;
        let adapter = HttpOrganizationIssuerResolver::new(
            &base,
            "test-internal-credential",
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            resolve_governed_issuer(&request(), &adapter, &NoPublic).await,
            Err(IssuerKeyResolutionError::Invalid)
        );
        server.abort();
    }
    #[test]
    fn credentials_cannot_be_embedded_in_or_redirected_through_untrusted_endpoints() {
        for base in [
            "file:///tmp/registry",
            "https://user:password@registry.example",
            "https://registry.example?token=secret",
            "https://registry.example/consumer-supplied-path",
        ] {
            assert!(HttpOrganizationIssuerResolver::new(
                base,
                "test-internal-credential",
                Duration::from_secs(2)
            )
            .is_err());
        }
    }
}
