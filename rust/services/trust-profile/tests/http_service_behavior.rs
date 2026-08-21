use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use marty_trust_profile::{
    trust_profile_router, MemoryTrustProfileRepository, TrustAuthorizationError,
    TrustProfileApplication, TrustProfileControlPlane, TrustProfileHttpState,
    TrustProfileRepository, TrustRegistrySyncError, TrustRegistrySynchronizer,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Debug)]
struct AllowControlPlane;

#[async_trait]
impl TrustProfileControlPlane for AllowControlPlane {
    async fn require_permission(
        &self,
        _user_id: &str,
        _organization_id: &str,
        _resource: &'static str,
        _action: &'static str,
    ) -> Result<(), TrustAuthorizationError> {
        Ok(())
    }
}

#[derive(Debug)]
struct EchoSynchronizer;

#[async_trait]
impl TrustRegistrySynchronizer for EchoSynchronizer {
    async fn synchronize(
        &self,
        profile: marty_trust_profile::TrustProfile,
    ) -> Result<Value, TrustRegistrySyncError> {
        Ok(json!({
            "trust_profile_id": profile.id,
            "sources": [{
                "url": "https://registry.example/sync",
                "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                "sequence": 1,
                "csca_entries": 1,
                "dsc_entries": 0,
                "synchronized_at": "2026-08-21T00:00:00Z"
            }],
            "synchronized_at": "2026-08-21T00:00:00Z"
        }))
    }
}

fn service() -> axum::Router {
    let repository: Arc<dyn TrustProfileRepository> =
        Arc::new(MemoryTrustProfileRepository::default());
    let application = Arc::new(TrustProfileApplication::new(
        Arc::clone(&repository),
        Arc::new(AllowControlPlane),
    ));
    trust_profile_router(TrustProfileHttpState {
        application,
        repository,
        service_authenticator: Arc::new(ServiceTokenAuthenticator::new(None, false).unwrap()),
        internal_api_key: Some(Arc::from("internal-test-key")),
        registry_synchronizer: Arc::new(EchoSynchronizer),
    })
}

async fn request(
    service: axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-user-id", "user-1");
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    service
        .oneshot(
            request
                .body(Body::from(
                    body.map_or_else(String::new, |value| value.to_string()),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn profile_http_contract_preserves_defaults_and_response_projection() {
    let response = request(
        service(),
        "POST",
        "/v1/trust-profiles",
        Some(json!({
            "organization_id": "org-1",
            "name": "Native Profile",
            "supported_formats": ["mdoc"]
        })),
    )
    .await;
    assert_eq!(response.status(), 200);
    let response = body(response).await;
    assert_eq!(response["status"], "draft");
    assert_eq!(response["profile_type"], "CUSTOM");
    assert_eq!(response["compliance_status"], "SETUP_REQUIRED");
    assert_eq!(response["supported_formats"], json!(["MDOC"]));
    assert_eq!(response["allowed_issuers"], json!([]));
    assert_eq!(
        response["allowed_algorithms"],
        json!(["ES256", "ES384", "EdDSA"])
    );
    assert!(response.get("validation_rules").is_none());
    assert_eq!(response["time_policy"]["clock_skew_seconds"], 300);
}

#[tokio::test]
async fn malformed_and_obsolete_public_shapes_fail_closed() {
    let obsolete = request(
        service(),
        "POST",
        "/v1/trust-profiles/00000000-0000-4000-8000-000000000001/issuers",
        Some(json!({"name": "Legacy", "issuer_did": "did:example:legacy"})),
    )
    .await;
    assert_eq!(obsolete.status(), 422);

    let private_metadata = request(
        service(),
        "POST",
        "/v1/issuer-entities",
        Some(json!({
            "organization_id": "org-1",
            "issuer_id": "did:example:issuer",
            "display_name": "Issuer",
            "metadata": {"verification_keys": [{"kty": "EC", "d": "private"}]}
        })),
    )
    .await;
    assert_eq!(private_metadata.status(), 422);
}

#[tokio::test]
async fn internal_owner_routes_require_the_distinct_constant_time_api_key() {
    let response = request(
        service(),
        "GET",
        "/internal/v1/resource-owners/trust-profiles/00000000-0000-4000-8000-000000000001",
        None,
    )
    .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn every_declared_http_method_is_registered_on_the_native_router() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-service-behavior.json"
    ))
    .unwrap();
    for operation in contract["http_operations"].as_array().unwrap() {
        let method = operation[0].as_str().unwrap();
        let uri = operation[1]
            .as_str()
            .unwrap()
            .replace("{organization_id}", "org-1")
            .replace("{country_code}", "US")
            .replace("{profile_id}", "00000000-0000-4000-8000-000000000001")
            .replace("{issuer_entity_id}", "00000000-0000-4000-8000-000000000002")
            .replace("{framework_id}", "00000000-0000-4000-8000-000000000003")
            .replace("{issuer_id}", "00000000-0000-4000-8000-000000000004");
        let response = request(
            service(),
            method,
            &uri,
            matches!(method, "POST" | "PUT" | "PATCH").then(|| json!({})),
        )
        .await;
        assert_ne!(
            response.status(),
            405,
            "native router omitted {method} {uri}"
        );
    }
}
