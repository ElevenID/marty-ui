use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use chrono::{Duration, Utc};
use marty_trust_profile::{
    trust_profile_router, CascadeRevocationPolicy, ComplianceStatus, IssuerEntity,
    IssuerEntityComplianceStatus, IssuerEntityType, MemoryTrustProfileRepository,
    TrustAuthorizationError, TrustProfile, TrustProfileApplication, TrustProfileControlPlane,
    TrustProfileHttpState, TrustProfileIssuer, TrustProfileRepository, TrustProfileStatus,
    TrustProfileType, TrustRegistrySyncError, TrustRegistrySynchronizer, TrustRelationshipStatus,
    TrustSource, TrustSourceType,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Map, Value};
use tower::ServiceExt;
use uuid::Uuid;

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
    service_with_repository(Arc::new(MemoryTrustProfileRepository::default()))
}

fn service_with_repository(repository: Arc<MemoryTrustProfileRepository>) -> axum::Router {
    let repository: Arc<dyn TrustProfileRepository> = repository;
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

fn profile(name: &str) -> TrustProfile {
    let now = Utc::now();
    TrustProfile {
        id: Uuid::new_v4(),
        organization_id: "org-1".into(),
        name: name.into(),
        description: None,
        status: TrustProfileStatus::Draft,
        profile_type: TrustProfileType::Custom,
        compliance_status: ComplianceStatus::SetupRequired,
        trust_sources: vec![],
        validation_rules: Default::default(),
        allowed_issuers: None,
        denied_issuers: None,
        system_issuer_overrides: Map::new(),
        compatible_compliance_codes: vec![],
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: Default::default(),
        revocation_profile_id: None,
        time_policy: Default::default(),
        supported_formats: vec!["MDOC".into()],
        created_at: now,
        updated_at: now,
    }
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
async fn internal_decisions_fail_closed_with_the_legacy_service_contract() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let mut unsynchronized = profile("Unsynchronized");
    unsynchronized.trust_sources.push(TrustSource {
        id: Uuid::new_v4(),
        name: "Registry".into(),
        source_type: TrustSourceType::TrustList,
        url: Some("https://registry.example/sync".into()),
        certificate_pem: None,
        issuer_did: None,
        description: None,
        pinned_certificates: vec![],
        refresh_interval_hours: 24,
        enabled: true,
        registry_sync: Some(json!({
            "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
            "refresh_interval_hours": 24
        })),
        registry_sync_token: None,
        registry_sequence: 0,
        registry_entries: Map::new(),
        registry_last_synced_at: None,
        extensions: Map::new(),
    });
    repository
        .save_profile(&unsynchronized, None)
        .await
        .unwrap();
    let service = service_with_repository(Arc::clone(&repository));
    let response = request(
        service,
        "GET",
        &format!("/internal/v1/trust-profiles/{}", unsynchronized.id),
        None,
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        body(response).await["detail"],
        "Trust Profile registry source has never synchronized"
    );

    let mut stale = profile("Stale");
    let mut source = unsynchronized.trust_sources[0].clone();
    source.registry_sync = Some(json!({
        "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
        "refresh_interval_hours": 1
    }));
    source.registry_last_synced_at = Some(Utc::now() - Duration::hours(2));
    stale.trust_sources.push(source);
    repository.save_profile(&stale, None).await.unwrap();
    let response = request(
        service_with_repository(Arc::clone(&repository)),
        "GET",
        &format!("/internal/v1/trust-profiles/{}", stale.id),
        None,
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        body(response).await["detail"],
        "Trust Profile registry source is stale"
    );

    let mut legacy = profile("Legacy URL");
    let mut source = unsynchronized.trust_sources[0].clone();
    source.registry_sync = None;
    legacy.trust_sources.push(source);
    repository.save_profile(&legacy, None).await.unwrap();
    let response = request(
        service_with_repository(repository),
        "GET",
        &format!("/internal/v1/trust-profiles/{}", legacy.id),
        None,
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        body(response).await["detail"],
        "Trust Profile registry source has no supported sync protocol"
    );
}

#[tokio::test]
async fn internal_decisions_reject_cross_tenant_and_private_key_relationships() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let cross_tenant = profile("Cross tenant");
    repository.save_profile(&cross_tenant, None).await.unwrap();
    let now = Utc::now();
    let foreign = IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: Some("org-other".into()),
        issuer_id: "did:web:foreign.example".into(),
        issuer_type: IssuerEntityType::Organization,
        display_name: "Foreign".into(),
        description: None,
        is_system_issuer: false,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: vec![],
        accreditation_date: None,
        valid_from: now,
        valid_until: None,
        trust_anchor_id: None,
        metadata: json!({}),
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        created_at: now,
        updated_at: now,
    };
    repository.save_issuer_entity(&foreign).await.unwrap();
    repository
        .save_profile_issuer(&TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: cross_tenant.id,
            issuer_id: foreign.id,
            trust_level: 100,
            relationship_status: TrustRelationshipStatus::Trusted,
            cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let response = request(
        service_with_repository(Arc::clone(&repository)),
        "GET",
        &format!("/internal/v1/trust-profiles/{}", cross_tenant.id),
        None,
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        body(response).await["detail"],
        "Trust Profile contains a cross-organization issuer relationship"
    );

    let private_key = profile("Private key");
    repository.save_profile(&private_key, None).await.unwrap();
    let mut malformed = foreign;
    malformed.id = Uuid::new_v4();
    malformed.organization_id = Some("org-1".into());
    malformed.issuer_id = "did:web:malformed.example".into();
    malformed.metadata = json!({
        "verification_keys": [{"kty": "EC", "d": "private"}]
    });
    repository.save_issuer_entity(&malformed).await.unwrap();
    repository
        .save_profile_issuer(&TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: private_key.id,
            issuer_id: malformed.id,
            trust_level: 100,
            relationship_status: TrustRelationshipStatus::Trusted,
            cascade_revocation_policy: CascadeRevocationPolicy::NotifyOnly,
            metadata: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    let response = request(
        service_with_repository(repository),
        "GET",
        &format!("/internal/v1/trust-profiles/{}", private_key.id),
        None,
    )
    .await;
    assert_eq!(response.status(), 503);
    assert_eq!(
        body(response).await["detail"],
        "Trust Profile contains invalid issuer verification keys"
    );
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
