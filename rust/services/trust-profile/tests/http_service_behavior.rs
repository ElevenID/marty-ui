use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use chrono::{Duration, Utc};
use marty_trust_profile::{
    trust_profile_router, CascadeRevocationPolicy, ComplianceStatus, IssuerEntity,
    IssuerEntityComplianceStatus, IssuerEntityType, MemoryTrustProfileRepository,
    TrustAuthorizationError, TrustProfile, TrustProfileApplication, TrustProfileControlPlane,
    TrustProfileHttpState, TrustProfileIssuer, TrustProfileRepository, TrustProfileStatus,
    TrustProfileType, TrustPurpose, TrustRegistrySyncError, TrustRegistrySynchronizer,
    TrustRelationshipStatus, TrustSource, TrustSourceType, TrustedAssertionFormat,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Map, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Debug)]
struct AllowControlPlane;

struct RejectKeyMembership;

#[async_trait]
impl TrustProfileControlPlane for RejectKeyMembership {
    async fn require_permission(
        &self,
        _user_id: &str,
        _organization_id: &str,
        _resource: &'static str,
        _action: &'static str,
    ) -> Result<(), TrustAuthorizationError> {
        Err(TrustAuthorizationError::MembershipRequired)
    }
}

#[tokio::test]
async fn delegated_profile_read_authenticates_actor_without_human_membership() {
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    let token = "s".repeat(32);
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let mut selected = profile("Delegated trust");
    selected.organization_id = ORG.into();
    repository.save_profile(&selected, None).await.unwrap();
    for configured in [true, false] {
        let application = Arc::new(TrustProfileApplication::new(
            repository.clone(),
            Arc::new(RejectKeyMembership),
        ));
        let app = trust_profile_router(TrustProfileHttpState {
            application,
            repository: repository.clone(),
            service_authenticator: Arc::new(
                ServiceTokenAuthenticator::new(configured.then(|| token.clone()), configured)
                    .unwrap(),
            ),
            internal_api_key: None,
            registry_synchronizer: Arc::new(EchoSynchronizer),
        });
        for (credential, key, organization, scopes, expected) in [
            (Some(token.as_str()), KEY, ORG, "trust:read", 200),
            (Some(token.as_str()), KEY, ORG, "trust:write", 200),
            (None, KEY, ORG, "trust:read", 401),
            (Some("incorrect"), KEY, ORG, "trust:read", 401),
            (Some(token.as_str()), "malformed", ORG, "trust:read", 401),
            (Some(token.as_str()), KEY, "invalid", "trust:read", 401),
            (Some(token.as_str()), KEY, OTHER, "admin:full", 403),
            (Some(token.as_str()), KEY, ORG, "templates:read", 403),
            (Some(token.as_str()), KEY, ORG, "", 403),
        ] {
            let mut request = Request::builder()
                .uri(format!("/v1/trust-profiles/{}", selected.id))
                .header("x-api-key-id", key)
                .header("x-organization-id", organization)
                .header("x-api-key-scopes", scopes)
                .header("x-user-id", "user-1");
            if let Some(credential) = credential {
                request = request.header("x-service-token", credential);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                if configured { expected } else { 401 }
            );
            if response.status().is_success() {
                assert_eq!(body(response).await["id"], selected.id.to_string());
            }
        }
        // A subsequent human request still takes the original membership path.
        let response = request(
            app,
            "GET",
            &format!("/v1/trust-profiles/{}", selected.id),
            None,
        )
        .await;
        assert_eq!(
            response.status().as_u16(),
            if configured { 401 } else { 403 }
        );
    }
}

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
        trust_purposes: None,
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
        trusted_assertion_formats: None,
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
async fn sparse_profile_edits_preserve_security_settings_and_reject_invalid_changes_atomically() {
    let service = service();
    let created = request(service.clone(), "POST", "/v1/trust-profiles", Some(json!({
        "organization_id": "org-1", "name": "Original", "description": "Original description",
        "supported_formats": ["SD_JWT_VC"], "allowed_algorithms": ["ES384"],
        "min_key_size_rsa": 4096, "min_key_size_ec": 384, "max_chain_depth": 3,
        "trust_sources": [{"source_type": "PINNED_ISSUER", "issuer_did": "did:web:issuer.example"}],
        "compatible_compliance_codes": ["ENTERPRISE_VC"], "auto_generated": true
    }))).await;
    assert_eq!(created.status(), 200);
    let original = body(created).await;
    let uri = format!("/v1/trust-profiles/{}", original["id"].as_str().unwrap());
    for changes in [
        json!({"name": "Renamed"}),
        json!({"description": "Changed description"}),
    ] {
        let before = body(request(service.clone(), "GET", &uri, None).await).await;
        let response = request(service.clone(), "PATCH", &uri, Some(changes.clone())).await;
        assert_eq!(response.status(), 200);
        let mut expected = before.as_object().unwrap().clone();
        expected.extend(changes.as_object().unwrap().clone());
        let after = body(request(service.clone(), "GET", &uri, None).await).await;
        expected.insert("updated_at".into(), after["updated_at"].clone());
        assert_eq!(after, Value::Object(expected));
    }
    let before = body(request(service.clone(), "GET", &uri, None).await).await;
    let rejected = request(
        service.clone(),
        "PATCH",
        &uri,
        Some(json!({"name": "Must not persist", "allowed_algorithms": []})),
    )
    .await;
    assert_eq!(rejected.status(), 422);
    assert_eq!(
        body(request(service, "GET", &uri, None).await).await,
        before
    );
}

#[tokio::test]
async fn did_source_controls_survive_storage_and_reject_cross_did_method_pins() {
    let service = service();
    let source = json!({
        "source_type": "PINNED_ISSUER", "issuer_did": "did:web:issuer.example",
        "organization_id": "org-1", "verification_method_ids": ["did:web:issuer.example#signing"],
        "did_resolution": {"resolver_type": "ORGANIZATION_REGISTRY", "allow_public_fallback": false, "cache_ttl_seconds": 0}
    });
    let payload =
        json!({"organization_id":"org-1", "name":"Scoped issuer", "trust_sources":[source]});
    let created = request(
        service.clone(),
        "POST",
        "/v1/trust-profiles",
        Some(payload.clone()),
    )
    .await;
    assert_eq!(created.status(), 200);
    let created = body(created).await;
    let uri = format!("/v1/trust-profiles/{}", created["id"].as_str().unwrap());
    let stored = body(request(service.clone(), "GET", &uri, None).await).await;
    for field in [
        "organization_id",
        "verification_method_ids",
        "did_resolution",
    ] {
        assert_eq!(stored["trust_sources"][0][field], source[field]);
    }
    let mut invalid = payload;
    invalid["trust_sources"][0]["verification_method_ids"] =
        json!(["did:web:other.example#signing"]);
    assert_eq!(
        request(service.clone(), "POST", "/v1/trust-profiles", Some(invalid))
            .await
            .status(),
        422
    );
    let mut invalid = source;
    invalid["did_resolution"]["resolver_url"] = json!("https://untrusted.example");
    assert_eq!(
        request(
            service,
            "PATCH",
            &uri,
            Some(json!({"trust_sources":[invalid]}))
        )
        .await
        .status(),
        422
    );
}

#[tokio::test]
async fn machine_identity_profile_round_trips_without_credential_defaults() {
    let response = request(
        service(),
        "POST",
        "/v1/trust-profiles",
        Some(json!({
            "organization_id": "org-1",
            "name": "Machine trust",
            "trust_purposes": ["MACHINE_IDENTITY_CA", "ATTESTATION_VERIFIER"],
            "trusted_assertion_formats": ["X509_CERTIFICATE", "EAT"],
            "trust_sources": [{
                "source_type": "PINNED_ISSUER",
                "issuer_did": "did:web:device-ca.example",
                "purposes": ["MACHINE_IDENTITY_CA"]
            }]
        })),
    )
    .await;
    assert_eq!(response.status(), 200);
    let response = body(response).await;
    assert_eq!(
        response["trust_purposes"],
        json!(["MACHINE_IDENTITY_CA", "ATTESTATION_VERIFIER"])
    );
    assert_eq!(
        response["trusted_assertion_formats"],
        json!(["X509_CERTIFICATE", "EAT"])
    );
    assert_eq!(
        response["trust_sources"][0]["purposes"],
        json!(["MACHINE_IDENTITY_CA"])
    );
    assert!(response.get("supported_formats").is_none());

    let incomplete = request(
        service(),
        "POST",
        "/v1/trust-profiles",
        Some(json!({
            "organization_id": "org-1",
            "name": "Incomplete machine trust",
            "trust_purposes": ["MACHINE_IDENTITY_CA"]
        })),
    )
    .await;
    assert_eq!(incomplete.status(), 422);
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
        purposes: None,
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
async fn wallet_issuer_key_projection_requires_active_trust_and_filters_denied_issuers() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let now = Utc::now();
    let mut selected = profile("Wallet SD-JWT");
    selected.status = TrustProfileStatus::Active;
    selected.compliance_status = ComplianceStatus::Compliant;
    selected.trust_purposes = Some(vec![TrustPurpose::CredentialIssuer]);
    selected.trusted_assertion_formats = Some(vec![TrustedAssertionFormat::Jwt]);
    selected.supported_formats = vec!["SD_JWT_VC".into()];
    repository.save_profile(&selected, None).await.unwrap();
    let issuer = IssuerEntity {
        id: Uuid::new_v4(),
        organization_id: Some("org-1".into()),
        issuer_id: "did:web:trusted.example".into(),
        issuer_type: IssuerEntityType::Organization,
        display_name: "Trusted".into(),
        description: None,
        is_system_issuer: false,
        compliance_status: IssuerEntityComplianceStatus::Compliant,
        accreditation_body: None,
        accreditations: vec![],
        accreditation_date: None,
        valid_from: now - Duration::minutes(1),
        valid_until: Some(now + Duration::days(1)),
        trust_anchor_id: None,
        metadata: json!({"verification_keys": [{
            "kty": "EC", "crv": "P-256", "kid": "did:web:trusted.example#key-1",
            "x": "public-x", "y": "public-y"
        }]}),
        revoked_at: None,
        revocation_reason: None,
        revoked_by: None,
        created_at: now,
        updated_at: now,
    };
    repository.save_issuer_entity(&issuer).await.unwrap();
    repository
        .save_profile_issuer(&TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: selected.id,
            issuer_id: issuer.id,
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
        &format!(
            "/internal/v1/trust-profiles/{}/wallet-issuer-keys",
            selected.id
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let snapshot = body(response).await;
    assert_eq!(snapshot["organization_id"], "org-1");
    assert_eq!(snapshot["trust_profile_id"], selected.id.to_string());
    assert_eq!(snapshot["issuer_keys"][0]["issuer"], issuer.issuer_id);
    assert_eq!(snapshot["issuer_keys"][0]["algorithm"], "ES256");
    assert_eq!(
        snapshot["issuer_keys"][0]["key_id"],
        "did:web:trusted.example#key-1"
    );
    assert_eq!(snapshot["issuer_keys"].as_array().unwrap().len(), 1);
    let generated =
        chrono::DateTime::parse_from_rfc3339(snapshot["generated_at"].as_str().unwrap()).unwrap();
    let expires =
        chrono::DateTime::parse_from_rfc3339(snapshot["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!(expires - generated, Duration::minutes(1));

    let mut denied = issuer.clone();
    denied.id = Uuid::new_v4();
    denied.issuer_id = "did:web:denied.example".into();
    denied.metadata = json!({"verification_keys": [{"kty":"EC","crv":"P-256","kid":"denied"}]});
    repository.save_issuer_entity(&denied).await.unwrap();
    repository
        .save_profile_issuer(&TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: selected.id,
            issuer_id: denied.id,
            trust_level: 100,
            relationship_status: TrustRelationshipStatus::Denied,
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
        &format!(
            "/internal/v1/trust-profiles/{}/wallet-issuer-keys",
            selected.id
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        body(response).await["issuer_keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let mut revoked = issuer.clone();
    revoked.revoked_at = Some(now);
    repository.save_issuer_entity(&revoked).await.unwrap();
    let response = request(
        service_with_repository(Arc::clone(&repository)),
        "GET",
        &format!(
            "/internal/v1/trust-profiles/{}/wallet-issuer-keys",
            selected.id
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), 403);

    selected.status = TrustProfileStatus::Suspended;
    repository.save_profile(&selected, None).await.unwrap();
    let response = request(
        service_with_repository(repository),
        "GET",
        &format!(
            "/internal/v1/trust-profiles/{}/wallet-issuer-keys",
            selected.id
        ),
        None,
    )
    .await;
    assert_eq!(response.status(), 403);
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

#[tokio::test]
async fn private_profile_overrides_fail_before_write_and_legacy_readback_is_closed() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-override-boundary.json"
    ))
    .unwrap();
    for case in fixture["rejected"].as_array().unwrap() {
        let repository = Arc::new(MemoryTrustProfileRepository::default());
        let original = profile("Public trust");
        repository.save_profile(&original, None).await.unwrap();
        let response = request(service_with_repository(repository.clone()), "POST", "/v1/trust-profiles", Some(json!({
            "organization_id":"org-1", "name":"Rejected trust", "system_issuer_overrides":case["overrides"]
        }))).await;
        assert_eq!(response.status(), 422, "{} create", case["name"]);
        assert!(!body(response)
            .await
            .to_string()
            .contains("synthetic-private"));
        assert_eq!(
            repository
                .profiles_by_organization("org-1")
                .await
                .unwrap()
                .len(),
            1
        );
        let response = request(
            service_with_repository(repository.clone()),
            "PATCH",
            &format!("/v1/trust-profiles/{}", original.id),
            Some(json!({
                "name":"Uncommitted name", "system_issuer_overrides":case["overrides"]
            })),
        )
        .await;
        assert_eq!(response.status(), 422, "{} patch", case["name"]);
        assert_eq!(
            repository
                .profile_by_id(original.id)
                .await
                .unwrap()
                .unwrap(),
            original
        );
        let mut legacy = original.clone();
        legacy.system_issuer_overrides = case["overrides"].as_object().unwrap().clone();
        repository.save_profile(&legacy, None).await.unwrap();
        for uri in [
            format!("/v1/trust-profiles/{}", original.id),
            "/v1/trust-profiles?organization_id=org-1".into(),
        ] {
            let response = request(
                service_with_repository(repository.clone()),
                "GET",
                &uri,
                None,
            )
            .await;
            assert_eq!(response.status(), 503, "{} read", case["name"]);
            assert_eq!(
                body(response).await,
                json!({"detail":"Trust Profile contains private custody metadata"})
            );
        }
        assert_eq!(
            repository
                .profile_by_id(original.id)
                .await
                .unwrap()
                .unwrap(),
            legacy
        );
        let response = request(
            service_with_repository(repository.clone()),
            "PATCH",
            &format!("/v1/trust-profiles/{}", original.id),
            Some(json!({"system_issuer_overrides":{}})),
        )
        .await;
        assert_eq!(response.status(), 200, "{} remediation", case["name"]);
        assert_eq!(body(response).await["system_issuer_overrides"], json!({}));
        let repaired = repository
            .profile_by_id(original.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repaired.name, original.name);
        assert!(repaired.system_issuer_overrides.is_empty());
    }
}

#[tokio::test]
async fn public_profile_overrides_round_trip_without_private_material() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-override-boundary.json"
    ))
    .unwrap();
    for case in fixture["supported"].as_array().unwrap() {
        let repository = Arc::new(MemoryTrustProfileRepository::default());
        let response = request(service_with_repository(repository.clone()), "POST", "/v1/trust-profiles", Some(json!({
            "organization_id":"org-1", "name":"Public trust", "system_issuer_overrides":case["overrides"]
        }))).await;
        assert_eq!(response.status(), 200, "{}", case["name"]);
        let created = body(response).await;
        assert_eq!(created["system_issuer_overrides"], case["overrides"]);
        let response = request(
            service_with_repository(repository),
            "GET",
            &format!("/v1/trust-profiles/{}", created["id"].as_str().unwrap()),
            None,
        )
        .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            body(response).await["system_issuer_overrides"],
            case["overrides"]
        );
    }
}

#[tokio::test]
async fn shared_native_trust_readbacks_match_http_and_pagination() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-readback-behavior.json"
    ))
    .unwrap();
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    for case in fixture["cases"].as_array().unwrap() {
        let stored: TrustProfile = serde_json::from_value(case["stored"].clone()).unwrap();
        repository.save_profile(&stored, None).await.unwrap();
        let response = request(
            service_with_repository(repository.clone()),
            "GET",
            &format!("/v1/trust-profiles/{}", stored.id),
            None,
        )
        .await;
        assert_eq!(response.status(), 200, "{}", case["name"]);
        assert_eq!(body(response).await, case["expected"], "{}", case["name"]);
    }
    for (query, length) in [
        ("limit=0", 0),
        ("limit=1", 1),
        ("offset=1", 2),
        ("limit=501", 3),
        ("offset=18446744073709551615", 0),
    ] {
        let response = request(
            service_with_repository(repository.clone()),
            "GET",
            &format!("/v1/trust-profiles?organization_id=org-1&{query}"),
            None,
        )
        .await;
        assert_eq!(response.status(), 200, "{query}");
        assert_eq!(
            body(response).await.as_array().unwrap().len(),
            length,
            "{query}"
        );
    }
    for query in [
        "limit=-1",
        "offset=-1",
        "limit=18446744073709551616",
        "offset=18446744073709551616",
    ] {
        let response = request(
            service_with_repository(repository.clone()),
            "GET",
            &format!("/v1/trust-profiles?organization_id=org-1&{query}"),
            None,
        )
        .await;
        assert_eq!(response.status(), 400, "{query}");
    }
    for index in 4..=501 {
        let mut stored: TrustProfile =
            serde_json::from_value(fixture["cases"][0]["stored"].clone()).unwrap();
        stored.id = Uuid::from_u128(index);
        repository.save_profile(&stored, None).await.unwrap();
    }
    let response = request(
        service_with_repository(repository),
        "GET",
        "/v1/trust-profiles?organization_id=org-1&limit=501",
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await.as_array().unwrap().len(), 500);
}

#[tokio::test]
async fn delegated_lifecycle_requires_service_identity_scope_and_profile_tenant_before_save() {
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    let token = "s".repeat(32);
    for action in ["activate", "suspend"] {
        for configured in [true, false] {
            for (credential, key, organization, scopes, expected) in [
                (Some(token.as_str()), KEY, ORG, "trust:write", 200),
                (Some(token.as_str()), KEY, ORG, "admin:full", 200),
                (None, KEY, ORG, "trust:write", 401),
                (Some("incorrect"), KEY, ORG, "trust:write", 401),
                (Some(token.as_str()), "malformed", ORG, "trust:write", 401),
                (Some(token.as_str()), KEY, "malformed", "trust:write", 401),
                (Some(token.as_str()), KEY, OTHER, "admin:full", 403),
                (Some(token.as_str()), KEY, ORG, "trust:read", 403),
                (Some(token.as_str()), KEY, ORG, "templates:write", 403),
                (Some(token.as_str()), KEY, ORG, "", 403),
                (Some(token.as_str()), "", ORG, "trust:write", 401),
            ] {
                let repository = Arc::new(MemoryTrustProfileRepository::default());
                let mut selected = profile("Lifecycle fixture");
                selected.organization_id = ORG.into();
                selected.status = if action == "activate" {
                    TrustProfileStatus::Draft
                } else {
                    TrustProfileStatus::Active
                };
                repository.save_profile(&selected, None).await.unwrap();
                let application = Arc::new(TrustProfileApplication::new(
                    repository.clone(),
                    Arc::new(RejectKeyMembership),
                ));
                let app = trust_profile_router(TrustProfileHttpState {
                    application,
                    repository: repository.clone(),
                    service_authenticator: Arc::new(
                        ServiceTokenAuthenticator::new(
                            configured.then(|| token.clone()),
                            configured,
                        )
                        .unwrap(),
                    ),
                    internal_api_key: None,
                    registry_synchronizer: Arc::new(EchoSynchronizer),
                });
                let mut builder = Request::builder()
                    .method("POST")
                    .uri(format!("/v1/trust-profiles/{}/{action}", selected.id))
                    .header("x-api-key-id", key)
                    .header("x-organization-id", organization)
                    .header("x-api-key-scopes", scopes)
                    .header("x-user-id", "forged-human");
                if let Some(credential) = credential {
                    builder = builder.header("x-service-token", credential);
                }
                let response = app
                    .oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let expected = if configured { expected } else { 401 };
                assert_eq!(
                    response.status().as_u16(),
                    expected,
                    "{action} configured={configured} {organization} {scopes}"
                );
                let stored = repository
                    .profile_by_id(selected.id)
                    .await
                    .unwrap()
                    .unwrap();
                if expected == 200 {
                    let expected_status = if action == "activate" {
                        TrustProfileStatus::Active
                    } else {
                        TrustProfileStatus::Suspended
                    };
                    assert_eq!(stored.status, expected_status);
                    let payload = body(response).await;
                    assert_eq!(
                        payload["status"],
                        if action == "activate" {
                            "active"
                        } else {
                            "suspended"
                        }
                    );
                    assert_eq!(payload["id"], selected.id.to_string());
                } else {
                    assert_eq!(stored, selected, "denied lifecycle changed storage");
                }
            }
        }
    }
}

#[tokio::test]
async fn human_lifecycle_persists_suspend_and_reactivation_without_replacing_configuration() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let selected = profile("Human lifecycle");
    repository.save_profile(&selected, None).await.unwrap();
    let app = service_with_repository(repository.clone());
    for (action, status) in [
        ("activate", TrustProfileStatus::Active),
        ("suspend", TrustProfileStatus::Suspended),
        ("activate", TrustProfileStatus::Active),
    ] {
        let response = request(
            app.clone(),
            "POST",
            &format!("/v1/trust-profiles/{}/{action}", selected.id),
            None,
        )
        .await;
        assert_eq!(response.status(), 200);
        let stored = repository
            .profile_by_id(selected.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, status);
        assert_eq!(stored.name, selected.name);
        assert_eq!(stored.supported_formats, selected.supported_formats);
        assert_eq!(
            body(response).await["organization_id"],
            selected.organization_id
        );
    }
}

#[tokio::test]
async fn machine_activation_retains_registry_readiness_and_suspension_can_disable_stale_trust() {
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let mut selected = profile("Unsynchronized machine trust");
    selected.organization_id = ORG.into();
    selected.trust_sources.push(TrustSource {
        id: Uuid::new_v4(),
        name: "Registry".into(),
        source_type: TrustSourceType::TrustList,
        url: Some("https://registry.example/sync".into()),
        certificate_pem: None,
        issuer_did: None,
        purposes: None,
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

    repository.save_profile(&selected, None).await.unwrap();
    let actor = marty_api_key_policy::GatewayApiKeyActor::parse(KEY, ORG, "trust:write").unwrap();
    let app = TrustProfileApplication::new(repository.clone(), Arc::new(RejectKeyMembership));
    assert_eq!(
        app.activate_profile_for_gateway_api_key(&actor, selected.id, Utc::now())
            .await
            .unwrap_err(),
        marty_trust_profile::TrustProfileApplicationError::Conflict("registry_never_synchronized")
    );
    assert_eq!(
        repository
            .profile_by_id(selected.id)
            .await
            .unwrap()
            .unwrap(),
        selected
    );
    assert_eq!(
        app.suspend_profile_for_gateway_api_key(&actor, selected.id, Utc::now())
            .await
            .unwrap()
            .status,
        TrustProfileStatus::Suspended
    );
}
