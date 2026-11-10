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
        json!({"description": null}),
    ] {
        let before = body(request(service.clone(), "GET", &uri, None).await).await;
        let response = request(service.clone(), "PATCH", &uri, Some(changes.clone())).await;
        assert_eq!(response.status(), 200);
        let mut expected = before.as_object().unwrap().clone();
        for (field, value) in changes.as_object().unwrap() {
            if value.is_null() {
                expected.remove(field);
            } else {
                expected.insert(field.clone(), value.clone());
            }
        }
        let after = body(request(service.clone(), "GET", &uri, None).await).await;
        expected.insert("updated_at".into(), after["updated_at"].clone());
        assert_eq!(after, Value::Object(expected));
    }
    for invalid in [
        json!({}),
        json!({"organization_id": "other"}),
        json!({"unexpected": null}),
    ] {
        let before = body(request(service.clone(), "GET", &uri, None).await).await;
        assert_eq!(
            request(service.clone(), "PATCH", &uri, Some(invalid))
                .await
                .status(),
            422
        );
        assert_eq!(
            body(request(service.clone(), "GET", &uri, None).await).await,
            before
        );
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

#[tokio::test]
async fn issuer_and_relationship_shared_fields_keep_scope_patch_and_atomic_refusals() {
    let app = service();
    let response = request(app.clone(), "POST", "/v1/issuer-entities", Some(json!({
        "organization_id":"org-1", "issuer_id":"did:example:shared-fields", "display_name":"Original",
        "description":"Keep until cleared", "metadata":{"note":"public"}
    }))).await;
    assert_eq!(response.status(), 200);
    let issuer = body(response).await;
    let issuer_uri = format!("/v1/issuer-entities/{}", issuer["id"].as_str().unwrap());
    let renamed = request(
        app.clone(),
        "PATCH",
        &issuer_uri,
        Some(json!({"organization_id":"org-1","display_name":"Renamed"})),
    )
    .await;
    assert_eq!(renamed.status(), 200);
    assert_eq!(body(renamed).await["description"], "Keep until cleared");
    let cleared = request(
        app.clone(),
        "PATCH",
        &issuer_uri,
        Some(json!({"organization_id":"org-1","description":null})),
    )
    .await;
    assert_eq!(cleared.status(), 200);
    assert!(body(cleared).await.get("description").is_none());
    let before = body(request(app.clone(), "GET", &issuer_uri, None).await).await;
    for (patch, status) in [
        (json!({"organization_id":"org-1"}), 422),
        (json!({"description":null}), 422),
        (json!({"organization_id":"org-1","unknown":true}), 422),
        (
            json!({"organization_id":"other","display_name":"Forbidden"}),
            404,
        ),
        (
            json!({"organization_id":"org-1","compliance_status":"REVOKED"}),
            422,
        ),
    ] {
        assert_eq!(
            request(app.clone(), "PATCH", &issuer_uri, Some(patch))
                .await
                .status(),
            status
        );
        assert_eq!(
            body(request(app.clone(), "GET", &issuer_uri, None).await).await,
            before
        );
    }
    let created = request(
        app.clone(),
        "POST",
        "/v1/trust-profiles",
        Some(
            json!({"organization_id":"org-1","name":"Relationships","supported_formats":["mdoc"]}),
        ),
    )
    .await;
    assert_eq!(created.status(), 200);
    let profile = body(created).await;
    let list_uri = format!(
        "/v1/trust-profiles/{}/issuers",
        profile["id"].as_str().unwrap()
    );
    let attached = request(
        app.clone(),
        "POST",
        &list_uri,
        Some(json!({"issuer_id":issuer["id"]})),
    )
    .await;
    assert_eq!(attached.status(), 200);
    let relationship = body(attached).await;
    let uri = format!("{}/{}", list_uri, relationship["id"].as_str().unwrap());
    let updated = request(
        app.clone(),
        "PATCH",
        &uri,
        Some(json!({"trust_level":50,"metadata":{"note":"kept"}})),
    )
    .await;
    assert_eq!(updated.status(), 200);
    assert_eq!(body(updated).await["trust_level"], 50);
    let before = body(request(app.clone(), "GET", &list_uri, None).await).await;
    for patch in [
        json!({}),
        json!({"unknown":true}),
        json!({"trust_level":null}),
        json!({"trust_level":101}),
    ] {
        assert_eq!(
            request(app.clone(), "PATCH", &uri, Some(patch))
                .await
                .status(),
            422
        );
        assert_eq!(
            body(request(app.clone(), "GET", &list_uri, None).await).await,
            before
        );
    }
}

mod credential_authority_tests {
    use super::*;
    use marty_oid4vp_contract::{
        trust_authority::{
            issuer_public_key_thumbprint, CredentialAuthoritySnapshotV1,
            CredentialTrustEvaluationRequestV1, CredentialTrustEvaluationResponseV1,
        },
        EvidenceCheckOutcome,
    };
    use marty_trust_profile::credential_authority::evaluate_credential_authority;

    const VCT: &str = "https://credentials.example.test/Employee";
    const SERVICE_TOKEN: &str = "credential-authority-service-token-32";

    fn public_key(second: bool) -> Value {
        // RFC 8032 Ed25519 public test keys; these fixtures contain no secret.
        json!({"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "use":"sig",
            "kid": if second {"key-2"} else {"key-1"},
            "x": if second {"PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw"}
                else {"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}})
    }

    async fn fixture(
        repository: &MemoryTrustProfileRepository,
    ) -> (TrustProfile, IssuerEntity, TrustProfileIssuer) {
        let mut selected = profile("Canonical issuer authority");
        selected.status = TrustProfileStatus::Active;
        selected.compliance_status = ComplianceStatus::Compliant;
        selected.trust_purposes = Some(vec![TrustPurpose::CredentialIssuer]);
        selected.supported_formats = vec!["SD_JWT_VC".into()];
        selected.revocation_policy.check_ocsp = false;
        selected.revocation_policy.check_crl = false;
        selected.revocation_policy.check_status_list = false;
        let now = Utc::now() - Duration::hours(1);
        let issuer = IssuerEntity {
            id: Uuid::new_v4(),
            organization_id: Some(selected.organization_id.clone()),
            issuer_id: "https://issuer.example.test/tenant-A".into(),
            issuer_type: IssuerEntityType::Organization,
            display_name: "Issuer".into(),
            description: None,
            is_system_issuer: false,
            compliance_status: IssuerEntityComplianceStatus::Compliant,
            accreditation_body: None,
            accreditations: vec!["Z".into(), "A".into()],
            accreditation_date: None,
            valid_from: now,
            valid_until: None,
            trust_anchor_id: None,
            revoked_at: None,
            revocation_reason: None,
            revoked_by: None,
            metadata: json!({"verification_keys":[public_key(false), public_key(true)]}),
            created_at: now,
            updated_at: now,
        };
        let relationship = TrustProfileIssuer {
            id: Uuid::new_v4(),
            trust_profile_id: selected.id,
            issuer_id: issuer.id,
            trust_level: 70,
            relationship_status: TrustRelationshipStatus::Trusted,
            cascade_revocation_policy: CascadeRevocationPolicy::Manual,
            metadata: json!({"marty_credential_authorizations_v1":[{"format":"SD_JWT_VC","vct":VCT}]}),
            created_at: now,
            updated_at: now,
        };
        repository.save_profile(&selected, None).await.unwrap();
        repository.save_issuer_entity(&issuer).await.unwrap();
        repository.save_profile_issuer(&relationship).await.unwrap();
        (selected, issuer, relationship)
    }

    fn authenticated_service(repository: Arc<MemoryTrustProfileRepository>) -> axum::Router {
        trust_profile_router(authenticated_state(repository))
    }

    fn authenticated_state(repository: Arc<MemoryTrustProfileRepository>) -> TrustProfileHttpState {
        let repository: Arc<dyn TrustProfileRepository> = repository;
        let application = Arc::new(TrustProfileApplication::new(
            repository.clone(),
            Arc::new(AllowControlPlane),
        ));
        TrustProfileHttpState {
            application,
            repository,
            service_authenticator: Arc::new(
                ServiceTokenAuthenticator::new(Some(SERVICE_TOKEN.into()), true).unwrap(),
            ),
            internal_api_key: None,
            registry_synchronizer: Arc::new(EchoSynchronizer),
        }
    }

    async fn post(
        app: &axum::Router,
        uri: &str,
        token: Option<&str>,
        value: Value,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-service-token", token);
        }
        app.clone()
            .oneshot(builder.body(Body::from(value.to_string())).unwrap())
            .await
            .unwrap()
    }

    fn evaluation(
        snapshot: &CredentialAuthoritySnapshotV1,
        issuer: &IssuerEntity,
    ) -> CredentialTrustEvaluationRequestV1 {
        CredentialTrustEvaluationRequestV1 {
            organization_id: snapshot.organization_id.clone(),
            expected_profile: snapshot.profile.clone(),
            issuer_id: issuer.issuer_id.clone(),
            format: "SD_JWT_VC".into(),
            vct: VCT.into(),
            issuer_algorithm: "EdDSA".into(),
            issuer_key_thumbprint: issuer_public_key_thumbprint(&public_key(false)).unwrap(),
            request_binding_digest: format!("sha256:{}", "1".repeat(64)),
        }
    }

    async fn snapshot(
        repository: &MemoryTrustProfileRepository,
        selected: &TrustProfile,
    ) -> CredentialAuthoritySnapshotV1 {
        repository
            .credential_authority_snapshot(&selected.organization_id, selected.id)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn owner_routes_require_service_auth_and_bind_exact_tenant_revision_and_selection() {
        for narrow in [false, true] {
            assert_owner_routes(narrow).await;
        }
    }

    async fn assert_owner_routes(narrow: bool) {
        let repository = Arc::new(MemoryTrustProfileRepository::default());
        let (selected, issuer, mut relationship) = fixture(&repository).await;
        let app = if narrow {
            marty_trust_profile::trust_credential_authority_router(authenticated_state(
                repository.clone(),
            ))
        } else {
            authenticated_service(repository.clone())
        };
        if narrow {
            for uri in [
                "/v1/trust-profiles",
                "/healthz",
                "/internal/v1/trust-registry",
            ] {
                let response = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), 404, "{uri}");
            }
        }

        let freeze_uri = format!(
            "/internal/v1/trust-profiles/{}/credential-authority-snapshot",
            selected.id
        );
        let assess_uri = format!(
            "/internal/v1/trust-profiles/{}/credential-trust-evaluations",
            selected.id
        );
        for token in [None, Some("incorrect")] {
            assert_eq!(
                post(&app, &freeze_uri, token, json!({"organization_id":"org-1"}))
                    .await
                    .status(),
                401
            );
        }
        let frozen = post(
            &app,
            &freeze_uri,
            Some(SERVICE_TOKEN),
            json!({"organization_id":"org-1"}),
        )
        .await;
        assert_eq!(frozen.status(), 200);
        assert_eq!(frozen.headers()["cache-control"], "no-store");
        let frozen: CredentialAuthoritySnapshotV1 =
            serde_json::from_value(body(frozen).await).unwrap();
        frozen.validate().unwrap();
        assert_eq!(frozen.profile.version, 1);
        assert_eq!(
            frozen.basis.issuer_relationships[0].issuer_id,
            issuer.issuer_id
        );
        assert_eq!(
            frozen.basis.issuer_relationships[0].issuer_entity_id,
            issuer.id.to_string()
        );
        let exact = evaluation(&frozen, &issuer);
        let unconfigured = service_with_repository(repository.clone());
        for token in [None, Some(SERVICE_TOKEN)] {
            assert_eq!(
                post(
                    &unconfigured,
                    &freeze_uri,
                    token,
                    json!({"organization_id":"org-1"})
                )
                .await
                .status(),
                401
            );
            assert_eq!(
                post(&unconfigured, &assess_uri, token, json!(exact))
                    .await
                    .status(),
                401
            );
        }
        for token in [None, Some("incorrect")] {
            assert_eq!(
                post(&app, &assess_uri, token, json!(exact)).await.status(),
                401
            );
        }
        let assessed = post(&app, &assess_uri, Some(SERVICE_TOKEN), json!(exact)).await;
        assert_eq!(assessed.status(), 200);
        assert_eq!(assessed.headers()["cache-control"], "no-store");
        let assessed: CredentialTrustEvaluationResponseV1 =
            serde_json::from_value(body(assessed).await).unwrap();
        assessed
            .validate_for_request(&exact, Utc::now().timestamp())
            .unwrap();
        assert_eq!(assessed.outcome, EvidenceCheckOutcome::Passed);
        assert_eq!(assessed.trust_level, Some(70));
        assert_eq!(assessed.compliance_statuses, ["COMPLIANT"]);
        assert_eq!(assessed.accreditations, ["A", "Z"]);

        for (field, value, status, reason) in [
            (
                "issuer_id",
                json!("https://issuer.example.test/tenant-a"),
                200,
                "TRUST_PROFILE.ISSUER_NOT_AUTHORIZED",
            ),
            (
                "vct",
                json!("https://credentials.example.test/employee"),
                200,
                "TRUST_PROFILE.CREDENTIAL_TYPE_NOT_AUTHORIZED",
            ),
            (
                "issuer_algorithm",
                json!("ES256"),
                200,
                "TRUST_PROFILE.ISSUER_KEY_NOT_AUTHORIZED",
            ),
            (
                "issuer_key_thumbprint",
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                200,
                "TRUST_PROFILE.ISSUER_KEY_NOT_AUTHORIZED",
            ),
            ("format", json!("MDOC"), 422, ""),
            ("format", json!("dc+sd-jwt"), 422, ""),
            ("organization_id", json!("org-other"), 404, ""),
        ] {
            let mut altered = json!(exact);
            altered[field] = value;
            let response = post(&app, &assess_uri, Some(SERVICE_TOKEN), altered).await;
            assert_eq!(response.status(), status, "{field}");
            if status == 200 {
                let response: CredentialTrustEvaluationResponseV1 =
                    serde_json::from_value(body(response).await).unwrap();
                assert_eq!(response.outcome, EvidenceCheckOutcome::Failed, "{field}");
                assert_eq!(response.reason_code, reason, "{field}");
                assert!(response.trust_level.is_none());
                assert!(response.compliance_statuses.is_empty());
                assert!(response.accreditations.is_empty());
            }
        }
        for field in ["version", "content_digest"] {
            let mut altered = json!(exact);
            altered["expected_profile"][field] = if field == "version" {
                json!(2)
            } else {
                json!(format!("sha256:{}", "2".repeat(64)))
            };
            assert_eq!(
                post(&app, &assess_uri, Some(SERVICE_TOKEN), altered)
                    .await
                    .status(),
                409
            );
        }
        let mut crossed = exact.clone();
        crossed.request_binding_digest = format!("sha256:{}", "2".repeat(64));
        assert!(assessed
            .validate_for_request(&crossed, assessed.checked_at_epoch_seconds)
            .is_err());
        assert!(assessed
            .validate_for_request(&exact, assessed.checked_at_epoch_seconds - 1)
            .is_err());
        assert!(assessed
            .validate_for_request(&exact, assessed.valid_until_epoch_seconds)
            .is_err());
        let mut forged = assessed.clone();
        forged.trust_level = Some(100);
        assert!(forged.validate().is_err());

        // An owner edit invalidates the frozen reference even if no row timestamp changes.
        relationship.trust_level = 71;
        repository.save_profile_issuer(&relationship).await.unwrap();
        assert_eq!(
            post(&app, &assess_uri, Some(SERVICE_TOKEN), json!(exact))
                .await
                .status(),
            409
        );
        assert_eq!(snapshot(&repository, &selected).await.profile.version, 2);
    }

    #[tokio::test]
    async fn unsupported_controls_are_rejected_and_still_advance_owner_revisions() {
        let repository = Arc::new(MemoryTrustProfileRepository::default());
        let (mut selected, issuer, _) = fixture(&repository).await;
        let app = authenticated_service(repository.clone());
        let uri = format!(
            "/internal/v1/trust-profiles/{}/credential-authority-snapshot",
            selected.id
        );
        let original = snapshot(&repository, &selected).await;
        selected.system_issuer_overrides.insert(
            issuer.issuer_id.clone(),
            json!({"public_jwk":public_key(true)}),
        );
        repository.save_profile(&selected, None).await.unwrap();
        assert_eq!(
            post(
                &app,
                &uri,
                Some(SERVICE_TOKEN),
                json!({"organization_id":"org-1"})
            )
            .await
            .status(),
            422
        );
        let overridden = snapshot(&repository, &selected).await;
        assert_eq!(overridden.profile.version, 2);
        assert_eq!(
            overridden
                .basis
                .policy_controls
                .unsupported_configuration_fields,
            ["system_issuer_overrides"]
        );
        assert!(evaluate_credential_authority(
            &overridden,
            &evaluation(&overridden, &issuer),
            Utc::now()
        )
        .is_err());
        selected.system_issuer_overrides.insert(
            issuer.issuer_id.clone(),
            json!({"public_jwk":public_key(false)}),
        );
        repository.save_profile(&selected, None).await.unwrap();
        assert_eq!(snapshot(&repository, &selected).await.profile.version, 3);
        selected.system_issuer_overrides.clear();
        repository.save_profile(&selected, None).await.unwrap();
        let restored = snapshot(&repository, &selected).await;
        assert_eq!(restored.profile.version, 4);
        assert_eq!(
            restored.profile.content_digest,
            original.profile.content_digest
        );
        for condition in ["min_ec", "freshness", "ocsp", "crl", "status_list"] {
            let mut restricted = selected.clone();
            match condition {
                "min_ec" => restricted.validation_rules.min_key_size_ec = 384,
                "freshness" => restricted.time_policy.credential_freshness_hours = Some(24),
                "ocsp" => restricted.revocation_policy.check_ocsp = true,
                "crl" => restricted.revocation_policy.check_crl = true,
                _ => restricted.revocation_policy.check_status_list = true,
            }
            repository.save_profile(&restricted, None).await.unwrap();
            assert_eq!(
                post(
                    &app,
                    &uri,
                    Some(SERVICE_TOKEN),
                    json!({"organization_id":"org-1"})
                )
                .await
                .status(),
                422,
                "{condition}"
            );
        }
    }

    #[tokio::test]
    async fn governed_keys_and_lifecycle_bound_receipts_without_resolution_or_row_time_shortcuts() {
        let repository = MemoryTrustProfileRepository::default();
        let (selected, mut issuer, _) = fixture(&repository).await;
        let original = snapshot(&repository, &selected).await;
        let fingerprints = original.basis.issuer_relationships[0]
            .verification_keys
            .iter()
            .map(|key| issuer_public_key_thumbprint(key).unwrap())
            .collect::<Vec<_>>();
        assert!(fingerprints[0] < fingerprints[1]);
        issuer.metadata["verification_keys"]
            .as_array_mut()
            .unwrap()
            .reverse();
        repository.save_issuer_entity(&issuer).await.unwrap();
        assert_eq!(snapshot(&repository, &selected).await, original);
        let observed_at = Utc::now();
        issuer.valid_until = Some(observed_at + Duration::seconds(20));
        repository.save_issuer_entity(&issuer).await.unwrap();
        let bounded = snapshot(&repository, &selected).await;
        assert_eq!(bounded.profile.version, 2);
        let exact = evaluation(&bounded, &issuer);
        let receipt = evaluate_credential_authority(&bounded, &exact, observed_at).unwrap();
        assert_eq!(receipt.outcome, EvidenceCheckOutcome::Passed);
        assert_eq!(
            receipt.valid_until_epoch_seconds,
            issuer.valid_until.unwrap().timestamp()
        );
        assert!(receipt
            .validate_for_request(&exact, receipt.valid_until_epoch_seconds)
            .is_err());
        let expired =
            evaluate_credential_authority(&bounded, &exact, issuer.valid_until.unwrap()).unwrap();
        assert_eq!(expired.outcome, EvidenceCheckOutcome::Failed);
        assert_eq!(expired.reason_code, "TRUST_PROFILE.ISSUER_NOT_CURRENT");
        issuer.valid_until = None;
        issuer.valid_from = observed_at + Duration::seconds(1);
        repository.save_issuer_entity(&issuer).await.unwrap();
        let future = snapshot(&repository, &selected).await;
        assert_eq!(
            evaluate_credential_authority(&future, &evaluation(&future, &issuer), observed_at)
                .unwrap()
                .outcome,
            EvidenceCheckOutcome::Failed
        );
        issuer.valid_from = observed_at - Duration::seconds(1);
        for compliance in [
            IssuerEntityComplianceStatus::Suspended,
            IssuerEntityComplianceStatus::Revoked,
        ] {
            issuer.compliance_status = compliance;
            repository.save_issuer_entity(&issuer).await.unwrap();
            let frozen = snapshot(&repository, &selected).await;
            assert_eq!(
                evaluate_credential_authority(&frozen, &evaluation(&frozen, &issuer), observed_at)
                    .unwrap()
                    .outcome,
                EvidenceCheckOutcome::Failed
            );
        }
        issuer.compliance_status = IssuerEntityComplianceStatus::Compliant;
        issuer.revoked_at = Some(observed_at - Duration::seconds(1));
        repository.save_issuer_entity(&issuer).await.unwrap();
        let revoked = snapshot(&repository, &selected).await;
        assert_eq!(
            evaluate_credential_authority(&revoked, &evaluation(&revoked, &issuer), observed_at)
                .unwrap()
                .outcome,
            EvidenceCheckOutcome::Failed
        );

        issuer.revoked_at = None;
        issuer.issuer_id = "did:web:never-resolve.example.test".into();
        issuer.metadata = json!({});
        repository.save_issuer_entity(&issuer).await.unwrap();
        let no_key = snapshot(&repository, &selected).await;
        assert!(no_key.basis.issuer_relationships[0]
            .verification_keys
            .is_empty());
        let denied =
            evaluate_credential_authority(&no_key, &evaluation(&no_key, &issuer), observed_at)
                .unwrap();
        assert_eq!(
            denied.reason_code,
            "TRUST_PROFILE.ISSUER_KEY_NOT_AUTHORIZED"
        );
        assert_eq!(
            repository
                .issuer_entity_by_id(issuer.id)
                .await
                .unwrap()
                .unwrap()
                .metadata,
            json!({})
        );
        issuer.organization_id = Some("other-org".into());
        issuer.is_system_issuer = true;
        repository.save_issuer_entity(&issuer).await.unwrap();
        assert!(repository
            .credential_authority_snapshot("org-1", selected.id)
            .await
            .is_err());
        assert!(repository
            .credential_authority_snapshot("other-org", selected.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn relationship_grant_writes_are_strict_and_atomic() {
        let repository = Arc::new(MemoryTrustProfileRepository::default());
        let (selected, _, relationship) = fixture(&repository).await;
        let app = service_with_repository(repository.clone());
        let uri = format!(
            "/v1/trust-profiles/{}/issuers/{}",
            selected.id, relationship.id
        );
        for malformed in [
            json!({"format":"SD_JWT_VC","vct":VCT}),
            json!([{"format":"SD_JWT_VC","vct":VCT,"allow":true}]),
            json!([{"format":"SD_JWT_VC"}]),
            json!([{"format":"MDOC","vct":VCT}]),
            json!([{"format":"SD_JWT_VC","vct":"not-a-uri"}]),
            json!([{"format":"SD_JWT_VC","vct":VCT},{"format":"SD_JWT_VC","vct":VCT}]),
        ] {
            let response = request(
                app.clone(),
                "PATCH",
                &uri,
                Some(json!({"metadata":{"marty_credential_authorizations_v1":malformed}})),
            )
            .await;
            assert_eq!(response.status(), 422);
            assert_eq!(
                repository
                    .profile_issuer_by_id(relationship.id)
                    .await
                    .unwrap(),
                Some(relationship.clone())
            );
        }
        let cleared = request(app, "PATCH", &uri, Some(json!({"metadata":{}}))).await;
        assert_eq!(cleared.status(), 200);
        let frozen = snapshot(&repository, &selected).await;
        assert!(frozen.basis.issuer_relationships[0]
            .credential_authorizations
            .is_empty());
    }
}
