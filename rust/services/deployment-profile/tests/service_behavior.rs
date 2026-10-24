use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::Utc;
use marty_deployment_profile::{
    deployment_router, ApiAuthConfiguration, AssignDeviceRequest, AuthMethod,
    CreateDeploymentProfileRequest, CreateLaneRequest, DeploymentError, DeploymentHttpState,
    DeploymentProfile, DeploymentRepository, DeploymentService, Lane, MemoryDeploymentRepository,
    PostgresDeploymentRepository, UpdateDeploymentProfileRequest,
};
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[derive(Clone)]
struct Memberships {
    permissions: BTreeSet<String>,
    active: bool,
}

#[async_trait]
impl TenantMembershipProvider for Memberships {
    async fn membership(
        &self,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        Ok(Some(TenantMembership {
            principal_id: principal_id.into(),
            tenant_id: tenant_id.into(),
            status: if self.active { "active" } else { "suspended" }.into(),
            role_names: BTreeSet::new(),
            permissions: self.permissions.clone(),
            is_owner: false,
        }))
    }
}

fn all_permissions() -> BTreeSet<String> {
    [
        "deployment-profile:create",
        "deployment-profile:view",
        "deployment-profile:edit",
        "deployment-profile:delete",
        "deployment-profile:activate",
        "deployment-profile:suspend",
        "api-key:create",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn harness(
    permissions: BTreeSet<String>,
) -> (Arc<DeploymentService>, Arc<dyn DeploymentRepository>) {
    let repository: Arc<dyn DeploymentRepository> = Arc::new(MemoryDeploymentRepository::new());
    let memberships = Arc::new(Memberships {
        permissions,
        active: true,
    });
    (
        Arc::new(DeploymentService::new(repository.clone(), memberships)),
        repository,
    )
}

fn create_request() -> CreateDeploymentProfileRequest {
    serde_json::from_value(json!({
        "organization_id":"org-1", "name":"Airport kiosk", "environment":"production",
        "trust_profile_id":"trust-1", "presentation_policy_ids":["policy-1","policy-1"],
        "credential_template_ids":["template-1","template-1"], "default_policy_id":"policy-1",
        "callbacks":{"issuance_complete_url":"https://example.test/issued","max_retries":4},
        "api_auth":{"auth_method":"mtls","mtls_ca_certificate":"certificate"},
        "rate_limits":{"requests_per_minute":42},
        "feature_flags":{"enable_canvas_lti":true,"custom_flags":{"preview":true}},
        "branding":{"organization_name":"Example","qr_size":512,"qr_logo_url":"https://example.test/logo.png"},
        "environment_config":{"language":"fr-FR","offline_cache_ttl_seconds":7200},
        "enabled_flow_ids":["flow-1","flow-1"], "update_channel":"beta"
    })).unwrap()
}

#[tokio::test]
async fn repository_rejects_private_key_material_before_database_access() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost:1/deployment_profile_test")
        .unwrap();
    let postgres = PostgresDeploymentRepository::new(pool);
    let memory = MemoryDeploymentRepository::new();

    let mut profile = DeploymentProfile::new(create_request(), Utc::now()).unwrap();
    profile.environment_config.insert(
        "issuer".into(),
        json!({"public_jwk":{"kty":"EC","crv":"P-256","d":"secret"}}),
    );
    for repository in [&postgres as &dyn DeploymentRepository, &memory] {
        assert!(matches!(
            repository.save_profile(profile.clone()).await,
            Err(DeploymentError::BadRequest(_))
        ));
    }

    let mut lane = Lane::new(
        &profile.id,
        serde_json::from_value(json!({"name":"Arrival"})).unwrap(),
        Utc::now(),
    )
    .unwrap();
    lane.metadata
        .insert("config".into(), json!(r#"{"private_key_pem":"secret"}"#));
    for repository in [&postgres as &dyn DeploymentRepository, &memory] {
        assert!(matches!(
            repository.save_lane(lane.clone()).await,
            Err(DeploymentError::BadRequest(_))
        ));
    }

    profile.environment_config.insert(
        "issuer".into(),
        json!({"public_jwk":{"kty":"EC","crv":"P-256","x":"public"},"key_reference":"transit/issuer/1"}),
    );
    memory.save_profile(profile).await.unwrap();
}

#[tokio::test]
async fn language_neutral_contract_declares_all_fourteen_routes_and_intended_features() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/deployment-profile-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["routes"].as_array().unwrap().len(), 14);
    for field in [
        "callbacks",
        "api_auth",
        "rate_limits",
        "feature_flags",
        "branding",
    ] {
        assert!(contract["configuration_sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == field));
    }
    assert!(contract["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str().unwrap().contains("transactionally serialized")));
}

#[test]
fn api_key_auth_reads_legacy_rust_spelling_and_writes_contract_spelling() {
    for spelling in ["api_key", "apikey"] {
        let configuration: ApiAuthConfiguration = serde_json::from_value(json!({
            "auth_method": spelling,
            "api_key_header": "X-API-Key"
        }))
        .unwrap();
        assert_eq!(configuration.auth_method, AuthMethod::ApiKey);
        assert_eq!(
            serde_json::to_value(configuration).unwrap()["auth_method"],
            "api_key"
        );
    }
}

#[tokio::test]
async fn complete_configuration_round_trips_and_protocol_response_stays_minimal() {
    let (service, repository) = harness(all_permissions());
    let response = service.create(create_request(), "user-1").await.unwrap();
    assert_eq!(response.presentation_policy_ids, ["policy-1"]);
    assert_eq!(response.credential_template_ids, ["template-1"]);
    assert_eq!(response.environment_config["language"], "fr-FR");
    assert_eq!(response.update_policy["channel"], "beta");
    assert!(response.canvas_feature_flags["enable_canvas_lti"]);
    let stored = repository.profile(&response.id).await.unwrap().unwrap();
    assert_eq!(stored.callbacks.max_retries, 4);
    assert_eq!(
        stored.api_auth.mtls_ca_certificate.as_deref(),
        Some("certificate")
    );
    assert_eq!(stored.rate_limits.requests_per_minute, 42);
    assert_eq!(stored.branding.qr_size, 512);
    let public = serde_json::to_value(response).unwrap();
    for private in [
        "environment",
        "callbacks",
        "api_auth",
        "rate_limits",
        "feature_flags",
        "branding",
        "api_key",
        "api_key_prefix",
    ] {
        assert!(public.get(private).is_none(), "{private} leaked");
    }
}

#[tokio::test]
async fn updates_persist_every_configuration_section_and_keep_derived_values_consistent() {
    let (service, repository) = harness(all_permissions());
    let profile = service.create(create_request(), "user-1").await.unwrap();
    let update: UpdateDeploymentProfileRequest = serde_json::from_value(json!({
        "update_channel":"stable", "offline_cache_ttl_hours":12,
        "callbacks":{"verification_complete_url":"https://example.test/verified"},
        "api_auth":{"auth_method":"jwt","jwt_issuer":"https://issuer.test"},
        "rate_limits":{"enabled":false}, "feature_flags":{"enable_batch_issuance":true},
        "branding":{"organization_name":"Updated","qr_error_correction":"Q"}
    }))
    .unwrap();
    let response = service.update(&profile.id, update, "user-1").await.unwrap();
    assert_eq!(response.update_policy["channel"], "stable");
    // Existing explicit seconds are intentionally retained for compatibility.
    assert_eq!(
        response.environment_config["offline_cache_ttl_seconds"],
        7200
    );
    let stored = repository.profile(&profile.id).await.unwrap().unwrap();
    assert_eq!(
        stored.callbacks.verification_complete_url.as_deref(),
        Some("https://example.test/verified")
    );
    assert_eq!(
        stored.api_auth.jwt_issuer.as_deref(),
        Some("https://issuer.test")
    );
    assert!(!stored.rate_limits.enabled);
    assert!(stored.feature_flags.enable_batch_issuance);
    assert_eq!(stored.branding.qr_error_correction, "Q");
}

#[tokio::test]
async fn api_key_is_one_time_only_and_environment_scoped() {
    let (service, _) = harness(all_permissions());
    let profile = service.create(create_request(), "user-1").await.unwrap();
    let generated = service
        .generate_api_key(&profile.id, "user-1")
        .await
        .unwrap();
    assert!(generated.api_key.starts_with("mk_live_"));
    assert!(generated.api_key_prefix.starts_with("mk_live_"));
    let fetched = serde_json::to_value(service.get(&profile.id, "user-1").await.unwrap()).unwrap();
    assert!(fetched.get("api_key").is_none());
    assert!(fetched.get("api_key_prefix").is_none());
}

#[tokio::test]
async fn lane_assignment_is_idempotent_unique_and_prevents_unsafe_deletion() {
    let (service, _) = harness(all_permissions());
    let profile = service.create(create_request(), "user-1").await.unwrap();
    let lane_a = service
        .create_lane(
            &profile.id,
            CreateLaneRequest {
                name: "A".into(),
                description: None,
                location: None,
                device_type: "kiosk".into(),
                default_policy_id: Some("policy-1".into()),
                metadata: Default::default(),
            },
            "user-1",
        )
        .await
        .unwrap();
    let lane_b = service
        .create_lane(
            &profile.id,
            CreateLaneRequest {
                name: "B".into(),
                description: None,
                location: None,
                device_type: "kiosk".into(),
                default_policy_id: None,
                metadata: Default::default(),
            },
            "user-1",
        )
        .await
        .unwrap();
    let assignment = AssignDeviceRequest {
        device_id: "device-1".into(),
        device_name: Some("Reader".into()),
    };
    service
        .assign_device(&profile.id, &lane_a.id, assignment.clone(), "user-1")
        .await
        .unwrap();
    let repeated = service
        .assign_device(&profile.id, &lane_a.id, assignment.clone(), "user-1")
        .await
        .unwrap();
    assert_eq!(repeated.device_ids, ["device-1"]);
    assert!(matches!(
        service
            .assign_device(&profile.id, &lane_b.id, assignment, "user-1")
            .await,
        Err(DeploymentError::Conflict(_))
    ));
    assert!(matches!(
        service.delete_lane(&profile.id, &lane_a.id, "user-1").await,
        Err(DeploymentError::Conflict(_))
    ));
    assert!(matches!(
        service.delete(&profile.id, "user-1").await,
        Err(DeploymentError::Conflict(_))
    ));
}

#[tokio::test]
async fn lifecycle_and_exact_tenant_permissions_fail_closed() {
    let (service, _) = harness(all_permissions());
    let profile = service.create(create_request(), "user-1").await.unwrap();
    service.activate(&profile.id, "user-1").await.unwrap();
    assert!(matches!(
        service.delete(&profile.id, "user-1").await,
        Err(DeploymentError::BadRequest(_))
    ));
    service.suspend(&profile.id, "user-1").await.unwrap();
    service.delete(&profile.id, "user-1").await.unwrap();

    let (restricted, _) = harness(BTreeSet::from(["deployment-profile:view".into()]));
    assert!(matches!(
        restricted.create(create_request(), "user-1").await,
        Err(DeploymentError::Forbidden(_))
    ));
    assert!(matches!(
        restricted.create(create_request(), "").await,
        Err(DeploymentError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn http_surface_preserves_validation_status_and_rejects_removed_aliases() {
    let (service, _) = harness(all_permissions());
    let profile = service.create(create_request(), "user-1").await.unwrap();
    let app = deployment_router(
        DeploymentHttpState::new(service)
            .with_service_token(Some("s".repeat(32)))
            .unwrap(),
    );
    let human = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/deployment-profiles/{}", profile.id))
                .header("x-user-id", "user-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(human.status(), StatusCode::OK);
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/deployment-profiles")
        .header("content-type", "application/json").header("x-user-id", "user-1")
        .body(Body::from(json!({"organization_id":"org-1","name":"Legacy","trust_profile_id":"trust-1","presentation_policy_ids":["policy-1"],"default_presentation_policy_id":"policy-1","ux_config":{}}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/deployment-profiles/not-found")
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let _ = to_bytes(response.into_body(), 1024).await.unwrap();
}

#[tokio::test]
async fn gateway_api_key_reads_and_writes_require_service_identity_tenant_and_exact_scope() {
    const ORG: &str = "20000000-0000-4000-8000-000000000001";
    const OTHER: &str = "20000000-0000-4000-8000-000000000002";
    const KEY: &str = "10000000-0000-4000-8000-000000000001";
    let (service, repository) = harness(BTreeSet::new());
    let mut request = create_request();
    request.organization_id = ORG.into();
    let profile = DeploymentProfile::new(request, Utc::now()).unwrap();
    let id = profile.id.clone();
    repository.save_profile(profile).await.unwrap();
    let token = "s".repeat(32);
    let app = deployment_router(
        DeploymentHttpState::new(service.clone())
            .with_service_token(Some(token.clone()))
            .unwrap(),
    );
    for (method, scopes, organization, supplied_token, key, status) in [
        (
            "GET",
            "deployment:read",
            ORG,
            token.as_str(),
            KEY,
            StatusCode::OK,
        ),
        (
            "GET",
            "deployment:read",
            ORG,
            "",
            KEY,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "deployment:read",
            ORG,
            "wrong-token",
            KEY,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "deployment:read",
            OTHER,
            token.as_str(),
            KEY,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "flows:read",
            ORG,
            token.as_str(),
            KEY,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "deployment:read",
            ORG,
            token.as_str(),
            "malformed",
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PATCH",
            "deployment:read",
            ORG,
            token.as_str(),
            KEY,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "deployment:write",
            OTHER,
            token.as_str(),
            KEY,
            StatusCode::FORBIDDEN,
        ),
        (
            "PATCH",
            "deployment:write",
            ORG,
            token.as_str(),
            KEY,
            StatusCode::OK,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/v1/deployment-profiles/{id}"))
                    .header("content-type", "application/json")
                    .header("x-service-token", supplied_token)
                    .header("x-api-key-id", key)
                    .header("x-api-key-scopes", scopes)
                    .header("x-organization-id", organization)
                    .body(Body::from(if method == "PATCH" {
                        r#"{"description":"API key metadata update"}"#
                    } else {
                        ""
                    }))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            status,
            "{method} {scopes} {organization}"
        );
    }
    let stored = repository.profile(&id).await.unwrap().unwrap();
    assert_eq!(stored.organization_id, ORG);
    assert_eq!(
        stored.description.as_deref(),
        Some("API key metadata update")
    );
    assert_eq!(stored.credential_template_ids, vec!["template-1"]);
    // An unconfigured development listener must not trust caller-supplied key metadata.
    let response = deployment_router(DeploymentHttpState::new(service))
        .oneshot(
            Request::builder()
                .uri(format!("/v1/deployment-profiles/{id}"))
                .header("x-api-key-id", KEY)
                .header("x-api-key-scopes", "admin:full")
                .header("x-organization-id", ORG)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn resource_owner_projection_is_minimal_and_service_authenticated() {
    let (service, repository) = harness(BTreeSet::new());
    let profile = DeploymentProfile::new(create_request(), Utc::now()).unwrap();
    let id = profile.id.clone();
    repository.save_profile(profile).await.unwrap();
    let token = "s".repeat(32);
    let app = deployment_router(
        DeploymentHttpState::new(service)
            .with_service_token(Some(token.clone()))
            .unwrap(),
    );
    for (supplied, expected) in [
        ("", StatusCode::UNAUTHORIZED),
        ("wrong", StatusCode::UNAUTHORIZED),
        (token.as_str(), StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/internal/v1/resource-owners/deployment-profiles/{id}"
                    ))
                    .header("x-service-token", supplied)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap())
                    .unwrap();
            assert_eq!(value, json!({"id":id,"organization_id":"org-1"}));
        }
    }
}
