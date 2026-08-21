use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use marty_compliance_profile::{
    compliance_router, system_profiles, ComplianceError, ComplianceHttpState, ComplianceRepository,
    ComplianceService, CreateComplianceProfileRequest, MemoryComplianceRepository,
    UpdateComplianceProfileRequest,
};
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};
use tower::ServiceExt;
#[derive(Clone)]
struct Memberships {
    permissions: BTreeSet<String>,
}
#[async_trait]
impl TenantMembershipProvider for Memberships {
    async fn membership(
        &self,
        p: &str,
        t: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        Ok(Some(TenantMembership {
            principal_id: p.into(),
            tenant_id: t.into(),
            status: "active".into(),
            role_names: BTreeSet::new(),
            permissions: self.permissions.clone(),
            is_owner: false,
        }))
    }
}
fn permissions() -> BTreeSet<String> {
    [
        "compliance-profile:create",
        "compliance-profile:view",
        "compliance-profile:edit",
        "compliance-profile:activate",
        "compliance-profile:suspend",
        "compliance-profile:delete",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn harness() -> (Arc<ComplianceService>, Arc<dyn ComplianceRepository>) {
    let r: Arc<dyn ComplianceRepository> = Arc::new(MemoryComplianceRepository::new());
    (
        Arc::new(ComplianceService::new(
            r.clone(),
            Arc::new(Memberships {
                permissions: permissions(),
            }),
        )),
        r,
    )
}
fn request() -> CreateComplianceProfileRequest {
    serde_json::from_value(json!({"organization_id":"org-1","name":"Enterprise SD-JWT VC","description":"Enterprise issuance baseline","compliance_code":"ENTERPRISE_VC","credential_format":"sd_jwt_vc","issuance_protocol":"OID4VCI_PRE_AUTH","issuer_artifact_requirements":{"requires_did":true,"requires_jwk":true,"recommended_algorithms":["ES256"]},"verification_policy_set_id":"policy-set-1","trust_profile_constraints":{"compatible_profile_types":["CUSTOM"],"required_source_types":["TRUST_LIST"],"required_formats":["SD_JWT_VC"]},"api_surface":[{"rel":"issuer","path_template":"/.well-known/openid-credential-issuer","auth_required":false}],"frameworks":["GDPR"],"data_retention":{"retention_period":"1_year","retain_metadata_only":true,"anonymize_after_days":30},"consent_requirement":{"consent_type":"explicit","consent_text":"Consent","consent_version":"2.0"},"audit_configuration":{"audit_level":"detailed","retention_days":730},"data_minimization_rules":[{"description":"Protect email","applies_to_claims":["email"],"action":"hash","parameters":{"algorithm":"sha256"}}],"jurisdictional_constraints":[{"name":"EU","allowed_countries":["DE","FR"],"data_residency_required":true,"allowed_data_regions":["eu"]}],"age_verification":{"enabled":true,"minimum_age":21,"verification_method":"derived"}})).unwrap()
}
#[tokio::test]
async fn language_neutral_contract_freezes_all_routes_and_policy_sections() {
    let c: Value = serde_json::from_str(include_str!(
        "../../../../contracts/compliance-profile-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(c["routes"].as_array().unwrap().len(), 8);
    assert_eq!(c["policy_sections"].as_array().unwrap().len(), 7);
    assert_eq!(c["system_profile_codes"].as_array().unwrap().len(), 4);
}
#[tokio::test]
async fn all_intended_policy_fields_round_trip_but_public_projection_stays_protocol_scoped() {
    let (s, r) = harness();
    let response = s.create(request(), "user-1").await.unwrap();
    assert_eq!(response.credential_format, "SD_JWT_VC");
    assert_eq!(
        response.trust_profile_constraints.required_formats,
        ["SD_JWT_VC"]
    );
    let stored = r.get(&response.id).await.unwrap().unwrap();
    assert_eq!(stored.frameworks, ["GDPR"]);
    assert_eq!(stored.data_retention.anonymize_after_days, Some(30));
    assert_eq!(stored.consent_requirement.consent_version, "2.0");
    assert_eq!(stored.audit_configuration.retention_days, 730);
    assert_eq!(
        stored.data_minimization_rules[0].parameters["algorithm"],
        "sha256"
    );
    assert_eq!(
        stored.jurisdictional_constraints[0].allowed_countries,
        ["DE", "FR"]
    );
    assert_eq!(stored.age_verification.minimum_age, 21);
    let public = serde_json::to_value(response).unwrap();
    for private in [
        "frameworks",
        "data_retention",
        "consent_requirement",
        "audit_configuration",
        "data_minimization_rules",
        "jurisdictional_constraints",
        "age_verification",
    ] {
        assert!(public.get(private).is_none());
    }
}
#[tokio::test]
async fn complete_update_and_lifecycle_are_durable() {
    let (s, r) = harness();
    let p = s.create(request(), "user-1").await.unwrap();
    let u:UpdateComplianceProfileRequest=serde_json::from_value(json!({"credential_format":"MDOC","frameworks":["AAMVA"],"data_retention":{"retention_period":"session"},"consent_requirement":{"consent_type":"none"},"audit_configuration":{"audit_level":"forensic","retention_days":2555},"data_minimization_rules":[],"jurisdictional_constraints":[],"age_verification":{"enabled":false,"minimum_age":18}})).unwrap();
    s.update(&p.id, u, "user-1").await.unwrap();
    s.activate(&p.id, "user-1").await.unwrap();
    let stored = r.get(&p.id).await.unwrap().unwrap();
    assert_eq!(stored.credential_format.canonical(), "MDOC");
    assert_eq!(format!("{:?}", stored.status), "Active");
    s.suspend(&p.id, "user-1").await.unwrap();
    s.delete(&p.id, "user-1").await.unwrap();
    assert!(r.get(&p.id).await.unwrap().is_none());
}
#[tokio::test]
async fn canonical_system_catalog_is_public_discoverable_and_immutable() {
    let (s, r) = harness();
    for p in system_profiles() {
        r.save(p).await.unwrap();
    }
    let values = s.discoverable().await.unwrap();
    assert_eq!(
        values
            .iter()
            .filter_map(|p| p.compliance_code.as_deref())
            .collect::<Vec<_>>(),
        ["OID4VC", "ISO_18013_5", "OPEN_BADGES_3", "ICAO_VDS_NC"]
    );
    let id = &values[0].id;
    assert!(matches!(
        s.update(id, UpdateComplianceProfileRequest::default(), "user-1")
            .await,
        Err(ComplianceError::Forbidden(_))
    ));
    assert!(matches!(
        s.delete(id, "user-1").await,
        Err(ComplianceError::Forbidden(_))
    ));
}
#[tokio::test]
async fn system_profile_creation_and_invalid_policy_values_fail_closed() {
    let (s, _) = harness();
    let mut raw = serde_json::to_value(request()).unwrap();
    raw["is_system"] = json!(true);
    raw["organization_id"] = Value::Null;
    let r: CreateComplianceProfileRequest = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        s.create(r, "user-1").await,
        Err(ComplianceError::BadRequest(_))
    ));
    let mut raw = serde_json::to_value(request()).unwrap();
    raw["age_verification"]["minimum_age"] = json!(151);
    let r: CreateComplianceProfileRequest = serde_json::from_value(raw).unwrap();
    assert!(matches!(
        s.create(r, "user-1").await,
        Err(ComplianceError::BadRequest(_))
    ));
}
#[tokio::test]
async fn exact_tenant_permissions_and_identity_are_required() {
    let r: Arc<dyn ComplianceRepository> = Arc::new(MemoryComplianceRepository::new());
    let s = ComplianceService::new(
        r,
        Arc::new(Memberships {
            permissions: BTreeSet::from(["compliance-profile:view".into()]),
        }),
    );
    assert!(matches!(
        s.create(request(), "user-1").await,
        Err(ComplianceError::Forbidden(_))
    ));
    assert!(matches!(
        s.create(request(), "").await,
        Err(ComplianceError::Unauthorized(_))
    ));
}
#[tokio::test]
async fn http_surface_rejects_removed_fields_and_put_alias() {
    let (s, _) = harness();
    let app = compliance_router(ComplianceHttpState { service: s });
    let response=app.clone().oneshot(Request::builder().method("POST").uri("/v1/compliance-profiles").header("content-type","application/json").header("x-user-id","user-1").body(Body::from(json!({"organization_id":"org-1","name":"Legacy","default_verification_rules":{}}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/compliance-profiles/profile-1")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
