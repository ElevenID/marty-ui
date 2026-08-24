use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request as HttpRequest, StatusCode},
};
use marty_flow::{
    CredentialClaimReference, CredentialTemplateProvider, CredentialTemplateReference,
    FlowProviderError, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference,
};
use marty_verification_service::{
    verification_proto::{
        verification_service_server::VerificationService as VerificationGrpc,
        EvaluatePresentationRequest as GrpcEvaluateRequest,
        StartVerificationRequest as GrpcStartRequest,
    },
    EvaluationProvider, EvaluationResult, InspectionProvider, ManagementPrincipal,
    MemorySessionStore, StartVerificationRequest, VerificationError, VerificationGrpcService,
    VerificationProviders, VerificationService,
};
use mmf_core::BuildInfo;
use mmf_runtime::RuntimeState;
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde_json::{json, Value};
use tonic::Request;
use tower::ServiceExt;

#[derive(Clone)]
struct Memberships;

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
            status: "active".into(),
            role_names: BTreeSet::new(),
            permissions: BTreeSet::from(["verification:execute".into()]),
            is_owner: false,
        }))
    }
}

#[derive(Clone)]
struct Policies;

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: policy_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements: vec![json!({
                "id": "member",
                "credential_template_id": "template-1",
                "requested_claims": [{"claim_name":"email","required":true}]
            })],
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("standalone Verification uses its richer evaluation adapter")
    }
}

#[derive(Clone)]
struct Templates;

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            id: template_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_type: "MemberCredential".into(),
            vct: "https://issuer.example/member".into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: vec![CredentialClaimReference {
                name: "email".into(),
                display_name: "Email".into(),
                description: String::new(),
                required: true,
                mdoc_namespace: String::new(),
                mdoc_element_identifier: String::new(),
            }],
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "dc+sd-jwt".into(),
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(
        &self,
        _organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        Ok(vec!["dc+sd-jwt".into()])
    }
}

#[derive(Clone)]
struct Evaluation;

#[async_trait]
impl EvaluationProvider for Evaluation {
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<EvaluationResult, VerificationError> {
        assert_eq!(request.principal_id, "user-1");
        Ok(EvaluationResult {
            result: "passed".into(),
            decision: "allow".into(),
            decision_reason: "requirements satisfied".into(),
            verified_claims: [("email".into(), json!("alice@example.com"))]
                .into_iter()
                .collect(),
            credential_results: vec![json!({
                "credential_template_id":"template-1",
                "satisfied":true,
                "revocation_checked":true,
                "presented_value":"must-not-persist"
            })],
            holder_binding_evidence: Some(json!({
                "verified":true,
                "holder":"did:example:1"
            })),
            total_requirements: 1,
            satisfied_requirements: 1,
            evaluation_timestamp: "2026-08-21T12:00:00Z".into(),
            nonce: request.nonce.clone(),
        })
    }
}

#[derive(Clone)]
struct Inspection;

#[async_trait]
impl InspectionProvider for Inspection {
    async fn inspect(&self, _item: &str) -> Result<Option<String>, VerificationError> {
        Ok(Some(
            json!({"result":"verified","document_number":"SECRET"}).to_string(),
        ))
    }
}

fn service(managed: bool) -> VerificationService {
    VerificationService::new(
        Arc::new(MemorySessionStore::new()),
        VerificationProviders::from_parts(
            Arc::new(Memberships),
            Arc::new(Templates),
            Arc::new(Policies),
            Arc::new(Evaluation),
            Arc::new(Inspection),
        ),
        "https://verifier.example",
        managed,
    )
}

fn principal() -> ManagementPrincipal {
    ManagementPrincipal {
        user_id: "user-1".into(),
        organization_id: "org-1".into(),
        ..ManagementPrincipal::default()
    }
}

fn start_request() -> StartVerificationRequest {
    StartVerificationRequest {
        organization_id: "org-1".into(),
        presentation_policy_id: Some("policy-1".into()),
        response_type: "vp_token".into(),
        trust_profile_id: None,
        deployment_profile_id: None,
        external_reference: Some("case-1".into()),
        callback_url: None,
        expiry_minutes: 15,
        purpose: "Membership".into(),
    }
}

#[tokio::test]
async fn managed_oid4vp_lifecycle_uses_canonical_policy_and_minimizes_terminal_data() {
    let service = service(true);
    let started = service.start(start_request(), &principal()).await.unwrap();
    let session_id = started["id"].as_str().unwrap();
    let request = service.request_object(session_id).await.unwrap();
    assert_eq!(request["response_type"], "vp_token");
    assert_eq!(request["dcql_query"]["credentials"][0]["id"], "member");

    let completed = service
        .submit(session_id, "raw-vp-token", true)
        .await
        .unwrap();
    assert_eq!(completed["status"], "PASSED");
    assert_eq!(completed["result"]["passed"], true);
    assert_eq!(completed["result"]["claims_satisfied"], json!(["email"]));
    let stored = service.session_record(session_id).await.unwrap();
    let encoded = serde_json::to_string(&stored).unwrap();
    assert!(stored.evaluation_principal_id.is_empty());
    assert_eq!(stored.verified_claims["email"], true);
    assert_eq!(stored.inspection_result, "verified");
    for secret in [
        "raw-vp-token",
        "alice@example.com",
        "must-not-persist",
        "SECRET",
    ] {
        assert!(!encoded.contains(secret), "{secret}");
    }

    let duplicate = service
        .submit(session_id, "raw-vp-token", true)
        .await
        .unwrap();
    assert_eq!(duplicate, completed);
    assert!(matches!(
        service.submit(session_id, "different-token", true).await,
        Err(VerificationError::Conflict(_))
    ));
}

#[tokio::test]
async fn siopv2_has_no_policy_dependency_and_management_is_fail_closed() {
    let service = service(true);
    let mut request = start_request();
    request.response_type = "id_token".into();
    request.presentation_policy_id = None;
    let started = service.start(request, &principal()).await.unwrap();
    let oidc = service
        .request_object(started["id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(oidc["scope"], "openid");
    assert!(oidc.get("dcql_query").is_none());

    assert!(matches!(
        service
            .start(start_request(), &ManagementPrincipal::default())
            .await,
        Err(VerificationError::Unauthorized(_))
    ));
    let mut callback = start_request();
    callback.callback_url = Some("https://callback.example".into());
    assert!(matches!(
        service.start(callback, &principal()).await,
        Err(VerificationError::BadRequest(_))
    ));
}

#[tokio::test]
async fn grpc_adapter_preserves_the_legacy_contract() {
    let service = Arc::new(service(false));
    let grpc = VerificationGrpcService::new(service.clone());
    let missing_principal = grpc
        .start_verification(Request::new(GrpcStartRequest {
            organization_id: "org-1".into(),
            presentation_policy_id: "policy-1".into(),
            purpose: "Membership".into(),
            ..GrpcStartRequest::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(missing_principal.code(), tonic::Code::Unauthenticated);

    let mut start = Request::new(GrpcStartRequest {
        organization_id: "org-1".into(),
        presentation_policy_id: "policy-1".into(),
        purpose: "Membership".into(),
        ..GrpcStartRequest::default()
    });
    start
        .metadata_mut()
        .insert("x-user-id", "user-1".parse().unwrap());
    start
        .metadata_mut()
        .insert("x-organization-id", "org-1".parse().unwrap());
    let response = grpc.start_verification(start).await.unwrap().into_inner();
    assert_eq!(response.status, "pending");
    assert_eq!(response.response_type, "vp_token");
    assert!(response.request_uri.ends_with("/request"));
    assert!(response
        .qr_code_data
        .starts_with("openid4vp://authorize?request_uri="));
    assert_eq!(
        service
            .session_record(&response.session_id)
            .await
            .unwrap()
            .evaluation_principal_id,
        "user-1"
    );

    let mut evaluation = Request::new(GrpcEvaluateRequest {
        vp_token: "header.payload.signature".into(),
        presentation_policy_id: "policy-1".into(),
        nonce: "nonce-1".into(),
        audience: "https://verifier.example".into(),
        ..GrpcEvaluateRequest::default()
    });
    evaluation
        .metadata_mut()
        .insert("x-user-id", "user-1".parse().unwrap());
    let evaluated = grpc
        .evaluate_presentation(evaluation)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(evaluated.decision, "allow");
}

#[tokio::test]
async fn http_adapter_preserves_management_and_public_wallet_boundaries() {
    let app =
        marty_verification_service::http::router(marty_verification_service::http::HttpState {
            service: Arc::new(service(true)),
            runtime: RuntimeState::new(BuildInfo {
                service: "verification".into(),
                version: "test".into(),
                build_revision: "test".into(),
                enabled_features: vec!["native_oid4vp".into()],
            }),
            release_version: "test".into(),
            build_revision: "test".into(),
        });
    let unauthorized = app
        .clone()
        .oneshot(
            HttpRequest::post("/v1/verify")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "organization_id":"org-1",
                        "presentation_policy_id":"policy-1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let started = app
        .clone()
        .oneshot(
            HttpRequest::post("/v1/verify")
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .header("x-organization-id", "org-1")
                .body(Body::from(
                    json!({
                        "organization_id":"org-1",
                        "presentation_policy_id":"policy-1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let started: Value =
        serde_json::from_slice(&to_bytes(started.into_body(), 64 * 1024).await.unwrap()).unwrap();
    let session_id = started["id"].as_str().unwrap();
    let wallet_request = app
        .oneshot(
            HttpRequest::get(format!("/v1/verify/{session_id}/request"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wallet_request.status(), StatusCode::OK);
}

#[test]
fn behavioral_contract_declares_siop_and_transport_parity() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/verification-service-behavior.json"
    ))
    .unwrap();
    let invariants = contract["invariants"].as_array().unwrap();
    assert!(invariants
        .iter()
        .any(|item| item.as_str().unwrap().contains("SIOPv2")));
    assert!(invariants.iter().any(|item| item
        .as_str()
        .unwrap()
        .contains("authenticated initiating principal")));
    assert_eq!(contract["transports"], json!(["http", "grpc"]));
}
