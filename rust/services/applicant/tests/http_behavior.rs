use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use marty_applicant::{
    http::{router, HttpState},
    issuance::IssuanceOffer,
    service::{
        ApplicationEvent, ApplicationTemplate, EventPublisher, FlowProvider, MemoryPersistence,
        MmfApprovalAuthorizer, ProviderError, TemplateProvider,
    },
    Applicant, Application,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct Templates;

#[async_trait]
impl TemplateProvider for Templates {
    async fn get(&self, id: &str) -> Result<ApplicationTemplate, ProviderError> {
        Ok(ApplicationTemplate {
            id: id.into(),
            organization_id: "issuer-org".into(),
            status: "ACTIVE".into(),
            credential_template_id: "credential-template-1".into(),
            name: Some("Airport badge".into()),
            description: Some("Airport access credential".into()),
            form_fields: Vec::new(),
            required_checks: Vec::new(),
            evidence_requirements: Vec::new(),
            approval_strategy: None,
            application_validity_days: 30,
            claim_collection_rules: Vec::new(),
        })
    }
}

#[derive(Clone)]
struct Flow;

#[async_trait]
impl FlowProvider for Flow {
    async fn issue(
        &self,
        _: &Application,
        _: &Applicant,
        _: &Map<String, Value>,
        _: Uuid,
    ) -> Result<IssuanceOffer, ProviderError> {
        Err(ProviderError::NoActiveFlow)
    }
}

#[derive(Clone)]
struct Events;

#[async_trait]
impl EventPublisher for Events {
    async fn publish(&self, _: &ApplicationEvent) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn app() -> axum::Router {
    let service = marty_applicant::service::ApplicantService::with_persistence(
        Arc::new(RwLock::new(Default::default())),
        Arc::new(Templates),
        Arc::new(Flow),
        Arc::new(MmfApprovalAuthorizer::new().unwrap()),
        Arc::new(Events),
        Arc::new(MemoryPersistence),
    );
    router(HttpState {
        service: Arc::new(service),
        issuance_url: "http://127.0.0.1:1".into(),
        issuance_api_key: None,
        client: reqwest::Client::new(),
    })
}

#[derive(Deserialize)]
struct Contract {
    http_operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Operation {
    method: String,
    path: String,
}

#[tokio::test]
async fn every_language_neutral_operation_is_registered_on_the_native_router() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/applicant-service-behavior.json"
    ))
    .unwrap();
    for operation in contract.http_operations {
        let path = operation
            .path
            .replace("{organization_id}", "issuer-org")
            .replace("{application_id}", "application-1")
            .replace("{evidence_id}", "evidence-1")
            .replace("{check_id}", "check-1");
        let request = Request::builder()
            .method(Method::from_bytes(operation.method.as_bytes()).unwrap())
            .uri(&path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{} {path}",
            operation.method
        );
    }
}

#[tokio::test]
async fn profile_and_application_workflow_preserves_released_http_shapes() {
    let app = app();
    let profile = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/v1/me/applicant-profile")
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .header("x-organization-id", "home-org")
                .body(Body::from(
                    json!({"email":"learner@example.com","given_name":"Ada"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(profile.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["organization_id"], "home-org");
    assert_eq!(body["given_name"], "Ada");
    assert_eq!(body["status"], "DRAFT");

    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/me/applications")
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .header("x-organization-id", "home-org")
                .body(Body::from(
                    json!({
                        "organization_id":"issuer-org",
                        "application_template_id":"application-template-1",
                        "form_data":{},
                        "integration_context":{}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(created.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["organization_id"], "issuer-org");
    assert_eq!(body["claim_state"], "NOT_READY");
    assert_eq!(body["credential_offer_uris"], json!({}));

    let application_id = body["id"].as_str().unwrap();
    let submitted = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/me/applications/{application_id}/submit"))
                .header("content-type", "application/json")
                .header("x-user-id", "user-1")
                .header("x-organization-id", "home-org")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(submitted.status(), StatusCode::OK);

    let competing_lock = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/organizations/issuer-org/applicants/{application_id}/lock"
                ))
                .header("x-user-id", "reviewer-2")
                .header("x-user-email", "reviewer-2@example.com")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(competing_lock.status(), StatusCode::OK);

    let contested_approval = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/organizations/issuer-org/applicants/{application_id}/approve"
                ))
                .header("content-type", "application/json")
                .header("x-user-id", "partner-api-key-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:approve")
                .header("x-request-id", "22222222-2222-4222-8222-222222222222")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(contested_approval.status(), StatusCode::CONFLICT);

    let released = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!(
                    "/v1/organizations/issuer-org/applicants/{application_id}/lock"
                ))
                .header("x-user-id", "reviewer-2")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::NO_CONTENT);

    let approved = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/organizations/issuer-org/applicants/{application_id}/approve"
                ))
                .header("content-type", "application/json")
                .header("x-user-id", "partner-api-key-1")
                .header("x-user-email", "northstar@partner.example")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:approve")
                .header("x-request-id", "11111111-1111-4111-8111-111111111111")
                .body(Body::from(
                    json!({"notes":"Approved by Northstar"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(approved.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["status"], "APPROVED");

    let lock = app
        .oneshot(
            Request::get(format!(
                "/v1/organizations/issuer-org/applicants/{application_id}/lock"
            ))
            .header("x-user-id", "partner-api-key-1")
            .header("x-organization-id", "issuer-org")
            .header("x-org-permissions", "application:review")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lock.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(lock.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["status"], "AVAILABLE");
}

#[tokio::test]
async fn operational_diagnostics_identify_the_required_native_backend() {
    let response = app()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["backend"], "rust");
    assert_eq!(body["service"], "applicant-service");
}
