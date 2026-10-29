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
        MmfApprovalAuthorizer, ProviderError, StorePersistence, TemplateProvider,
    },
    store::StoreDocument,
    Applicant, Application, LifecycleStatus,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{Notify, RwLock};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct Templates;

#[async_trait]
impl TemplateProvider for Templates {
    async fn get(&self, _: &str, id: &str) -> Result<ApplicationTemplate, ProviderError> {
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
    app_with_store(StoreDocument::default()).0
}

fn app_with_store(
    store: StoreDocument,
) -> (
    axum::Router,
    Arc<marty_applicant::service::ApplicantService>,
) {
    app_with_issuance(store, "http://127.0.0.1:1".into())
}

fn app_with_issuance(
    store: StoreDocument,
    issuance_url: String,
) -> (
    axum::Router,
    Arc<marty_applicant::service::ApplicantService>,
) {
    app_with_dependencies(
        store,
        issuance_url,
        Arc::new(Flow),
        Arc::new(MemoryPersistence),
    )
}

fn app_with_dependencies(
    store: StoreDocument,
    issuance_url: String,
    flow: Arc<dyn FlowProvider>,
    persistence: Arc<dyn StorePersistence>,
) -> (
    axum::Router,
    Arc<marty_applicant::service::ApplicantService>,
) {
    let service = Arc::new(
        marty_applicant::service::ApplicantService::with_persistence(
            Arc::new(RwLock::new(store)),
            Arc::new(Templates),
            flow,
            Arc::new(MmfApprovalAuthorizer::new().unwrap()),
            Arc::new(Events),
            persistence,
        ),
    );
    let app = router(HttpState {
        service: service.clone(),
        issuance_url,
        issuance_api_key: None,
        client: reqwest::Client::new(),
        management_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap(),
    });
    (app, service)
}

fn withdrawal_store(status: LifecycleStatus) -> StoreDocument {
    let now = chrono::Utc::now();
    let mut applicant = Applicant::new("issuer-org".into(), "holder@example.com".into(), now);
    applicant.id = "applicant-1".into();
    applicant.user_id = Some("user-1".into());
    let application: Application = serde_json::from_value(json!({
        "id":"application-1", "applicant_id":applicant.id,
        "organization_id":"issuer-org", "application_template_id":"template-1",
        "credential_template_id":"credential-template-1", "status":status,
        "created_at":now, "updated_at":now
    }))
    .unwrap();
    StoreDocument {
        applicants: vec![applicant],
        applications: vec![application],
        ..Default::default()
    }
}

#[tokio::test]
async fn claim_rejects_unsupported_options_and_malformed_json_before_mutation() {
    let cases = [
        (
            r#"{"canvas_credentials_consent":true}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            r#"{"canvas_credentials_consent":false}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            r#"{"delivery_destination_ids":["canvas-destination"]}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            r#"{"delivery_destination_ids":[]}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            r#"{"canvas_credentials_consent":null}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            r#"{"arbitrary":"do-not-echo-this-value"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            "[]",
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        (
            "null",
            StatusCode::UNPROCESSABLE_ENTITY,
            "CLAIM_OPTIONS_UNSUPPORTED",
        ),
        ("{", StatusCode::BAD_REQUEST, "INVALID_CLAIM_JSON"),
    ];
    for (request_body, status, code) in cases {
        let before = withdrawal_store(LifecycleStatus::Approved);
        let (app, service) = app_with_store(before.clone());
        let response = app
            .oneshot(
                Request::post("/v1/me/applications/application-1/claim")
                    .header("x-user-id", "user-1")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{request_body}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["detail"]["error"], code);
        assert!(!String::from_utf8_lossy(&body).contains("do-not-echo-this-value"));
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}

#[tokio::test]
async fn claim_checks_holder_ownership_before_reporting_body_errors() {
    for (user, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("other-user"), StatusCode::FORBIDDEN),
    ] {
        let before = withdrawal_store(LifecycleStatus::Approved);
        let (app, service) = app_with_store(before.clone());
        let mut request = Request::post("/v1/me/applications/application-1/claim")
            .header("content-type", "application/json");
        if let Some(user) = user {
            request = request.header("x-user-id", user);
        }
        let response = app
            .oneshot(request.body(Body::from("{")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}

#[tokio::test]
async fn claim_reuses_the_pending_offer_and_reports_real_read_only_capabilities() {
    let reads = Arc::new(AtomicUsize::new(0));
    let observed_reads = reads.clone();
    let issuer = axum::Router::new().route(
        "/v1/issuance/transactions/transaction-1",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let reads = observed_reads.clone();
            async move {
                assert_eq!(headers["x-organization-id"], "issuer-org");
                reads.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"id":"transaction-1", "status":"pending"}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer).await.unwrap() });
    let mut before = withdrawal_store(LifecycleStatus::Offered);
    before.applications[0].claim_state = marty_applicant::ClaimState::OfferReady;
    before.applications[0].system_data = json!({
        "issuance_transaction_id":"transaction-1", "issuance_status":"pending",
        "credential_offer_uri":"openid-credential-offer://canonical-existing-offer",
        "offer_expires_at":(chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
    })
    .as_object()
    .unwrap()
    .clone();
    let (app, service) = app_with_issuance(before.clone(), origin);
    let expected_capabilities = json!({
        "oid4vci_wallet":true, "delivery_destination_selection":false,
        "canvas_credentials_mirror":false, "offer_reuse":"pending_until_consumed_or_expired"
    });
    for body in ["", "{}"] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/me/applications/application-1/claim")
                    .header("x-user-id", "user-1")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            value["credential_offer_uri"],
            "openid-credential-offer://canonical-existing-offer"
        );
        assert_eq!(value["claim_capabilities"], expected_capabilities);
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
    let response = app
        .oneshot(
            Request::get("/v1/me/applications/application-1")
                .header("x-user-id", "user-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(value["claim_capabilities"], expected_capabilities);
    assert_eq!(reads.load(Ordering::SeqCst), 3);
    assert_eq!(
        serde_json::to_value(&*service.store().read().await).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    server.abort();
}

struct ReplacementOffer(IssuanceOffer);

#[async_trait]
impl FlowProvider for ReplacementOffer {
    async fn issue(
        &self,
        _: &Application,
        _: &Applicant,
        _: &Map<String, Value>,
        _: Uuid,
    ) -> Result<IssuanceOffer, ProviderError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct PersistenceCount(AtomicUsize);

impl StorePersistence for PersistenceCount {
    fn persist(&self, _: &StoreDocument) -> Result<(), ProviderError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

async fn reconcile_delayed_transaction(status: &'static str, reissue: bool) {
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let read_entered = entered.clone();
    let read_resume = resume.clone();
    let issuer = axum::Router::new().route(
        "/v1/issuance/transactions/transaction-1",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let entered = read_entered.clone();
            let resume = read_resume.clone();
            async move {
                assert_eq!(headers["x-organization-id"], "issuer-org");
                entered.notify_one();
                resume.notified().await;
                axum::Json(json!({
                    "id":"transaction-1", "status":status,
                    "issued_at":chrono::Utc::now().to_rfc3339()
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer).await.unwrap() });
    let mut initial = withdrawal_store(LifecycleStatus::Offered);
    let expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    initial.applications[0].claim_state = marty_applicant::ClaimState::OfferReady;
    initial.applications[0].system_data = json!({
        "issuance_transaction_id":"transaction-1", "issuance_status":"pending",
        "credential_offer_uri":"openid-credential-offer://old-offer",
        "offer_expires_at":expiry
    })
    .as_object()
    .unwrap()
    .clone();
    let replacement = IssuanceOffer {
        id: Some("transaction-2".into()),
        credential_offer_uri: Some("openid-credential-offer://replacement-offer".into()),
        credential_offer_uris: Map::new(),
        credential_offer_labels: Map::new(),
        expires_at: Some(expiry),
        status: "pending".into(),
        flow_instance_id: Some("replacement-flow-instance".into()),
        flow_definition_id: Some("flow-definition-1".into()),
        source: Some("flow".into()),
    };
    let persistence = Arc::new(PersistenceCount::default());
    let (app, service) = app_with_dependencies(
        initial,
        origin,
        Arc::new(ReplacementOffer(replacement.clone())),
        persistence.clone(),
    );
    let reading = tokio::spawn(
        app.clone().oneshot(
            Request::get("/v1/me/applications/application-1")
                .header("x-user-id", "user-1")
                .body(Body::empty())
                .unwrap(),
        ),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    if reissue {
        let response = app
            .oneshot(
                Request::post("/v1/organizations/issuer-org/applicants/application-1/issue")
                    .header("x-user-id", "operator-1")
                    .header("x-organization-id", "issuer-org")
                    .header("x-org-permissions", "issuance:initiate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            service.store().read().await.applications[0].system_data["issuance_transaction_id"],
            "transaction-2"
        );
    }
    let before = service.store().read().await.clone();
    let writes = persistence.0.load(Ordering::SeqCst);
    resume.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), reading)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    server.abort();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    if reissue {
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
        assert_eq!(persistence.0.load(Ordering::SeqCst), writes);
        assert_eq!(
            value["credential_offer_uri"],
            json!(replacement.credential_offer_uri)
        );
        assert_eq!(value["status"], "OFFERED");
        assert_eq!(value["claim_state"], "OFFER_READY");
        assert!(value["claim_blocker"].is_null());
        assert!(value["issued_at"].is_null());
    } else {
        let current = service.store().read().await;
        assert_eq!(
            current.applications[0].system_data["issuance_transaction_id"],
            "transaction-1"
        );
        assert_eq!(
            current.applications[0].system_data["issuance_status"],
            status
        );
        assert_eq!(persistence.0.load(Ordering::SeqCst), writes + 1);
        if status == "issued" {
            assert_eq!(value["status"], "CREDENTIALED");
            assert_eq!(value["claim_state"], "CLAIMED");
            assert!(current.applications[0].issued_at.is_some());
            assert_eq!(current.applicants[0].status, LifecycleStatus::Credentialed);
        } else {
            assert_eq!(value["status"], "OFFERED");
            assert_eq!(value["claim_state"], "EXPIRED");
            assert_eq!(value["claim_blocker"]["code"], "ISSUANCE_REVOKED");
        }
    }
}

#[tokio::test]
async fn issuance_reconciliation_discards_old_revoked_response_after_reissue() {
    reconcile_delayed_transaction("revoked", true).await;
}

#[tokio::test]
async fn issuance_reconciliation_discards_old_issued_response_after_reissue() {
    reconcile_delayed_transaction("issued", true).await;
}

#[tokio::test]
async fn issuance_reconciliation_applies_current_transaction_responses() {
    for status in ["revoked", "issued"] {
        reconcile_delayed_transaction(status, false).await;
    }
}

#[tokio::test]
async fn withdrawal_routes_preserve_authentication_authority_and_tenant_boundaries() {
    let before = withdrawal_store(LifecycleStatus::Draft);
    let (app, service) = app_with_store(before.clone());
    let organization_path = "/v1/organizations/issuer-org/applicants/application-1/withdraw";
    let cases = [
        (
            organization_path,
            None,
            None,
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            organization_path,
            Some("reviewer-1"),
            Some("issuer-org"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            organization_path,
            Some("reviewer-1"),
            Some("other-org"),
            Some("application:review"),
            StatusCode::FORBIDDEN,
        ),
        (
            "/v1/organizations/other-org/applicants/application-1/withdraw",
            Some("reviewer-1"),
            Some("other-org"),
            Some("application:review"),
            StatusCode::NOT_FOUND,
        ),
        (
            "/v1/me/applications/application-1/withdraw",
            None,
            None,
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/v1/me/applications/application-1/withdraw",
            Some("other-user"),
            None,
            None,
            StatusCode::FORBIDDEN,
        ),
    ];
    for (path, user, organization, permissions, expected) in cases {
        let mut request = Request::post(path).header("content-type", "application/json");
        for (name, value) in [
            ("x-user-id", user),
            ("x-organization-id", organization),
            ("x-org-permissions", permissions),
        ] {
            if let Some(value) = value {
                request = request.header(name, value);
            }
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            expected,
            "{path}, user={user:?}, organization={organization:?}"
        );
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}

#[tokio::test]
async fn withdrawal_routes_return_conflict_for_issuance_without_lifecycle_side_effects() {
    for organization in [false, true] {
        for status in [
            LifecycleStatus::Approved,
            LifecycleStatus::Offered,
            LifecycleStatus::Credentialed,
            LifecycleStatus::Suspended,
        ] {
            let before = withdrawal_store(status);
            let (app, service) = app_with_store(before.clone());
            let path = if organization {
                "/v1/organizations/issuer-org/applicants/application-1/withdraw"
            } else {
                "/v1/me/applications/application-1/withdraw"
            };
            let response = app
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .header("x-user-id", "user-1")
                        .header("x-organization-id", "issuer-org")
                        .header("x-org-permissions", "application:review")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::CONFLICT,
                "organization={organization}, status={status:?}"
            );
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(
                body["detail"],
                "Issuance must be reconciled before withdrawing this application"
            );
            assert_eq!(
                serde_json::to_value(&*service.store().read().await).unwrap(),
                serde_json::to_value(&before).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn offer_retirement_requires_both_scopes_and_matching_issuer_revocation() {
    let revocations = Arc::new(AtomicUsize::new(0));
    let observed = revocations.clone();
    let issuer = axum::Router::new().route(
        "/v1/issuance/transactions/transaction-1/cancel-unissued",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                let observed = observed.clone();
                async move {
                    assert_eq!(headers["x-organization-id"], "issuer-org");
                    assert_eq!(body["application_id"], "application-1");
                    assert_eq!(body["reason"], "Retire synthetic offer");
                    observed.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"id":"transaction-1","status":"revoked"}))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer).await.unwrap() });
    let mut before = withdrawal_store(LifecycleStatus::Offered);
    before.applications[0].claim_state = marty_applicant::ClaimState::OfferReady;
    before.applications[0]
        .system_data
        .insert("issuance_transaction_id".into(), json!("transaction-1"));
    let (app, service) = app_with_issuance(before.clone(), origin);
    let path = "/v1/organizations/issuer-org/applicants/application-1/retire-offer";
    for permissions in ["application:review", "issuance:revoke"] {
        let response = app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .header("x-user-id", "operator-1")
                    .header("x-organization-id", "issuer-org")
                    .header("x-org-permissions", permissions)
                    .body(Body::from(r#"{"reason":"Retire synthetic offer"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(revocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        serde_json::to_value(&*service.store().read().await).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .header("x-user-id", "operator-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review,issuance:revoke")
                .body(Body::from(r#"{"reason":"Retire synthetic offer"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(revocations.load(Ordering::SeqCst), 1);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["status"], "WITHDRAWN");
    assert_eq!(
        service.store().read().await.applications[0].claim_state,
        marty_applicant::ClaimState::Expired
    );
    let retry = app
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .header("x-user-id", "operator-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review,issuance:revoke")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(revocations.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn offer_retirement_rejects_mismatched_revocation_without_local_mutation() {
    let issuer = axum::Router::new().route(
        "/v1/issuance/transactions/transaction-1/cancel-unissued",
        axum::routing::post(|| async {
            axum::Json(json!({"id":"another-transaction","status":"revoked"}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer).await.unwrap() });
    let mut before = withdrawal_store(LifecycleStatus::Offered);
    before.applications[0].claim_state = marty_applicant::ClaimState::OfferReady;
    before.applications[0]
        .system_data
        .insert("issuance_transaction_id".into(), json!("transaction-1"));
    let (app, service) = app_with_issuance(before.clone(), origin);
    let response = app
        .oneshot(
            Request::post("/v1/organizations/issuer-org/applicants/application-1/retire-offer")
                .header("content-type", "application/json")
                .header("x-user-id", "operator-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review,issuance:revoke")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        serde_json::to_value(&*service.store().read().await).unwrap(),
        serde_json::to_value(&before).unwrap()
    );
    server.abort();
}

#[tokio::test]
async fn offer_retirement_refuses_a_replaced_local_offer_after_upstream_cancellation() {
    let service_slot = Arc::new(std::sync::Mutex::new(
        None::<Arc<marty_applicant::service::ApplicantService>>,
    ));
    let callback_slot = service_slot.clone();
    let issuer = axum::Router::new().route(
        "/v1/issuance/transactions/transaction-1/cancel-unissued",
        axum::routing::post(move || {
            let service = callback_slot.lock().unwrap().as_ref().unwrap().clone();
            async move {
                service.store().write().await.applications[0]
                    .system_data
                    .insert(
                        "issuance_transaction_id".into(),
                        json!("replacement-transaction"),
                    );
                axum::Json(json!({"id":"transaction-1","status":"revoked"}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, issuer).await.unwrap() });
    let mut before = withdrawal_store(LifecycleStatus::Offered);
    before.applications[0].claim_state = marty_applicant::ClaimState::OfferReady;
    before.applications[0]
        .system_data
        .insert("issuance_transaction_id".into(), json!("transaction-1"));
    let (app, service) = app_with_issuance(before, origin);
    *service_slot.lock().unwrap() = Some(service.clone());
    let response = app
        .oneshot(
            Request::post("/v1/organizations/issuer-org/applicants/application-1/retire-offer")
                .header("content-type", "application/json")
                .header("x-user-id", "operator-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review,issuance:revoke")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let current = &service.store().read().await.applications[0];
    assert_eq!(current.status, LifecycleStatus::Offered);
    assert_eq!(
        current.system_data["issuance_transaction_id"],
        "replacement-transaction"
    );
    assert!(current
        .system_data
        .get("retired_issuance_transaction_id")
        .is_none());
    server.abort();
}

#[tokio::test]
async fn organization_withdrawal_still_accepts_an_unissued_application_under_review() {
    let (app, service) = app_with_store(withdrawal_store(LifecycleStatus::UnderReview));
    let response = app
        .oneshot(
            Request::post("/v1/organizations/issuer-org/applicants/application-1/withdraw")
                .header("content-type", "application/json")
                .header("x-user-id", "reviewer-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review")
                .body(Body::from(
                    json!({"reason":"Duplicate review request"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["id"], "application-1");
    assert_eq!(body["status"], "WITHDRAWN");
    let state = service.store().read().await;
    assert_eq!(
        state.applications[0].system_data["withdrawal_reason"],
        "Duplicate review request"
    );
    assert_eq!(state.applicants[0].status, LifecycleStatus::Draft);
}

#[tokio::test]
async fn applicant_reads_accept_view_permission_without_review_permission() {
    let app = app();
    let queue = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/organizations/issuer-org/applicants")
                .header("x-user-id", "reader-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:view")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(queue.status(), StatusCode::OK);

    let denied = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/organizations/issuer-org/applicants")
                .header("x-user-id", "reader-1")
                .header("x-organization-id", "issuer-org")
                .header("x-org-permissions", "application:review")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
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
    assert_eq!(released.status(), StatusCode::OK);

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

#[tokio::test]
async fn per_offer_lifetime_does_not_expand_issue_authority_or_tenant_scope() {
    let before = withdrawal_store(LifecycleStatus::Approved);
    let (app, service) = app_with_store(before.clone());
    for (path, user, organization, permissions, expected) in [
        (
            "/v1/organizations/issuer-org/applicants/application-1/issue",
            None,
            None,
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/v1/organizations/issuer-org/applicants/application-1/issue",
            Some("operator"),
            Some("issuer-org"),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "/v1/organizations/issuer-org/applicants/application-1/issue",
            Some("operator"),
            Some("other-org"),
            Some("issuance:initiate"),
            StatusCode::FORBIDDEN,
        ),
        (
            "/v1/organizations/other-org/applicants/application-1/issue",
            Some("operator"),
            Some("other-org"),
            Some("issuance:initiate"),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let mut request = Request::post(path).header("content-type", "application/json");
        for (name, value) in [
            ("x-user-id", user),
            ("x-organization-id", organization),
            ("x-org-permissions", permissions),
        ] {
            if let Some(value) = value {
                request = request.header(name, value);
            }
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::from(r#"{"offer_ttl_seconds":60}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            serde_json::to_value(&*service.store().read().await).unwrap(),
            serde_json::to_value(&before).unwrap()
        );
    }
}
