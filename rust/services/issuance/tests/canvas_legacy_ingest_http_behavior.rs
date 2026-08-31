use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    canvas_award_candidate_approval::{CanvasAwardApprovalSeed, CanvasAwardApprovalSeedGenerator},
    canvas_legacy_ingest::{
        CanvasEvidenceEvent, CanvasEvidenceEventResponse, CanvasLegacyApplicationSnapshot,
        CanvasLegacyCommit, CanvasLegacyCommitOutcome, CanvasLegacyIdGenerator,
        CanvasLegacyIngestConfig, CanvasLegacyIngestError, CanvasLegacyIngestRepository,
        CanvasLegacyIngestService, CanvasLegacyIngestSnapshot, CanvasLegacyRepositoryError,
        CanvasLegacyStoredReceipt,
    },
    canvas_lti_launch::CanvasLtiClock,
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
    http::router_with_canvas_legacy_ingest,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "legacy-webhook-secret";

struct Repository {
    calls: AtomicUsize,
}

#[async_trait]
impl CanvasLegacyIngestRepository for Repository {
    async fn load(
        &self,
        _event: &CanvasEvidenceEvent,
        _payload_hash: &str,
    ) -> Result<Option<CanvasLegacyIngestSnapshot>, CanvasLegacyRepositoryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(CanvasLegacyIngestSnapshot::New(Box::new(snapshot()))))
    }

    async fn replay(
        &self,
        _event: &CanvasEvidenceEvent,
        _payload_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<CanvasLegacyStoredReceipt, CanvasLegacyIngestError> {
        Err(CanvasLegacyIngestError::RepositoryUnavailable)
    }

    async fn commit(
        &self,
        _snapshot: &CanvasLegacyApplicationSnapshot,
        commit: &CanvasLegacyCommit,
    ) -> Result<CanvasLegacyCommitOutcome, CanvasLegacyIngestError> {
        Ok(CanvasLegacyCommitOutcome::Created(Box::new(
            CanvasEvidenceEventResponse {
                id: commit.event.canvas_event_id.clone(),
                application_id: commit.event.application_id.clone(),
                organization_id: commit.event.organization_id.clone().unwrap_or_default(),
                canvas_account_id: commit.event.canvas_account_id.clone(),
                evidence_type: commit.event.evidence_type.clone(),
                status: "evidence_received".to_owned(),
                application_status: Some("pending".to_owned()),
                source_event_id: commit.event.canvas_event_id.clone(),
                replayed: false,
                evidence: commit.evidence.clone(),
                mip_primitives: commit.mip_primitives.clone(),
                evidence_facts: vec![commit.safe_fact.clone()],
                policy_decision: commit.policy_decision.clone(),
            },
        )))
    }
}

struct Resolver;

#[async_trait]
impl IssuerContextResolver for Resolver {
    async fn resolve(
        &self,
        _transaction: &CredentialTransaction,
        _credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        Err(CredentialIssuanceError::IssuerUnavailable(
            "not used by non-auto test".to_owned(),
        ))
    }
}

struct Seeds;

impl CanvasAwardApprovalSeedGenerator for Seeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        CanvasAwardApprovalSeed {
            transaction_id: "transaction-1".to_owned(),
            pre_authorized_code: "private-code".to_owned(),
        }
    }
}

struct Ids;

impl CanvasLegacyIdGenerator for Ids {
    fn receipt_id(&self) -> String {
        "receipt-1".to_owned()
    }

    fn fact_id(&self) -> String {
        "fact-1".to_owned()
    }
}

struct Clock;

impl CanvasLtiClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0)
            .single()
            .expect("time")
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object")
}

fn snapshot() -> CanvasLegacyApplicationSnapshot {
    CanvasLegacyApplicationSnapshot {
        application: object(json!({
            "id":"application-1","organization_id":"org-1",
            "application_template_id":"application-template-1",
            "applicant_identifier":"learner@example.edu","form_data":{},
            "integration_context":{},"status":"pending"
        })),
        application_template: Some(object(json!({
            "id":"application-template-1","organization_id":"org-1",
            "credential_template_id":"credential-template-1","status":"active"
        }))),
        platform: object(json!({"id":"platform-1","organization_id":"org-1"})),
        binding: object(json!({
            "id":"binding-1","organization_id":"org-1","platform_id":"platform-1",
            "application_template_id":"application-template-1",
            "credential_template_id":"credential-template-1",
            "auto_approve_on_evidence":false,
            "feature_flags":{
                "enable_canvas_evidence":true,"enable_canvas_ags":true,"enable_canvas_nrps":true
            },
            "evidence_requirements":[
                "canvas.course_completion","canvas.assignment_score","canvas.nrps_membership"
            ],
            "delivery_mode":"wallet_only"
        })),
        evidence_facts: Vec::new(),
        policy_set: None,
        existing_transaction: None,
    }
}

fn app(enabled: bool, repository: Arc<Repository>) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_legacy_ingest(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.edu", "Issuer"),
        TransportPolicy::new(Vec::new()),
        CanvasLegacyIngestService::new(
            repository,
            Arc::new(Resolver),
            Arc::new(Seeds),
            Arc::new(Ids),
            Arc::new(Clock),
            CanvasLegacyIngestConfig {
                enabled,
                shared_secret: Some(SECRET.to_owned()),
                shared_secret_file: None,
                signature_tolerance_seconds: 300,
            },
        ),
    )
}

fn signed_request(path: &str, body: Vec<u8>) -> Request<Body> {
    let timestamp = Clock.now().timestamp().to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("HMAC key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&body);
    Request::post(path)
        .header("content-type", "application/json")
        .header("x-canvas-timestamp", timestamp)
        .header(
            "x-canvas-signature-256",
            format!("sha256={}", hex::encode(mac.finalize().into_bytes())),
        )
        .body(Body::from(body))
        .expect("request")
}

fn evidence_payload(extension_size: usize) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "canvas_event_id":"event-1","application_id":"application-1",
        "canvas_account_id":"account-1","canvas_course_id":"course-1",
        "canvas_course_name":"Course","canvas_enrollment_id":"enrollment-1",
        "canvas_user_id":"user-1","learner_email":"learner@example.edu",
        "achievement_name":"Completed","completion_at":"2026-08-31T12:00:00Z",
        "extension":"x".repeat(extension_size)
    }))
    .expect("payload")
}

fn ags_payload() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "canvas_event_id":"ags-event-1","application_id":"application-1",
        "canvas_account_id":"account-1","canvas_course_id":"course-1",
        "canvas_user_id":"user-1","canvas_enrollment_id":"enrollment-1",
        "canvas_assignment_id":"assignment-1","line_item_id":"line-item-1",
        "score":8.0,"score_maximum":10.0,"activity_progress":"Completed",
        "grading_progress":"FullyGraded","learner_email":"learner@example.edu",
        "timestamp":"2026-08-31T12:00:00Z"
    }))
    .expect("AGS payload")
}

fn nrps_payload() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "canvas_event_id":"nrps-event-1","application_id":"application-1",
        "canvas_account_id":"account-1","canvas_course_id":"course-1",
        "canvas_user_id":"user-1","canvas_enrollment_id":"enrollment-1",
        "roles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        "status":"Active","learner_email":"learner@example.edu",
        "timestamp":"2026-08-31T12:00:00Z"
    }))
    .expect("NRPS payload")
}

#[tokio::test]
async fn disabled_switch_wins_before_malformed_and_oversized_body_extraction() {
    let repository = Arc::new(Repository {
        calls: AtomicUsize::new(0),
    });
    let response = app(false, repository.clone())
        .oneshot(
            Request::post("/v1/integrations/canvas/evidence-events")
                .body(Body::from(vec![b'x'; 11 * 1024 * 1024]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::GONE);
    assert!(response.headers().get("deprecation").is_none());
    assert!(response.headers().get("sunset").is_none());
    assert!(response.headers().get("link").is_none());
    assert_eq!(repository.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body")
        )
        .expect("json"),
        json!({"detail":"Legacy Canvas event ingestion is disabled; use portable synchronization"})
    );
}

#[tokio::test]
async fn enabled_errors_have_no_deprecation_headers_and_keep_route_shapes() {
    let repository = Arc::new(Repository {
        calls: AtomicUsize::new(0),
    });
    for (path, expected) in [
        (
            "/v1/integrations/canvas/evidence-events",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "/v1/integrations/canvas/ags/score-events",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/v1/integrations/canvas/nrps/membership-events",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app(true, repository.clone())
            .oneshot(signed_request(path, b"[]".to_vec()))
            .await
            .expect("response");
        assert_eq!(response.status(), expected);
        assert!(response.headers().get("deprecation").is_none());
        assert!(response.headers().get("sunset").is_none());
        assert!(response.headers().get("link").is_none());
    }
    let response = app(true, repository)
        .oneshot(
            Request::post("/v1/integrations/canvas/evidence-events")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("deprecation").is_none());
}

#[tokio::test]
async fn successful_large_body_gets_only_the_frozen_success_headers() {
    let repository = Arc::new(Repository {
        calls: AtomicUsize::new(0),
    });
    let response = app(true, repository.clone())
        .oneshot(signed_request(
            "/v1/integrations/canvas/evidence-events",
            evidence_payload(70 * 1024),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["deprecation"], "true");
    assert_eq!(
        response.headers()["sunset"],
        "Wed, 14 Oct 2026 00:00:00 GMT"
    );
    assert_eq!(
        response.headers()["link"],
        "</docs/canvas-portable-integration>; rel=\"deprecation\""
    );
    assert_eq!(repository.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ags_and_nrps_adapters_return_success_with_only_shared_deprecation_headers() {
    let repository = Arc::new(Repository {
        calls: AtomicUsize::new(0),
    });
    for (path, payload, expected_type) in [
        (
            "/v1/integrations/canvas/ags/score-events",
            ags_payload(),
            "canvas.assignment_score",
        ),
        (
            "/v1/integrations/canvas/nrps/membership-events",
            nrps_payload(),
            "canvas.nrps_membership",
        ),
    ] {
        let response = app(true, repository.clone())
            .oneshot(signed_request(path, payload))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["deprecation"], "true");
        assert_eq!(
            response.headers()["sunset"],
            "Wed, 14 Oct 2026 00:00:00 GMT"
        );
        assert!(response.headers().get("link").is_none());
        let body = serde_json::from_slice::<Value>(
            &to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["evidence_type"], expected_type);
        assert_eq!(body["status"], "evidence_received");
        assert_eq!(body["replayed"], false);
    }
    assert_eq!(repository.calls.load(Ordering::SeqCst), 2);
}
