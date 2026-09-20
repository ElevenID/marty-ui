use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use chrono::{DateTime, TimeZone, Utc};
use http_body_util::BodyExt;
use marty_issuance_service::{
    application_template_domain::{
        ApplicationTemplateCreate, ApplicationTemplateRecord, ApplicationTemplateStatus,
    },
    internal_application_domain::{
        ApplicationCreate, ApplicationRecord, ApplicationStatus, EvidenceFactRecord,
        IssuanceEventRecord,
    },
    internal_application_http,
    internal_application_service::{
        InternalApplicationClock, InternalApplicationIdGenerator, InternalApplicationRepository,
        InternalApplicationRepositoryError, InternalApplicationService,
    },
};
use serde_json::{json, Map, Value};
use tower::ServiceExt;

#[derive(Default)]
struct MemoryState {
    templates: BTreeMap<String, ApplicationTemplateRecord>,
    applications: BTreeMap<String, ApplicationRecord>,
    evidence_facts: Vec<EvidenceFactRecord>,
    issuance_events: Vec<IssuanceEventRecord>,
}

#[derive(Default)]
struct MemoryRepository {
    state: Mutex<MemoryState>,
    reject_compare_and_swap: AtomicBool,
}

impl MemoryRepository {
    fn seed_template(&self, template: ApplicationTemplateRecord) {
        self.state
            .lock()
            .expect("repository state")
            .templates
            .insert(template.id.clone(), template);
    }

    fn seed_application(&self, application: ApplicationRecord) {
        self.state
            .lock()
            .expect("repository state")
            .applications
            .insert(application.id.clone(), application);
    }

    fn seed_evidence_fact(&self, fact: EvidenceFactRecord) {
        self.state
            .lock()
            .expect("repository state")
            .evidence_facts
            .push(fact);
    }

    fn seed_issuance_event(&self, event: IssuanceEventRecord) {
        self.state
            .lock()
            .expect("repository state")
            .issuance_events
            .push(event);
    }
}

#[async_trait]
impl InternalApplicationRepository for MemoryRepository {
    async fn get_application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, InternalApplicationRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .templates
            .get(template_id)
            .cloned())
    }

    async fn insert_application(
        &self,
        application: &ApplicationRecord,
    ) -> Result<(), InternalApplicationRepositoryError> {
        self.state
            .lock()
            .expect("repository state")
            .applications
            .insert(application.id.clone(), application.clone());
        Ok(())
    }

    async fn list_applications(
        &self,
        organization_id: &str,
        status: Option<ApplicationStatus>,
        template_id: Option<&str>,
    ) -> Result<Vec<ApplicationRecord>, InternalApplicationRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .applications
            .values()
            .filter(|application| application.organization_id == organization_id)
            .filter(|application| status.is_none_or(|status| application.status == status))
            .filter(|application| {
                template_id
                    .is_none_or(|template_id| application.application_template_id == template_id)
            })
            .cloned()
            .collect())
    }

    async fn get_application(
        &self,
        application_id: &str,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .applications
            .get(application_id)
            .cloned())
    }

    async fn list_evidence_facts_for_application(
        &self,
        application_id: &str,
    ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .evidence_facts
            .iter()
            .filter(|fact| fact.application_id == application_id)
            .cloned()
            .collect())
    }

    async fn list_events_for_application(
        &self,
        application_id: &str,
    ) -> Result<Vec<IssuanceEventRecord>, InternalApplicationRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .issuance_events
            .iter()
            .filter(|event| event.application_id.as_deref() == Some(application_id))
            .cloned()
            .collect())
    }

    async fn replace_application_if_revision(
        &self,
        application: &ApplicationRecord,
        expected_status: ApplicationStatus,
        expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, InternalApplicationRepositoryError> {
        if self.reject_compare_and_swap.load(Ordering::SeqCst) {
            return Ok(false);
        }
        let mut state = self.state.lock().expect("repository state");
        let Some(stored) = state.applications.get_mut(&application.id) else {
            return Ok(false);
        };
        if stored.organization_id != application.organization_id
            || stored.status != expected_status
            || stored.updated_at != expected_updated_at
        {
            return Ok(false);
        }
        *stored = application.clone();
        Ok(true)
    }
}

struct FixedRuntime;

impl InternalApplicationClock for FixedRuntime {
    fn now(&self) -> DateTime<Utc> {
        fixed_time()
    }
}

impl InternalApplicationIdGenerator for FixedRuntime {
    fn application_id(&self) -> String {
        "application-1".to_owned()
    }

    fn applicant_identifier(&self) -> String {
        "applicant_deadbeef".to_owned()
    }
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
        .single()
        .expect("fixed timestamp")
}

fn template(organization_id: &str, status: ApplicationTemplateStatus) -> ApplicationTemplateRecord {
    let request: ApplicationTemplateCreate = serde_json::from_value(json!({
        "organization_id": organization_id,
        "name": "Employee application"
    }))
    .expect("template request");
    let mut template = request
        .into_record("template-1".to_owned(), fixed_time())
        .expect("template record");
    template.status = status;
    template
}

fn application(id: &str, organization_id: &str, status: ApplicationStatus) -> ApplicationRecord {
    let request = ApplicationCreate {
        application_template_id: "template-1".to_owned(),
        applicant_data: Map::new(),
        integration_context: Map::new(),
    };
    let mut application = ApplicationRecord::new(
        id.to_owned(),
        organization_id.to_owned(),
        request,
        "applicant_deadbeef",
        fixed_time(),
    )
    .expect("application record");
    application.status = status;
    application
}

fn evidence_fact(application_id: &str) -> EvidenceFactRecord {
    EvidenceFactRecord {
        id: "fact-1".to_owned(),
        organization_id: "org-123".to_owned(),
        application_id: application_id.to_owned(),
        subject_id: "ada@example.test".to_owned(),
        provider: "contract-provider".to_owned(),
        fact_type: "identity.document".to_owned(),
        scope: Map::from_iter([("document_type".to_owned(), json!("passport"))]),
        assertion: Map::from_iter([("verified".to_owned(), json!(true))]),
        verification: Map::from_iter([
            ("method".to_owned(), json!("CONTRACT")),
            ("status".to_owned(), json!("VERIFIED")),
        ]),
        source: Map::from_iter([("event_id".to_owned(), json!("event-1"))]),
        requirement_id: Some("requirement-1".to_owned()),
        logical_key: "logical-key-1".to_owned(),
        source_revision: "revision-1".to_owned(),
        payload_hash: "payload-hash-1".to_owned(),
        observed_at: fixed_time(),
        effective_at: Some(fixed_time()),
        superseded_fact_id: Some("fact-0".to_owned()),
        created_at: fixed_time(),
    }
}

fn issuance_event(application_id: &str) -> IssuanceEventRecord {
    IssuanceEventRecord {
        id: "issuance-event-1".to_owned(),
        transaction_id: Some("transaction-1".to_owned()),
        application_id: Some(application_id.to_owned()),
        event_type: "offer_viewed".to_owned(),
        metadata: Map::from_iter([("channel".to_owned(), json!("contract"))]),
        created_at: fixed_time(),
    }
}

fn service(
    repository: Arc<MemoryRepository>,
    management_api_key: Option<&str>,
) -> InternalApplicationService {
    InternalApplicationService::new(
        repository,
        Arc::new(FixedRuntime),
        Arc::new(FixedRuntime),
        management_api_key,
    )
}

async fn request(
    service: &InternalApplicationService,
    method: Method,
    uri: &str,
    body: Option<Value>,
    api_key: Option<&str>,
    organization_id: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }
    if let Some(organization_id) = organization_id {
        builder = builder.header("x-organization-id", organization_id);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let response = internal_application_http::router(service.clone())
        .oneshot(
            builder
                .body(Body::from(
                    body.map(|value| serde_json::to_vec(&value).expect("request JSON"))
                        .unwrap_or_default(),
                ))
                .expect("management request"),
        )
        .await
        .expect("management response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("management response body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("management response JSON")
    };
    (status, body)
}

#[tokio::test]
async fn completed_http_slice_replays_create_read_evidence_and_rejection() {
    let repository = Arc::new(MemoryRepository::default());
    repository.seed_template(template("org-123", ApplicationTemplateStatus::Active));
    let service = service(repository, Some("secret"));

    let (status, created) = request(
        &service,
        Method::POST,
        "/internal/applications",
        Some(json!({
            "application_template_id": "template-1",
            "applicant_data": {"given_name": "Ada", "family_name": "Lovelace"},
            "integration_context": {"source": "contract"},
            "unknown": true
        })),
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["id"], "application-1");
    assert_eq!(created["applicant_identifier"], "Ada_Lovelace");
    assert_eq!(created["status"], "pending");
    assert_eq!(
        created
            .as_object()
            .expect("ApplicationResponse")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "application_template_id",
            "applicant_identifier",
            "evidence_submissions",
            "expires_at",
            "form_data",
            "id",
            "integration_context",
            "issuance_transaction_id",
            "organization_id",
            "review_notes",
            "reviewed_at",
            "reviewer_id",
            "status",
            "submitted_at"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let (status, listed) = request(
        &service,
        Method::GET,
        "/internal/applications?organization_id=org-123&status=pending&application_template_id=template-1",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed, json!([created.clone()]));

    let (status, fetched) = request(
        &service,
        Method::GET,
        "/internal/applications/application-1",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fetched, created);

    let (status, evidenced) = request(
        &service,
        Method::POST,
        "/internal/applications/application-1/submit-evidence",
        Some(json!({
            "evidence_type": "DOCUMENT_SCAN",
            "evidence_data": {"digest": "sha256:1"},
            "unknown": true
        })),
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        evidenced["evidence_submissions"].as_array().unwrap().len(),
        1
    );

    let (status, rejected) = request(
        &service,
        Method::POST,
        "/internal/applications/application-1/reject",
        Some(json!({"review_notes": "Insufficient evidence"})),
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["review_notes"], "Insufficient evidence");
    assert_eq!(rejected["reviewer_id"], "issuance-management-api");
}

#[tokio::test]
async fn authentication_tenant_and_template_failures_match_the_frozen_boundary() {
    let repository = Arc::new(MemoryRepository::default());
    repository.seed_template(template("org-123", ApplicationTemplateStatus::Active));
    let configured = service(repository.clone(), Some("secret"));
    let body = json!({"application_template_id": "template-1", "applicant_data": {}});

    for (api_key, organization_id, expected_status, detail) in [
        (
            None,
            Some("org-123"),
            StatusCode::UNAUTHORIZED,
            "X-API-Key header is missing",
        ),
        (
            Some("wrong"),
            Some("org-123"),
            StatusCode::UNAUTHORIZED,
            "Invalid API Key",
        ),
        (
            Some("secret"),
            None,
            StatusCode::BAD_REQUEST,
            "X-Organization-ID is required for application management",
        ),
    ] {
        let (status, response) = request(
            &configured,
            Method::POST,
            "/internal/applications",
            Some(body.clone()),
            api_key,
            organization_id,
        )
        .await;
        assert_eq!(status, expected_status);
        assert_eq!(response, json!({"detail": detail}));
    }

    let unconfigured = service(repository, None);
    let (status, response) = request(
        &unconfigured,
        Method::POST,
        "/internal/applications",
        Some(body.clone()),
        None,
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response,
        json!({"detail": "ISSUANCE_API_KEY not configured on server"})
    );

    let repository = Arc::new(MemoryRepository::default());
    let missing = service(repository, Some("secret"));
    let (status, response) = request(
        &missing,
        Method::POST,
        "/internal/applications",
        Some(body.clone()),
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        response,
        json!({"detail": "Application template not found"})
    );

    for (organization_id, template_status, expected_status, detail) in [
        (
            "org-123",
            ApplicationTemplateStatus::Draft,
            StatusCode::UNPROCESSABLE_ENTITY,
            "Application template must be active",
        ),
        (
            "org-other",
            ApplicationTemplateStatus::Active,
            StatusCode::NOT_FOUND,
            "Application resource not found",
        ),
    ] {
        let repository = Arc::new(MemoryRepository::default());
        repository.seed_template(template(organization_id, template_status));
        let service = service(repository, Some("secret"));
        let (status, response) = request(
            &service,
            Method::POST,
            "/internal/applications",
            Some(body.clone()),
            Some("secret"),
            Some("org-123"),
        )
        .await;
        assert_eq!(status, expected_status);
        assert_eq!(response, json!({"detail": detail}));
    }
}

#[tokio::test]
async fn list_and_item_boundaries_hide_tenants_and_validate_status() {
    let repository = Arc::new(MemoryRepository::default());
    repository.seed_application(application(
        "application-foreign",
        "org-other",
        ApplicationStatus::Pending,
    ));
    let service = service(repository, Some("secret"));

    let (status, response) = request(
        &service,
        Method::GET,
        "/internal/applications",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response["detail"][0]["loc"],
        json!(["query", "organization_id"])
    );

    let (status, response) = request(
        &service,
        Method::GET,
        "/internal/applications?organization_id=org-other",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        response,
        json!({"detail": "Application resource not found"})
    );

    let (status, response) = request(
        &service,
        Method::GET,
        "/internal/applications?organization_id=org-123&status=not-a-status",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response, json!({"detail": "Invalid application status"}));

    let (status, response) = request(
        &service,
        Method::GET,
        "/internal/applications/application-foreign",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(response, json!({"detail": "Application not found"}));
}

#[tokio::test]
async fn evidence_and_event_reads_match_the_frozen_typed_projections() {
    let repository = Arc::new(MemoryRepository::default());
    let mut template = template("org-123", ApplicationTemplateStatus::Active);
    template.evidence_requirements = vec![json!({
        "evidence_id": "check-1",
        "evidence_type": "EXTERNAL_API",
        "description": "Contract API check",
        "provider": "contract-provider",
        "fact_type": "identity.document",
        "required": true,
        "verification_method": "CONTRACT_API",
        "auto_issue_on_permit": false,
        "scope": {"document_type": "passport"},
        "api": {
            "method": "get",
            "url": "https://provider.example.test/check",
            "secret_headers": {"authorization": "Bearer secret-token"}
        }
    })];
    repository.seed_template(template);
    let mut application = application(
        "application-read",
        "org-123",
        ApplicationStatus::UnderReview,
    );
    application.integration_context = json!({
        "policy": {
            "allowed": true,
            "policy_source": "contract",
            "policy_set_id": "policy-1"
        },
        "canvas": {"course_id": "course-1"}
    })
    .as_object()
    .expect("integration context")
    .clone();
    application.issuance_transaction_id = Some("transaction-1".to_owned());
    repository.seed_application(application);
    repository.seed_evidence_fact(evidence_fact("application-read"));
    repository.seed_issuance_event(issuance_event("application-read"));
    let service = service(repository, Some("secret"));

    let (status, facts) = request(
        &service,
        Method::GET,
        "/internal/applications/application-read/evidence-facts",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(facts[0]["id"], "fact-1");
    assert_eq!(facts[0]["effective_at"], "2026-09-19T12:34:56+00:00");
    assert_eq!(
        facts[0]
            .as_object()
            .expect("EvidenceFactResponse")
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "application_id",
            "assertion",
            "created_at",
            "effective_at",
            "fact_type",
            "id",
            "logical_key",
            "observed_at",
            "organization_id",
            "payload_hash",
            "provider",
            "requirement_id",
            "scope",
            "source",
            "source_revision",
            "subject_id",
            "superseded_fact_id",
            "verification"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let (status, summary) = request(
        &service,
        Method::GET,
        "/internal/applications/application-read/evidence-summary",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["status"], "under_review");
    assert_eq!(summary["evidence_facts"], facts);
    assert_eq!(summary["policy_source"], "contract");
    assert_eq!(summary["policy_set_id"], "policy-1");
    assert_eq!(summary["canvas"], json!({"course_id": "course-1"}));
    assert_eq!(summary["available_api_checks"][0]["check_id"], "check-1");
    assert_eq!(summary["available_api_checks"][0]["api_method"], "GET");
    assert!(summary.to_string().find("secret-token").is_none());
    assert!(summary.to_string().find("provider.example.test").is_none());

    let (status, events) = request(
        &service,
        Method::GET,
        "/internal/applications/application-read/issuance-events",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        events,
        json!([{
            "id": "issuance-event-1",
            "transaction_id": "transaction-1",
            "application_id": "application-read",
            "event_type": "offer_viewed",
            "metadata": {"channel": "contract"},
            "created_at": "2026-09-19T12:34:56+00:00"
        }])
    );

    for path in [
        "/internal/applications/application-read/evidence-facts",
        "/internal/applications/application-read/evidence-summary",
        "/internal/applications/application-read/issuance-events",
    ] {
        let (status, response) = request(
            &service,
            Method::GET,
            path,
            None,
            Some("secret"),
            Some("org-other"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(response, json!({"detail": "Application not found"}));
    }
}

#[tokio::test]
async fn lifecycle_and_revision_conflicts_preserve_exact_public_details() {
    for (operation, status, detail) in [
        (
            "submit-evidence",
            ApplicationStatus::Approved,
            "Cannot submit evidence for application in ApplicationStatus.APPROVED status",
        ),
        (
            "reject",
            ApplicationStatus::Withdrawn,
            "Cannot reject application in ApplicationStatus.WITHDRAWN status",
        ),
    ] {
        let repository = Arc::new(MemoryRepository::default());
        repository.seed_application(application("application-state", "org-123", status));
        let service = service(repository, Some("secret"));
        let body = if operation == "submit-evidence" {
            json!({"evidence_type": "DOCUMENT_SCAN", "evidence_data": {}})
        } else {
            json!({"review_notes": "Rejected"})
        };
        let (status, response) = request(
            &service,
            Method::POST,
            &format!("/internal/applications/application-state/{operation}"),
            Some(body),
            Some("secret"),
            Some("org-123"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response, json!({"detail": detail}));
    }

    for (operation, detail) in [
        (
            "submit-evidence",
            "Application lifecycle changed during evidence submission",
        ),
        ("reject", "Application lifecycle changed during rejection"),
    ] {
        let repository = Arc::new(MemoryRepository::default());
        repository.seed_application(application(
            "application-conflict",
            "org-123",
            ApplicationStatus::Pending,
        ));
        repository
            .reject_compare_and_swap
            .store(true, Ordering::SeqCst);
        let service = service(repository, Some("secret"));
        let body = if operation == "submit-evidence" {
            json!({"evidence_type": "DOCUMENT_SCAN", "evidence_data": {}})
        } else {
            json!({"review_notes": "Rejected"})
        };
        let (status, response) = request(
            &service,
            Method::POST,
            &format!("/internal/applications/application-conflict/{operation}"),
            Some(body),
            Some("secret"),
            Some("org-123"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response, json!({"detail": detail}));
    }
}

#[tokio::test]
async fn auth_preflight_precedes_json_validation_and_siblings_remain_closed() {
    let service = service(Arc::new(MemoryRepository::default()), Some("secret"));
    for (method, path, body) in [
        (Method::GET, "/internal/applications", None),
        (
            Method::POST,
            "/internal/applications",
            Some(json!({"application_template_id": "template-1", "applicant_data": {}})),
        ),
        (Method::GET, "/internal/applications/application-1", None),
        (
            Method::GET,
            "/internal/applications/application-1/evidence-facts",
            None,
        ),
        (
            Method::GET,
            "/internal/applications/application-1/evidence-summary",
            None,
        ),
        (
            Method::POST,
            "/internal/applications/application-1/submit-evidence",
            Some(json!({"evidence_type": "DOCUMENT_SCAN", "evidence_data": {}})),
        ),
        (
            Method::POST,
            "/internal/applications/application-1/reject",
            Some(json!({"review_notes": "Rejected"})),
        ),
        (
            Method::GET,
            "/internal/applications/application-1/issuance-events",
            None,
        ),
    ] {
        let (status, response) = request(
            &service,
            method.clone(),
            path,
            body.clone(),
            None,
            Some("org-123"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(
            response,
            json!({"detail": "X-API-Key header is missing"}),
            "{method} {path}"
        );

        let (status, response) = request(
            &service,
            method.clone(),
            path,
            body.clone(),
            Some("wrong"),
            Some("org-123"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(
            response,
            json!({"detail": "Invalid API Key"}),
            "{method} {path}"
        );

        let (status, response) =
            request(&service, method.clone(), path, body, Some("secret"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert_eq!(
            response,
            json!({"detail": "X-Organization-ID is required for application management"}),
            "{method} {path}"
        );
    }

    let (status, response) = request(
        &service,
        Method::POST,
        "/internal/applications",
        Some(json!({"applicant_data": {}})),
        None,
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(response, json!({"detail": "X-API-Key header is missing"}));

    let (status, _) = request(
        &service,
        Method::POST,
        "/internal/applications",
        Some(json!({"applicant_data": {}})),
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = request(
        &service,
        Method::GET,
        "/v1/applications",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = request(
        &service,
        Method::DELETE,
        "/internal/applications/application-1",
        None,
        Some("secret"),
        Some("org-123"),
    )
    .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}
