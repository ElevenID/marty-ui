use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::{Arc, Mutex},
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
    internal_application_diagnostics::ordinary_issuer_context_dependency_unavailable_diagnostic,
    internal_application_domain::{
        ApplicationRecord, ApplicationStatus, EvidenceFactRecord, IssuanceEventRecord,
    },
    internal_application_http,
    internal_application_service::{
        InternalApplicationApprovalError, InternalApplicationApprover, InternalApplicationClock,
        InternalApplicationIdGenerator, InternalApplicationRepository,
        InternalApplicationRepositoryError, InternalApplicationService,
    },
};
use serde_json::{json, Value};
use tower::ServiceExt;

const API_KEY: &str = "probe-management-key";
const ORGANIZATION_ID: &str = "org-probe";

#[derive(Default)]
struct RepositoryState {
    template: Option<ApplicationTemplateRecord>,
    applications: BTreeMap<String, ApplicationRecord>,
}

#[derive(Default)]
struct MemoryRepository {
    state: Mutex<RepositoryState>,
    fail_template_read: bool,
}

impl MemoryRepository {
    fn with_template(template: ApplicationTemplateRecord) -> Self {
        Self {
            state: Mutex::new(RepositoryState {
                template: Some(template),
                applications: BTreeMap::new(),
            }),
            fail_template_read: false,
        }
    }

    fn unavailable() -> Self {
        Self {
            fail_template_read: true,
            ..Self::default()
        }
    }
}

#[async_trait]
impl InternalApplicationRepository for MemoryRepository {
    async fn get_application_template(
        &self,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, InternalApplicationRepositoryError> {
        if self.fail_template_read {
            return Err(InternalApplicationRepositoryError::Unavailable);
        }
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .template
            .as_ref()
            .filter(|template| template.id == template_id)
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
            .filter(|application| status.is_none_or(|value| application.status == value))
            .filter(|application| {
                template_id.is_none_or(|value| application.application_template_id == value)
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
        _application_id: &str,
    ) -> Result<Vec<EvidenceFactRecord>, InternalApplicationRepositoryError> {
        Ok(Vec::new())
    }

    async fn list_events_for_application(
        &self,
        _application_id: &str,
    ) -> Result<Vec<IssuanceEventRecord>, InternalApplicationRepositoryError> {
        Ok(Vec::new())
    }

    async fn replace_application_if_revision(
        &self,
        _application: &ApplicationRecord,
        _expected_status: ApplicationStatus,
        _expected_updated_at: DateTime<Utc>,
    ) -> Result<bool, InternalApplicationRepositoryError> {
        Ok(false)
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
        "application-probe-1".to_owned()
    }

    fn applicant_identifier(&self) -> String {
        "applicant-probe-fallback".to_owned()
    }
}

struct IssuerUnavailableApprover;

#[async_trait]
impl InternalApplicationApprover for IssuerUnavailableApprover {
    async fn approve(
        &self,
        _application: &ApplicationRecord,
        _template: &ApplicationTemplateRecord,
        _reviewer_id: &str,
        _review_notes: Option<&str>,
    ) -> Result<ApplicationRecord, InternalApplicationApprovalError> {
        Err(InternalApplicationApprovalError::IssuerContextUnavailable)
    }
}

struct CaseResult {
    id: &'static str,
    operation_id: &'static str,
    public_status: u16,
    public_message: String,
    safe_server_diagnostic: String,
}

fn fixed_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 19, 12, 34, 56)
        .single()
        .expect("fixed probe timestamp")
}

fn active_template() -> ApplicationTemplateRecord {
    let request: ApplicationTemplateCreate = serde_json::from_value(json!({
        "organization_id": ORGANIZATION_ID,
        "name": "Probe application"
    }))
    .expect("template request");
    let mut template = request
        .into_record("template-probe-1".to_owned(), fixed_time())
        .expect("template record");
    template.status = ApplicationTemplateStatus::Active;
    template.credential_template_id = Some("credential-template-probe-1".to_owned());
    template
}

fn service(repository: Arc<MemoryRepository>) -> InternalApplicationService {
    InternalApplicationService::new(
        repository,
        Arc::new(FixedRuntime),
        Arc::new(FixedRuntime),
        Some(API_KEY),
    )
}

async fn request(
    service: &InternalApplicationService,
    method: Method,
    uri: &str,
    body: Value,
    api_key: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-organization-id", ORGANIZATION_ID);
    if let Some(api_key) = api_key {
        builder = builder.header("x-api-key", api_key);
    }
    let response = internal_application_http::router(service.clone())
        .oneshot(
            builder
                .body(Body::from(
                    serde_json::to_vec(&body).expect("probe request JSON"),
                ))
                .expect("probe request"),
        )
        .await
        .expect("probe response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("probe response body")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).expect("probe response JSON");
    (status, body)
}

fn response_message(body: &Value) -> String {
    body.get("detail")
        .and_then(Value::as_str)
        .or_else(|| body.get("applicant_identifier").and_then(Value::as_str))
        .map(str::to_owned)
        .unwrap_or_else(|| serde_json::to_string(body).expect("response is JSON"))
}

async fn case(
    id: &'static str,
    operation_id: &'static str,
    service: &InternalApplicationService,
    uri: &str,
    body: Value,
    api_key: Option<&str>,
    safe_server_diagnostic: String,
) -> CaseResult {
    let (status, body) = request(service, Method::POST, uri, body, api_key).await;
    CaseResult {
        id,
        operation_id,
        public_status: status.as_u16(),
        public_message: response_message(&body),
        safe_server_diagnostic,
    }
}

fn observations(cases: Vec<CaseResult>) -> Vec<Value> {
    cases
        .into_iter()
        .flat_map(|case| {
            [
                ("public_status", json!(case.public_status)),
                ("public_message", json!(case.public_message)),
                ("safe_server_diagnostic", json!(case.safe_server_diagnostic)),
            ]
            .map(move |(dimension, value)| {
                serde_json::to_value(BTreeMap::from([
                    ("case_id", json!(case.id)),
                    ("dimension", json!(dimension)),
                    ("id", json!(format!("{}.{}", case.id, dimension))),
                    ("operation_id", json!(case.operation_id)),
                    ("value", value),
                ]))
                .expect("observation fields are JSON values")
            })
        })
        .collect()
}

async fn document() -> String {
    let create_body = json!({
        "application_template_id": "template-probe-1",
        "applicant_data": {
            "given_name": " Ada ",
            "family_name": ["Lovelace"],
            "email": "ignored@example.test"
        },
        "integration_context": {"source": "feature-regression-probe"}
    });

    let repository = Arc::new(MemoryRepository::with_template(active_template()));
    let base_service = service(repository);
    let success = case(
        "create-success",
        "internal-application.create",
        &base_service,
        "/internal/applications",
        create_body.clone(),
        Some(API_KEY),
        String::new(),
    )
    .await;
    let auth = case(
        "auth-missing",
        "internal-application.create",
        &base_service,
        "/internal/applications",
        create_body.clone(),
        None,
        String::new(),
    )
    .await;
    let missing_template = case(
        "template-missing",
        "internal-application.create",
        &service(Arc::new(MemoryRepository::default())),
        "/internal/applications",
        create_body.clone(),
        Some(API_KEY),
        String::new(),
    )
    .await;
    let repository_failure = case(
        "repository-unavailable",
        "internal-application.create",
        &service(Arc::new(MemoryRepository::unavailable())),
        "/internal/applications",
        create_body,
        Some(API_KEY),
        String::new(),
    )
    .await;

    let approval_service = base_service.with_approver(Arc::new(IssuerUnavailableApprover));
    let diagnostic =
        ordinary_issuer_context_dependency_unavailable_diagnostic("application-probe-1")
            .safe_server_diagnostic();
    let issuer_failure = case(
        "issuer-context-unavailable",
        "internal-application.approve",
        &approval_service,
        "/internal/applications/application-probe-1/approve",
        json!({"review_notes": "feature regression probe"}),
        Some(API_KEY),
        diagnostic,
    )
    .await;

    let root = BTreeMap::from([
        (
            "observations",
            json!(observations(vec![
                success,
                auth,
                missing_template,
                repository_failure,
                issuer_failure,
            ])),
        ),
        ("schema", json!("elevenid.behavior-subject-output/v2")),
    ]);
    serde_json::to_string(&root).expect("probe output is serializable")
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    io::stdout()
        .write_all(document().await.as_bytes())
        .expect("write probe output");
}
