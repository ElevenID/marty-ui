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
    application_issuance::{ApplicationClock, ApprovalSeed, ApprovalSeedGenerator},
    application_template_domain::{
        ApplicationTemplateCreate, ApplicationTemplateRecord, ApplicationTemplateStatus,
    },
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
    internal_application_approval::{
        InternalApplicationApprovalDependencies, InternalApplicationApprovalRepository,
        InternalApplicationCredentialTemplate, OrdinaryInternalApplicationApprover,
    },
    internal_application_domain::{
        ApplicationRecord, ApplicationStatus, EvidenceFactRecord, IssuanceEventRecord,
    },
    internal_application_http,
    internal_application_service::{
        InternalApplicationApprovalError, InternalApplicationClock, InternalApplicationIdGenerator,
        InternalApplicationRepository, InternalApplicationRepositoryError,
        InternalApplicationService,
    },
    observe_internal_application_diagnostics,
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

#[async_trait]
impl InternalApplicationApprovalRepository for MemoryRepository {
    async fn reserve_ordinary_approval(
        &self,
        application: &ApplicationRecord,
        transaction: &CredentialTransaction,
        reviewer_id: &str,
        review_notes: Option<&str>,
        reviewed_at: DateTime<Utc>,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError> {
        let mut approved = application.clone();
        approved
            .approve_reserved(
                transaction.id.clone(),
                review_notes.map(str::to_owned),
                reviewer_id,
                reviewed_at,
            )
            .map_err(|_| InternalApplicationApprovalError::Unavailable)?;
        self.state
            .lock()
            .expect("repository state")
            .applications
            .insert(approved.id.clone(), approved.clone());
        Ok(Some(approved))
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

impl ApplicationClock for FixedRuntime {
    fn now(&self) -> DateTime<Utc> {
        fixed_time()
    }
}

struct FixedApprovalDependencies;

#[async_trait]
impl InternalApplicationApprovalDependencies for FixedApprovalDependencies {
    async fn credential_template(
        &self,
        _template_id: &str,
    ) -> Result<Option<InternalApplicationCredentialTemplate>, InternalApplicationApprovalError>
    {
        Ok(Some(InternalApplicationCredentialTemplate {
            organization_id: ORGANIZATION_ID.to_owned(),
            status: "ACTIVE".to_owned(),
            credential_type: "ProbeCredential".to_owned(),
            vct: Some("https://credentials.probe.invalid/internal-application".to_owned()),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".to_owned(),
            revocation_profile_id: None,
            wallet_configs: Vec::new(),
            selective_disclosure_claims: vec!["email".to_owned()],
            zk_predicate_claims: Vec::new(),
            validity_days: 30,
            renewable: false,
            renewal_window_days: 7,
            issuer_did: "did:web:issuer.probe.invalid".to_owned(),
            issuer_algorithm: "ES256".to_owned(),
        }))
    }

    async fn validate_revocation_profile(
        &self,
        _organization_id: &str,
        _profile_id: Option<&str>,
    ) -> Result<(), InternalApplicationApprovalError> {
        Ok(())
    }
}

struct FailingIssuerContextResolver;

#[async_trait]
impl IssuerContextResolver for FailingIssuerContextResolver {
    async fn resolve(
        &self,
        _transaction: &CredentialTransaction,
        _credential_format: &str,
        _force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        Err(CredentialIssuanceError::RepositoryUnavailable)
    }
}

struct FixedApprovalSeeds;

impl ApprovalSeedGenerator for FixedApprovalSeeds {
    fn generate(&self) -> ApprovalSeed {
        ApprovalSeed {
            transaction_id: "transaction-probe-1".to_owned(),
            pre_authorized_code: "pre-authorized-code-probe-1".to_owned(),
        }
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
) -> CaseResult {
    let ((status, body), diagnostics) = observe_internal_application_diagnostics(request(
        service,
        Method::POST,
        uri,
        body,
        api_key,
    ))
    .await;
    let safe_server_diagnostic = match diagnostics.as_slice() {
        [] => String::new(),
        [diagnostic] => diagnostic.clone(),
        _ => panic!("one HTTP request emitted multiple operational diagnostics"),
    };
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
        "integration_context": {}
    });

    let repository = Arc::new(MemoryRepository::with_template(active_template()));
    let base_service = service(repository.clone());
    let success = case(
        "create-success",
        "internal-application.create",
        &base_service,
        "/internal/applications",
        create_body.clone(),
        Some(API_KEY),
    )
    .await;
    let auth = case(
        "auth-missing",
        "internal-application.create",
        &base_service,
        "/internal/applications",
        create_body.clone(),
        None,
    )
    .await;
    let missing_template = case(
        "template-missing",
        "internal-application.create",
        &service(Arc::new(MemoryRepository::default())),
        "/internal/applications",
        create_body.clone(),
        Some(API_KEY),
    )
    .await;
    let repository_failure = case(
        "repository-unavailable",
        "internal-application.create",
        &service(Arc::new(MemoryRepository::unavailable())),
        "/internal/applications",
        create_body,
        Some(API_KEY),
    )
    .await;

    let approval_service =
        base_service.with_approver(Arc::new(OrdinaryInternalApplicationApprover::new(
            repository,
            Arc::new(FixedApprovalDependencies),
            Arc::new(FailingIssuerContextResolver),
            Arc::new(FixedApprovalSeeds),
            Arc::new(FixedRuntime),
            "https://issuer.probe.invalid",
            30,
        )));
    let issuer_failure = case(
        "issuer-context-unavailable",
        "internal-application.approve",
        &approval_service,
        "/internal/applications/application-probe-1/approve",
        json!({"review_notes": "feature regression probe"}),
        Some(API_KEY),
    )
    .await;

    let mut observed = observations(vec![
        success,
        auth,
        missing_template,
        repository_failure,
        issuer_failure,
    ]);
    observed.extend(configuration_observations());
    let root = BTreeMap::from([
        ("observations", json!(observed)),
        ("schema", json!("elevenid.behavior-subject-output/v2")),
    ]);
    // Production dependencies may enable serde_json's preserve_order feature.
    // Canonical output must sort nested result objects as well as the root.
    let mut document = serde_json::to_value(root).expect("probe output is JSON");
    document.sort_all_objects();
    serde_json::to_string(&document).expect("probe output is serializable")
}

// These library boundaries have no HTTP status or browser message. Record that
// absence explicitly; the diagnostic value is projected from the real result.
// Never replace the returned result with an expected contract fixture.
fn configuration_case(id: &str, operation: &str, result: Value) -> Vec<Value> {
    [
        ("public_status", json!("not_exposed")),
        ("public_message", json!("not_exposed")),
        ("safe_server_diagnostic", result),
    ]
    .into_iter()
    .map(|(dimension, value)| {
        serde_json::to_value(BTreeMap::from([
            ("case_id", json!(id)),
            ("dimension", json!(dimension)),
            ("id", json!(format!("{id}.{dimension}"))),
            ("operation_id", json!(operation)),
            ("value", value),
        ]))
        .expect("configuration observation is JSON")
    })
    .collect()
}

fn configuration_observations() -> Vec<Value> {
    let mut observed = Vec::new();
    for (id, values) in [
        ("auth-missing-realm", BTreeMap::new()),
        (
            "auth-invalid-provider",
            BTreeMap::from([("OIDC_PROVIDER_MODE".into(), "unsupported".into())]),
        ),
    ] {
        let result = match marty_auth::oidc_config_from_values(values) {
            Ok(_) => json!({"result": "accepted"}),
            Err(error) => json!({"result": "rejected", "error": error.to_string()}),
        };
        observed.extend(configuration_case(id, "auth.oidc-configuration", result));
    }
    observed.extend(configuration_case(
        "auth-pkce-s256",
        "auth.pkce",
        json!({"challenge": marty_auth::pkce_s256_challenge(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )}),
    ));

    let baseline = BTreeMap::from([
        ("ENVIRONMENT".into(), "test".into()),
        (
            "DATABASE_URL".into(),
            "postgresql://database.invalid/qualification".into(),
        ),
        ("REDIS_URL".into(), "redis://cache.invalid:6379/3".into()),
        ("FLOW_DATABASE_MAX_CONNECTIONS".into(), "2".into()),
    ]);
    for (id, setting, value) in [
        ("flow-pool-two", "FLOW_DATABASE_MAX_CONNECTIONS", Some("2")),
        ("flow-pool-zero", "FLOW_DATABASE_MAX_CONNECTIONS", Some("0")),
        ("flow-missing-database", "DATABASE_URL", None),
        ("flow-missing-redis", "REDIS_URL", None),
        ("flow-invalid-redis-database", "REDIS_DB_FLOW", Some("256")),
    ] {
        let mut values = baseline.clone();
        if let Some(value) = value {
            values.insert(setting.into(), value.into());
        } else {
            values.remove(setting);
        }
        let result = match marty_flow::FlowServiceConfig::from_values(values) {
            Ok(config) => json!({"result": "accepted",
                "database_max_connections": config.database_max_connections,
                "redis_database": config.redis_database}),
            Err(error) => json!({"result": "rejected", "error": error.to_string()}),
        };
        observed.extend(configuration_case(id, "flow.configuration", result));
    }
    observed
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    io::stdout()
        .write_all(document().await.as_bytes())
        .expect("write probe output");
}
