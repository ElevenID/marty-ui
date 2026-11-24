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
    observed.extend(auth_baseline::observations().await);
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

// The application and HTTP router are real production owners. Only persistence,
// identity-provider transport and provisioning are isolated fixture ports. This
// observes orchestration and HTTP behavior, not live-provider or JWT parity.
mod auth_baseline {
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{header, Method, Request},
        Router,
    };
    use chrono::{Duration, Utc};
    use http_body_util::BodyExt;
    use marty_auth::*;
    use serde_json::{json, Value};
    use std::{
        collections::BTreeMap,
        fmt::Debug,
        sync::{Arc, Mutex},
    };
    use tower::ServiceExt;
    use tracing::{
        field::{Field, Visit},
        Event, Subscriber,
    };
    use tracing_subscriber::{layer::Context, prelude::*, Layer};

    const UI: &str = "https://console.probe.invalid";
    const PRIVATE_DETAIL: &str = "private-auth-probe-dependency-detail";

    #[derive(Default)]
    struct Ports {
        mode: Mutex<&'static str>,
        sessions: Mutex<BTreeMap<String, Session>>,
        states: Mutex<BTreeMap<String, PkceState>>,
        authorization: Mutex<Option<OidcAuthorizationRequest>>,
        events: Mutex<Vec<AuthEvent>>,
    }
    impl Ports {
        fn fails(&self, stage: &str) -> bool {
            *self.mode.lock().unwrap() == stage
        }
        fn check(&self, stage: &str) -> Result<(), PortError> {
            if self.fails(stage) {
                Err(PortError::new("fixture_dependency", PRIVATE_DETAIL))
            } else {
                Ok(())
            }
        }
        fn set(&self, mode: &'static str) {
            *self.mode.lock().unwrap() = mode;
        }
    }
    #[async_trait]
    impl SessionRepository for Ports {
        async fn save(&self, value: &Session) -> Result<(), PortError> {
            self.check("session_save")?;
            self.sessions
                .lock()
                .unwrap()
                .insert(value.session_id.clone(), value.clone());
            Ok(())
        }
        async fn get(&self, id: &str) -> Result<Option<Session>, PortError> {
            self.check("session_get")?;
            Ok(self.sessions.lock().unwrap().get(id).cloned())
        }
        async fn delete(&self, id: &str) -> Result<(), PortError> {
            self.sessions.lock().unwrap().remove(id);
            Ok(())
        }
        async fn get_by_user(&self, user: &str) -> Result<Vec<Session>, PortError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.user.user_id == user)
                .cloned()
                .collect())
        }
        async fn delete_all_for_user(&self, user: &str) -> Result<usize, PortError> {
            let mut sessions = self.sessions.lock().unwrap();
            let before = sessions.len();
            sessions.retain(|_, s| s.user.user_id != user);
            Ok(before - sessions.len())
        }
    }
    #[async_trait]
    impl PkceStateRepository for Ports {
        async fn save(&self, state: &PkceState) -> Result<(), PortError> {
            self.check("state_save")?;
            self.states
                .lock()
                .unwrap()
                .insert(state.state.clone(), state.clone());
            Ok(())
        }
        async fn take(&self, id: &str) -> Result<Option<PkceState>, PortError> {
            self.check("state_take")?;
            Ok(self.states.lock().unwrap().remove(id))
        }
    }
    #[async_trait]
    impl OidcProvider for Ports {
        fn capabilities(&self) -> Result<OidcProviderCapabilities, PortError> {
            Ok(OidcProviderCapabilities {
                provider_mode: "external",
                provider_name: "Probe identity".into(),
                registration_supported: !self.fails("registration_disabled"),
                account_url: None,
                recovery_url: None,
                passkey_enrollment_supported: false,
                provider_logout_supported: true,
            })
        }
        fn authorization_url(
            &self,
            request: &OidcAuthorizationRequest,
        ) -> Result<String, PortError> {
            self.check("authorization_url")?;
            if request.registration && self.fails("registration_disabled") {
                return Err(PortError::new(
                    "oidc_registration_unsupported",
                    PRIVATE_DETAIL,
                ));
            }
            *self.authorization.lock().unwrap() = Some(request.clone());
            Ok("https://identity.probe.invalid/authorize".into())
        }
        async fn exchange_code(
            &self,
            request: &OidcCodeExchange,
        ) -> Result<OidcTokenSet, PortError> {
            self.check("exchange")?;
            let authorization = self.authorization.lock().unwrap();
            let original = authorization.as_ref().unwrap();
            assert_eq!(
                pkce_s256_challenge(&request.code_verifier),
                original.code_challenge
            );
            assert_eq!(request.redirect_uri, original.redirect_uri);
            Ok(OidcTokenSet {
                access_token: if self.fails("missing_access") {
                    String::new()
                } else {
                    "probe-access-secret".into()
                },
                id_token: (!self.fails("missing_id")).then(|| "probe-id-secret".into()),
                refresh_token: Some("probe-refresh-secret".into()),
            })
        }
        async fn validate_tokens(
            &self,
            id: &str,
            access: &str,
            nonce: &str,
        ) -> Result<OidcValidatedIdentity, PortError> {
            self.check("validate")?;
            assert_eq!(id, "probe-id-secret");
            assert_eq!(access, "probe-access-secret");
            assert_eq!(
                nonce,
                self.authorization.lock().unwrap().as_ref().unwrap().nonce
            );
            let claims = json!({"sub":"probe-auth-user","email":"fixture@example.invalid","email_verified":true});
            Ok(OidcValidatedIdentity {
                user_info: OidcUserInfo::from_claims(&claims, None),
                id_token_claims: claims,
                access_token_claims: json!({"sub":"probe-auth-user"}),
            })
        }
        fn logout_url(&self, _request: &OidcLogoutRequest) -> Result<Option<String>, PortError> {
            Ok(Some("https://identity.probe.invalid/logout".into()))
        }
    }
    #[async_trait]
    impl UserProvisioner for Ports {
        async fn provision(
            &self,
            _identity: &OidcValidatedIdentity,
        ) -> Result<AuthenticatedUser, PortError> {
            self.check("provision")?;
            Ok(serde_json::from_value(
                json!({"user_id":"probe-auth-user","email":"fixture@example.invalid"}),
            )
            .unwrap())
        }
    }
    #[async_trait]
    impl AuthEventPublisher for Ports {
        async fn publish(&self, event: &AuthEvent) -> Result<(), PortError> {
            match event {
                AuthEvent::UserAuthenticated { .. } => self.check("login_event")?,
                AuthEvent::SessionCreated { .. } => self.check("session_event")?,
                _ => {}
            }
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }
    struct UnusedCredentialLogin;
    #[async_trait]
    impl CredentialLoginHttpService for UnusedCredentialLogin {
        async fn start_login(&self) -> Result<CredentialLoginStartResult, CredentialHttpError> {
            unreachable!("not a credential-login probe")
        }
        async fn poll_login(
            &self,
            _nonce: &str,
        ) -> Result<CredentialLoginPoll, CredentialHttpError> {
            unreachable!("not a credential-login probe")
        }
        async fn finalize_login(
            &self,
            _nonce: &str,
        ) -> Result<Option<CredentialLoginCompletion>, CredentialHttpError> {
            unreachable!("not a credential-login probe")
        }
        async fn verified_callback(
            &self,
            _payload: &CredentialVerifiedPayload,
            _headers: &CredentialCallbackHeaders,
            _context: &CredentialCallbackContext,
        ) -> Result<CredentialCallbackResult, CredentialHttpError> {
            unreachable!("not a credential-login probe")
        }
    }
    struct Codes(Vec<String>);
    impl Visit for Codes {
        fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
            if field.name() == "error_code" {
                self.0.push(format!("{value:?}"));
            }
        }
    }
    struct Diagnostics(Arc<Mutex<Vec<String>>>);
    impl<S: Subscriber> Layer<S> for Diagnostics {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            if event.metadata().target().starts_with("marty_auth::") {
                let mut codes = Codes(Vec::new());
                event.record(&mut codes);
                self.0.lock().unwrap().extend(codes.0);
            }
        }
    }
    fn router(ports: Arc<Ports>) -> Router {
        let application = AuthApplication::new(
            AuthApplicationPorts {
                passkey_email: None,
                sessions: ports.clone(),
                pkce_states: ports.clone(),
                oidc: ports.clone(),
                provisioner: ports.clone(),
                events: ports.clone(),
                audit: None,
            },
            AuthApplicationConfig {
                passkeys_enabled: false,
                passkey_client_id: "probe-client".into(),
                session_ttl_seconds: 3600,
                post_logout_redirect_uri: format!("{UI}/"),
            },
        );
        auth_core_router(AuthHttpState {
            application: Arc::new(application),
            credential_login: Arc::new(UnusedCredentialLogin),
            sessions: ports,
            origins: UiOriginPolicy::new(UI, std::iter::empty::<&str>()).unwrap(),
            cookie: SessionCookieConfig {
                name: "sessionId".into(),
                secure: true,
                same_site: "lax".into(),
                maximum_age_seconds: 3600,
                path: "/".into(),
            },
            impersonation_handoff_cookie_name: "probe-handoff".into(),
        })
        .unwrap()
    }
    async fn request(
        router: &Router,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: &str,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        router
            .clone()
            .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }
    async fn begin(router: &Router, ports: &Ports) -> String {
        let response = request(
            router,
            Method::GET,
            "/v1/auth/login?redirect_uri=%2Fconsole%2Fprofile",
            None,
            "",
        )
        .await;
        assert!(response.status().is_redirection());
        ports
            .authorization
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .state
            .clone()
    }
    async fn complete(router: &Router, state: &str) -> axum::response::Response {
        request(
            router,
            Method::GET,
            &format!("/v1/auth/callback?code=probe-code&state={state}"),
            None,
            "",
        )
        .await
    }
    fn session_cookie(ports: &Ports) -> String {
        format!(
            "sessionId={}",
            ports.sessions.lock().unwrap().keys().next().unwrap()
        )
    }
    async fn observe(id: &str, mode: &'static str) -> Vec<Value> {
        let ports = Arc::new(Ports::default());
        let router = router(ports.clone());
        let codes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Diagnostics(codes.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);
        let response = match mode {
            "login" => {
                request(
                    &router,
                    Method::GET,
                    "/v1/auth/login?redirect_uri=%2Fconsole%2Fprofile",
                    None,
                    "",
                )
                .await
            }
            "locale" => {
                request(
                    &router,
                    Method::GET,
                    "/v1/auth/login?ui_locales=en&kc_locale=de",
                    None,
                    "",
                )
                .await
            }
            "registration_disabled" => {
                ports.set(mode);
                request(&router, Method::GET, "/v1/auth/register", None, "").await
            }
            "state_save" | "authorization_url" => {
                ports.set(mode);
                request(&router, Method::GET, "/v1/auth/login", None, "").await
            }
            "missing_parameters" => {
                request(&router, Method::GET, "/v1/auth/callback", None, "").await
            }
            "unknown_state" => complete(&router, "unknown-probe-state").await,
            "anonymous" => request(&router, Method::GET, "/v1/auth/me", None, "").await,
            _ => {
                let state = begin(&router, &ports).await;
                match mode {
                    "expired" => {
                        ports
                            .states
                            .lock()
                            .unwrap()
                            .get_mut(&state)
                            .unwrap()
                            .expires_at = Utc::now() - Duration::hours(1)
                    }
                    "missing_nonce" => {
                        ports.states.lock().unwrap().get_mut(&state).unwrap().nonce = None
                    }
                    "replay" => {
                        complete(&router, &state).await;
                    }
                    "authenticated" | "logout" | "after_logout" | "invalid_picture"
                    | "session_get" | "profile_save" => {}
                    _ => ports.set(mode),
                }
                let callback = complete(&router, &state).await;
                match mode {
                    "authenticated" => {
                        request(
                            &router,
                            Method::GET,
                            "/v1/auth/me",
                            Some(&session_cookie(&ports)),
                            "",
                        )
                        .await
                    }
                    "logout" => {
                        request(
                            &router,
                            Method::POST,
                            "/v1/auth/logout",
                            Some(&session_cookie(&ports)),
                            "",
                        )
                        .await
                    }
                    "after_logout" => {
                        let cookie = session_cookie(&ports);
                        request(&router, Method::POST, "/v1/auth/logout", Some(&cookie), "").await;
                        request(&router, Method::GET, "/v1/auth/me", Some(&cookie), "").await
                    }
                    "invalid_picture" => {
                        request(
                            &router,
                            Method::PATCH,
                            "/v1/auth/me",
                            Some(&session_cookie(&ports)),
                            r#"{"picture":"http://image.probe.invalid/picture"}"#,
                        )
                        .await
                    }
                    "profile_save" => {
                        ports.set("session_save");
                        request(
                            &router,
                            Method::PATCH,
                            "/v1/auth/me",
                            Some(&session_cookie(&ports)),
                            r#"{"picture":"https://image.probe.invalid/picture"}"#,
                        )
                        .await
                    }
                    "session_get" => {
                        ports.set(mode);
                        request(
                            &router,
                            Method::GET,
                            "/v1/auth/me",
                            Some(&session_cookie(&ports)),
                            "",
                        )
                        .await
                    }
                    _ => callback,
                }
            }
        };
        let status = response.status().as_u16();
        let headers = response.headers();
        let text = |key| {
            headers
                .get(key)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let location = text(header::LOCATION);
        let cache = text(header::CACHE_CONTROL);
        let cookie_attributes = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter(|value| value.starts_with("sessionId="))
            .map(|value| {
                let mut parts = value.split(';').skip(1).map(str::trim).collect::<Vec<_>>();
                parts.sort_unstable();
                parts.join(";")
            })
            .collect::<Vec<_>>();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert!(bytes.len() < 65536);
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        let public_body = if let Some(authenticated) = body.get("authenticated") {
            let mut fields = body
                .get("user")
                .and_then(Value::as_object)
                .map(|user| user.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            fields.sort();
            json!({"authenticated":authenticated,"user_fields":fields})
        } else {
            body
        };
        let message = json!({"body":public_body,"location":location,"cache_control":cache,"session_cookie_attributes":cookie_attributes});
        let encoded = serde_json::to_string(&message).unwrap();
        for private in [
            PRIVATE_DETAIL,
            "probe-access-secret",
            "probe-id-secret",
            "probe-refresh-secret",
        ] {
            assert!(
                !encoded.contains(private),
                "private fixture material escaped HTTP projection"
            );
        }
        if let Some(request) = ports.authorization.lock().unwrap().as_ref() {
            assert!(
                !encoded.contains(&request.state) && !encoded.contains(&request.nonce),
                "one-time state escaped HTTP projection"
            );
        }
        for session in ports.sessions.lock().unwrap().keys() {
            assert!(
                !encoded.contains(session),
                "session identifier escaped HTTP projection"
            );
        }
        let diagnostics = codes.lock().unwrap().clone();
        [("public_status",json!(status)),("public_message",message),("safe_server_diagnostic",json!(diagnostics))].into_iter()
            .map(|(dimension,value)|json!({"case_id":id,"dimension":dimension,"id":format!("{id}.{dimension}"),"operation_id":"auth.http-session","value":value})).collect()
    }
    pub(super) async fn observations() -> Vec<Value> {
        let mut results = Vec::new();
        for (id, mode) in [
            ("auth-http-login", "login"),
            ("auth-http-invalid-locale", "locale"),
            ("auth-http-registration-disabled", "registration_disabled"),
            ("auth-http-state-save-failure", "state_save"),
            ("auth-http-authorization-failure", "authorization_url"),
            ("auth-http-missing-parameters", "missing_parameters"),
            ("auth-http-unknown-state", "unknown_state"),
            ("auth-http-expired-state", "expired"),
            ("auth-http-missing-nonce", "missing_nonce"),
            ("auth-http-state-consume-failure", "state_take"),
            ("auth-http-exchange-failure", "exchange"),
            ("auth-http-missing-access", "missing_access"),
            ("auth-http-missing-id", "missing_id"),
            ("auth-http-token-validation-failure", "validate"),
            ("auth-http-provision-failure", "provision"),
            ("auth-http-session-save-failure", "session_save"),
            ("auth-http-login-event-failure", "login_event"),
            ("auth-http-session-event-failure", "session_event"),
            ("auth-http-callback-success", "success"),
            ("auth-http-callback-replay", "replay"),
            ("auth-http-anonymous", "anonymous"),
            ("auth-http-authenticated", "authenticated"),
            ("auth-http-logout", "logout"),
            ("auth-http-after-logout", "after_logout"),
            ("auth-http-invalid-picture", "invalid_picture"),
            ("auth-http-session-get-failure", "session_get"),
            ("auth-http-profile-save-failure", "profile_save"),
        ] {
            results.extend(observe(id, mode).await);
        }
        results
    }
}
