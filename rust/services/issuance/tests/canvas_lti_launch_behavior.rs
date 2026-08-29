use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use marty_issuance_service::{
    canvas_lti_launch::{
        feature_enabled, launch_scope, merge_verified_lti_binding_capabilities,
        plan_ags_line_item_pin, plan_verified_identity, private_launch_response,
        public_launch_response, scope_matches, select_binding, select_binding_with_staff_fallback,
        CanvasLtiAgsPinRepository, CanvasLtiAgsPinRequest, CanvasLtiAgsPinService,
        CanvasLtiAgsServiceUrlValidator, CanvasLtiCapabilitySnapshotRepository,
        CanvasLtiCapabilitySnapshotRequest, CanvasLtiClock, CanvasLtiIdentityRecord,
        CanvasLtiIdentityRepository, CanvasLtiIdentityRequest, CanvasLtiIdentityService,
        CanvasLtiIdentityStatus, CanvasLtiJwksRefreshService, CanvasLtiJwksRefresher,
        CanvasLtiLaunchContextRepository, CanvasLtiLaunchPlanError, CanvasLtiLaunchPorts,
        CanvasLtiLaunchService, CanvasLtiLaunchServiceError, CanvasLtiLaunchStateRepository,
        CanvasLtiLaunchStateService, CanvasLtiLaunchSubmission, CanvasLtiProgramBinding,
        CanvasLtiStoredLaunchState,
    },
    canvas_lti_login::{
        CanvasLtiLaunchState, CanvasLtiLoginError, CanvasLtiLoginRepository, CanvasLtiLoginService,
        CanvasLtiPlatform,
    },
    canvas_lti_postgres::MartyCanvasLtiAgsServiceUrlValidator,
    http::router_with_canvas_lti_launch,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use marty_oid4vci::lti::VerifiedLtiLaunch;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct StateRepository {
    states: Mutex<HashMap<String, CanvasLtiStoredLaunchState>>,
}

impl StateRepository {
    fn insert(&self, state: CanvasLtiStoredLaunchState) {
        self.states
            .lock()
            .unwrap()
            .insert(state.state.clone(), state);
    }
}

#[async_trait]
impl CanvasLtiLaunchStateRepository for StateRepository {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok(self.states.lock().unwrap().get(state).cloned())
    }

    async fn consume_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        let mut states = self.states.lock().unwrap();
        let Some(stored) = states.get_mut(state) else {
            return Ok(None);
        };
        if stored.status != "pending" || stored.expired {
            return Ok(None);
        }
        stored.status = "consumed".to_owned();
        Ok(Some(stored.clone()))
    }
}

#[derive(Default)]
struct IdentityRepository {
    identities: Mutex<Vec<CanvasLtiIdentityRecord>>,
}

struct JwksRefresher {
    calls: Mutex<usize>,
    refreshed: CanvasLtiPlatform,
    fails: bool,
}

struct AgsUrlValidator;

#[async_trait]
impl CanvasLtiAgsServiceUrlValidator for AgsUrlValidator {
    async fn validate(&self, service_url: &str) -> Result<String, String> {
        if service_url.starts_with("https://") {
            Ok(service_url.to_owned())
        } else {
            Err("Canvas LTI service URLs must use HTTPS".to_owned())
        }
    }
}

struct AgsRepository {
    binding: Mutex<CanvasLtiProgramBinding>,
    readiness_invalidations: Mutex<usize>,
}

#[async_trait]
impl CanvasLtiAgsPinRepository for AgsRepository {
    async fn pin_verified_line_item(
        &self,
        binding: &CanvasLtiProgramBinding,
        request: &CanvasLtiAgsPinRequest,
    ) -> Result<bool, CanvasLtiLaunchPlanError> {
        let mut stored = self.binding.lock().unwrap();
        if stored.id != binding.id || request.binding_id != binding.id {
            return Err(CanvasLtiLaunchPlanError::AgsBindingMismatch);
        }
        let Some(updated) = plan_ags_line_item_pin(&stored.evidence_requirements, request)? else {
            return Ok(false);
        };
        stored.evidence_requirements = updated;
        stored.enabled = false;
        *self.readiness_invalidations.lock().unwrap() += 1;
        Ok(true)
    }
}

#[async_trait]
impl CanvasLtiJwksRefresher for JwksRefresher {
    async fn refresh_platform_jwks(
        &self,
        _platform: &CanvasLtiPlatform,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLaunchPlanError> {
        *self.calls.lock().unwrap() += 1;
        if self.fails {
            Err(CanvasLtiLaunchPlanError::RepositoryUnavailable)
        } else {
            Ok(self.refreshed.clone())
        }
    }
}

#[async_trait]
impl CanvasLtiIdentityRepository for IdentityRepository {
    async fn reconcile_verified_identity(
        &self,
        request: &CanvasLtiIdentityRequest,
    ) -> Result<CanvasLtiIdentityRecord, CanvasLtiLaunchPlanError> {
        let mut identities = self.identities.lock().unwrap();
        let same_scope = |record: &&CanvasLtiIdentityRecord| {
            record.organization_id == request.organization_id
                && record.platform_id == request.platform_id
                && record.deployment_id == request.deployment_id
        };
        let existing_subject = identities
            .iter()
            .filter(same_scope)
            .find(|record| record.lti_subject == request.lti_subject)
            .cloned();
        let existing_numeric = request.canvas_user_id.as_ref().and_then(|canvas_user_id| {
            identities
                .iter()
                .filter(same_scope)
                .find(|record| record.canvas_user_id.as_ref() == Some(canvas_user_id))
                .cloned()
        });
        let new_id = format!("identity-{}", identities.len() + 1);
        let plan = plan_verified_identity(
            request,
            existing_subject.as_ref(),
            existing_numeric.as_ref(),
            &new_id,
        );
        if let Some(existing) = plan.quarantine_existing {
            let stored = identities
                .iter_mut()
                .find(|record| record.id == existing.id)
                .expect("existing numeric identity");
            *stored = existing;
        }
        if let Some(stored) = identities
            .iter_mut()
            .find(|record| record.id == plan.identity.id)
        {
            *stored = plan.identity.clone();
        } else {
            identities.push(plan.identity.clone());
        }
        Ok(plan.identity)
    }
}

fn pending_state(platform_id: &str, state: &str) -> CanvasLtiStoredLaunchState {
    CanvasLtiStoredLaunchState {
        platform_id: platform_id.to_owned(),
        state: state.to_owned(),
        nonce: "nonce-1".to_owned(),
        status: "pending".to_owned(),
        expired: false,
    }
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-lti-foundation.json"
    ))
    .expect("valid Canvas LTI contract")
}

fn lti_jwk(kid: &str, verifying_key: &VerifyingKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
    })
}

fn lti_token(kid: &str, key_byte: u8) -> (String, Value) {
    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let claims = json!({
        "iss": "https://canvas.instructure.com",
        "sub": "opaque-subject",
        "aud": ["client-1"],
        "exp": 4102444800u64,
        "iat": 1700000000u64,
        "nonce": "nonce-1",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-1",
        "https://purl.imsglobal.org/spec/lti/claim/roles": ["Learner"],
    });
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let header = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    (token, lti_jwk(kid, &signing_key.verifying_key()))
}

fn platform_from(value: &Value) -> CanvasLtiPlatform {
    CanvasLtiPlatform {
        id: value["id"].as_str().unwrap().to_owned(),
        organization_id: value["organization_id"].as_str().unwrap().to_owned(),
        canvas_account_id: value["canvas_account_id"].as_str().unwrap().to_owned(),
        canvas_base_url: Some("https://school.canvas.example".to_owned()),
        lti_client_id: Some("client-1".to_owned()),
        lti_deployment_id: Some("deployment-1".to_owned()),
        lti_trust_profile: "hosted_global".to_owned(),
        lti_issuer: Some("https://canvas.instructure.com".to_owned()),
        lti_jwks_url: Some("https://sso.canvaslms.com/api/lti/security/jwks".to_owned()),
        lti_jwks_json: Some(json!({"keys": []})),
        lti_openid_configuration: None,
        config_version: 1,
        enabled: true,
    }
}

fn binding_from(value: &Value, platform: &CanvasLtiPlatform) -> CanvasLtiProgramBinding {
    CanvasLtiProgramBinding {
        id: value["id"].as_str().unwrap().to_owned(),
        organization_id: platform.organization_id.clone(),
        platform_id: platform.id.clone(),
        application_template_id: value["application_template_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        credential_template_id: value["credential_template_id"].as_str().unwrap().to_owned(),
        delivery_mode: "wallet_only".to_owned(),
        deployment_profile_id: None,
        feature_flags: json!({}),
        evidence_requirements: Vec::new(),
        canvas_scope: json!({}),
        enabled: true,
        archived: false,
        config_version: 1,
    }
}

#[derive(Default)]
struct OrchestrationRepository {
    platform: Mutex<Option<CanvasLtiPlatform>>,
    states: Mutex<HashMap<String, CanvasLtiStoredLaunchState>>,
    bindings: Mutex<Vec<CanvasLtiProgramBinding>>,
    calls: Mutex<Vec<&'static str>>,
    identity_count: Mutex<usize>,
    capability_requests: Mutex<Vec<CanvasLtiCapabilitySnapshotRequest>>,
    fail_binding_resolution: Mutex<bool>,
    fail_capability_persistence: Mutex<bool>,
}

impl OrchestrationRepository {
    fn record(&self, stage: &'static str) {
        self.calls.lock().unwrap().push(stage);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl CanvasLtiLoginRepository for OrchestrationRepository {
    async fn get_platform(
        &self,
        platform_id: &str,
    ) -> Result<Option<CanvasLtiPlatform>, CanvasLtiLoginError> {
        self.record("load-platform");
        Ok(self
            .platform
            .lock()
            .unwrap()
            .clone()
            .filter(|platform| platform.id == platform_id))
    }

    async fn save_launch_state(
        &self,
        _launch_state: &CanvasLtiLaunchState,
    ) -> Result<(), CanvasLtiLoginError> {
        unreachable!("launch orchestration never creates login state")
    }
}

#[async_trait]
impl CanvasLtiLaunchStateRepository for OrchestrationRepository {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        self.record("load-state");
        Ok(self.states.lock().unwrap().get(state).cloned())
    }

    async fn consume_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        self.record("consume-state-atomically");
        let mut states = self.states.lock().unwrap();
        let Some(stored) = states.get_mut(state) else {
            return Ok(None);
        };
        if stored.status != "pending" || stored.expired {
            return Ok(None);
        }
        stored.status = "consumed".to_owned();
        Ok(Some(stored.clone()))
    }
}

#[async_trait]
impl CanvasLtiLaunchContextRepository for OrchestrationRepository {
    async fn list_program_bindings(
        &self,
        _organization_id: &str,
        _platform_id: &str,
    ) -> Result<Vec<CanvasLtiProgramBinding>, CanvasLtiLaunchPlanError> {
        self.record("resolve-binding-and-feature-gate");
        if *self.fail_binding_resolution.lock().unwrap() {
            Ok(Vec::new())
        } else {
            Ok(self.bindings.lock().unwrap().clone())
        }
    }
}

#[async_trait]
impl CanvasLtiIdentityRepository for OrchestrationRepository {
    async fn reconcile_verified_identity(
        &self,
        request: &CanvasLtiIdentityRequest,
    ) -> Result<CanvasLtiIdentityRecord, CanvasLtiLaunchPlanError> {
        self.record("persist-verified-identity");
        *self.identity_count.lock().unwrap() += 1;
        Ok(CanvasLtiIdentityRecord {
            id: "identity-1".to_owned(),
            organization_id: request.organization_id.clone(),
            platform_id: request.platform_id.clone(),
            deployment_id: request.deployment_id.clone(),
            lti_subject: request.lti_subject.clone(),
            canvas_user_id: request.canvas_user_id.clone(),
            status: CanvasLtiIdentityStatus::Linked,
            conflict_reason: None,
        })
    }
}

#[async_trait]
impl CanvasLtiAgsPinRepository for OrchestrationRepository {
    async fn pin_verified_line_item(
        &self,
        binding: &CanvasLtiProgramBinding,
        request: &CanvasLtiAgsPinRequest,
    ) -> Result<bool, CanvasLtiLaunchPlanError> {
        self.record("persist-verified-ags-line-item");
        let mut bindings = self.bindings.lock().unwrap();
        let stored = bindings
            .iter_mut()
            .find(|candidate| candidate.id == binding.id)
            .ok_or(CanvasLtiLaunchPlanError::AgsBindingMismatch)?;
        let Some(updated) = plan_ags_line_item_pin(&stored.evidence_requirements, request)? else {
            return Ok(false);
        };
        stored.evidence_requirements = updated;
        stored.config_version += 1;
        Ok(true)
    }
}

#[async_trait]
impl CanvasLtiCapabilitySnapshotRepository for OrchestrationRepository {
    async fn persist_verified_capabilities(
        &self,
        request: &CanvasLtiCapabilitySnapshotRequest,
    ) -> Result<Value, CanvasLtiLaunchPlanError> {
        self.record("merge-capabilities-and-persist-platform-validation");
        if *self.fail_capability_persistence.lock().unwrap() {
            return Err(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift);
        }
        self.capability_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(request.launch_capabilities.clone())
    }
}

struct OrchestrationJwksRefresher {
    repository: Arc<OrchestrationRepository>,
    refreshed: CanvasLtiPlatform,
}

#[async_trait]
impl CanvasLtiJwksRefresher for OrchestrationJwksRefresher {
    async fn refresh_platform_jwks(
        &self,
        _platform: &CanvasLtiPlatform,
    ) -> Result<CanvasLtiPlatform, CanvasLtiLaunchPlanError> {
        self.repository
            .record("verify-jwt-with-bounded-jwks-refresh");
        Ok(self.refreshed.clone())
    }
}

struct FixedClock(DateTime<Utc>);

impl CanvasLtiClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn orchestration_token(kid: &str, key_byte: u8) -> (String, Value) {
    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let claims = json!({
        "iss": "https://canvas.instructure.com",
        "sub": "opaque-subject",
        "aud": ["client-1"],
        "exp": 4102444800u64,
        "iat": 1700000000u64,
        "nonce": "nonce-1",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id": "deployment-1",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
        "https://purl.imsglobal.org/spec/lti/claim/version": "1.3.0",
        "https://purl.imsglobal.org/spec/lti/claim/roles": ["Learner"],
        "https://purl.imsglobal.org/spec/lti/claim/context": {"id": "course-1"},
        "https://purl.imsglobal.org/spec/lti/claim/resource_link": {"id": "resource-1"},
        "https://purl.imsglobal.org/spec/lti/claim/custom": {
            "canvas_course_id": "course-1",
            "canvas_program_binding_id": "binding-1",
            "canvas_requirement_id": "score-1",
            "canvas_resource_id": "resource-1",
            "canvas_user_id": "42"
        },
        "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": {
            "lineitem": "https://school.canvas.example/api/lti/courses/course-1/line_items/7",
            "scope": ["https://purl.imsglobal.org/spec/lti-ags/scope/score"]
        }
    });
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let header = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let signature = signing_key.sign(signing_input.as_bytes());
    (
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ),
        lti_jwk(kid, &signing_key.verifying_key()),
    )
}

fn orchestration_binding(platform: &CanvasLtiPlatform) -> CanvasLtiProgramBinding {
    let mut binding = binding_from(
        &json!({
            "id": "binding-1",
            "application_template_id": "application-1",
            "credential_template_id": "credential-1"
        }),
        platform,
    );
    binding.config_version = 4;
    binding.canvas_scope = json!({"course_id": "course-1"});
    binding.evidence_requirements = vec![json!({
        "requirement_id": "score-1",
        "source": "ags_result",
        "fact_type": "canvas.assignment_score",
        "scope": {"course_id": "course-1", "resource_id": "resource-1"},
        "pass_rule": {"min_score_percent": 80},
        "required": true
    })];
    binding
}

fn orchestration_platform() -> CanvasLtiPlatform {
    let mut platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    platform.lti_openid_configuration = Some(json!({
        "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect"
    }));
    platform
}

fn orchestration_app(service: CanvasLtiLaunchService) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_lti_launch(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.test", "Issuer"),
        TransportPolicy::new(vec!["https://canvas.example.test".to_owned()]),
        service,
    )
}

async fn post_launch_json(app: axum::Router, payload: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-1/launch")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    (status, body)
}

fn orchestration_service(
    repository: Arc<OrchestrationRepository>,
    refreshed: CanvasLtiPlatform,
) -> CanvasLtiLaunchService {
    let login = CanvasLtiLoginService::new(
        repository.clone(),
        "https://issuer.example.test",
        true,
        BTreeSet::from(["org-1".to_owned()]),
        Duration::from_secs(600),
        Vec::new(),
    )
    .unwrap();
    CanvasLtiLaunchService::new(
        login,
        CanvasLtiLaunchPorts {
            state_repository: repository.clone(),
            context_repository: repository.clone(),
            jwks_refresher: Arc::new(OrchestrationJwksRefresher {
                repository: repository.clone(),
                refreshed,
            }),
            identity_repository: repository.clone(),
            ags_repository: repository.clone(),
            ags_url_validator: Arc::new(AgsUrlValidator),
            capability_repository: repository,
            clock: Arc::new(FixedClock(
                Utc.with_ymd_and_hms(2026, 8, 29, 12, 0, 0).unwrap(),
            )),
        },
    )
}

#[tokio::test]
async fn launch_orchestration_replays_order_and_atomic_persistence_contract() {
    let policy = &contract()["launch"]["orchestration"];
    assert_eq!(
        policy["ordered_stages"],
        json!([
            "load-platform",
            "authorize-and-validate-platform",
            "parse-submission",
            "load-state",
            "consume-state-atomically",
            "verify-jwt-with-bounded-jwks-refresh",
            "persist-verified-identity",
            "resolve-binding-and-feature-gate",
            "persist-verified-ags-line-item",
            "project-private-response",
            "merge-binding-capability-snapshot",
            "persist-platform-validation-state"
        ])
    );
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    platform.config_version = 3;
    platform.lti_jwks_json = Some(json!({"keys": [{"kid": "old-key"}]}));
    let (token, jwk) = orchestration_token("new-key", 31);
    let mut refreshed = platform.clone();
    refreshed.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    repository
        .bindings
        .lock()
        .unwrap()
        .push(orchestration_binding(&platform));
    let service = orchestration_service(repository.clone(), refreshed);

    let result = service
        .launch(
            "platform-1",
            CanvasLtiLaunchSubmission {
                id_token: Some(token),
                state: Some("state-1".to_owned()),
            },
        )
        .await
        .unwrap();

    assert_eq!(result.consumed_state.status, "consumed");
    assert_eq!(
        result.response.identity_mapping_status.as_deref(),
        Some("linked")
    );
    assert_eq!(
        result.response.evidence_requirements[0]["scope"]["line_item_url"],
        "https://school.canvas.example/api/lti/courses/course-1/line_items/7"
    );
    let calls = repository.calls();
    for ordered_pair in [
        ("load-state", "consume-state-atomically"),
        (
            "consume-state-atomically",
            "verify-jwt-with-bounded-jwks-refresh",
        ),
        (
            "verify-jwt-with-bounded-jwks-refresh",
            "persist-verified-identity",
        ),
        (
            "persist-verified-identity",
            "resolve-binding-and-feature-gate",
        ),
        (
            "resolve-binding-and-feature-gate",
            "persist-verified-ags-line-item",
        ),
        (
            "persist-verified-ags-line-item",
            "merge-capabilities-and-persist-platform-validation",
        ),
    ] {
        let left = calls
            .iter()
            .position(|stage| *stage == ordered_pair.0)
            .unwrap();
        let right = calls
            .iter()
            .position(|stage| *stage == ordered_pair.1)
            .unwrap();
        assert!(left < right, "{calls:?}");
    }
    assert_eq!(
        calls.last(),
        Some(&"merge-capabilities-and-persist-platform-validation")
    );
    let requests = repository.capability_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].selected_platform_config_version, 3);
    assert_eq!(requests[0].selected_binding_config_version, 4);
    assert_eq!(requests[0].signed_course_id, "course-1");
    assert!(requests[0].line_item_configuration_changed);
    assert_eq!(
        requests[0].verified_at,
        Utc.with_ymd_and_hms(2026, 8, 29, 12, 0, 0).unwrap()
    );
}

#[tokio::test]
async fn jwt_failure_keeps_state_consumed_without_identity_or_capability_writes() {
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    let (token, signing_jwk) = orchestration_token("same-key", 41);
    let (_, wrong_jwk) = orchestration_token("same-key", 42);
    platform.lti_jwks_json = Some(json!({"keys": [wrong_jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    let mut refreshed = platform;
    refreshed.lti_jwks_json = Some(json!({"keys": [signing_jwk]}));
    let service = orchestration_service(repository.clone(), refreshed);

    assert!(service
        .launch(
            "platform-1",
            CanvasLtiLaunchSubmission {
                id_token: Some(token),
                state: Some("state-1".to_owned()),
            },
        )
        .await
        .is_err());

    assert_eq!(
        repository.states.lock().unwrap()["state-1"].status,
        "consumed"
    );
    assert_eq!(*repository.identity_count.lock().unwrap(), 0);
    assert!(repository.capability_requests.lock().unwrap().is_empty());
    assert_eq!(
        repository.calls(),
        vec!["load-platform", "load-state", "consume-state-atomically"]
    );
}

#[tokio::test]
async fn binding_failure_preserves_consumed_state_and_verified_identity_only() {
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    let (token, jwk) = orchestration_token("current-key", 51);
    platform.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    *repository.fail_binding_resolution.lock().unwrap() = true;
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    let service = orchestration_service(repository.clone(), platform);

    assert!(service
        .launch(
            "platform-1",
            CanvasLtiLaunchSubmission {
                id_token: Some(token),
                state: Some("state-1".to_owned()),
            },
        )
        .await
        .is_err());

    assert_eq!(
        repository.states.lock().unwrap()["state-1"].status,
        "consumed"
    );
    assert_eq!(*repository.identity_count.lock().unwrap(), 1);
    assert!(repository.capability_requests.lock().unwrap().is_empty());
    assert_eq!(
        repository.calls(),
        vec![
            "load-platform",
            "load-state",
            "consume-state-atomically",
            "persist-verified-identity",
            "resolve-binding-and-feature-gate"
        ]
    );
}

#[tokio::test]
async fn capability_failure_returns_no_response_after_prior_durable_writes() {
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    platform.lti_openid_configuration = Some(json!({
        "authorization_endpoint": "https://sso.canvaslms.com/api/lti/authorize_redirect"
    }));
    platform.config_version = 3;
    let (token, jwk) = orchestration_token("current-key", 61);
    platform.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    *repository.fail_capability_persistence.lock().unwrap() = true;
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    repository
        .bindings
        .lock()
        .unwrap()
        .push(orchestration_binding(&platform));
    let service = orchestration_service(repository.clone(), platform);

    let error = service
        .launch(
            "platform-1",
            CanvasLtiLaunchSubmission {
                id_token: Some(token),
                state: Some("state-1".to_owned()),
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        CanvasLtiLaunchServiceError::Launch(CanvasLtiLaunchPlanError::CapabilityConfigurationDrift)
    ));
    assert_eq!(
        repository.states.lock().unwrap()["state-1"].status,
        "consumed"
    );
    assert_eq!(*repository.identity_count.lock().unwrap(), 1);
    assert!(repository.capability_requests.lock().unwrap().is_empty());
    let bindings = repository.bindings.lock().unwrap();
    assert_eq!(bindings[0].config_version, 5);
    assert_eq!(
        bindings[0].evidence_requirements[0]["scope"]["line_item_url"],
        "https://school.canvas.example/api/lti/courses/course-1/line_items/7"
    );
    assert_eq!(
        repository.calls().last(),
        Some(&"merge-capabilities-and-persist-platform-validation")
    );
}

#[tokio::test]
async fn launch_http_form_uses_last_duplicate_and_returns_only_public_projection() {
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    let (token, jwk) = orchestration_token("current-key", 61);
    platform.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    repository
        .bindings
        .lock()
        .unwrap()
        .push(orchestration_binding(&platform));
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token", "discarded-token")
        .append_pair("state", "discarded-state")
        .append_pair("id_token", &token)
        .append_pair("state", "state-1")
        .finish();
    let response = orchestration_app(orchestration_service(repository.clone(), platform))
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-1/launch")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["verified"], true);
    assert_eq!(body["canvas_platform_id"], "platform-1");
    assert_eq!(body["canvas_program_binding_id"], "binding-1");
    assert_eq!(body["application_template_id"], "application-1");
    for private_field in [
        "subject",
        "nonce",
        "state",
        "learner_identity",
        "raw_claims",
        "lti_capabilities",
        "target_link_uri",
    ] {
        assert!(body.get(private_field).is_none(), "{private_field}");
    }
    assert_eq!(
        repository.states.lock().unwrap()["state-1"].status,
        "consumed"
    );
}

#[tokio::test]
async fn launch_http_rejects_malformed_non_object_and_oversized_bodies() {
    let cases = [
        ("application/json", "{".to_owned(), "Invalid JSON body"),
        (
            "application/json",
            "[]".to_owned(),
            "Canvas LTI JSON body must be an object",
        ),
        (
            "text/plain",
            "id_token=header.payload.signature&state=state-1".to_owned(),
            "Canvas LTI launch requires id_token",
        ),
        (
            "application/x-www-form-urlencoded",
            "x".repeat(64 * 1024 + 1),
            "Canvas LTI request body exceeds the size limit",
        ),
    ];
    for (content_type, body, detail) in cases {
        let repository = Arc::new(OrchestrationRepository::default());
        let platform = orchestration_platform();
        *repository.platform.lock().unwrap() = Some(platform.clone());
        let response = orchestration_app(orchestration_service(repository, platform))
            .oneshot(
                Request::post("/v1/integrations/canvas/lti/platforms/platform-1/launch")
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(body, json!({"detail": detail}));
    }
}

#[tokio::test]
async fn launch_http_replays_every_frozen_submission_failure() {
    let contract = contract();
    let failures = contract["launch"]["submission"]["failures"]
        .as_array()
        .unwrap();
    let expected = |name: &str| {
        let failure = failures
            .iter()
            .find(|failure| failure["name"] == name)
            .unwrap();
        (
            StatusCode::from_u16(failure["status_code"].as_u64().unwrap() as u16).unwrap(),
            json!({"detail": failure["detail"]}),
        )
    };

    for (name, payload) in [
        ("id_token_missing", json!({"state": "state-1"})),
        (
            "state_missing",
            json!({"id_token": "header.payload.signature"}),
        ),
        (
            "state_unknown",
            json!({"id_token": "header.payload.signature", "state": "state-1"}),
        ),
    ] {
        let repository = Arc::new(OrchestrationRepository::default());
        let platform = orchestration_platform();
        *repository.platform.lock().unwrap() = Some(platform.clone());
        assert_eq!(
            post_launch_json(
                orchestration_app(orchestration_service(repository, platform)),
                payload,
            )
            .await,
            expected(name)
        );
    }

    let repository = Arc::new(OrchestrationRepository::default());
    let platform = orchestration_platform();
    *repository.platform.lock().unwrap() = Some(platform.clone());
    let mut consumed = pending_state("platform-1", "state-1");
    consumed.status = "consumed".to_owned();
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), consumed);
    assert_eq!(
        post_launch_json(
            orchestration_app(orchestration_service(repository, platform)),
            json!({"id_token": "header.payload.signature", "state": "state-1"}),
        )
        .await,
        expected("state_consumed")
    );

    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    let (token, jwk) = orchestration_token("current-key", 81);
    platform.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    let mut binding = orchestration_binding(&platform);
    binding.feature_flags = json!({"enable_canvas_lti": false});
    repository.bindings.lock().unwrap().push(binding);
    assert_eq!(
        post_launch_json(
            orchestration_app(orchestration_service(repository, platform)),
            json!({"id_token": token, "state": "state-1"}),
        )
        .await,
        expected("feature_disabled")
    );
}

#[tokio::test]
async fn launch_http_maps_binding_failure_to_frozen_conflict_response() {
    let repository = Arc::new(OrchestrationRepository::default());
    let mut platform = orchestration_platform();
    let (token, jwk) = orchestration_token("current-key", 71);
    platform.lti_jwks_json = Some(json!({"keys": [jwk]}));
    *repository.platform.lock().unwrap() = Some(platform.clone());
    *repository.fail_binding_resolution.lock().unwrap() = true;
    repository
        .states
        .lock()
        .unwrap()
        .insert("state-1".to_owned(), pending_state("platform-1", "state-1"));
    let response = orchestration_app(orchestration_service(repository.clone(), platform))
        .oneshot(
            Request::post("/v1/integrations/canvas/lti/platforms/platform-1/launch")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"id_token": token, "state": "state-1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"detail": "Canvas LTI launch did not match an enabled Canvas program binding"})
    );
    assert_eq!(*repository.identity_count.lock().unwrap(), 1);
    assert!(repository.capability_requests.lock().unwrap().is_empty());
}

#[test]
fn public_projection_replays_the_python_oracle_contract() {
    let contract = contract();
    let vector = &contract["launch"]["public_response_vector"];
    let platform = platform_from(&vector["platform"]);
    let binding = binding_from(&vector["binding"], &platform);
    let verified: VerifiedLtiLaunch =
        serde_json::from_value(vector["verified"].clone()).expect("valid verified launch vector");
    let identity_status = vector["verified"]["identity_mapping_status"]
        .as_str()
        .map(str::to_owned);
    let private = private_launch_response(
        &platform,
        &binding,
        "private-state",
        verified,
        identity_status,
    );
    assert_eq!(private.lti_capabilities["resource_link"], true);
    assert_eq!(
        private.lti_capabilities["binding_evidence_fact_types"],
        json!(["canvas.course_completion"])
    );
    let public = serde_json::to_value(public_launch_response(&private)).unwrap();

    assert_eq!(public, vector["expected"]);
    for private_field in contract["launch"]["private_response_fields"]
        .as_array()
        .unwrap()
    {
        assert!(public.get(private_field.as_str().unwrap()).is_none());
    }
}

#[test]
fn launch_submission_replays_required_and_non_string_json_semantics() {
    let contract = contract();
    let failures = contract["launch"]["submission"]["failures"]
        .as_array()
        .unwrap();
    let failure = |name: &str| {
        failures
            .iter()
            .find(|failure| failure["name"] == name)
            .unwrap()["detail"]
            .as_str()
            .unwrap()
    };
    let cases = [
        (json!({"state": "state-1"}), "id_token_missing"),
        (
            json!({"id_token": "header.payload.signature"}),
            "state_missing",
        ),
        (
            json!({"id_token": 7, "state": "state-1"}),
            "id_token_missing",
        ),
        (
            json!({"id_token": "header.payload.signature", "state": false}),
            "state_missing",
        ),
    ];
    for (value, expected_failure) in cases {
        let submission = CanvasLtiLaunchSubmission::from_json_object(value.as_object().unwrap());
        assert_eq!(
            submission.required().unwrap_err().to_string(),
            failure(expected_failure)
        );
    }
    assert_eq!(
        CanvasLtiLaunchSubmission {
            id_token: Some(" token ".to_owned()),
            state: Some(" state-1 ".to_owned()),
        }
        .required()
        .unwrap(),
        ("token".to_owned(), "state-1".to_owned())
    );
}

#[tokio::test]
async fn jwks_refresh_replays_bounded_fail_closed_contract() {
    let contract = contract();
    let policy = &contract["launch"]["jwt"]["jwks_refresh_policy"];
    assert_eq!(policy["maximum_refreshes"], 1);
    assert_eq!(policy["maximum_verification_attempts"], 2);

    for case in policy["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut platform = platform_from(&json!({
            "id": "platform-1",
            "organization_id": "org-1",
            "canvas_account_id": "account-1"
        }));
        if !case["canvas_base_url"].as_bool().unwrap() {
            platform.canvas_base_url = None;
        }

        let kid = "new-kid";
        let (token, new_jwk) = lti_token(kid, 7);
        platform.lti_jwks_json = Some(json!({"keys": [{"kid": "old-kid"}]}));
        if case["first_verification"] == "invalid_signature" {
            let (_, wrong_jwk) = lti_token(kid, 9);
            platform.lti_jwks_json = Some(json!({"keys": [wrong_jwk]}));
        }

        let mut refreshed = platform.clone();
        refreshed.lti_jwks_json = if case["second_verification"] == "unknown_kid" {
            Some(json!({"keys": [{"kid": "still-old-kid"}]}))
        } else {
            Some(json!({"keys": [new_jwk]}))
        };
        let refresher = Arc::new(JwksRefresher {
            calls: Mutex::new(0),
            refreshed,
            fails: case["refresh"] == "fails",
        });
        let service = CanvasLtiJwksRefreshService::new(refresher.clone());
        let result = service
            .verify_with_refresh(&platform, &token, "nonce-1")
            .await;

        if case["status_code"] == 200 {
            let (actual_platform, verified) = result.unwrap();
            assert_eq!(verified.subject, "opaque-subject", "{name}");
            assert_eq!(
                actual_platform.lti_jwks_json,
                refresher.refreshed.lti_jwks_json
            );
        } else {
            let error = result.unwrap_err().to_string();
            assert!(
                error.starts_with(case["detail_prefix"].as_str().unwrap()),
                "{name}: {error}"
            );
        }
        assert_eq!(
            *refresher.calls.lock().unwrap(),
            case["refresh_attempts"].as_u64().unwrap() as usize,
            "{name}"
        );
    }
}

#[test]
fn staff_draft_binding_fallback_replays_the_python_oracle_contract() {
    let contract = contract();
    let policy = &contract["launch"]["draft_binding_fallback"];
    let platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    for case in policy["cases"].as_array().unwrap() {
        let mut verified: VerifiedLtiLaunch = serde_json::from_value(json!({
            "issuer": "https://canvas.instructure.com",
            "subject": "opaque-subject",
            "audience": ["client-1"],
            "deployment_id": "deployment-1",
            "message_type": case["message_type"],
            "roles": case["roles"],
            "raw_claims": {
                "custom": {"canvas_course_id": "course-1"}
            },
            "learner_identity": {}
        }))
        .unwrap();
        if !case["requested_binding_id"].is_null() {
            verified.raw_claims["custom"]["canvas_program_binding_id"] =
                case["requested_binding_id"].clone();
        }
        let bindings = case["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| {
                let mut binding = binding_from(
                    &json!({
                        "id": candidate["id"],
                        "application_template_id": format!("application-{}", candidate["id"]),
                        "credential_template_id": format!("credential-{}", candidate["id"])
                    }),
                    &platform,
                );
                binding.canvas_scope = json!({"course_id": candidate["course_id"]});
                binding.enabled = false;
                binding.archived = candidate["archived"].as_bool().unwrap();
                binding
            })
            .collect::<Vec<_>>();

        let actual = select_binding_with_staff_fallback(&platform, &verified, &bindings)
            .ok()
            .map(|binding| binding.id.as_str());
        assert_eq!(
            actual,
            case["expected_binding_id"].as_str(),
            "{}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn ags_line_item_planner_replays_the_python_oracle_contract() {
    let contract = contract();
    let policy = &contract["launch"]["ags_line_item_pinning"];
    let platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    for case in policy["cases"].as_array().unwrap() {
        let mut binding = binding_from(
            &json!({
                "id": "binding-1",
                "application_template_id": "application-1",
                "credential_template_id": "credential-1"
            }),
            &platform,
        );
        let mut scope = json!({"course_id": "course-1", "resource_id": "resource-1"});
        if !case["existing_line_item_url"].is_null() {
            scope["line_item_url"] = case["existing_line_item_url"].clone();
        }
        binding.evidence_requirements = vec![json!({
            "requirement_id": "score-1",
            "source": case["requirement_source"],
            "fact_type": "canvas.assignment_score",
            "scope": scope,
            "pass_rule": {"min_score_percent": 80},
            "required": true
        })];
        let mut ags = json!({});
        if !case["line_item_url"].is_null() {
            ags["lineitem"] = case["line_item_url"].clone();
        }
        let verified: VerifiedLtiLaunch = serde_json::from_value(json!({
            "issuer": "https://canvas.instructure.com",
            "subject": "opaque-subject",
            "audience": ["client-1"],
            "deployment_id": "deployment-1",
            "raw_claims": {
                "https://purl.imsglobal.org/spec/lti/claim/custom": {
                    "canvas_program_binding_id": case["signed_binding_id"],
                    "canvas_requirement_id": case["signed_requirement_id"],
                    "canvas_resource_id": case["signed_resource_id"]
                },
                "https://purl.imsglobal.org/spec/lti-ags/claim/endpoint": ags
            },
            "roles": [],
            "learner_identity": {}
        }))
        .unwrap();
        let repository = Arc::new(AgsRepository {
            binding: Mutex::new(binding.clone()),
            readiness_invalidations: Mutex::new(0),
        });
        let service = CanvasLtiAgsPinService::new(repository.clone(), Arc::new(AgsUrlValidator));
        let result = service
            .persist_verified_line_item(&binding, &verified)
            .await;
        let name = case["name"].as_str().unwrap();

        if case["status_code"] == 200 {
            let changed = result.unwrap();
            assert_eq!(changed, case["changed"].as_bool().unwrap(), "{name}");
            assert_eq!(
                *repository.readiness_invalidations.lock().unwrap(),
                usize::from(changed),
                "{name}"
            );
            let stored = repository.binding.lock().unwrap();
            if changed {
                assert_eq!(
                    stored.evidence_requirements[0]["scope"]["line_item_url"],
                    case["line_item_url"],
                    "{name}"
                );
                assert!(!stored.enabled, "{name}");
            }
        } else {
            let error = result.unwrap_err().to_string();
            if let Some(detail) = case.get("detail").and_then(Value::as_str) {
                assert_eq!(error, detail, "{name}");
            } else {
                assert!(
                    error.starts_with(case["detail_prefix"].as_str().unwrap()),
                    "{name}: {error}"
                );
            }
            assert_eq!(*repository.readiness_invalidations.lock().unwrap(), 0);
        }
    }
    assert_eq!(policy["incomplete_claim_policy"], "no-op");
    assert_eq!(policy["matching_requirement_source"], "ags_result");
    assert_eq!(
        policy["changed_binding_policy"]["config_version_increment"],
        1
    );
}

#[test]
fn capability_snapshot_planner_replays_the_python_oracle_contract() {
    let contract = contract();
    let policy = &contract["launch"]["capability_snapshot_persistence"];
    assert_eq!(policy["authority"], "verified-signed-launch-claims");
    assert_eq!(policy["authorization_index"], "verified_binding_launches");
    assert_eq!(
        policy["ags_pin_version_exception"],
        "one-version-behind-only-when-line-item-changed"
    );
    assert_eq!(
        policy["verified_ags_line_items"],
        "sorted-deduplicated-union"
    );

    for case in policy["cases"].as_array().unwrap() {
        let mut snapshot = json!({"diagnostic_from_last_launch": "replace-me"});
        let mut prior = case["prior"].clone();
        if let Some(prior_object) = prior.as_object_mut() {
            let snapshot_key = prior_object
                .remove("snapshot_key")
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap();
            snapshot["verified_binding_launches"] = json!({snapshot_key: prior});
        }
        let binding_id = case["binding_id"].as_str().unwrap();
        let actual = merge_verified_lti_binding_capabilities(
            &snapshot,
            &case["launch_capabilities"],
            binding_id,
            case["binding_config_version"].as_i64().unwrap(),
            case["signed_course_id"].as_str().unwrap(),
            case["line_item_configuration_changed"].as_bool().unwrap(),
            "2026-08-29T12:00:00+00:00",
        );
        assert_eq!(
            actual["verified_binding_launches"][binding_id],
            case["expected_binding_capabilities"],
            "{}",
            case["name"].as_str().unwrap()
        );
        for (key, value) in case["launch_capabilities"].as_object().unwrap() {
            assert_eq!(&actual[key], value, "{}", case["name"].as_str().unwrap());
        }
        assert_eq!(actual["verified_binding_id"], binding_id);
        assert_eq!(
            actual["verified_binding_config_version"],
            case["binding_config_version"]
        );
        assert_eq!(actual["verified_course_id"], case["signed_course_id"]);
        assert_eq!(actual["verified_at"], "2026-08-29T12:00:00+00:00");
        if case["preserve_other_binding"].as_bool() == Some(true) {
            let snapshot_key = case["prior"]["snapshot_key"].as_str().unwrap();
            assert_eq!(actual["verified_binding_launches"][snapshot_key], prior);
        }
    }
}

#[tokio::test]
async fn ags_service_url_validation_is_https_dns_and_exact_allowlist_bound() {
    let hardened = MartyCanvasLtiAgsServiceUrlValidator::new(Vec::new());
    assert!(hardened
        .validate("http://127.0.0.1/internal")
        .await
        .unwrap_err()
        .contains("must use HTTPS"));
    assert!(hardened
        .validate("https://127.0.0.1/internal")
        .await
        .unwrap_err()
        .contains("exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST"));
    assert!(hardened
        .validate("https://100.64.0.1/internal")
        .await
        .unwrap_err()
        .contains("exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST"));
    assert!(hardened
        .validate("https://192.0.2.1/internal")
        .await
        .unwrap_err()
        .contains("exact CANVAS_PRIVATE_ORIGIN_ALLOWLIST"));
    assert!(hardened
        .validate("https://user:secret@127.0.0.1/internal")
        .await
        .is_err());

    let allowlisted = MartyCanvasLtiAgsServiceUrlValidator::new(vec![
        "https://127.0.0.1/".to_owned(),
        "not-a-valid-origin".to_owned(),
    ]);
    assert_eq!(
        allowlisted
            .validate("https://127.0.0.1/internal")
            .await
            .unwrap(),
        "https://127.0.0.1/internal"
    );
}

#[test]
fn scope_matching_preserves_canvas_identity_namespaces_and_aliases() {
    let verified = VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: "opaque-lti-subject".to_owned(),
        audience: vec!["client-1".to_owned()],
        deployment_id: "deployment-1".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: Some("LtiResourceLinkRequest".to_owned()),
        lti_version: Some("1.3.0".to_owned()),
        target_link_uri: None,
        context: Some(json!({"id": "course-101"})),
        roles: vec!["Learner".to_owned()],
        learner_identity: json!({}),
        raw_claims: json!({
            "https://purl.imsglobal.org/spec/lti/claim/custom": {
                "canvas_user_id": "42"
            },
            "https://purl.imsglobal.org/spec/lti/claim/resource_link": {
                "id": "resource-7"
            }
        }),
    };
    let actual = launch_scope(&verified, "account-1");

    assert!(scope_matches(
        &json!({"canvas_course_id": "course-101", "assignment_id": "resource-7"}),
        &actual
    ));
    assert!(scope_matches(
        &json!({"resource_link_id": "resource-7"}),
        &actual
    ));
    assert!(scope_matches(&json!({"canvas_user_id": 42}), &actual));
    assert!(scope_matches(
        &json!({"lti_subject": "opaque-lti-subject"}),
        &actual
    ));
    assert!(!scope_matches(
        &json!({"canvas_user_id": "opaque-lti-subject"}),
        &actual
    ));
    assert!(!scope_matches(&json!({"lti_subject": "42"}), &actual));
    assert!(!scope_matches(&json!(["course-101"]), &actual));
}

#[tokio::test]
async fn identity_mapping_replays_the_python_oracle_contract() {
    let contract = contract();
    let identity_contract = &contract["launch"]["identity_mapping"];
    let cases = identity_contract["cases"].as_array().unwrap();
    let case = |name: &str| cases.iter().find(|case| case["name"] == name).unwrap();
    let platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    let repository = Arc::new(IdentityRepository::default());
    let service = CanvasLtiIdentityService::new(repository.clone());
    let verified = |subject: &str, canvas_user_id: Option<&str>| VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: subject.to_owned(),
        audience: vec!["client-1".to_owned()],
        deployment_id: "deployment-1".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: None,
        lti_version: None,
        target_link_uri: None,
        context: None,
        roles: Vec::new(),
        learner_identity: json!({"email": "profile-only@example.test"}),
        raw_claims: json!({
            "email": "profile-only@example.test",
            "https://purl.imsglobal.org/spec/lti/claim/custom": canvas_user_id
                .map(|value| json!({"canvas_user_id": value}))
                .unwrap_or_else(|| json!({}))
        }),
    };

    let subject_case = case("subject_is_recorded_before_numeric_id_is_available");
    let status = service
        .record_verified_launch(
            &platform,
            &verified(subject_case["subject"].as_str().unwrap(), None),
        )
        .await
        .unwrap();
    assert_eq!(
        status,
        identity_contract["subject_only"]["launch_response_status"]
    );
    let subject_id = repository.identities.lock().unwrap()[0].id.clone();

    for name in [
        "subject_only_record_is_enriched_in_place",
        "same_verified_pair_is_idempotent",
    ] {
        let current = case(name);
        let status = service
            .record_verified_launch(
                &platform,
                &verified(
                    current["subject"].as_str().unwrap(),
                    current["canvas_user_id"].as_str(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(status, current["expected_status"]);
        assert_eq!(repository.identities.lock().unwrap()[0].id, subject_id);
    }

    let conflict = case("numeric_id_cannot_move_to_another_subject");
    let status = service
        .record_verified_launch(
            &platform,
            &verified(
                conflict["subject"].as_str().unwrap(),
                conflict["canvas_user_id"].as_str(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(status, conflict["expected_status"]);
    {
        let identities = repository.identities.lock().unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities
            .iter()
            .all(|identity| identity.status == CanvasLtiIdentityStatus::Quarantined));
        assert!(identities.iter().all(|identity| {
            identity.conflict_reason.as_deref() == conflict["reason"].as_str()
        }));
        assert!(identities.iter().all(|identity| {
            !identity.lti_subject.contains('@')
                && identity.canvas_user_id.as_deref() != Some("profile-only@example.test")
        }));
    }

    for name in [
        "quarantined_pair_cannot_reactivate",
        "quarantined_numeric_id_cannot_move_to_a_third_subject",
    ] {
        let current = case(name);
        let status = service
            .record_verified_launch(
                &platform,
                &verified(
                    current["subject"].as_str().unwrap(),
                    current["canvas_user_id"].as_str(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(status, current["expected_status"]);
    }
    let identities = repository.identities.lock().unwrap();
    assert_eq!(identities.len(), 3);
    assert!(identities
        .iter()
        .all(|identity| identity.status == CanvasLtiIdentityStatus::Quarantined));
}

#[test]
fn binding_selection_is_tenant_bound_ordered_and_fail_closed_on_flags() {
    let platform = platform_from(&json!({
        "id": "platform-1",
        "organization_id": "org-1",
        "canvas_account_id": "account-1"
    }));
    let verified = VerifiedLtiLaunch {
        issuer: "https://canvas.instructure.com".to_owned(),
        subject: "student-1".to_owned(),
        audience: vec!["client-1".to_owned()],
        deployment_id: "deployment-1".to_owned(),
        nonce: Some("nonce-1".to_owned()),
        issued_at: None,
        expires_at: None,
        message_type: None,
        lti_version: None,
        target_link_uri: None,
        context: Some(json!({"id": "course-101"})),
        roles: vec![],
        learner_identity: json!({}),
        raw_claims: json!({}),
    };
    let base = binding_from(
        &json!({
            "id": "binding-1",
            "application_template_id": "app-1",
            "credential_template_id": "credential-1"
        }),
        &platform,
    );
    let mut wrong_tenant = base.clone();
    wrong_tenant.id = "wrong-tenant".to_owned();
    wrong_tenant.organization_id = "org-2".to_owned();
    let mut disabled = base.clone();
    disabled.id = "disabled".to_owned();
    disabled.enabled = false;
    let mut archived = base.clone();
    archived.id = "archived".to_owned();
    archived.archived = true;
    let mut selected = base.clone();
    selected.canvas_scope = json!({"course_id": "course-101"});

    assert_eq!(
        select_binding(
            &platform,
            &verified,
            &[wrong_tenant, disabled, archived, selected.clone()]
        )
        .unwrap()
        .id,
        selected.id
    );

    selected.feature_flags = json!({"enable_canvas_evidence": true});
    assert!(matches!(
        select_binding(&platform, &verified, &[selected]),
        Err(CanvasLtiLaunchPlanError::FeatureDisabled)
    ));
    assert!(feature_enabled(&json!({}), "enable_canvas_lti"));
    assert!(!feature_enabled(
        &json!({"enable_canvas_evidence": true}),
        "enable_canvas_lti"
    ));
}

#[tokio::test]
async fn launch_state_is_platform_bound_and_consumed_before_verification() {
    let repository = Arc::new(StateRepository::default());
    repository.insert(pending_state("platform-1", "state-1"));
    let service = CanvasLtiLaunchStateService::new(repository);

    assert!(matches!(
        service.claim("platform-2", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateUnknown)
    ));
    assert_eq!(
        service.claim("platform-1", "state-1").await.unwrap().status,
        "consumed"
    );
    assert!(matches!(
        service.claim("platform-1", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateExpired)
    ));
}

#[tokio::test]
async fn launch_state_claim_is_atomic_under_race() {
    let repository = Arc::new(StateRepository::default());
    repository.insert(pending_state("platform-1", "state-1"));
    let service = CanvasLtiLaunchStateService::new(repository);
    let first = service.clone();
    let second = service;
    let (first, second) = tokio::join!(
        first.claim("platform-1", "state-1"),
        second.claim("platform-1", "state-1")
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = if first.is_err() { first } else { second };
    assert!(matches!(loser, Err(CanvasLtiLaunchPlanError::StateExpired)));
}

#[tokio::test]
async fn expired_state_never_reaches_atomic_consume() {
    let repository = Arc::new(StateRepository::default());
    let mut expired = pending_state("platform-1", "state-1");
    expired.expired = true;
    repository.insert(expired);
    let service = CanvasLtiLaunchStateService::new(repository);

    assert!(matches!(
        service.claim("platform-1", "state-1").await,
        Err(CanvasLtiLaunchPlanError::StateExpired)
    ));
}
