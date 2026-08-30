use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_deep_linking::{
        plan_deep_linking_response, CanvasLtiDeepLinkingBinding, CanvasLtiDeepLinkingError,
        CanvasLtiDeepLinkingNonceGenerator, CanvasLtiDeepLinkingPersistenceScope,
        CanvasLtiDeepLinkingPlatform, CanvasLtiDeepLinkingRepository, CanvasLtiDeepLinkingService,
    },
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionContext,
        CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{
        CanvasLtiAgsServiceUrlValidator, CanvasLtiClock, CanvasLtiLaunchPlanError,
        CanvasLtiLaunchStateRepository, CanvasLtiStoredLaunchState,
    },
    canvas_lti_tool_signing::{CanvasLtiToolJwtSigner, CanvasLtiToolSigningError},
    http::router_with_canvas_lti_deep_linking,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 30, 0).unwrap()
}

fn generated_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn evidence_requirements() -> Vec<Value> {
    vec![
        json!({
            "requirement_id": "assignment-1",
            "source": "ags_result",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "course-42", "resource_id": "resource-1"},
            "pass_rule": {"min_score_percent": 80},
            "required": true,
        }),
        json!({
            "requirement_id": "module-1",
            "source": "canvas_rest",
            "fact_type": "canvas.module_completion",
            "scope": {"course_id": "course-42", "module_id": "module-1"},
            "pass_rule": {"completed": true},
            "required": true,
        }),
    ]
}

fn stored_session() -> CanvasLtiStoredLaunchState {
    CanvasLtiStoredLaunchState {
        id: "session-id-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "private-session-digest".to_owned(),
        nonce: "private-session-nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state-1",
            "verified_launch": {
                "issuer": "https://canvas.example.test",
                "deployment_id": "deployment-1",
                "roles": [
                    "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"
                ],
                "context": {
                    "id": "course-42",
                    "title": "Signed Course Title"
                },
                "raw_claims": {
                    "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
                        "deep_link_return_url": "https://canvas.example.test/deep-link-return",
                        "accept_types": ["ltiResourceLink"],
                        "accept_presentation_document_targets": ["iframe", "window"],
                        "data": "opaque-canvas-state"
                    }
                }
            },
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_template_id": "application-template-1",
                "credential_template_id": "credential-template-1",
                "lti_capabilities": {
                    "deep_linking": true,
                    "deep_link_return_url": "https://canvas.example.test/deep-link-return",
                    "deep_link_accept_types": ["ltiResourceLink"]
                }
            }}
        }),
        expired: false,
    }
}

fn context() -> CanvasLtiExperienceSessionContext {
    canvas_lti_experience_session_context(stored_session()).unwrap()
}

fn platform() -> CanvasLtiDeepLinkingPlatform {
    CanvasLtiDeepLinkingPlatform {
        id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        lti_client_id: Some("canvas-client-1".to_owned()),
        lti_deployment_id: Some("platform-deployment-1".to_owned()),
        lti_issuer: Some("https://platform-issuer.example.test".to_owned()),
        config_version: 7,
    }
}

fn binding() -> CanvasLtiDeepLinkingBinding {
    CanvasLtiDeepLinkingBinding {
        id: "binding-1".to_owned(),
        organization_id: "org-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        display_name: Some("Biology Credential".to_owned()),
        application_template_id: "application-template-1".to_owned(),
        credential_template_id: "credential-template-1".to_owned(),
        feature_flags: json!({"enable_canvas_deep_linking": true}),
        evidence_requirements: evidence_requirements(),
        config_version: 11,
    }
}

#[test]
fn plan_preserves_python_content_item_and_lti_claim_contract() {
    let nonce = generated_nonce();
    let plan = plan_deep_linking_response(
        &context(),
        &platform(),
        &binding(),
        Some("elevenid-tool-client"),
        "https://issuer.example.test/",
        &nonce,
        now(),
    )
    .unwrap();

    assert_eq!(plan.response.content_items.len(), 1);
    assert_eq!(
        plan.response.content_items[0],
        json!({
            "type": "ltiResourceLink",
            "title": "Biology Credential",
            "text": "Open the Marty credential application for this course.",
            "url": "https://issuer.example.test/v1/integrations/canvas/lti/platforms/platform-1/experience",
            "custom": {
                "canvas_account_id": "account-1",
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_template_id": "application-template-1",
                "credential_template_id": "credential-template-1",
                "canvas_course_id": "course-42",
                "canvas_requirement_id": "assignment-1",
                "canvas_resource_id": "resource-1"
            },
            "presentation": {"documentTarget": "window", "windowTarget": "_blank"},
            "lineItem": {
                "scoreMaximum": 100,
                "label": "Biology Credential",
                "resourceId": "resource-1",
                "tag": "marty:assignment-1"
            }
        })
    );
    assert_eq!(plan.jwt_payload["iss"], "elevenid-tool-client");
    assert_eq!(plan.jwt_payload["aud"], "https://canvas.example.test");
    assert_eq!(plan.jwt_payload["iat"], 1_788_021_000_i64);
    assert_eq!(plan.jwt_payload["exp"], 1_788_021_300_i64);
    assert_eq!(
        plan.jwt_payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"],
        "deployment-1"
    );
    assert_eq!(
        plan.jwt_payload["https://purl.imsglobal.org/spec/lti-dl/claim/data"],
        "opaque-canvas-state"
    );
    assert_eq!(plan.persistence_scope.platform_config_version, 7);
    assert_eq!(plan.persistence_scope.binding_config_version, 11);

    let plan_debug = format!("{plan:?}");
    assert!(plan_debug.contains("platform-1"));
    assert!(plan_debug.contains("[REDACTED]"));
    assert!(!plan_debug.contains("opaque-canvas-state"));
    assert!(!plan_debug.contains(&nonce));

    let mut private_scope = plan.persistence_scope.clone();
    private_scope.session_id = "private-session-id".to_owned();
    private_scope.session_state = "private-session-state".to_owned();
    let scope_debug = format!("{private_scope:?}");
    assert!(!scope_debug.contains("private-session-id"));
    assert!(!scope_debug.contains("private-session-state"));

    let mut private_response = plan.response;
    private_response.jwt = "private-deep-link-jwt".to_owned();
    private_response.form_post = json!({"secret": "private-form-post"});
    let response_debug = format!("{private_response:?}");
    assert!(response_debug.contains("platform-1"));
    assert!(response_debug.contains("[REDACTED]"));
    assert!(!response_debug.contains("private-deep-link-jwt"));
    assert!(!response_debug.contains("private-form-post"));
}

#[test]
fn plan_requires_string_signing_claims_and_uuid_compatible_nonce() {
    let nonce = generated_nonce();
    let mut fallback_context = context();
    fallback_context.verified_launch["issuer"] = Value::Null;
    fallback_context.verified_launch["deployment_id"] = json!("");
    let plan = plan_deep_linking_response(
        &fallback_context,
        &platform(),
        &binding(),
        None,
        "https://issuer.example.test",
        &nonce,
        now(),
    )
    .unwrap();
    assert_eq!(plan.jwt_payload["iss"], "canvas-client-1");
    assert_eq!(
        plan.jwt_payload["aud"],
        "https://platform-issuer.example.test"
    );
    assert_eq!(
        plan.jwt_payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"],
        "platform-deployment-1"
    );

    let mut no_client = platform();
    no_client.lti_client_id = None;
    assert_eq!(
        plan_deep_linking_response(
            &context(),
            &no_client,
            &binding(),
            None,
            "https://issuer.example.test",
            &nonce,
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::SigningClaimsInvalid
    );

    let mut non_string_audience = context();
    non_string_audience.verified_launch["issuer"] = json!({"unexpected": "issuer"});
    assert_eq!(
        plan_deep_linking_response(
            &non_string_audience,
            &platform(),
            &binding(),
            None,
            "https://issuer.example.test",
            &nonce,
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::SigningClaimsInvalid
    );

    let mut blank_deployment = context();
    blank_deployment.verified_launch["deployment_id"] = json!("   ");
    assert_eq!(
        plan_deep_linking_response(
            &blank_deployment,
            &platform(),
            &binding(),
            None,
            "https://issuer.example.test",
            &nonce,
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::SigningClaimsInvalid
    );

    assert_eq!(
        plan_deep_linking_response(
            &context(),
            &platform(),
            &binding(),
            None,
            "https://issuer.example.test",
            &format!("{nonce}0"),
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::NonceGenerationFailed
    );
}

#[test]
fn plan_emits_one_generic_item_without_ags_and_ordered_items_for_each_ags_requirement() {
    let nonce = generated_nonce();
    let mut without_ags = binding();
    without_ags.evidence_requirements = vec![without_ags.evidence_requirements[1].clone()];
    let plan = plan_deep_linking_response(
        &context(),
        &platform(),
        &without_ags,
        None,
        "https://issuer.example.test",
        &nonce,
        now(),
    )
    .unwrap();
    assert_eq!(plan.response.content_items.len(), 1);
    assert!(plan.response.content_items[0].get("lineItem").is_none());
    assert!(plan.response.content_items[0]["custom"]
        .get("canvas_requirement_id")
        .is_none());

    let mut multiple_ags = binding();
    let mut second = multiple_ags.evidence_requirements[0].clone();
    second["requirement_id"] = json!("assignment-2");
    second["scope"]["resource_id"] = json!("resource-2");
    multiple_ags.evidence_requirements.insert(1, second);
    let plan = plan_deep_linking_response(
        &context(),
        &platform(),
        &multiple_ags,
        None,
        "https://issuer.example.test",
        &nonce,
        now(),
    )
    .unwrap();
    assert_eq!(plan.response.content_items.len(), 2);
    assert_eq!(
        plan.response.content_items[0]["custom"]["canvas_requirement_id"],
        "assignment-1"
    );
    assert_eq!(
        plan.response.content_items[1]["custom"]["canvas_requirement_id"],
        "assignment-2"
    );
    assert_eq!(
        plan.response.content_items[1]["lineItem"]["resourceId"],
        "resource-2"
    );
}

#[test]
fn plan_rejects_capability_accept_type_return_url_and_evidence_drift() {
    let mut session_context = context();
    session_context.lti_capabilities = json!({"deep_linking": false});
    session_context
        .verified_launch
        .get_mut("raw_claims")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .clear();
    assert_eq!(
        plan_deep_linking_response(
            &session_context,
            &platform(),
            &binding(),
            None,
            "https://issuer.example.test",
            &generated_nonce(),
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::CapabilityMissing
    );

    let mut session_context = context();
    session_context.lti_capabilities["deep_link_accept_types"] = json!(["html"]);
    assert_eq!(
        plan_deep_linking_response(
            &session_context,
            &platform(),
            &binding(),
            None,
            "https://issuer.example.test",
            &generated_nonce(),
            now(),
        )
        .unwrap_err(),
        CanvasLtiDeepLinkingError::ResourceLinksNotAccepted
    );

    let mut binding = binding();
    binding.evidence_requirements[0]["scope"] = json!({"course_id": "course-42"});
    assert!(matches!(
        plan_deep_linking_response(
            &context(),
            &platform(),
            &binding,
            None,
            "https://issuer.example.test",
            &generated_nonce(),
            now(),
        ),
        Err(CanvasLtiDeepLinkingError::InvalidEvidenceRequirements(_))
    ));
}

#[derive(Default)]
struct SessionRepository {
    session: Mutex<Option<CanvasLtiStoredLaunchState>>,
}

#[async_trait]
impl CanvasLtiLaunchStateRepository for SessionRepository {
    async fn get_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok(self.session.lock().unwrap().clone())
    }

    async fn consume_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        unreachable!("Deep Linking never consumes its session")
    }
}

struct Repository {
    feature_enabled: Option<bool>,
    platform: Option<CanvasLtiDeepLinkingPlatform>,
    binding: Option<CanvasLtiDeepLinkingBinding>,
    persisted: Mutex<Vec<(CanvasLtiDeepLinkingPersistenceScope, Value)>>,
}

#[async_trait]
impl CanvasLtiDeepLinkingRepository for Repository {
    async fn bound_feature_enabled(
        &self,
        organization_id: &str,
        binding_id: &str,
    ) -> Result<Option<bool>, CanvasLtiDeepLinkingError> {
        assert_eq!(organization_id, "org-1");
        assert_eq!(binding_id, "binding-1");
        Ok(self.feature_enabled)
    }

    async fn get_platform(
        &self,
        _context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiDeepLinkingPlatform>, CanvasLtiDeepLinkingError> {
        Ok(self.platform.clone())
    }

    async fn get_binding(
        &self,
        _context: &CanvasLtiExperienceSessionContext,
        _platform: &CanvasLtiDeepLinkingPlatform,
    ) -> Result<Option<CanvasLtiDeepLinkingBinding>, CanvasLtiDeepLinkingError> {
        Ok(self.binding.clone())
    }

    async fn persist_response(
        &self,
        scope: &CanvasLtiDeepLinkingPersistenceScope,
        response_metadata: &Value,
    ) -> Result<(), CanvasLtiDeepLinkingError> {
        self.persisted
            .lock()
            .unwrap()
            .push((scope.clone(), response_metadata.clone()));
        Ok(())
    }
}

struct Validator(Mutex<Vec<String>>);

#[async_trait]
impl CanvasLtiAgsServiceUrlValidator for Validator {
    async fn validate(&self, service_url: &str) -> Result<String, String> {
        self.0.lock().unwrap().push(service_url.to_owned());
        Ok(format!("{}?trusted=1", service_url.trim_end_matches('/')))
    }
}

struct Signer(Mutex<Vec<Value>>);

#[async_trait]
impl CanvasLtiToolJwtSigner for Signer {
    async fn sign_jwt(&self, payload: &Value) -> Result<String, CanvasLtiToolSigningError> {
        self.0.lock().unwrap().push(payload.clone());
        Ok("signed.deep-link.jwt".to_owned())
    }

    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        unreachable!("Deep Linking does not publish keys")
    }
}

struct FailingSigner;

#[async_trait]
impl CanvasLtiToolJwtSigner for FailingSigner {
    async fn sign_jwt(&self, _payload: &Value) -> Result<String, CanvasLtiToolSigningError> {
        Err(CanvasLtiToolSigningError::SigningFailed(
            "private-signing-outage-detail".to_owned(),
        ))
    }

    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        unreachable!("Deep Linking does not publish keys")
    }
}

struct FixedClock;

impl CanvasLtiClock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        now()
    }
}

struct FixedNonce;

impl CanvasLtiDeepLinkingNonceGenerator for FixedNonce {
    fn generate(&self) -> String {
        generated_nonce()
    }
}

struct InvalidNonce;

impl CanvasLtiDeepLinkingNonceGenerator for InvalidNonce {
    fn generate(&self) -> String {
        format!("{}0", generated_nonce())
    }
}

fn service(
    session: CanvasLtiStoredLaunchState,
    repository: Arc<Repository>,
    validator: Arc<Validator>,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
) -> CanvasLtiDeepLinkingService {
    service_with_nonce(session, repository, validator, signer, Arc::new(FixedNonce))
}

fn service_with_nonce(
    session: CanvasLtiStoredLaunchState,
    repository: Arc<Repository>,
    validator: Arc<Validator>,
    signer: Arc<dyn CanvasLtiToolJwtSigner>,
    nonce_generator: Arc<dyn CanvasLtiDeepLinkingNonceGenerator>,
) -> CanvasLtiDeepLinkingService {
    CanvasLtiDeepLinkingService::new(
        CanvasLtiExperienceSessionService::new(Arc::new(SessionRepository {
            session: Mutex::new(Some(session)),
        })),
        repository,
        validator,
        signer,
        Arc::new(FixedClock),
        nonce_generator,
        true,
        BTreeSet::from(["org-1".to_owned()]),
        None,
        "https://issuer.example.test",
    )
}

fn service_app(service: CanvasLtiDeepLinkingService) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_lti_deep_linking(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.test", "Issuer"),
        TransportPolicy::new(Vec::new()),
        service,
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn assert_private_no_store(response: &axum::response::Response) {
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
}

#[tokio::test]
async fn service_validates_signs_and_persists_before_returning_browser_safe_response() {
    let repository = Arc::new(Repository {
        feature_enabled: Some(true),
        platform: Some(platform()),
        binding: Some(binding()),
        persisted: Mutex::new(Vec::new()),
    });
    let validator = Arc::new(Validator(Mutex::new(Vec::new())));
    let signer = Arc::new(Signer(Mutex::new(Vec::new())));
    let response = service(
        stored_session(),
        repository.clone(),
        validator.clone(),
        signer.clone(),
    )
    .create_response("private-session-token")
    .await
    .unwrap();

    assert_eq!(
        validator.0.lock().unwrap().as_slice(),
        ["https://canvas.example.test/deep-link-return"]
    );
    assert_eq!(signer.0.lock().unwrap().len(), 1);
    assert_eq!(response.jwt, "signed.deep-link.jwt");
    assert_eq!(
        response.deep_link_return_url,
        "https://canvas.example.test/deep-link-return?trusted=1"
    );
    assert_eq!(
        response.form_post,
        json!({
            "method": "POST",
            "action": "https://canvas.example.test/deep-link-return?trusted=1",
            "fields": {"JWT": "signed.deep-link.jwt"}
        })
    );
    let persisted = repository.persisted.lock().unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(
        persisted[0].1["created_at"],
        "2026-08-29T16:30:00.000000+00:00"
    );
    assert_eq!(
        persisted[0].1["content_items"],
        json!(response.content_items)
    );
}

#[tokio::test]
async fn service_preserves_dependency_order_and_fails_closed_for_role_and_binding_scope() {
    let repository = Arc::new(Repository {
        feature_enabled: Some(false),
        platform: Some(platform()),
        binding: Some(binding()),
        persisted: Mutex::new(Vec::new()),
    });
    let result = service(
        stored_session(),
        repository,
        Arc::new(Validator(Mutex::new(Vec::new()))),
        Arc::new(Signer(Mutex::new(Vec::new()))),
    )
    .create_response("token")
    .await;
    assert_eq!(
        result.unwrap_err(),
        CanvasLtiDeepLinkingError::FeatureDisabled
    );

    let mut session = stored_session();
    session.metadata["verified_launch"]["roles"] = json!(["Learner"]);
    let repository = Arc::new(Repository {
        feature_enabled: Some(true),
        platform: None,
        binding: None,
        persisted: Mutex::new(Vec::new()),
    });
    let result = service(
        session,
        repository,
        Arc::new(Validator(Mutex::new(Vec::new()))),
        Arc::new(Signer(Mutex::new(Vec::new()))),
    )
    .create_response("token")
    .await;
    assert_eq!(
        result.unwrap_err(),
        CanvasLtiDeepLinkingError::StaffRoleRequired
    );

    let mut mismatched = binding();
    mismatched.organization_id = "other-org".to_owned();
    let repository = Arc::new(Repository {
        feature_enabled: Some(true),
        platform: Some(platform()),
        binding: Some(mismatched),
        persisted: Mutex::new(Vec::new()),
    });
    let result = service(
        stored_session(),
        repository,
        Arc::new(Validator(Mutex::new(Vec::new()))),
        Arc::new(Signer(Mutex::new(Vec::new()))),
    )
    .create_response("token")
    .await;
    assert_eq!(
        result.unwrap_err(),
        CanvasLtiDeepLinkingError::BindingMismatch
    );
}

#[tokio::test]
async fn service_rejects_invalid_claims_and_nonce_before_signing() {
    let mut invalid_claims_session = stored_session();
    invalid_claims_session.metadata["verified_launch"]["issuer"] = json!({"unexpected": "issuer"});
    let signer = Arc::new(Signer(Mutex::new(Vec::new())));
    let result = service(
        invalid_claims_session,
        Arc::new(Repository {
            feature_enabled: Some(true),
            platform: Some(platform()),
            binding: Some(binding()),
            persisted: Mutex::new(Vec::new()),
        }),
        Arc::new(Validator(Mutex::new(Vec::new()))),
        signer.clone(),
    )
    .create_response("token")
    .await;
    assert_eq!(
        result.unwrap_err(),
        CanvasLtiDeepLinkingError::SigningClaimsInvalid
    );
    assert!(signer.0.lock().unwrap().is_empty());

    let signer = Arc::new(Signer(Mutex::new(Vec::new())));
    let result = service_with_nonce(
        stored_session(),
        Arc::new(Repository {
            feature_enabled: Some(true),
            platform: Some(platform()),
            binding: Some(binding()),
            persisted: Mutex::new(Vec::new()),
        }),
        Arc::new(Validator(Mutex::new(Vec::new()))),
        signer.clone(),
        Arc::new(InvalidNonce),
    )
    .create_response("token")
    .await;
    assert_eq!(
        result.unwrap_err(),
        CanvasLtiDeepLinkingError::NonceGenerationFailed
    );
    assert!(signer.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn http_route_requires_bearer_before_body_and_forbids_caller_owned_fields() {
    let make_app = || {
        service_app(service(
            stored_session(),
            Arc::new(Repository {
                feature_enabled: Some(true),
                platform: Some(platform()),
                binding: Some(binding()),
                persisted: Mutex::new(Vec::new()),
            }),
            Arc::new(Validator(Mutex::new(Vec::new()))),
            Arc::new(Signer(Mutex::new(Vec::new()))),
        ))
    };
    let path = "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response";

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("not-json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert_private_no_store(&response);

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer private-session-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"caller_owned":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_private_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["detail"][0]["type"], "extra_forbidden");
    assert_eq!(body["detail"][0]["loc"], json!(["body", "caller_owned"]));

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, "Bearer private-session-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_private_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(body["canvas_platform_id"], "platform-1");
    assert_eq!(body["jwt"], "signed.deep-link.jwt");
    assert_eq!(body["form_post"]["method"], "POST");
}

#[tokio::test]
async fn http_route_rejects_empty_untyped_malformed_non_object_and_oversized_bodies() {
    let make_app = || {
        service_app(service(
            stored_session(),
            Arc::new(Repository {
                feature_enabled: Some(true),
                platform: Some(platform()),
                binding: Some(binding()),
                persisted: Mutex::new(Vec::new()),
            }),
            Arc::new(Validator(Mutex::new(Vec::new()))),
            Arc::new(Signer(Mutex::new(Vec::new()))),
        ))
    };
    let path = "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response";
    let authorized = || (header::AUTHORIZATION, "Bearer private-session-token");

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(authorized().0, authorized().1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_private_no_store(&response);
    assert_eq!(
        response_json(response).await["detail"][0]["type"],
        "missing"
    );

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(authorized().0, authorized().1)
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(response).await["detail"][0]["type"],
        "model_attributes_type"
    );

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(authorized().0, authorized().1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(response).await["detail"][0]["type"],
        "json_invalid"
    );

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(authorized().0, authorized().1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response_json(response).await["detail"][0]["type"],
        "model_attributes_type"
    );

    let response = make_app()
        .oneshot(
            Request::post(path)
                .header(authorized().0, authorized().1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b' '; 64 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_private_no_store(&response);
}

#[tokio::test]
async fn http_route_sanitizes_signing_failures_and_prevents_caching() {
    let response = service_app(service(
        stored_session(),
        Arc::new(Repository {
            feature_enabled: Some(true),
            platform: Some(platform()),
            binding: Some(binding()),
            persisted: Mutex::new(Vec::new()),
        }),
        Arc::new(Validator(Mutex::new(Vec::new()))),
        Arc::new(FailingSigner),
    ))
    .oneshot(
        Request::post(
            "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response",
        )
        .header(header::AUTHORIZATION, "Bearer private-session-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private_no_store(&response);
    let body = response_json(response).await;
    assert_eq!(
        body,
        json!({"detail": "Canvas LTI tool signing is temporarily unavailable"})
    );
    assert!(!body.to_string().contains("private-signing-outage-detail"));

    let response = service_app(service_with_nonce(
        stored_session(),
        Arc::new(Repository {
            feature_enabled: Some(true),
            platform: Some(platform()),
            binding: Some(binding()),
            persisted: Mutex::new(Vec::new()),
        }),
        Arc::new(Validator(Mutex::new(Vec::new()))),
        Arc::new(Signer(Mutex::new(Vec::new()))),
        Arc::new(InvalidNonce),
    ))
    .oneshot(
        Request::post(
            "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response",
        )
        .header(header::AUTHORIZATION, "Bearer private-session-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_private_no_store(&response);
    assert_eq!(
        response_json(response).await,
        json!({"detail": "Canvas LTI tool signing is temporarily unavailable"})
    );
}
