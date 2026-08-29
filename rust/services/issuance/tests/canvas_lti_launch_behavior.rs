use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use marty_issuance_service::{
    canvas_lti_launch::{
        feature_enabled, launch_scope, plan_ags_line_item_pin, plan_verified_identity,
        private_launch_response, public_launch_response, scope_matches, select_binding,
        select_binding_with_staff_fallback, CanvasLtiAgsPinRepository, CanvasLtiAgsPinRequest,
        CanvasLtiAgsPinService, CanvasLtiAgsServiceUrlValidator, CanvasLtiIdentityRecord,
        CanvasLtiIdentityRepository, CanvasLtiIdentityRequest, CanvasLtiIdentityService,
        CanvasLtiIdentityStatus, CanvasLtiJwksRefreshService, CanvasLtiJwksRefresher,
        CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository, CanvasLtiLaunchStateService,
        CanvasLtiLaunchSubmission, CanvasLtiProgramBinding, CanvasLtiStoredLaunchState,
    },
    canvas_lti_login::CanvasLtiPlatform,
    canvas_lti_postgres::MartyCanvasLtiAgsServiceUrlValidator,
};
use marty_oid4vci::lti::VerifiedLtiLaunch;
use serde_json::{json, Value};

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
    }
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
