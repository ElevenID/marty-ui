use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    canvas_lti_evidence::{
        project_canvas_lti_evidence_status, CanvasLtiEvidenceApplication, CanvasLtiEvidenceBinding,
        CanvasLtiEvidenceCandidate, CanvasLtiEvidenceError, CanvasLtiEvidenceFact,
        CanvasLtiEvidencePlatform, CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceRepository,
        CanvasLtiEvidenceScope, CanvasLtiEvidenceService, CanvasLtiEvidenceSyncJob,
        CanvasLtiEvidenceSyncTarget,
    },
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionContext,
        CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{
        CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository, CanvasLtiStoredLaunchState,
    },
    http::router_with_canvas_lti_evidence,
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

fn time(minute: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, minute, 0).unwrap()
}

fn requirements() -> Vec<Value> {
    vec![
        json!({
            "requirement_id": "required-score",
            "source": "ags_result",
            "fact_type": "canvas.assignment_score",
            "scope": {"course_id": "course-42", "resource_id": "resource-1"},
            "pass_rule": {"min_score_percent": 80},
            "required": true
        }),
        json!({
            "requirement_id": "optional-module",
            "source": "canvas_rest",
            "fact_type": "canvas.module_completion",
            "scope": {"course_id": "course-42", "module_id": "module-1"},
            "pass_rule": {"completed": true},
            "required": false
        }),
    ]
}

fn scope() -> CanvasLtiEvidenceScope {
    CanvasLtiEvidenceScope {
        application: CanvasLtiEvidenceApplication {
            id: "application-1".to_owned(),
            organization_id: "org-1".to_owned(),
            application_template_id: "application-template-1".to_owned(),
            status: "approved".to_owned(),
            credential_id: None,
            integration_context: json!({"canvas": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "canvas_award_candidate_id": "candidate-1",
                "lti_state": "launch-state-1",
                "last_lti_state": "launch-state-2",
                "lti_states": ["launch-state-1", "launch-state-2"]
            }}),
        },
        binding: CanvasLtiEvidenceBinding {
            id: "binding-1".to_owned(),
            organization_id: "org-1".to_owned(),
            platform_id: "platform-1".to_owned(),
            application_template_id: "application-template-1".to_owned(),
            evidence_requirements: requirements(),
            config_version: 7,
        },
        platform: CanvasLtiEvidencePlatform {
            id: "platform-1".to_owned(),
            organization_id: "org-1".to_owned(),
        },
    }
}

fn verified_fact(requirement_id: &str, observed_minute: u32) -> CanvasLtiEvidenceFact {
    CanvasLtiEvidenceFact {
        provider: "canvas".to_owned(),
        requirement_id: Some(requirement_id.to_owned()),
        source: json!({"source": "ags_result"}),
        verification: json!({"status": "verified"}),
        observed_at: time(observed_minute),
    }
}

fn target() -> CanvasLtiEvidenceSyncTarget {
    CanvasLtiEvidenceSyncTarget {
        id: "target-1".to_owned(),
        application_id: Some("application-1".to_owned()),
        binding_id: "binding-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        config_version: 7,
    }
}

#[test]
fn projection_requires_current_config_success_and_returns_only_browser_safe_counts() {
    let response = project_canvas_lti_evidence_status(
        &scope(),
        &CanvasLtiEvidenceProjectionData {
            facts: vec![
                verified_fact("required-score", 10),
                CanvasLtiEvidenceFact {
                    source: json!({"source": "canvas_rest"}),
                    ..verified_fact("optional-module", 12)
                },
                CanvasLtiEvidenceFact {
                    provider: "forged-provider".to_owned(),
                    ..verified_fact("required-score", 15)
                },
            ],
            target: Some(target()),
            jobs: vec![
                CanvasLtiEvidenceSyncJob {
                    id: "job-current".to_owned(),
                    status: "leased".to_owned(),
                    result: json!({}),
                    created_at: time(20),
                    completed_at: None,
                },
                CanvasLtiEvidenceSyncJob {
                    id: "job-success".to_owned(),
                    status: "succeeded".to_owned(),
                    result: json!({"config_version": 7, "policy_allowed": true}),
                    created_at: time(5),
                    completed_at: Some(time(8)),
                },
            ],
            candidate: Some(CanvasLtiEvidenceCandidate {
                id: "candidate-1".to_owned(),
                application_id: Some("application-1".to_owned()),
                binding_id: "binding-1".to_owned(),
                platform_id: "platform-1".to_owned(),
                state: "pending_claim".to_owned(),
            }),
        },
    )
    .unwrap();

    assert_eq!(response.application_status, "approved");
    assert_eq!(response.sync.as_ref().unwrap().job_id, "job-current");
    assert_eq!(response.sync.as_ref().unwrap().status, "running");
    assert_eq!(
        response.sync.as_ref().unwrap().requested_at,
        "2026-08-29T16:20:00+00:00"
    );
    assert_eq!(response.evidence.required_count, 1);
    assert_eq!(response.evidence.current_authoritative_count, 2);
    assert_eq!(response.evidence.verified_authoritative_count, 2);
    assert_eq!(response.evidence.verified_required_count, 1);
    assert_eq!(response.evidence.status, "verified");
    assert_eq!(
        response.evidence.last_observed_at.as_deref(),
        Some("2026-08-29T16:12:00+00:00")
    );
    assert_eq!(response.policy.status, "permitted");
    assert_eq!(response.claim.status, "ready_to_claim");
    assert!(response.claim.unsigned);
    assert!(response.claim.available);
}

#[test]
fn projection_hides_colliding_targets_and_requires_a_scoped_candidate() {
    let mut mismatched_target = target();
    mismatched_target.binding_id = "other-binding".to_owned();
    let response = project_canvas_lti_evidence_status(
        &CanvasLtiEvidenceScope {
            application: CanvasLtiEvidenceApplication {
                status: "pending".to_owned(),
                ..scope().application
            },
            ..scope()
        },
        &CanvasLtiEvidenceProjectionData {
            facts: vec![verified_fact("required-score", 10)],
            target: Some(mismatched_target),
            jobs: vec![CanvasLtiEvidenceSyncJob {
                id: "foreign-job".to_owned(),
                status: "succeeded".to_owned(),
                result: json!({"config_version": 7, "policy_allowed": true}),
                created_at: time(5),
                completed_at: Some(time(8)),
            }],
            candidate: Some(CanvasLtiEvidenceCandidate {
                id: "candidate-1".to_owned(),
                application_id: Some("other-application".to_owned()),
                binding_id: "binding-1".to_owned(),
                platform_id: "platform-1".to_owned(),
                state: "claimed".to_owned(),
            }),
        },
    )
    .unwrap();

    assert!(response.sync.is_none());
    assert_eq!(response.evidence.status, "partial");
    assert_eq!(response.evidence.verified_authoritative_count, 0);
    assert_eq!(response.policy.status, "not_evaluated");
    assert_eq!(response.claim.status, "not_available");
}

#[test]
fn projection_preserves_claim_priority_and_rejects_invalid_requirements() {
    let mut claimed = scope();
    claimed.application.credential_id = Some("credential-1".to_owned());
    let response =
        project_canvas_lti_evidence_status(&claimed, &CanvasLtiEvidenceProjectionData::default())
            .unwrap();
    assert_eq!(response.claim.status, "claimed");
    assert!(!response.claim.unsigned);

    let mut invalid = scope();
    invalid.binding.evidence_requirements.clear();
    assert_eq!(
        project_canvas_lti_evidence_status(&invalid, &CanvasLtiEvidenceProjectionData::default())
            .unwrap_err(),
        CanvasLtiEvidenceError::EvidenceConfigurationUnavailable
    );
}

#[test]
fn projection_rejects_unknown_durable_job_statuses() {
    assert_eq!(
        project_canvas_lti_evidence_status(
            &scope(),
            &CanvasLtiEvidenceProjectionData {
                target: Some(target()),
                jobs: vec![CanvasLtiEvidenceSyncJob {
                    id: "job-unknown".to_owned(),
                    status: "unexpected".to_owned(),
                    result: json!({}),
                    created_at: time(20),
                    completed_at: None,
                }],
                ..CanvasLtiEvidenceProjectionData::default()
            }
        )
        .unwrap_err(),
        CanvasLtiEvidenceError::RepositoryUnavailable
    );
}

#[derive(Clone)]
struct SessionRepository(CanvasLtiStoredLaunchState);

#[async_trait]
impl CanvasLtiLaunchStateRepository for SessionRepository {
    async fn get_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok(Some(self.0.clone()))
    }

    async fn consume_launch_state(
        &self,
        _state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        unreachable!("evidence reads never consume a session")
    }
}

struct Repository {
    scope: Option<CanvasLtiEvidenceScope>,
    data: CanvasLtiEvidenceProjectionData,
}

#[async_trait]
impl CanvasLtiEvidenceRepository for Repository {
    async fn load_scope(
        &self,
        _context: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiEvidenceScope>, CanvasLtiEvidenceError> {
        Ok(self.scope.clone())
    }

    async fn load_projection_data(
        &self,
        _scope: &CanvasLtiEvidenceScope,
    ) -> Result<CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceError> {
        Ok(self.data.clone())
    }
}

fn stored_session(application_id: Option<&str>) -> CanvasLtiStoredLaunchState {
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "session-id-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "session-digest".to_owned(),
        nonce: "session-nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state-2",
            "verified_launch": {"raw_claims": {}},
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1",
                "application_id": application_id
            }}
        }),
        expired: false,
    })
    .unwrap()
    .launch_state
}

fn service(
    session: CanvasLtiStoredLaunchState,
    scope: Option<CanvasLtiEvidenceScope>,
    portable_enabled: bool,
) -> CanvasLtiEvidenceService {
    CanvasLtiEvidenceService::new(
        CanvasLtiExperienceSessionService::new(Arc::new(SessionRepository(session))),
        Arc::new(Repository {
            scope,
            data: CanvasLtiEvidenceProjectionData::default(),
        }),
        portable_enabled,
        BTreeSet::from(["org-1".to_owned()]),
    )
}

fn service_app(service: CanvasLtiEvidenceService) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_lti_evidence(
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

#[tokio::test]
async fn service_resolves_only_the_session_application_and_preserves_gate_order() {
    assert_eq!(
        service(stored_session(None), Some(scope()), true)
            .status("token")
            .await
            .unwrap_err(),
        CanvasLtiEvidenceError::BootstrapRequired
    );
    assert_eq!(
        service(stored_session(Some("application-1")), None, true)
            .status("token")
            .await
            .unwrap_err(),
        CanvasLtiEvidenceError::ContextNotFound
    );
    assert_eq!(
        service(stored_session(Some("application-1")), Some(scope()), false)
            .status("token")
            .await
            .unwrap_err(),
        CanvasLtiEvidenceError::PilotDisabled
    );
}

#[tokio::test]
async fn evidence_status_http_requires_session_bearer_and_disables_browser_caching() {
    let path = "/v1/integrations/canvas/lti/experience-sessions/current/evidence-status";
    let make_app = || {
        service_app(service(
            stored_session(Some("application-1")),
            Some(scope()),
            true,
        ))
    };

    let unauthorized = make_app()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.headers()[header::WWW_AUTHENTICATE], "Bearer");

    let response = make_app()
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, "Bearer private-session-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let body = response_json(response).await;
    assert_eq!(body["application_status"], "approved");
    assert_eq!(body["evidence"]["status"], "not_observed");
    assert_eq!(body["claim"]["status"], "ready_to_claim");

    let bootstrap_required = service_app(service(stored_session(None), Some(scope()), true))
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, "Bearer private-session-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bootstrap_required.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(bootstrap_required).await,
        json!({"detail": "Bootstrap the Canvas application before synchronizing evidence"})
    );
}
