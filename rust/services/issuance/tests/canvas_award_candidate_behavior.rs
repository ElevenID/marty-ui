use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    canvas_award_candidate::{
        canvas_auto_approval_ready, plan_canvas_award_candidate_materialization,
        CanvasAwardCandidate, CanvasAwardCandidateMaterializationPlan, CanvasCandidateObservation,
        CanvasIdentityJoin, CanvasLinkedIdentity,
    },
    canvas_award_candidate_service::{
        CanvasAwardCandidateApprovalError, CanvasAwardCandidateApprover,
        CanvasAwardCandidateMaterializerConfig, CanvasAwardCandidateMaterializerService,
        CanvasAwardCandidateRepository, CanvasAwardCandidateRepositoryError,
        CanvasAwardCandidateSnapshot, CanvasEvidenceFactIdGenerator,
    },
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::canvas_lti_experience_session_context,
    canvas_lti_launch::{CanvasLtiClock, CanvasLtiStoredLaunchState},
};
use serde_json::{json, Map, Value};

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-lti-foundation.json"
    ))
    .expect("valid Canvas LTI contract")
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, 0)
        .single()
        .unwrap()
}

fn context() -> marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext {
    let vector = &contract()["experience"]["bootstrap"]["vector"];
    let values = &vector["session_values"];
    let mip_context = values
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "state" | "canvas_account_id" | "launch_url"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "candidate-session-id".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "private-session-digest".to_owned(),
        nonce: "private-session-nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": values["state"],
            "verified_launch": vector["verified_launch"],
            "mip_primitives": {"context": mip_context},
        }),
        expired: false,
    })
    .unwrap()
}

fn application() -> CanvasLtiBootstrapApplication {
    CanvasLtiBootstrapApplication {
        id: "application-1".to_owned(),
        organization_id: "org-1".to_owned(),
        application_template_id: "application-template-1".to_owned(),
        applicant_identifier: "canvas_lti:learner-subject-1".to_owned(),
        form_data: json!({}),
        integration_context: json!({"canvas": {"source": "canvas_lti_bootstrap"}}),
        status: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
    }
}

fn binding() -> Map<String, Value> {
    json!({
        "id": "binding-1",
        "organization_id": "org-1",
        "platform_id": "platform-1",
        "application_template_id": "application-template-1",
        "credential_template_id": "credential-template-1",
        "auto_approve_on_evidence": true,
        "enabled": true,
        "archived_at": null,
        "feature_flags": {"enable_canvas_evidence": true},
        "config_version": 3,
        "validated_config_version": 3,
        "readiness_checks": [{"code": "kms", "status": "ready", "blocking": true}],
        "readiness_validated_at": "2026-08-29T15:59:00Z",
        "credential_template_snapshot": {"id": "credential-template-1"},
        "evidence_requirements": [{
            "requirement_id": "score-1",
            "source": "ags_result",
            "fact_type": "canvas.assignment_score",
            "scope": {
                "course_id": "course-1",
                "resource_id": "marty:score",
                "line_item_url": "https://canvas.example.edu/api/lti/courses/1/line_items/1"
            },
            "pass_rule": {"min_score_percent": 80},
            "required": true
        }]
    })
    .as_object()
    .unwrap()
    .clone()
}

fn candidate(id: &str, observed_at: DateTime<Utc>) -> CanvasAwardCandidate {
    CanvasAwardCandidate {
        id: id.to_owned(),
        organization_id: "org-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        binding_id: "binding-1".to_owned(),
        learner_identity_id: None,
        canvas_user_id: None,
        lti_subject: Some("learner-subject-1".to_owned()),
        state: "pending_claim".to_owned(),
        observed_at,
    }
}

fn observation(observed_at: DateTime<Utc>) -> CanvasCandidateObservation {
    CanvasCandidateObservation {
        id: "observation-1".to_owned(),
        requirement_id: "score-1".to_owned(),
        assertion: json!({"completed": true, "score_percent": 95}),
        verification: json!({"status": "VERIFIED", "method": "LTI_AGS_RESULT_READ"}),
        payload_hash: "candidate-score-95".to_owned(),
        observed_at,
    }
}

#[test]
fn candidate_debug_output_redacts_identity_evidence_and_materialization_data() {
    let identity_secret = "private-linked-identity";
    let canvas_user_secret = "private-canvas-user";
    let subject_secret = "private-lti-subject";
    let assertion_secret = "private-assertion";
    let verification_secret = "private-verification";
    let fact_secret = "private-materialized-fact";
    let patch_secret = "private-application-patch";

    let mut private_candidate = candidate("candidate-safe-id", now());
    private_candidate.learner_identity_id = Some(identity_secret.to_owned());
    private_candidate.canvas_user_id = Some(canvas_user_secret.to_owned());
    private_candidate.lti_subject = Some(subject_secret.to_owned());
    let candidate_debug = format!("{private_candidate:?}");
    assert!(candidate_debug.contains("candidate-safe-id"));
    assert!(candidate_debug.contains("[REDACTED]"));
    for secret in [identity_secret, canvas_user_secret, subject_secret] {
        assert!(!candidate_debug.contains(secret));
    }

    let mut private_observation = observation(now());
    private_observation.assertion = json!({"secret": assertion_secret});
    private_observation.verification = json!({"secret": verification_secret});
    let observation_debug = format!("{private_observation:?}");
    assert!(observation_debug.contains("observation-1"));
    assert!(observation_debug.contains("[REDACTED]"));
    assert!(!observation_debug.contains(assertion_secret));
    assert!(!observation_debug.contains(verification_secret));

    let linked_identity = CanvasLinkedIdentity {
        id: "identity-safe-id".to_owned(),
        lti_subject: subject_secret.to_owned(),
        canvas_user_id: Some(canvas_user_secret.to_owned()),
        status: "linked".to_owned(),
    };
    let identity_debug = format!("{linked_identity:?}");
    assert!(identity_debug.contains("identity-safe-id"));
    assert!(identity_debug.contains("[REDACTED]"));
    assert!(!identity_debug.contains(subject_secret));
    assert!(!identity_debug.contains(canvas_user_secret));

    let materialization = CanvasAwardCandidateMaterializationPlan {
        candidate_id: "candidate-safe-id".to_owned(),
        lti_subject: Some(subject_secret.to_owned()),
        canvas_user_id: Some(canvas_user_secret.to_owned()),
        learner_identity_id: Some(identity_secret.to_owned()),
        facts: vec![json!({"secret": fact_secret})],
        application_canvas_patch: json!({"secret": patch_secret}).as_object().unwrap().clone(),
        materialized_at: now(),
    };
    let materialization_debug = format!("{materialization:?}");
    assert!(materialization_debug.contains("candidate-safe-id"));
    assert!(materialization_debug.contains("[REDACTED]"));
    for secret in [
        subject_secret,
        canvas_user_secret,
        identity_secret,
        fact_secret,
        patch_secret,
    ] {
        assert!(!materialization_debug.contains(secret));
    }
}

#[test]
fn subject_candidate_materializes_exact_authoritative_fact_and_links() {
    let policy = &contract()["experience"]["bootstrap"]["candidate_materialization"];
    assert_eq!(policy["first-matching-candidate"], true);
    assert_eq!(
        policy["numeric-rest-match"],
        "exact-current-non-quarantined-subject-and-canvas-user-identity-join"
    );
    let stale = candidate(
        "candidate-stale-first",
        now() - chrono::Duration::seconds(901),
    );
    let fresh = candidate("candidate-fresh", now() - chrono::Duration::seconds(60));
    assert!(plan_canvas_award_candidate_materialization(
        &context(),
        &application(),
        &binding(),
        &[stale, fresh.clone()],
        CanvasIdentityJoin::default(),
        &[observation(now() - chrono::Duration::seconds(30))],
        now(),
        Duration::from_secs(900),
        || "fact-1".to_owned(),
    )
    .is_none());

    let plan = plan_canvas_award_candidate_materialization(
        &context(),
        &application(),
        &binding(),
        &[fresh],
        CanvasIdentityJoin::default(),
        &[observation(now() - chrono::Duration::seconds(30))],
        now(),
        Duration::from_secs(900),
        || "fact-1".to_owned(),
    )
    .unwrap();
    assert_eq!(plan.candidate_id, "candidate-fresh");
    assert_eq!(plan.lti_subject.as_deref(), Some("learner-subject-1"));
    assert_eq!(plan.canvas_user_id.as_deref(), Some("42"));
    assert_eq!(plan.learner_identity_id, None);
    assert_eq!(
        plan.application_canvas_patch,
        json!({
            "canvas_award_candidate_id": "candidate-fresh",
            "candidate_materialized_at": "2026-08-29T16:00:00+00:00"
        })
        .as_object()
        .unwrap()
        .clone()
    );
    assert_eq!(plan.facts.len(), 1);
    let fact = &plan.facts[0];
    assert_eq!(fact["id"], "fact-1");
    assert_eq!(fact["subject_id"], "learner-subject-1");
    assert_eq!(fact["verification"]["method"], "LTI_AGS_RESULT_READ");
    assert_eq!(
        fact["payload_hash"],
        "2bcf7b67851e3e440fed3bb219fb588b1531420c8d96058cefb10132a0d3f35d"
    );
    assert_eq!(fact["source_revision"], fact["payload_hash"]);
    assert_eq!(
        fact["source"]["provider_event_id"],
        "82a8a9bf-fe4f-5534-a145-658c845f3c15"
    );
    assert_eq!(
        fact["logical_key"],
        "99f5f364cb3f7b4d84dcb4a28726f5a98b94feb87257eff803e87d86b96dbd66"
    );
    assert_eq!(fact["observed_at"], "2026-08-29T15:59:30+00:00");
    assert_eq!(fact["effective_at"], fact["observed_at"]);
}

#[test]
fn numeric_candidate_requires_one_exact_current_linked_identity() {
    let mut numeric = candidate("candidate-numeric", now());
    numeric.canvas_user_id = Some("42".to_owned());
    numeric.learner_identity_id = Some("identity-1".to_owned());
    let identity = CanvasLinkedIdentity {
        id: "identity-1".to_owned(),
        lti_subject: "learner-subject-1".to_owned(),
        canvas_user_id: Some("42".to_owned()),
        status: "linked".to_owned(),
    };
    let plan = |by_subject, by_canvas_user| {
        plan_canvas_award_candidate_materialization(
            &context(),
            &application(),
            &binding(),
            &[numeric.clone()],
            CanvasIdentityJoin {
                by_subject,
                by_canvas_user,
            },
            &[observation(now())],
            now(),
            Duration::from_secs(900),
            || "fact-1".to_owned(),
        )
    };
    assert_eq!(
        plan(Some(&identity), Some(&identity))
            .unwrap()
            .learner_identity_id
            .as_deref(),
        Some("identity-1")
    );
    let subject_only = candidate("candidate-subject-with-link", now());
    assert_eq!(
        plan_canvas_award_candidate_materialization(
            &context(),
            &application(),
            &binding(),
            &[subject_only],
            CanvasIdentityJoin {
                by_subject: Some(&identity),
                by_canvas_user: Some(&identity),
            },
            &[observation(now())],
            now(),
            Duration::from_secs(900),
            || "fact-1".to_owned(),
        )
        .unwrap()
        .learner_identity_id
        .as_deref(),
        Some("identity-1")
    );
    let mut quarantined = identity.clone();
    quarantined.status = "quarantined".to_owned();
    assert!(plan(Some(&quarantined), Some(&quarantined)).is_none());
    let mut conflicting = identity.clone();
    conflicting.id = "identity-2".to_owned();
    assert!(plan(Some(&identity), Some(&conflicting)).is_none());
    assert!(plan(Some(&identity), None).is_none());
}

#[test]
fn candidate_and_required_observation_freshness_fail_closed() {
    let candidate = candidate("candidate-1", now());
    let planned = |binding: &Map<String, Value>, observation: CanvasCandidateObservation| {
        plan_canvas_award_candidate_materialization(
            &context(),
            &application(),
            binding,
            std::slice::from_ref(&candidate),
            CanvasIdentityJoin::default(),
            &[observation],
            now(),
            Duration::from_secs(900),
            || "fact-1".to_owned(),
        )
    };
    let mut unverified = observation(now());
    unverified.verification["status"] = json!("UNVERIFIED");
    assert!(planned(&binding(), unverified).is_none());
    assert!(planned(
        &binding(),
        observation(now() - chrono::Duration::seconds(901))
    )
    .is_none());
    assert!(planned(
        &binding(),
        observation(now() + chrono::Duration::seconds(1))
    )
    .is_none());
    let mut below_threshold = observation(now());
    below_threshold.assertion["score_percent"] = json!(79);
    assert!(planned(&binding(), below_threshold).is_none());
    let mut invalid_binding = binding();
    invalid_binding["evidence_requirements"][0]["browser_extension"] = json!(true);
    assert!(planned(&invalid_binding, observation(now())).is_none());
}

#[test]
fn fact_hash_matches_python_canonical_unicode_escaping() {
    let mut observed = observation(now());
    observed.assertion["note"] = json!("\u{1f393}\u{e9}");
    observed.payload_hash = "candidate-score-unicode".to_owned();
    let plan = plan_canvas_award_candidate_materialization(
        &context(),
        &application(),
        &binding(),
        &[candidate("candidate-1", now())],
        CanvasIdentityJoin::default(),
        &[observed],
        now(),
        Duration::from_secs(900),
        || "fact-1".to_owned(),
    )
    .unwrap();
    assert_eq!(
        plan.facts[0]["payload_hash"],
        "ccc61167b54377a217f56ab3cf2cf3a2a46fab1b3b34234bbe92106a51c563ce"
    );
    assert_eq!(
        plan.facts[0]["source"]["provider_event_id"],
        "c89b2e22-3e78-5f4e-8b58-7bb1b431c535"
    );
}

#[test]
fn auto_approval_rechecks_feature_and_current_readiness() {
    let mut value = binding();
    assert!(canvas_auto_approval_ready(
        &value,
        now(),
        Duration::from_secs(900)
    ));
    value["feature_flags"] = json!({"enable_canvas_evidence": false});
    assert!(!canvas_auto_approval_ready(
        &value,
        now(),
        Duration::from_secs(900)
    ));
    value = binding();
    value["validated_config_version"] = json!(2);
    assert!(!canvas_auto_approval_ready(
        &value,
        now(),
        Duration::from_secs(900)
    ));
    value = binding();
    value["readiness_validated_at"] = json!("2026-08-29T15:44:59Z");
    assert!(!canvas_auto_approval_ready(
        &value,
        now(),
        Duration::from_secs(900)
    ));
}

struct MaterializationRepository {
    events: Arc<Mutex<Vec<String>>>,
    snapshot: Mutex<Option<CanvasAwardCandidateSnapshot>>,
    observations: Vec<CanvasCandidateObservation>,
    policy_allowed: bool,
}

#[async_trait]
impl CanvasAwardCandidateRepository for MaterializationRepository {
    async fn load_snapshot(
        &self,
        _context: &marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext,
        _application: &CanvasLtiBootstrapApplication,
    ) -> Result<Option<CanvasAwardCandidateSnapshot>, CanvasAwardCandidateRepositoryError> {
        self.events.lock().unwrap().push("load".to_owned());
        Ok(self.snapshot.lock().unwrap().clone())
    }

    async fn current_observations(
        &self,
        _organization_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CanvasCandidateObservation>, CanvasAwardCandidateRepositoryError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("observations:{candidate_id}"));
        Ok(self.observations.clone())
    }

    async fn record_fact_and_evaluate_policy(
        &self,
        _application: &CanvasLtiBootstrapApplication,
        _binding: &Map<String, Value>,
        _application_template: &Map<String, Value>,
        fact: &Value,
    ) -> Result<bool, CanvasAwardCandidateRepositoryError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("fact:{}", fact["id"].as_str().unwrap()));
        Ok(self.policy_allowed)
    }

    async fn link_candidate(
        &self,
        _application: &CanvasLtiBootstrapApplication,
        plan: &marty_issuance_service::canvas_award_candidate::CanvasAwardCandidateMaterializationPlan,
    ) -> Result<(), CanvasAwardCandidateRepositoryError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("link:{}", plan.candidate_id));
        Ok(())
    }
}

struct MaterializationApprover {
    events: Arc<Mutex<Vec<String>>>,
    result: CanvasAwardCandidateApprovalError,
    succeeds: bool,
}

#[async_trait]
impl CanvasAwardCandidateApprover for MaterializationApprover {
    async fn approve_if_ready(
        &self,
        _context: &marty_issuance_service::canvas_lti_experience::CanvasLtiExperienceSessionContext,
        _application: &CanvasLtiBootstrapApplication,
        plan: &marty_issuance_service::canvas_award_candidate::CanvasAwardCandidateMaterializationPlan,
        policy_allowed: bool,
    ) -> Result<(), CanvasAwardCandidateApprovalError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("approve:{}:{policy_allowed}", plan.candidate_id));
        if self.succeeds {
            Ok(())
        } else {
            Err(self.result.clone())
        }
    }
}

struct FixedFactIds;

impl CanvasEvidenceFactIdGenerator for FixedFactIds {
    fn generate(&self) -> String {
        "fact-service-1".to_owned()
    }
}

struct FixedClock;

impl CanvasLtiClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        now()
    }
}

fn service_config(enabled: bool, pilot: bool) -> CanvasAwardCandidateMaterializerConfig {
    CanvasAwardCandidateMaterializerConfig {
        enabled,
        pilot_organizations: if pilot {
            BTreeSet::from(["org-1".to_owned()])
        } else {
            BTreeSet::new()
        },
        evidence_max_age: Duration::from_secs(900),
    }
}

fn service_repository(events: Arc<Mutex<Vec<String>>>) -> Arc<MaterializationRepository> {
    Arc::new(MaterializationRepository {
        events,
        snapshot: Mutex::new(Some(CanvasAwardCandidateSnapshot {
            binding: binding(),
            application_template: json!({
                "id": "application-template-1",
                "organization_id": "org-1",
                "approval_policy_set_id": null,
            })
            .as_object()
            .unwrap()
            .clone(),
            candidates: vec![candidate("candidate-service", now())],
            identity_by_subject: None,
            identity_by_canvas_user: None,
        })),
        observations: vec![observation(now())],
        policy_allowed: true,
    })
}

#[tokio::test]
async fn materializer_service_preserves_order_and_ignores_only_readiness_drift() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let repository = service_repository(events.clone());
    let approver = Arc::new(MaterializationApprover {
        events: events.clone(),
        result: CanvasAwardCandidateApprovalError::ReadinessDrift,
        succeeds: false,
    });
    let service = CanvasAwardCandidateMaterializerService::new(
        repository,
        approver,
        Arc::new(FixedFactIds),
        Arc::new(FixedClock),
        service_config(true, true),
    );
    service
        .materialize_candidate(&context(), &application())
        .await
        .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "load",
            "observations:candidate-service",
            "fact:fact-service-1",
            "link:candidate-service",
            "approve:candidate-service:true",
        ]
    );
}

#[tokio::test]
async fn materializer_service_pilot_noops_and_dependency_failures_propagate() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let repository = service_repository(events.clone());
    let service = CanvasAwardCandidateMaterializerService::new(
        repository,
        Arc::new(MaterializationApprover {
            events: events.clone(),
            result: CanvasAwardCandidateApprovalError::Unavailable,
            succeeds: true,
        }),
        Arc::new(FixedFactIds),
        Arc::new(FixedClock),
        service_config(true, false),
    );
    service
        .materialize_candidate(&context(), &application())
        .await
        .unwrap();
    assert!(events.lock().unwrap().is_empty());

    let repository = service_repository(events.clone());
    let service = CanvasAwardCandidateMaterializerService::new(
        repository,
        Arc::new(MaterializationApprover {
            events,
            result: CanvasAwardCandidateApprovalError::Unavailable,
            succeeds: false,
        }),
        Arc::new(FixedFactIds),
        Arc::new(FixedClock),
        service_config(true, true),
    );
    assert_eq!(
        service
            .materialize_candidate(&context(), &application())
            .await,
        Err(CanvasAwardCandidateRepositoryError::Unavailable)
    );
}
