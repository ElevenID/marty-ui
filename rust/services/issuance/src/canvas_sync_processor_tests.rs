
use std::sync::Mutex;

use super::*;

#[test]
fn roster_bounds_use_lossless_integer_grammar_and_clamp_before_conversion() {
    assert_eq!(
        CanvasRosterBounds::from_values(None, None).unwrap(),
        CanvasRosterBounds::new(500, 5000)
    );
    for (batch, limit, expected) in [
        ("0", "-9", (1, 1)),
        ("+1_000", "9", (1000, 1000)),
        ("\u{a0}+٢_٠٠٠\u{a0}", "１００００", (2000, 10000)),
        (
            "999999999999999999999999999999",
            "999999999999999999999999999999",
            (2000, 10000),
        ),
        (
            "-999999999999999999999999999999",
            "-999999999999999999999999999999",
            (1, 1),
        ),
    ] {
        let actual = CanvasRosterBounds::from_values(Some(batch), Some(limit)).unwrap();
        assert_eq!((actual.batch_size, actual.limit), expected);
    }
    let maximum_digits = "9".repeat(4300);
    assert_eq!(
        CanvasRosterBounds::from_values(Some(&maximum_digits), Some(&maximum_digits)).unwrap(),
        CanvasRosterBounds::new(2000, 10000)
    );
    for invalid in [
        "",
        " ",
        "synthetic-invalid-bound",
        "1__0",
        "1.5",
        "1e3",
        &"9".repeat(4301),
    ] {
        for (batch, limit) in [(Some(invalid), None), (None, Some(invalid))] {
            let error = CanvasRosterBounds::from_values(batch, limit).unwrap_err();
            assert_eq!(
                error,
                CanvasSyncProcessingError::terminal(
                    "canvas_roster_configuration_invalid",
                    "Canvas roster bounds are invalid"
                )
            );
            assert!(!format!("{error:?}").contains("synthetic-invalid-bound"));
        }
    }
}

#[tokio::test]
async fn roster_configuration_error_is_deferred_without_disabling_application_work() {
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(vec![requirement(
            "assignment",
            "canvas_rest",
            "canvas.assignment_score",
            json!({"course_id":"1","activity_id":"2"}),
            json!({"min_score_percent":70}),
        )]),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(None),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    let processor = NativeCanvasSyncProcessor::new_with_roster_configuration(
        repository.clone(),
        Arc::new(SimulatorProvider),
        enabled_config(),
        CanvasRosterBounds::from_values(Some("synthetic-invalid-bound"), None),
    );
    let error = run_simulated(&processor, target(CanvasSyncTargetType::BackgroundRoster))
        .await
        .unwrap_err();
    assert_eq!(error.code, "canvas_roster_configuration_invalid");
    assert_eq!(error.summary, "Canvas roster bounds are invalid");
    assert!(!error.retryable);
    assert!(repository.facts.lock().unwrap().is_empty());
    assert!(repository.candidates.lock().unwrap().is_empty());
    for kind in [
        CanvasSyncTargetType::LearnerApplication,
        CanvasSyncTargetType::IssuedDrift,
    ] {
        let result = run_simulated(&processor, target(kind)).await.unwrap();
        assert_eq!(
            result.get("requirements_checked").map(|value| value.get()),
            Some("1")
        );
    }
    assert_eq!(
        run_simulated(&processor, target(CanvasSyncTargetType::AwardCandidate))
            .await
            .unwrap_err()
            .code,
        "canvas_sync_target_type_unsupported"
    );
    let mut closed = processor;
    closed.config.portable_enabled = false;
    assert_eq!(
        run_simulated(&closed, target(CanvasSyncTargetType::BackgroundRoster))
            .await
            .unwrap()
            .get("no_change")
            .map(|value| value.get()),
        Some("true")
    );
}

#[tokio::test]
async fn frozen_validation_processor_cases_preserve_tracked_state_without_provider_reads() {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-oracle.json"
    ))
    .unwrap();
    // These seven are processor dispatch, not the thirteen repository
    // validation cases. The template-removal race remains native; this
    // isolated seam proves only its processor error after resources vanish.
    // The simulator's patch ports are no-op successes, so this is not
    // durable or comprehensive write-absence evidence; native replay owns
    // those effects.
    let expected = [
        (
            "invalid_roster_batch",
            "canvas_roster_configuration_invalid",
        ),
        (
            "invalid_roster_limit",
            "canvas_roster_configuration_invalid",
        ),
        (
            "invalid_roster_bounds_do_not_preempt_application",
            "canvas_lti_identity_missing",
        ),
        (
            "invalid_evidence_requirements",
            "canvas_requirements_invalid",
        ),
        ("missing_lti_subject", "canvas_lti_identity_missing"),
        (
            "unsupported_award_candidate",
            "canvas_sync_target_type_unsupported",
        ),
        (
            "template_removed_after_application_read",
            "canvas_application_template_unavailable",
        ),
    ];
    let discovered = scenarios["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] == "processor_dispatch")
        .map(|case| case["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(discovered.len(), expected.len());
    assert_eq!(
        discovered
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
            .iter()
            .map(|(name, _)| *name)
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(scenarios["cases"].as_array().unwrap().len(), 20);

    for (name, expected_code) in expected {
        let scenario = scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        assert_eq!(scenario["code"], expected_code, "{name}");
        let mut resources = simulator_resources(vec![requirement(
            "assignment",
            "canvas_rest",
            "canvas.assignment_score",
            json!({"course_id":"1","activity_id":"2"}),
            json!({"min_score_percent":70}),
        )]);
        let mut kind = CanvasSyncTargetType::LearnerApplication;
        let mut roster_batch = None;
        let mut roster_limit = None;
        match name {
            "invalid_roster_batch" => {
                kind = CanvasSyncTargetType::BackgroundRoster;
                roster_batch = Some("synthetic-invalid-bound");
            }
            "invalid_roster_limit" => {
                kind = CanvasSyncTargetType::BackgroundRoster;
                roster_limit = Some("synthetic-invalid-bound");
            }
            "invalid_roster_bounds_do_not_preempt_application" => {
                roster_batch = Some("synthetic-invalid-bound");
                roster_limit = Some("synthetic-invalid-bound");
                resources
                    .application
                    .as_mut()
                    .unwrap()
                    .application
                    .integration_context = json!({"canvas":{}});
            }
            "invalid_evidence_requirements" => {
                resources.binding.insert(
                    "evidence_requirements".into(),
                    json!([{
                        "requirement_id":"broken", "source":"canvas_rest",
                        "fact_type":"not-a-canvas-fact", "scope":{},
                        "pass_rule":{}, "required":true
                    }]),
                );
            }
            "missing_lti_subject" => {
                resources
                    .application
                    .as_mut()
                    .unwrap()
                    .application
                    .integration_context = json!({"canvas":{}});
            }
            "unsupported_award_candidate" => kind = CanvasSyncTargetType::AwardCandidate,
            "template_removed_after_application_read" => {
                resources.application_template = None;
            }
            _ => unreachable!(),
        }
        let repository = Arc::new(SimulatorRepository {
            resources,
            facts: Mutex::new(Vec::new()),
            identities: Mutex::new(None),
            candidates: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            observation_payloads: Mutex::new(BTreeMap::new()),
            cursor: Mutex::new(None),
            disabled: Mutex::new(false),
        });
        let provider = Arc::new(RunCountingProvider::default());
        let processor = NativeCanvasSyncProcessor::new_with_roster_configuration(
            repository.clone(),
            provider.clone(),
            enabled_config(),
            CanvasRosterBounds::from_values(roster_batch, roster_limit),
        );
        let mut case_target = target(kind);
        if matches!(kind, CanvasSyncTargetType::BackgroundRoster) {
            case_target.application_id = None;
        }
        if matches!(kind, CanvasSyncTargetType::AwardCandidate) {
            case_target.application_id = None;
            case_target.candidate_id = Some("candidate-unsupported".into());
        }
        let error = run_simulated(&processor, case_target).await.unwrap_err();
        let frozen = &oracle[name]["observations"][0]["jobs"][0];
        assert_eq!(error.code, expected_code, "{name}");
        assert_eq!(error.code, frozen["last_error_code"], "{name}");
        assert_eq!(error.summary, frozen["last_error_summary"], "{name}");
        assert!(!error.retryable, "{name}");
        assert_eq!(error.retry_after_seconds, None, "{name}");
        assert!(repository.facts.lock().unwrap().is_empty(), "{name}");
        assert!(repository.candidates.lock().unwrap().is_empty(), "{name}");
        assert!(repository.observations.lock().unwrap().is_empty(), "{name}");
        assert!(
            repository.observation_payloads.lock().unwrap().is_empty(),
            "{name}"
        );
        assert!(repository.identities.lock().unwrap().is_none(), "{name}");
        assert_eq!(*repository.cursor.lock().unwrap(), None, "{name}");
        assert!(!*repository.disabled.lock().unwrap(), "{name}");
        assert!(provider.calls.lock().unwrap().is_empty(), "{name}");
        assert!(
            provider
                .scoped_calls
                .lock()
                .unwrap()
                .iter()
                .all(|(_, _, action)| *action == "start"),
            "{name}: provider REST or roster read occurred"
        );
    }
}

#[test]
fn candidate_ags_projection_preserves_full_learner_and_rest_observations() {
    let record =
        json!({"id":"result-7","resultScore":90,"resultMaximum":100,"resultStatus":"FullyGraded"});
    let full = CanvasAuthoritativeObservation {
        assertion: ags_assertion(&record),
        source_payload: record.as_object().unwrap().clone(),
        verification_method: "LTI_AGS_RESULT_READ",
        effective_at: Some(Utc::now()),
    };
    let candidate = full.clone().into_candidate("ags_result");
    assert_eq!(
        candidate.assertion,
        json!({"completed":true,"score":90.0,"score_maximum":100.0,"score_percent":90.0})
            .as_object()
            .unwrap()
            .clone()
    );
    assert_eq!(
        candidate.source_payload,
        json!({"resultScore":90,"resultMaximum":100,"resultStatus":"FullyGraded"})
            .as_object()
            .unwrap()
            .clone()
    );
    assert_eq!(candidate.effective_at, full.effective_at);
    assert_eq!(candidate.verification_method, full.verification_method);
    assert_eq!(full.assertion["result_status"], "FullyGraded");
    assert_eq!(full.source_payload["id"], "result-7");
    assert_eq!(full.clone().into_candidate("canvas_rest"), full);
}

#[test]
fn all_four_provider_fact_projections_have_exact_assertion_semantics() {
    let assignment = rest_assertion(
        "canvas.assignment_score",
        &json!({
            "score": 8, "workflow_state": "graded", "assignment": {"points_possible": 10}
        }),
    );
    assert_eq!(assignment.get("completed"), Some(&Value::Bool(true)));
    assert_eq!(
        assignment.get("score_percent").and_then(Value::as_f64),
        Some(80.0)
    );
    let quiz = rest_assertion(
        "canvas.quiz_score",
        &json!({
            "score": 9, "workflow_state": "unsubmitted", "assignment": {"points_possible": 10}
        }),
    );
    assert_eq!(quiz.get("completed"), Some(&Value::Bool(false)));
    let module = rest_assertion("canvas.module_completion", &json!({"state": "completed"}));
    assert_eq!(module.get("completed"), Some(&Value::Bool(true)));
    let course = rest_assertion(
        "canvas.course_completion",
        &json!({
            "requirement_count": 3, "requirement_completed_count": 3
        }),
    );
    assert_eq!(course.get("completed"), Some(&Value::Bool(true)));
}

#[derive(Debug)]
struct SimulatorRepository {
    resources: CanvasSyncResources,
    facts: Mutex<Vec<Value>>,
    identities: Mutex<Option<BTreeMap<String, CanvasLinkedIdentitySnapshot>>>,
    candidates: Mutex<BTreeMap<String, CanvasRosterCandidate>>,
    observations: Mutex<BTreeMap<String, Vec<CanvasCandidateObservationSnapshot>>>,
    observation_payloads: Mutex<BTreeMap<(String, String), String>>,
    cursor: Mutex<Option<(usize, usize)>>,
    disabled: Mutex<bool>,
}

#[async_trait]
impl CanvasSyncProcessorRepository for SimulatorRepository {
    fn for_lease(
        self: Arc<Self>,
        lease: CanvasSyncLease,
    ) -> Arc<dyn CanvasSyncProcessorRepository> {
        assert_eq!(
            lease.organization_id,
            self.resources.platform.organization_id
        );
        self
    }
    async fn resources(
        &self,
        _: &CanvasSyncTarget,
    ) -> Result<Option<CanvasSyncResources>, CanvasSyncProcessingError> {
        Ok(Some(self.resources.clone()))
    }
    async fn linked_identity_by_subject(
        &self,
        _: &str,
        _: &str,
        _: &str,
        subject: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
        Ok(Some(CanvasLinkedIdentitySnapshot {
            id: "identity-1".into(),
            lti_subject: subject.into(),
            canvas_user_id: Some("42".into()),
            status: "linked".into(),
        }))
    }
    async fn linked_identity_by_canvas_user(
        &self,
        _: &str,
        _: &str,
        _: &str,
        user: &str,
    ) -> Result<Option<CanvasLinkedIdentitySnapshot>, CanvasSyncProcessingError> {
        if let Some(identities) = self.identities.lock().unwrap().as_ref() {
            return Ok(identities.get(user).cloned());
        }
        Ok(Some(CanvasLinkedIdentitySnapshot {
            id: format!("identity-{user}"),
            lti_subject: format!("subject-{user}"),
            canvas_user_id: Some(user.into()),
            status: "linked".into(),
        }))
    }
    async fn record_fact(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        fact: &Value,
    ) -> Result<CanvasFactCommit, CanvasSyncProcessingError> {
        self.facts.lock().unwrap().push(fact.clone());
        Ok(CanvasFactCommit {
            fact_id: text(fact.get("id")),
            inserted: true,
            policy_allowed: true,
        })
    }
    async fn patch_application_sync(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[String],
        _: bool,
    ) -> Result<bool, CanvasSyncProcessingError> {
        Ok(true)
    }
    async fn patch_platform_validation(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: Option<&str>,
    ) -> Result<bool, CanvasSyncProcessingError> {
        Ok(true)
    }
    async fn disable_target(&self, _: &CanvasSyncTarget) -> Result<(), CanvasSyncProcessingError> {
        *self.disabled.lock().unwrap() = true;
        Ok(())
    }
    async fn existing_candidates(
        &self,
        _: &str,
        _: &str,
        _: usize,
    ) -> Result<Vec<CanvasRosterCandidate>, CanvasSyncProcessingError> {
        Ok(self.candidates.lock().unwrap().values().cloned().collect())
    }
    async fn save_candidate(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        candidate: &CanvasRosterCandidate,
    ) -> Result<String, CanvasSyncProcessingError> {
        self.candidates
            .lock()
            .unwrap()
            .insert(candidate.candidate_key.clone(), candidate.clone());
        Ok(candidate.id.clone())
    }
    async fn save_candidate_observation(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        candidate: &str,
        requirement: &str,
        observation: &CanvasAuthoritativeObservation,
    ) -> Result<bool, CanvasSyncProcessingError> {
        let canonical = crate::canvas_award_candidate::python_canonical_json(&json!({
            "assertion": observation.assertion,
            "payload": observation.source_payload,
        }));
        let key = (candidate.to_owned(), requirement.to_owned());
        let mut payloads = self.observation_payloads.lock().unwrap();
        if payloads.get(&key) == Some(&canonical) {
            return Ok(false);
        }
        payloads.insert(key, canonical);
        let mut all = self.observations.lock().unwrap();
        let current = all.entry(candidate.into()).or_default();
        current.retain(|item| item.requirement_id != requirement);
        current.push(CanvasCandidateObservationSnapshot {
            requirement_id: requirement.into(),
            assertion: observation.assertion.clone(),
        });
        Ok(true)
    }
    async fn current_candidate_observations(
        &self,
        _: &str,
        candidate: &str,
    ) -> Result<Vec<CanvasCandidateObservationSnapshot>, CanvasSyncProcessingError> {
        Ok(self
            .observations
            .lock()
            .unwrap()
            .get(candidate)
            .cloned()
            .unwrap_or_default())
    }
    async fn update_roster_cursor(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        cursor: usize,
        size: usize,
    ) -> Result<(), CanvasSyncProcessingError> {
        *self.cursor.lock().unwrap() = Some((cursor, size));
        Ok(())
    }
}

#[derive(Debug)]
struct SimulatorProvider;

#[async_trait]
impl CanvasAuthoritativeProvider for SimulatorProvider {
    fn for_run(
        self: Arc<Self>,
        _scope: CanvasProviderRunScope,
    ) -> Arc<dyn CanvasAuthoritativeProvider> {
        self
    }

    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        requirement: &Value,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        let fact_type = text(requirement.get("fact_type"));
        let assertion = match fact_type.as_str() {
            "canvas.assignment_score" => rest_assertion(
                &fact_type,
                &json!({"score":8,"workflow_state":"graded","assignment":{"points_possible":10}}),
            ),
            "canvas.quiz_score" => ags_assertion(
                &json!({"resultScore":9,"resultMaximum":10,"resultStatus":"FullyGraded"}),
            ),
            "canvas.module_completion" => rest_assertion(&fact_type, &json!({"state":"completed"})),
            "canvas.course_completion" => rest_assertion(
                &fact_type,
                &json!({"requirement_count":1,"requirement_completed_count":1}),
            ),
            _ => return Err(CanvasProviderReadError::InvalidConfiguration),
        };
        Ok(CanvasAuthoritativeObservation {
            assertion,
            source_payload: Map::new(),
            verification_method: if text(requirement.get("source")) == "ags_result" {
                "LTI_AGS_RESULT_READ"
            } else {
                "CANVAS_OAUTH_API_READ"
            },
            effective_at: None,
        })
    }
    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        Ok(CanvasRosterSnapshot {
            canvas_user_ids: vec!["42".into(), "84".into()],
            lti_subjects: Vec::new(),
            preloaded_observations: BTreeMap::new(),
        })
    }
}

fn simulator_resources(requirements: Vec<Value>) -> CanvasSyncResources {
    let now = Utc::now();
    CanvasSyncResources {
        platform: CanvasSyncPlatformSnapshot {
            id: "platform-1".into(),
            organization_id: "org-1".into(),
            canvas_base_url: "https://canvas.test".into(),
            lti_trust_profile: "self_managed_same_origin".into(),
            lti_issuer: "https://canvas.test".into(),
            lti_client_id: "client".into(),
            lti_deployment_id: "deployment".into(),
            lti_auth_token_url: "https://canvas.test/login/oauth2/token".into(),
            config_version: 1,
        },
        binding: Map::from_iter([
            ("id".into(), Value::String("binding-1".into())),
            ("organization_id".into(), Value::String("org-1".into())),
            (
                "application_template_id".into(),
                Value::String("template-1".into()),
            ),
            ("evidence_requirements".into(), Value::Array(requirements)),
        ]),
        application: Some(CanvasSyncApplicationSnapshot {
            application: CanvasLtiBootstrapApplication {
                id: "application-1".into(),
                organization_id: "org-1".into(),
                application_template_id: "template-1".into(),
                applicant_identifier: "opaque".into(),
                form_data: json!({}),
                integration_context: json!({"canvas":{"lti_subject":"subject-42"}}),
                status: "approved".into(),
                created_at: now,
                updated_at: now,
            },
            credential_id: Some("credential-1".into()),
        }),
        application_template: Some(Map::from_iter([
            ("id".into(), Value::String("template-1".into())),
            ("organization_id".into(), Value::String("org-1".into())),
        ])),
    }
}

fn requirement(id: &str, source: &str, fact_type: &str, scope: Value, pass_rule: Value) -> Value {
    json!({"requirement_id":id,"source":source,"fact_type":fact_type,"scope":scope,"pass_rule":pass_rule,"required":true})
}

fn target(kind: CanvasSyncTargetType) -> CanvasSyncTarget {
    CanvasSyncTarget {
        id: "target-1".into(),
        organization_id: "org-1".into(),
        platform_id: "platform-1".into(),
        binding_id: "binding-1".into(),
        target_type: kind,
        logical_key: "logical".into(),
        application_id: Some("application-1".into()),
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 1,
        metadata: Map::new(),
        created_at: Utc::now(),
    }
}

async fn run_simulated(
    processor: &NativeCanvasSyncProcessor,
    target: CanvasSyncTarget,
) -> Result<CanvasSyncResult, CanvasSyncProcessingError> {
    let lease = CanvasSyncLease {
        job_id: "simulator-job".into(),
        organization_id: target.organization_id.clone(),
        target_id: target.id.clone(),
        worker_id: processor.config.worker_id.clone(),
        attempt_count: 1,
    };
    processor.process(&target, &lease).await
}

fn enabled_config() -> CanvasSyncWorkerConfig {
    CanvasSyncWorkerConfig {
        worker_id: "sim".into(),
        batch_size: 10_u64.into(),
        lease_seconds: 120_u64.into(),
        job_timeout: std::time::Duration::from_secs(600),
        schedule_limit: 100_u64.into(),
        oauth_revocation_limit: 25_u64.into(),
        poll_interval: std::time::Duration::from_secs(5),
        portable_enabled: true,
        pilot_organizations: ["org-1".to_owned()].into_iter().collect(),
    }
}

#[derive(Default)]
struct RunCountingProvider {
    runs: Arc<std::sync::atomic::AtomicUsize>,
    calls: Arc<Mutex<Vec<usize>>>,
    scoped_calls: Arc<Mutex<Vec<ScopedProviderCall>>>,
    run_id: Option<usize>,
    run_scope: Option<CanvasProviderRunScope>,
}

type ScopedProviderCall = (usize, CanvasProviderRunScope, &'static str);

#[async_trait]
impl CanvasAuthoritativeProvider for RunCountingProvider {
    fn for_run(
        self: Arc<Self>,
        scope: CanvasProviderRunScope,
    ) -> Arc<dyn CanvasAuthoritativeProvider> {
        let run_id = self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.scoped_calls
            .lock()
            .unwrap()
            .push((run_id, scope, "start"));
        Arc::new(Self {
            runs: self.runs.clone(),
            calls: self.calls.clone(),
            scoped_calls: self.scoped_calls.clone(),
            run_id: Some(run_id),
            run_scope: Some(scope),
        })
    }

    async fn read_requirement(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        canvas_user_id: Option<&str>,
        lti_subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        self.scoped_calls.lock().unwrap().push((
            self.run_id.expect("read must use the run provider"),
            self.run_scope.expect("read must retain the run scope"),
            "read",
        ));
        self.calls.lock().unwrap().push(
            self.run_id
                .expect("processor must use the returned run provider"),
        );
        SimulatorProvider
            .read_requirement(resources, requirement, canvas_user_id, lti_subject)
            .await
    }

    async fn roster(
        &self,
        target: &CanvasSyncTarget,
        resources: &CanvasSyncResources,
        requirements: &[Value],
        limit: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        self.scoped_calls.lock().unwrap().push((
            self.run_id.expect("roster must use the run provider"),
            self.run_scope.expect("roster must retain the run scope"),
            "roster",
        ));
        assert!(
            self.run_id.is_some(),
            "roster must also use the run provider"
        );
        SimulatorProvider
            .roster(target, resources, requirements, limit)
            .await
    }
}

#[tokio::test]
async fn processor_scopes_trait_object_provider_once_per_valid_invocation() {
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(vec![requirement(
            "assignment",
            "canvas_rest",
            "canvas.assignment_score",
            json!({"course_id":"1","activity_id":"2"}),
            json!({"min_score_percent":70}),
        )]),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(None),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    let provider = Arc::new(RunCountingProvider::default());
    let processor =
        NativeCanvasSyncProcessor::new(repository, provider.clone(), enabled_config(), 500, 5000);
    let (first, concurrent) = tokio::join!(
        run_simulated(&processor, target(CanvasSyncTargetType::LearnerApplication)),
        run_simulated(&processor, target(CanvasSyncTargetType::LearnerApplication))
    );
    for result in [first, concurrent] {
        assert_eq!(
            result
                .unwrap()
                .get("requirements_checked")
                .map(|value| value.get().to_owned()),
            Some("1".to_owned())
        );
    }
    let invalid_lease = CanvasSyncLease {
        job_id: "synthetic-job".into(),
        organization_id: "wrong-tenant".into(),
        target_id: "target-1".into(),
        worker_id: "sim".into(),
        attempt_count: 1,
    };
    assert_eq!(
        processor
            .process(
                &target(CanvasSyncTargetType::LearnerApplication),
                &invalid_lease
            )
            .await
            .unwrap_err(),
        lease_lost()
    );
    assert_eq!(provider.runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    let mut calls = provider.calls.lock().unwrap().clone();
    calls.sort_unstable();
    assert_eq!(calls, vec![0, 1]);

    run_simulated(&processor, target(CanvasSyncTargetType::IssuedDrift))
        .await
        .unwrap();
    run_simulated(&processor, target(CanvasSyncTargetType::BackgroundRoster))
        .await
        .unwrap();
    let scoped_calls = provider.scoped_calls.lock().unwrap().clone();
    for run_id in 0..3 {
        assert_eq!(
            scoped_calls
                .iter()
                .filter(|entry| entry.0 == run_id)
                .copied()
                .collect::<Vec<_>>(),
            vec![
                (run_id, CanvasProviderRunScope::Application, "start"),
                (run_id, CanvasProviderRunScope::Application, "read"),
            ],
        );
    }
    // Even with application resources present, collection and BOTH roster
    // candidate evidence reads retain the explicitly selected roster scope.
    assert_eq!(
        scoped_calls
            .iter()
            .filter(|entry| entry.0 == 3)
            .copied()
            .collect::<Vec<_>>(),
        vec![
            (3, CanvasProviderRunScope::BackgroundRoster, "start"),
            (3, CanvasProviderRunScope::BackgroundRoster, "roster"),
            (3, CanvasProviderRunScope::BackgroundRoster, "read"),
            (3, CanvasProviderRunScope::BackgroundRoster, "read"),
        ],
    );
    assert_eq!(
        run_simulated(&processor, target(CanvasSyncTargetType::AwardCandidate))
            .await
            .unwrap_err()
            .code,
        "canvas_sync_target_type_unsupported",
    );
    let mut closed = processor.clone();
    closed.config.portable_enabled = false;
    assert!(
        run_simulated(&closed, target(CanvasSyncTargetType::AwardCandidate))
            .await
            .is_ok()
    );
    assert_eq!(provider.runs.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert_eq!(*provider.scoped_calls.lock().unwrap(), scoped_calls);
}

#[tokio::test]
async fn executable_simulator_reconciles_all_four_facts_without_signing() {
    let requirements = vec![
        requirement(
            "assignment",
            "canvas_rest",
            "canvas.assignment_score",
            json!({"course_id":"1","activity_id":"2"}),
            json!({"min_score_percent":70}),
        ),
        requirement(
            "quiz",
            "ags_result",
            "canvas.quiz_score",
            json!({"course_id":"1","line_item_url":"https://canvas.test/lineitems/2"}),
            json!({"min_score_percent":70}),
        ),
        requirement(
            "module",
            "canvas_rest",
            "canvas.module_completion",
            json!({"course_id":"1","module_id":"3"}),
            json!({"completed":true}),
        ),
        requirement(
            "course",
            "canvas_rest",
            "canvas.course_completion",
            json!({"course_id":"1"}),
            json!({"completed":true}),
        ),
    ];
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(requirements),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(None),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        Arc::new(SimulatorProvider),
        enabled_config(),
        500,
        5000,
    );
    let result = run_simulated(&processor, target(CanvasSyncTargetType::LearnerApplication))
        .await
        .unwrap();
    assert_eq!(
        result.get("requirements_checked").map(|value| value.get()),
        Some("4")
    );
    let facts = repository.facts.lock().unwrap();
    assert_eq!(facts.len(), 4);
    assert!(facts.iter().all(|fact| fact
        .get("verification")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        == Some("VERIFIED")));
    assert!(facts.iter().all(|fact| fact.get("credential_id").is_none()));
}

#[tokio::test]
async fn executable_simulator_bounds_roster_cursor_and_preserves_claimed_state() {
    let requirements = vec![requirement(
        "assignment",
        "canvas_rest",
        "canvas.assignment_score",
        json!({"course_id":"1","activity_id":"2"}),
        json!({"min_score_percent":70}),
    )];
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(requirements),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(None),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    let claimed_key = candidate_key("platform-1", "binding-1", Some("42"), Some("subject-42"));
    repository.candidates.lock().unwrap().insert(
        claimed_key.clone(),
        CanvasRosterCandidate {
            id: "claimed".into(),
            candidate_key: claimed_key,
            canvas_user_id: Some("42".into()),
            lti_subject: Some("subject-42".into()),
            learner_identity_id: Some("identity-42".into()),
            state: "claimed".into(),
        },
    );
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        Arc::new(SimulatorProvider),
        enabled_config(),
        1,
        2,
    );
    let result = run_simulated(&processor, target(CanvasSyncTargetType::BackgroundRoster))
        .await
        .unwrap();
    assert_eq!(
        result.get("candidates_seen").map(|value| value.get()),
        Some("1")
    );
    assert_eq!(*repository.cursor.lock().unwrap(), Some((1, 2)));
    assert_eq!(
        result.get("roster_remaining").map(|value| value.get()),
        Some("1")
    );
    assert!(repository
        .candidates
        .lock()
        .unwrap()
        .values()
        .any(|candidate| candidate.state == "claimed"));
    let mut next = target(CanvasSyncTargetType::BackgroundRoster);
    next.metadata.insert("roster_cursor".into(), Value::from(1));
    let result = run_simulated(&processor, next).await.unwrap();
    assert_eq!(
        result.get("roster_remaining").map(|value| value.get()),
        Some("0")
    );
    assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 2)));
}

#[derive(Debug)]
struct MixedRosterProvider;

fn mixed_roster_snapshot(active_12: bool) -> CanvasRosterSnapshot {
    let matrix: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-mixed-roster-scenarios.json"
    ))
    .unwrap();
    let users = matrix["roster_users"].as_array().unwrap();
    CanvasRosterSnapshot {
        canvas_user_ids: users.iter().map(|value| value.to_string()).collect(),
        lti_subjects: matrix["identities"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|identity| {
                identity["status"] == "linked" && (identity["user"] != "12" || active_12)
            })
            .map(|identity| format!("subject-{}", identity["user"].as_str().unwrap()))
            .collect(),
        preloaded_observations: BTreeMap::new(),
    }
}

#[async_trait]
impl CanvasAuthoritativeProvider for MixedRosterProvider {
    fn for_run(self: Arc<Self>, _: CanvasProviderRunScope) -> Arc<dyn CanvasAuthoritativeProvider> {
        self
    }

    async fn read_requirement(
        &self,
        resources: &CanvasSyncResources,
        requirement: &Value,
        canvas_user_id: Option<&str>,
        lti_subject: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        SimulatorProvider
            .read_requirement(resources, requirement, canvas_user_id, lti_subject)
            .await
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        let matrix: Value = serde_json::from_str(include_str!(
            "../../../../contracts/canvas-worker-mixed-roster-scenarios.json"
        ))
        .unwrap();
        let active_12 = matrix["cases"][0]["stages"][0]["active_12"] == true;
        Ok(mixed_roster_snapshot(active_12))
    }
}

fn mixed_roster_fixture() -> (Value, Arc<SimulatorRepository>) {
    let matrix: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-mixed-roster-scenarios.json"
    ))
    .unwrap();
    let requirements: Vec<Value> = serde_json::from_str(
        &serde_json::to_string(&matrix["requirements"])
            .unwrap()
            .replace("{origin}", "https://canvas.test"),
    )
    .unwrap();
    let identities = matrix["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|identity| {
            let user = identity["user"].as_str().unwrap();
            (
                user.to_owned(),
                CanvasLinkedIdentitySnapshot {
                    id: format!("identity-{user}"),
                    lti_subject: format!("subject-{user}"),
                    canvas_user_id: Some(user.to_owned()),
                    status: identity["status"].as_str().unwrap().to_owned(),
                },
            )
        })
        .collect();
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(requirements),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(Some(identities)),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    for terminal in matrix["terminal_candidates"].as_array().unwrap() {
        let user = terminal["user"].as_str().unwrap();
        let state = terminal["state"].as_str().unwrap();
        let key = candidate_key("platform-1", "binding-1", Some(user), None);
        repository.candidates.lock().unwrap().insert(
            key.clone(),
            CanvasRosterCandidate {
                id: format!("candidate-{user}"),
                candidate_key: key,
                canvas_user_id: Some(user.to_owned()),
                lti_subject: None,
                learner_identity_id: None,
                state: state.to_owned(),
            },
        );
    }
    (matrix, repository)
}

#[tokio::test]
async fn mixed_roster_unit_window_preserves_terminal_states_and_identity_gates() {
    let (matrix, repository) = mixed_roster_fixture();
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        Arc::new(MixedRosterProvider),
        enabled_config(),
        matrix["batch_size"].as_u64().unwrap() as usize,
        matrix["roster_limit"].as_u64().unwrap() as usize,
    );
    let mut first = target(CanvasSyncTargetType::BackgroundRoster);
    first.metadata.insert(
        "roster_cursor".into(),
        matrix["cases"][0]["initial_cursor"].clone(),
    );
    let first_result = run_simulated(&processor, first).await.unwrap();
    assert_eq!(first_result["candidates_seen"].get(), "3");
    assert_eq!(first_result["pending_claim"].get(), "1");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 6)));

    let second_result = run_simulated(&processor, target(CanvasSyncTargetType::BackgroundRoster))
        .await
        .unwrap();
    assert_eq!(second_result["candidates_seen"].get(), "3");
    assert_eq!(second_result["pending_claim"].get(), "0");
    assert_eq!(second_result["identity_link_required"].get(), "3");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((3, 6)));
    let candidates = repository.candidates.lock().unwrap();
    for (user, state) in [
        ("7", "claimed"),
        ("8", "dismissed"),
        ("9", "pending_claim"),
        ("10", "identity_link_required"),
        ("11", "identity_link_required"),
        ("12", "identity_link_required"),
    ] {
        let key = candidate_key("platform-1", "binding-1", Some(user), None);
        assert_eq!(candidates[&key].state, state, "user {user}");
    }
}

#[derive(Clone, Copy, Debug)]
enum TailResponse {
    Negative,
    Unavailable,
    Positive,
}

#[derive(Debug)]
struct ScriptedTailProvider {
    response: Mutex<TailResponse>,
    active_12: Mutex<bool>,
}

#[async_trait]
impl CanvasAuthoritativeProvider for ScriptedTailProvider {
    fn for_run(self: Arc<Self>, _: CanvasProviderRunScope) -> Arc<dyn CanvasAuthoritativeProvider> {
        self
    }

    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        requirement: &Value,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        let source = requirement["source"].as_str().unwrap();
        let score = match (*self.response.lock().unwrap(), source) {
            (TailResponse::Unavailable, _) => return Err(CanvasProviderReadError::Unavailable),
            (TailResponse::Negative, "ags_result") => 1,
            (TailResponse::Negative | TailResponse::Positive, _) => 9,
        };
        let assertion = match source {
            "canvas_rest" => rest_assertion(
                "canvas.assignment_score",
                &json!({"score":score,"workflow_state":"graded","assignment":{"points_possible":10}}),
            ),
            "ags_result" => ags_assertion(
                &json!({"resultScore":score,"resultMaximum":10,"resultStatus":"FullyGraded"}),
            ),
            _ => panic!("unexpected frozen source"),
        };
        Ok(CanvasAuthoritativeObservation {
            assertion,
            source_payload: Map::new(),
            verification_method: if source == "canvas_rest" {
                "CANVAS_OAUTH_API_READ"
            } else {
                "LTI_AGS_RESULT_READ"
            },
            effective_at: None,
        })
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        Ok(mixed_roster_snapshot(*self.active_12.lock().unwrap()))
    }
}

#[tokio::test]
async fn mixed_roster_tail_outage_preserves_negative_heads_until_positive_recovery() {
    let (matrix, repository) = mixed_roster_fixture();
    let provider = Arc::new(ScriptedTailProvider {
        response: Mutex::new(TailResponse::Negative),
        active_12: Mutex::new(false),
    });
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        provider.clone(),
        enabled_config(),
        matrix["batch_size"].as_u64().unwrap() as usize,
        matrix["roster_limit"].as_u64().unwrap() as usize,
    );
    let mut tail = target(CanvasSyncTargetType::BackgroundRoster);
    tail.metadata.insert("roster_cursor".into(), Value::from(3));

    let negative = run_simulated(&processor, tail.clone()).await.unwrap();
    assert_eq!(negative["candidates_seen"].get(), "3");
    assert_eq!(negative["pending_claim"].get(), "0");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 6)));
    let ordinary_key = candidate_key("platform-1", "binding-1", Some("9"), None);
    let ordinary_id = repository.candidates.lock().unwrap()[&ordinary_key]
        .id
        .clone();
    let negative_heads = repository.observations.lock().unwrap()[&ordinary_id].clone();
    assert_eq!(negative_heads.len(), 2);
    for (requirement, score) in [("rest", 90.0), ("ags", 10.0)] {
        let head = negative_heads
            .iter()
            .find(|head| head.requirement_id == requirement)
            .unwrap();
        assert_eq!(head.assertion["score_percent"], score);
    }

    *provider.response.lock().unwrap() = TailResponse::Unavailable;
    let unavailable = run_simulated(&processor, tail.clone()).await.unwrap();
    assert_eq!(unavailable["observations_written"].get(), "0");
    assert_eq!(
        repository.observations.lock().unwrap()[&ordinary_id],
        negative_heads
    );
    assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 6)));

    *provider.response.lock().unwrap() = TailResponse::Positive;
    let recovery = run_simulated(&processor, tail).await.unwrap();
    assert_eq!(recovery["pending_claim"].get(), "1");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((0, 6)));
    let recovered_heads = repository.observations.lock().unwrap()[&ordinary_id].clone();
    assert_eq!(recovered_heads.len(), 2);
    assert!(recovered_heads
        .iter()
        .all(|head| head.assertion["score_percent"] == 90.0));
    let candidates = repository.candidates.lock().unwrap();
    for (user, state) in [("7", "claimed"), ("8", "dismissed"), ("9", "pending_claim")] {
        let key = candidate_key("platform-1", "binding-1", Some(user), None);
        assert_eq!(candidates[&key].state, state, "user {user}");
    }
}

#[tokio::test]
async fn mixed_roster_active_head_reconciles_once_and_preserves_duplicate_heads() {
    let (matrix, repository) = mixed_roster_fixture();
    let provider = Arc::new(ScriptedTailProvider {
        response: Mutex::new(TailResponse::Positive),
        active_12: Mutex::new(false),
    });
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        provider.clone(),
        enabled_config(),
        matrix["batch_size"].as_u64().unwrap() as usize,
        matrix["roster_limit"].as_u64().unwrap() as usize,
    );
    let head = target(CanvasSyncTargetType::BackgroundRoster);
    let gated = run_simulated(&processor, head.clone()).await.unwrap();
    assert_eq!(gated["identity_link_required"].get(), "3");
    assert_eq!(gated["observations_written"].get(), "0");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((3, 6)));

    *provider.active_12.lock().unwrap() = true;
    let active = run_simulated(&processor, head.clone()).await.unwrap();
    assert_eq!(active["identity_link_required"].get(), "2");
    assert_eq!(active["pending_claim"].get(), "1");
    assert_eq!(active["observations_written"].get(), "2");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((3, 6)));
    let active_key = candidate_key("platform-1", "binding-1", Some("12"), None);
    let active_id = repository.candidates.lock().unwrap()[&active_key]
        .id
        .clone();
    let active_heads = repository.observations.lock().unwrap()[&active_id].clone();
    assert_eq!(active_heads.len(), 2);
    assert!(active_heads
        .iter()
        .all(|head| head.assertion["score_percent"] == 90.0));

    let duplicate = run_simulated(&processor, head).await.unwrap();
    assert_eq!(duplicate["identity_link_required"].get(), "2");
    assert_eq!(duplicate["pending_claim"].get(), "1");
    assert_eq!(duplicate["observations_written"].get(), "0");
    assert_eq!(*repository.cursor.lock().unwrap(), Some((3, 6)));
    assert_eq!(
        repository.observations.lock().unwrap()[&active_id],
        active_heads
    );
    let candidates = repository.candidates.lock().unwrap();
    for (user, state) in [
        ("7", "claimed"),
        ("8", "dismissed"),
        ("10", "identity_link_required"),
        ("11", "identity_link_required"),
        ("12", "pending_claim"),
    ] {
        let key = candidate_key("platform-1", "binding-1", Some(user), None);
        assert_eq!(candidates[&key].state, state, "user {user}");
    }
}

#[tokio::test]
async fn expired_issued_drift_disables_without_provider_or_fact_mutation() {
    let repository = Arc::new(SimulatorRepository {
        resources: simulator_resources(vec![requirement(
            "course",
            "canvas_rest",
            "canvas.course_completion",
            json!({"course_id":"1"}),
            json!({"completed":true}),
        )]),
        facts: Mutex::new(Vec::new()),
        identities: Mutex::new(None),
        candidates: Mutex::new(BTreeMap::new()),
        observations: Mutex::new(BTreeMap::new()),
        observation_payloads: Mutex::new(BTreeMap::new()),
        cursor: Mutex::new(None),
        disabled: Mutex::new(false),
    });
    let processor = NativeCanvasSyncProcessor::new(
        repository.clone(),
        Arc::new(SimulatorProvider),
        enabled_config(),
        500,
        5000,
    );
    let mut drift = target(CanvasSyncTargetType::IssuedDrift);
    drift.metadata.insert(
        "drift_until".into(),
        Value::String("2020-01-01T00:00:00Z".into()),
    );
    let result = run_simulated(&processor, drift).await.unwrap();
    assert_eq!(
        result.get("no_change").map(|value| value.get()),
        Some("true")
    );
    assert!(*repository.disabled.lock().unwrap());
    assert!(repository.facts.lock().unwrap().is_empty());
}

#[test]
fn roster_failure_summaries_match_published_process() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-roster-failure-oracle.json"
    ))
    .unwrap();
    for (name, provider) in [
        (
            "roster_oauth_unavailable",
            CanvasProviderReadError::RosterOAuthUnavailable,
        ),
        (
            "nrps_context_unavailable",
            CanvasProviderReadError::NrpsRosterUnavailable,
        ),
        (
            "roster_collection_too_large",
            CanvasProviderReadError::RosterCollectionTooLarge,
        ),
        (
            "roster_authoritative_read_failed",
            CanvasProviderReadError::Unavailable,
        ),
        (
            "roster_http_status_failed",
            CanvasProviderReadError::RosterHttpStatusFailure,
        ),
    ] {
        let actual = provider_processing_error(provider);
        let job = &reference[name]["observations"][0]["jobs"][0];
        assert_eq!(actual.code, job["last_error_code"], "{name}");
        assert_eq!(actual.summary, job["last_error_summary"], "{name}");
        assert_eq!(actual.retryable, job["status"] == "retry", "{name}");
    }
}

#[derive(Debug)]
struct RateLimitedSimulatorProvider {
    retry_after_seconds: u64,
}

#[async_trait]
impl CanvasAuthoritativeProvider for RateLimitedSimulatorProvider {
    fn for_run(
        self: Arc<Self>,
        _scope: CanvasProviderRunScope,
    ) -> Arc<dyn CanvasAuthoritativeProvider> {
        self
    }

    async fn read_requirement(
        &self,
        _: &CanvasSyncResources,
        _: &Value,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<CanvasAuthoritativeObservation, CanvasProviderReadError> {
        Err(CanvasProviderReadError::RateLimited {
            retry_after_seconds: self.retry_after_seconds,
        })
    }

    async fn roster(
        &self,
        _: &CanvasSyncTarget,
        _: &CanvasSyncResources,
        _: &[Value],
        _: usize,
    ) -> Result<CanvasRosterSnapshot, CanvasProviderReadError> {
        panic!("application rate-limit test must not request a roster")
    }
}

#[tokio::test]
async fn retry_after_matrix_keeps_parser_delay_and_processor_category_without_io() {
    let matrix: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-retry-after-scenarios.json"
    ))
    .unwrap();
    let now: DateTime<Utc> = "2026-09-02T00:00:00Z".parse().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for case in matrix["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(seen.insert(name), "duplicate retry-after case: {name}");
        let raw = if let Some(offset) = case["retry_after_offset_seconds"].as_i64() {
            let epoch_seconds = now
                .timestamp()
                .checked_add(offset)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .expect("bounded retry-after date");
            let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch_seconds);
            httpdate::fmt_http_date(when)
        } else {
            case["headers"]["Retry-After"].as_str().unwrap().to_owned()
        };
        let expected_hint = match name {
            "http_date_future" => Some(60),
            "http_date_past" | "negative" | "zero" => Some(0),
            "malformed" => None,
            "clamped" | "huge_integer" => Some(86_400),
            _ => panic!("unclassified retry-after case: {name}"),
        };
        let hint = crate::canvas_sync_worker::retry_after_seconds(&raw, now);
        assert_eq!(hint, expected_hint, "{name}");
        let (minimum, maximum) = if name == "http_date_future" {
            assert!(case.get("delay_bounds").is_none());
            (60, 60)
        } else {
            (
                case["delay_bounds"][0].as_u64().unwrap(),
                case["delay_bounds"][1].as_u64().unwrap(),
            )
        };
        for jitter in [0, 5, u64::MAX] {
            let delay = crate::canvas_sync_worker::job_retry_delay_seconds(1, hint, jitter);
            assert!((minimum..=maximum).contains(&delay), "{name}: {delay}");
        }

        let repository = Arc::new(SimulatorRepository {
            resources: simulator_resources(vec![requirement(
                "assignment",
                "canvas_rest",
                "canvas.assignment_score",
                json!({"course_id":"1","activity_id":"2"}),
                json!({"min_score_percent":70}),
            )]),
            facts: Mutex::new(Vec::new()),
            identities: Mutex::new(None),
            candidates: Mutex::new(BTreeMap::new()),
            observations: Mutex::new(BTreeMap::new()),
            observation_payloads: Mutex::new(BTreeMap::new()),
            cursor: Mutex::new(None),
            disabled: Mutex::new(false),
        });
        let processor = NativeCanvasSyncProcessor::new(
            repository.clone(),
            Arc::new(RateLimitedSimulatorProvider {
                retry_after_seconds: hint.unwrap_or(0),
            }),
            enabled_config(),
            500,
            5000,
        );
        let error = run_simulated(&processor, target(CanvasSyncTargetType::LearnerApplication))
            .await
            .unwrap_err();
        assert_eq!(error.code, "canvas_rate_limited", "{name}");
        assert_eq!(
            error.summary, "Canvas rate limited one or more authoritative evidence reads",
            "{name}"
        );
        assert!(error.retryable, "{name}");
        assert_eq!(error.retry_after_seconds, Some(hint.unwrap_or(0)), "{name}");
        assert!(repository.facts.lock().unwrap().is_empty(), "{name}");
        assert!(repository.candidates.lock().unwrap().is_empty(), "{name}");
        assert_eq!(*repository.cursor.lock().unwrap(), None, "{name}");
        assert!(!*repository.disabled.lock().unwrap(), "{name}");
    }
    assert_eq!(seen.len(), 7);
}

#[test]
fn roster_provider_failures_keep_the_frozen_retry_categories() {
    for (provider, code, retryable) in [
        (
            CanvasProviderReadError::RosterConfigurationInvalid,
            "canvas_roster_configuration_invalid",
            false,
        ),
        (
            CanvasProviderReadError::RosterOAuthUnavailable,
            "canvas_roster_oauth_unavailable",
            true,
        ),
        (
            CanvasProviderReadError::NrpsRosterUnavailable,
            "canvas_nrps_roster_unavailable",
            true,
        ),
        (
            CanvasProviderReadError::RosterCollectionTooLarge,
            "canvas_roster_collection_too_large",
            false,
        ),
    ] {
        let actual = provider_processing_error(provider);
        assert_eq!(actual.code, code);
        assert_eq!(actual.retryable, retryable, "{code}");
        assert_eq!(actual.retry_after_seconds, None, "{code}");
    }
}
