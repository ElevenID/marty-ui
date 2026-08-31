use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    canvas_award_candidate_approval::{
        plan_canvas_approval_transaction, CanvasAwardApprovalSeed, CanvasAwardApprovalSeedGenerator,
    },
    canvas_legacy_ingest::{
        CanvasEvidenceEvent, CanvasEvidenceEventResponse, CanvasLegacyApplicationSnapshot,
        CanvasLegacyCommit, CanvasLegacyCommitOutcome, CanvasLegacyEventKind,
        CanvasLegacyIdGenerator, CanvasLegacyIngestConfig, CanvasLegacyIngestError,
        CanvasLegacyIngestRepository, CanvasLegacyIngestService, CanvasLegacyIngestSnapshot,
        CanvasLegacyRepositoryError, CanvasLegacyStoredReceipt,
    },
    canvas_lti_launch::CanvasLtiClock,
    credential::{
        CredentialIssuanceError, CredentialTransaction, IssuerContext, IssuerContextResolver,
    },
};
use serde_json::{json, Map, Value};
use sha2::Sha256;

const SECRET: &str = "legacy-secret";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0)
        .single()
        .expect("time")
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("object")
}

fn snapshot(auto: bool, strict: bool, fact_type: &str) -> CanvasLegacyApplicationSnapshot {
    let pass_rule = if matches!(fact_type, "canvas.assignment_score" | "canvas.quiz_score") {
        json!({"min_score_percent":0})
    } else if fact_type == "canvas.nrps_membership" {
        json!({"eligible":true})
    } else {
        json!({"completed":true})
    };
    let mut binding = object(json!({
        "id":"binding-1","organization_id":"org-1","platform_id":"platform-1",
        "application_template_id":"application-template-1",
        "credential_template_id":"credential-template-1",
        "auto_approve_on_evidence":auto,"delivery_mode":"wallet_plus_canvas_mirror",
        "feature_flags":{
            "enable_canvas_evidence":true,"enable_canvas_ags":true,"enable_canvas_nrps":true
        },
        "evidence_requirements":[{
            "requirement_id":"requirement-1","provider":"canvas",
            "fact_type":fact_type,"scope":{"course_id":"course-1"},"pass_rule":pass_rule,"required":true
        }]
    }));
    if strict {
        binding.insert("credential_template_snapshot".to_owned(), json!({
            "id":"credential-template-1","organization_id":"org-1","status":"active",
            "credential_type":"OpenBadgeCredential",
            "credential_payload_format":"w3c_vcdm_v2_sd_jwt",
            "revocation_profile_id":"revocation-profile-1",
            "issuer_did":"did:web:issuer.example:orgs:org-1","issuer_algorithm":"ES256",
            "wallet_configs":[],"selective_disclosure_fields":[],"zk_predicate_claims":[],
            "validity_rules":{"default_validity_days":365,"renewable":false,"renewal_window_days":30}
        }));
    }
    CanvasLegacyApplicationSnapshot {
        application: object(json!({
            "id":"application-1","organization_id":"org-1",
            "application_template_id":"application-template-1",
            "applicant_identifier":"learner@example.test","form_data":{},
            "integration_context":{"canvas":{
                "lti_subject":"verified-subject-1",
                "application_template_id":"application-template-1",
                "credential_template_id":"credential-template-1",
                "verified_launch":{"nonce":"preserve-me"}
            }},"status":"pending"
        })),
        application_template: Some(object(json!({
            "id":"application-template-1","organization_id":"org-1",
            "credential_template_id":"credential-template-1","status":"active"
        }))),
        platform: object(json!({"id":"platform-1","organization_id":"org-1"})),
        binding,
        evidence_facts: Vec::new(),
        policy_set: None,
        existing_transaction: None,
    }
}

#[derive(Clone)]
struct Repository {
    loaded: Arc<Mutex<CanvasLegacyIngestSnapshot>>,
    committed: Arc<Mutex<Vec<CanvasLegacyCommit>>>,
}

#[async_trait]
impl CanvasLegacyIngestRepository for Repository {
    async fn load(
        &self,
        _event: &CanvasEvidenceEvent,
        _payload_hash: &str,
    ) -> Result<Option<CanvasLegacyIngestSnapshot>, CanvasLegacyRepositoryError> {
        Ok(Some(self.loaded.lock().expect("loaded").clone()))
    }

    async fn replay(
        &self,
        _event: &CanvasEvidenceEvent,
        _payload_hash: &str,
        _now: DateTime<Utc>,
    ) -> Result<CanvasLegacyStoredReceipt, CanvasLegacyIngestError> {
        match self.loaded.lock().expect("loaded").clone() {
            CanvasLegacyIngestSnapshot::Replay(receipt) => Ok(receipt),
            CanvasLegacyIngestSnapshot::New(_) => {
                Err(CanvasLegacyIngestError::RepositoryUnavailable)
            }
        }
    }

    async fn commit(
        &self,
        _snapshot: &CanvasLegacyApplicationSnapshot,
        commit: &CanvasLegacyCommit,
    ) -> Result<CanvasLegacyCommitOutcome, CanvasLegacyIngestError> {
        self.committed
            .lock()
            .expect("committed")
            .push(commit.clone());
        Ok(CanvasLegacyCommitOutcome::Created(Box::new(
            CanvasEvidenceEventResponse {
                id: commit.event.canvas_event_id.clone(),
                application_id: commit.event.application_id.clone(),
                organization_id: commit.event.organization_id.clone().unwrap_or_default(),
                canvas_account_id: commit.event.canvas_account_id.clone(),
                evidence_type: commit.event.evidence_type.clone(),
                status: "evidence_received".to_owned(),
                application_status: Some(
                    if commit.transaction.is_some() {
                        "approved"
                    } else {
                        "pending"
                    }
                    .to_owned(),
                ),
                source_event_id: commit.event.canvas_event_id.clone(),
                replayed: false,
                evidence: commit.evidence.clone(),
                mip_primitives: commit.mip_primitives.clone(),
                evidence_facts: vec![commit.safe_fact.clone()],
                policy_decision: commit.policy_decision.clone(),
            },
        )))
    }
}

struct Clock;
impl CanvasLtiClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        now()
    }
}

struct Seeds;
impl CanvasAwardApprovalSeedGenerator for Seeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        CanvasAwardApprovalSeed {
            transaction_id: "transaction-new".to_owned(),
            pre_authorized_code: "private-code".to_owned(),
        }
    }
}

struct Ids;
impl CanvasLegacyIdGenerator for Ids {
    fn receipt_id(&self) -> String {
        "receipt-1".to_owned()
    }
    fn fact_id(&self) -> String {
        "fact-1".to_owned()
    }
}

struct Resolver {
    fail: bool,
}

#[async_trait]
impl IssuerContextResolver for Resolver {
    async fn resolve(
        &self,
        _transaction: &CredentialTransaction,
        credential_format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        assert_eq!(credential_format, "dc+sd-jwt");
        assert!(force);
        if self.fail {
            return Err(CredentialIssuanceError::RepositoryUnavailable);
        }
        let did = "did:web:issuer.example:orgs:org-1";
        Ok(IssuerContext {
            issuer_profile_id: "issuer-profile-1".to_owned(),
            issuer_did: did.to_owned(),
            signing_service_id: "kms-service-1".to_owned(),
            algorithm: "ES256".to_owned(),
            verification_method_id: Some(format!("{did}#key-1")),
            public_jwk: Some(json!({"kty":"EC","crv":"P-256","x":"x","y":"y"})),
            certificate_chain: Vec::new(),
            raw_context: json!({
                "organization_id":"org-1","issuer_profile_id":"issuer-profile-1",
                "issuer_did":did,"algorithm":"ES256","signing_service_id":"kms-service-1",
                "signing_key_reference":"org_secret://org-1/key-1",
                "verification_method_id":format!("{did}#key-1"),"key_purpose":"vc_jwt_issuer",
                "public_jwk":{"kty":"EC"},
                "issuer_profile":{"id":"issuer-profile-1","status":"active","organization_id":"org-1",
                    "issuer_did":did,"algorithm":"ES256","signing_service_id":"kms-service-1",
                    "signing_key_reference":"org_secret://org-1/key-1",
                    "verification_method_id":format!("{did}#key-1"),"key_purpose":"vc_jwt_issuer"},
                "service":{"id":"kms-service-1","algorithm":"ES256"}
            }),
        })
    }
}

fn make_service(
    snapshot: CanvasLegacyIngestSnapshot,
    fail_resolver: bool,
) -> (CanvasLegacyIngestService, Repository) {
    let repository = Repository {
        loaded: Arc::new(Mutex::new(snapshot)),
        committed: Arc::new(Mutex::new(Vec::new())),
    };
    let service = CanvasLegacyIngestService::new(
        Arc::new(repository.clone()),
        Arc::new(Resolver {
            fail: fail_resolver,
        }),
        Arc::new(Seeds),
        Arc::new(Ids),
        Arc::new(Clock),
        CanvasLegacyIngestConfig {
            enabled: true,
            shared_secret: Some(SECRET.to_owned()),
            shared_secret_file: None,
            signature_tolerance_seconds: 300,
        },
    );
    (service, repository)
}

fn signed(payload: &Value) -> (Vec<u8>, BTreeMap<String, String>) {
    let body = serde_json::to_vec(payload).expect("payload");
    let timestamp = now().timestamp().to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).expect("HMAC");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&body);
    let headers = BTreeMap::from([
        ("x-canvas-timestamp".to_owned(), timestamp),
        (
            "x-canvas-signature-256".to_owned(),
            hex::encode(mac.finalize().into_bytes()),
        ),
    ]);
    (body, headers)
}

fn evidence(event_id: &str) -> Value {
    json!({
        "canvas_event_id":event_id,"application_id":"application-1","canvas_account_id":"account-1",
        "canvas_course_id":"course-1","canvas_course_name":"Course","canvas_enrollment_id":"enrollment-1",
        "canvas_user_id":"user-1","learner_email":"learner@example.test","achievement_name":"Completed",
        "completion_at":"2026-08-31T12:00:00Z","evidence_type":"canvas.course_completion"
    })
}

#[tokio::test]
async fn evidence_non_auto_persists_the_python_compatible_fact_and_safe_response() {
    let (service, repository) = make_service(
        CanvasLegacyIngestSnapshot::New(Box::new(snapshot(
            false,
            false,
            "canvas.course_completion",
        ))),
        false,
    );
    let (body, headers) = signed(&evidence("event-evidence"));
    let response = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .expect("evidence");
    assert_eq!(response.application_status.as_deref(), Some("pending"));
    let commit = repository
        .committed
        .lock()
        .expect("committed")
        .pop()
        .expect("commit");
    assert!(!commit.evaluate_policy);
    assert!(commit.transaction.is_none());
    assert!(commit.fact["requirement_id"].is_null());
    assert_eq!(commit.fact["scope"]["course_id"], "course-1");
    assert!(commit.fact["source"].get("source").is_none());
    assert_eq!(
        commit.safe_fact["source"]["provider_event_id"],
        "event-evidence"
    );
    assert_eq!(
        commit.application["integration_context"]["canvas"]["lti_subject"],
        "verified-subject-1"
    );
    assert_eq!(
        commit.application["integration_context"]["canvas"]["verified_launch"]["nonce"],
        "preserve-me"
    );
}

#[tokio::test]
async fn ags_and_nrps_thin_adapters_preserve_normalization() {
    let (ags_service, ags_repository) = make_service(
        CanvasLegacyIngestSnapshot::New(Box::new(snapshot(false, false, "canvas.quiz_score"))),
        false,
    );
    let (body, headers) = signed(&json!({
        "canvas_event_id":"event-ags","application_id":"application-1","canvas_account_id":"account-1",
        "canvas_course_id":"course-1","canvas_user_id":"user-1","score_given":"2","score_maximum":"3",
        "activity_progress":"Completed","grading_progress":"FullyGraded","line_item_id":"line-1","canvas_quiz_id":"quiz-1"
    }));
    ags_service
        .process(CanvasLegacyEventKind::AgsScore, &body, &headers)
        .await
        .expect("AGS");
    let ags = ags_repository
        .committed
        .lock()
        .expect("commit")
        .pop()
        .expect("AGS commit");
    assert_eq!(ags.event.score_percent, Some(66.666_667));
    assert_eq!(ags.event.canvas_assignment_id.as_deref(), Some("line-1"));
    assert_eq!(ags.event.canvas_quiz_id.as_deref(), Some("quiz-1"));
    assert_eq!(ags.event.completed, Some(true));

    let (nrps_service, nrps_repository) = make_service(
        CanvasLegacyIngestSnapshot::New(Box::new(snapshot(false, false, "canvas.nrps_membership"))),
        false,
    );
    let (body, headers) = signed(&json!({
        "canvas_event_id":"event-nrps","application_id":"application-1","canvas_account_id":"account-1",
        "canvas_course_id":"course-1","canvas_user_id":"user-1","membership_id":"membership-1",
        "roles":["Learner","Mentor"],"membership_status":"active"
    }));
    nrps_service
        .process(CanvasLegacyEventKind::NrpsMembership, &body, &headers)
        .await
        .expect("NRPS");
    let nrps = nrps_repository
        .committed
        .lock()
        .expect("commit")
        .pop()
        .expect("NRPS commit");
    assert_eq!(nrps.event.canvas_enrollment_id, "membership-1");
    assert_eq!(
        nrps.event.roles,
        Some(vec!["Learner".to_owned(), "Mentor".to_owned()])
    );
    assert_eq!(nrps.event.eligible, Some(true));
}

#[tokio::test]
async fn hybrid_auto_approval_supports_historical_and_strict_snapshots_and_fails_closed() {
    for strict in [false, true] {
        let (service, repository) = make_service(
            CanvasLegacyIngestSnapshot::New(Box::new(snapshot(
                true,
                strict,
                "canvas.course_completion",
            ))),
            false,
        );
        let (body, headers) = signed(&evidence(if strict { "strict" } else { "historical" }));
        service
            .process(CanvasLegacyEventKind::Evidence, &body, &headers)
            .await
            .expect("auto approval");
        let commit = repository
            .committed
            .lock()
            .expect("commit")
            .pop()
            .expect("commit");
        let transaction = commit.transaction.expect("transaction");
        assert_eq!(transaction.delivery_mode, "wallet_plus_canvas_mirror");
        assert_eq!(
            transaction.issuer_profile_id.as_deref(),
            Some("issuer-profile-1")
        );
        assert_eq!(
            transaction.credential_type.as_deref(),
            Some(if strict {
                "OpenBadgeCredential"
            } else {
                "org.iso.18013.5.1.mDL"
            })
        );
    }
    let mut malformed = snapshot(true, false, "canvas.course_completion");
    malformed
        .binding
        .insert("credential_template_snapshot".to_owned(), json!({}));
    let (service, repository) =
        make_service(CanvasLegacyIngestSnapshot::New(Box::new(malformed)), false);
    let (body, headers) = signed(&evidence("malformed-modern"));
    service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .expect("caught ValueError");
    let commit = repository
        .committed
        .lock()
        .expect("commit")
        .pop()
        .expect("commit");
    assert!(commit.transaction.is_none());
    assert_eq!(
        commit.approval_failure.as_deref(),
        Some("Credential template snapshot is missing credential_type")
    );

    let (service, _) = make_service(
        CanvasLegacyIngestSnapshot::New(Box::new(snapshot(
            true,
            false,
            "canvas.course_completion",
        ))),
        true,
    );
    let (body, headers) = signed(&evidence("resolver-down"));
    assert_eq!(
        service
            .process(CanvasLegacyEventKind::Evidence, &body, &headers)
            .await,
        Err(CanvasLegacyIngestError::AutoApprovalUnavailable)
    );
}

#[tokio::test]
async fn legacy_auto_approval_reuses_and_refreshes_the_exact_pending_transaction() {
    let mut current = snapshot(true, true, "canvas.course_completion");
    let existing_seed = CanvasAwardApprovalSeed {
        transaction_id: "transaction-existing".to_owned(),
        pre_authorized_code: "existing-private-code".to_owned(),
    };
    let mut existing = plan_canvas_approval_transaction(
        &current.application,
        &current.binding,
        &existing_seed,
        now(),
    )
    .expect("existing transaction");
    existing.nonce = Some("existing-nonce".to_owned());
    existing
        .claims
        .insert("preserved_claim".to_owned(), json!("keep-me"));
    existing.delivery_mode = "wallet_only".to_owned();
    existing.credential_type = Some("stale-type".to_owned());
    existing.issuer_profile_id = Some("stale-profile".to_owned());
    existing.signing_service_id = Some("stale-service".to_owned());
    current.application.insert(
        "issuance_transaction_id".to_owned(),
        json!(existing.id.clone()),
    );
    current.existing_transaction = Some(existing);

    let (service, repository) =
        make_service(CanvasLegacyIngestSnapshot::New(Box::new(current)), false);
    let (body, headers) = signed(&evidence("event-existing"));
    service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .expect("auto approval");
    let commit = repository
        .committed
        .lock()
        .expect("commit")
        .pop()
        .expect("commit");
    let transaction = commit.transaction.expect("transaction");
    assert_eq!(transaction.id, "transaction-existing");
    assert_eq!(transaction.pre_authorized_code, "existing-private-code");
    assert_eq!(transaction.nonce.as_deref(), Some("existing-nonce"));
    assert_eq!(transaction.claims["preserved_claim"], "keep-me");
    assert_eq!(transaction.delivery_mode, "wallet_plus_canvas_mirror");
    assert_eq!(
        transaction.credential_type.as_deref(),
        Some("OpenBadgeCredential")
    );
    assert_eq!(
        transaction.issuer_profile_id.as_deref(),
        Some("issuer-profile-1")
    );
}

#[tokio::test]
async fn runtime_binding_feature_tenant_template_status_and_requirement_failures_are_exact() {
    let mut cases = Vec::new();

    let mut missing_binding = snapshot(false, false, "canvas.course_completion");
    missing_binding.binding.insert("id".to_owned(), json!(""));
    cases.push((
        "missing binding",
        missing_binding,
        evidence("missing-binding"),
        CanvasLegacyIngestError::ProgramBindingNotFound,
    ));

    let mut disabled = snapshot(false, false, "canvas.course_completion");
    disabled.binding["feature_flags"]["enable_canvas_evidence"] = json!(false);
    cases.push((
        "feature disabled",
        disabled,
        evidence("feature-disabled"),
        CanvasLegacyIngestError::FeatureDisabled("enable_canvas_evidence"),
    ));

    let mut wrong_org = snapshot(false, false, "canvas.course_completion");
    wrong_org
        .binding
        .insert("organization_id".to_owned(), json!("org-2"));
    cases.push((
        "organization mismatch",
        wrong_org,
        evidence("wrong-org"),
        CanvasLegacyIngestError::OrganizationMismatch,
    ));

    let mut nonpending = snapshot(false, false, "canvas.course_completion");
    nonpending
        .application
        .insert("status".to_owned(), json!("approved"));
    cases.push((
        "nonpending",
        nonpending,
        evidence("nonpending"),
        CanvasLegacyIngestError::InvalidApplicationStatus("ApplicationStatus.APPROVED".to_owned()),
    ));

    let mut wrong_template = snapshot(false, false, "canvas.course_completion");
    wrong_template.binding.insert(
        "application_template_id".to_owned(),
        json!("other-template"),
    );
    cases.push((
        "application template mismatch",
        wrong_template,
        evidence("wrong-template"),
        CanvasLegacyIngestError::ApplicationTemplateMismatch,
    ));

    let mut wrong_binding_credential = evidence("wrong-binding-credential");
    wrong_binding_credential["credential_template_id"] = json!("other-credential");
    cases.push((
        "binding credential mismatch",
        snapshot(false, false, "canvas.course_completion"),
        wrong_binding_credential,
        CanvasLegacyIngestError::BindingCredentialTemplateMismatch,
    ));

    let mut wrong_application_credential = snapshot(false, false, "canvas.course_completion");
    wrong_application_credential
        .application_template
        .as_mut()
        .expect("template")
        .insert(
            "credential_template_id".to_owned(),
            json!("other-credential"),
        );
    cases.push((
        "application credential mismatch",
        wrong_application_credential,
        evidence("wrong-application-credential"),
        CanvasLegacyIngestError::ApplicationCredentialTemplateMismatch,
    ));

    cases.push((
        "evidence not required",
        snapshot(false, false, "canvas.assignment_score"),
        evidence("not-required"),
        CanvasLegacyIngestError::EvidenceNotRequired,
    ));

    for (name, snapshot, payload, expected) in cases {
        let (service, repository) =
            make_service(CanvasLegacyIngestSnapshot::New(Box::new(snapshot)), false);
        let (body, headers) = signed(&payload);
        assert_eq!(
            service
                .process(CanvasLegacyEventKind::Evidence, &body, &headers)
                .await,
            Err(expected),
            "{name}"
        );
        assert!(repository.committed.lock().expect("committed").is_empty());
    }
}

#[tokio::test]
async fn replay_restores_old_response_defaults_and_rejects_payload_or_flow_conflicts() {
    let payload = evidence("event-replay");
    let (body, headers) = signed(&payload);
    let (initial, repository) = make_service(
        CanvasLegacyIngestSnapshot::New(Box::new(snapshot(
            false,
            false,
            "canvas.course_completion",
        ))),
        false,
    );
    initial
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .expect("initial event");
    let hash = repository
        .committed
        .lock()
        .expect("commit")
        .pop()
        .expect("commit")
        .payload_hash;
    let old = CanvasLegacyStoredReceipt {
        payload_hash: hash.clone(),
        status: "evidence_received".to_owned(),
        response: json!({
            "id":"event-replay","application_id":"application-1","organization_id":"org-1","canvas_account_id":"account-1",
            "evidence_type":"canvas.course_completion","status":"evidence_received","evidence":{},"mip_primitives":{}
        }),
    };
    let (service, _) = make_service(CanvasLegacyIngestSnapshot::Replay(old.clone()), false);
    let response = service
        .process(CanvasLegacyEventKind::Evidence, &body, &headers)
        .await
        .expect("replay");
    assert!(response.replayed);
    assert!(response.evidence_facts.is_empty());

    let mut conflict = old.clone();
    conflict.payload_hash = "different".to_owned();
    let (service, _) = make_service(CanvasLegacyIngestSnapshot::Replay(conflict), false);
    assert_eq!(
        service
            .process(CanvasLegacyEventKind::Evidence, &body, &headers)
            .await,
        Err(CanvasLegacyIngestError::ReplayPayloadConflict)
    );
    let mut flow = old;
    flow.status = "processing".to_owned();
    let (service, _) = make_service(CanvasLegacyIngestSnapshot::Replay(flow), false);
    assert_eq!(
        service
            .process(CanvasLegacyEventKind::Evidence, &body, &headers)
            .await,
        Err(CanvasLegacyIngestError::ReplayFlowConflict)
    );
}
