use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    canvas_award_candidate::CanvasAwardCandidateMaterializationPlan,
    canvas_award_candidate_approval::{
        plan_canvas_award_approval, CanvasAwardApprovalRepository, CanvasAwardApprovalSeed,
        CanvasAwardApprovalSeedGenerator, CanvasAwardApprovalSnapshot,
        CanvasAwardCandidateApprovalService,
    },
    canvas_award_candidate_service::{
        CanvasAwardCandidateApprovalError, CanvasAwardCandidateApprover,
    },
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::{
        canvas_lti_experience_session_context, CanvasLtiExperienceSessionContext,
    },
    canvas_lti_launch::{CanvasLtiClock, CanvasLtiStoredLaunchState},
    credential::{
        CredentialIssuanceError, CredentialTransaction, CredentialTransactionStatus, IssuerContext,
        IssuerContextResolver,
    },
};
use serde_json::{json, Map, Value};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, 0)
        .single()
        .unwrap()
}

fn context() -> CanvasLtiExperienceSessionContext {
    canvas_lti_experience_session_context(CanvasLtiStoredLaunchState {
        id: "approval-session".to_owned(),
        platform_id: "platform-1".to_owned(),
        organization_id: "org-1".to_owned(),
        canvas_account_id: "account-1".to_owned(),
        state: "digest".to_owned(),
        nonce: "nonce".to_owned(),
        redirect_uri: "https://ui.example.test/canvas/lti/experience".to_owned(),
        status: "session".to_owned(),
        metadata: json!({
            "kind": "canvas_lti_experience_session",
            "launch_state": "launch-state",
            "verified_launch": {
                "subject": "learner-subject-1",
                "deployment_id": "deployment-1",
                "raw_claims": {
                    "https://purl.imsglobal.org/spec/lti/claim/custom": {
                        "canvas_user_id": "42"
                    }
                }
            },
            "mip_primitives": {"context": {
                "canvas_platform_id": "platform-1",
                "canvas_program_binding_id": "binding-1"
            }}
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
        form_data: json!({"achievement": "Portable Canvas"}),
        integration_context: json!({}),
        status: "pending".to_owned(),
        created_at: now(),
        updated_at: now(),
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn binding() -> Map<String, Value> {
    object(json!({
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
        "readiness_checks": [{"code":"kms","status":"ready","blocking":true}],
        "readiness_validated_at": "2026-08-29T15:59:00Z",
        "credential_template_snapshot": {
            "id": "credential-template-1",
            "organization_id": "org-1",
            "status": "active",
            "credential_type": "OpenBadgeCredential",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "revocation_profile_id": "revocation-profile-1",
            "issuer_did": "did:web:issuer.example:orgs:org-1",
            "issuer_algorithm": "ES256",
            "vct": "https://credentials.example/open-badge",
            "wallet_configs": [{"wallet_id":"wallet-1"}, "ignored"],
            "selective_disclosure_fields": ["achievement"],
            "zk_predicate_claims": ["score"],
            "validity_rules": {
                "default_validity_days": 730,
                "renewable": true,
                "renewal_window_days": 45
            }
        }
    }))
}

fn snapshot() -> CanvasAwardApprovalSnapshot {
    CanvasAwardApprovalSnapshot {
        application: object(json!({
            "id": "application-1",
            "organization_id": "org-1",
            "application_template_id": "application-template-1",
            "applicant_identifier": "canvas_lti:learner-subject-1",
            "form_data": {"achievement":"Portable Canvas"},
            "integration_context": {
                "delivery": {"mode":"wallet_plus_canvas_mirror"},
                "canvas": {"source":"canvas_lti_bootstrap"}
            },
            "status": "pending"
        })),
        application_template: object(json!({
            "id":"application-template-1",
            "organization_id":"org-1",
            "credential_template_id":"credential-template-1",
            "status":"active"
        })),
        binding: binding(),
        identity_still_linked: true,
    }
}

fn plan() -> CanvasAwardCandidateMaterializationPlan {
    CanvasAwardCandidateMaterializationPlan {
        candidate_id: "candidate-1".to_owned(),
        lti_subject: Some("learner-subject-1".to_owned()),
        canvas_user_id: Some("42".to_owned()),
        learner_identity_id: Some("identity-1".to_owned()),
        facts: Vec::new(),
        application_canvas_patch: Map::new(),
        materialized_at: now(),
    }
}

fn seed() -> CanvasAwardApprovalSeed {
    CanvasAwardApprovalSeed {
        transaction_id: "transaction-1".to_owned(),
        pre_authorized_code: "pre-authorized-code-1".to_owned(),
    }
}

fn issuer() -> IssuerContext {
    let issuer_did = "did:web:issuer.example:orgs:org-1";
    IssuerContext {
        issuer_profile_id: "issuer-profile-1".to_owned(),
        issuer_did: issuer_did.to_owned(),
        signing_service_id: "kms-service-1".to_owned(),
        algorithm: "ES256".to_owned(),
        verification_method_id: Some(format!("{issuer_did}#badge-key-1")),
        public_jwk: Some(json!({"kty":"EC","crv":"P-256","x":"x","y":"y"})),
        certificate_chain: Vec::new(),
        raw_context: json!({
            "organization_id":"org-1",
            "issuer_did":issuer_did,
            "algorithm":"ES256",
            "issuer_profile_id":"issuer-profile-1",
            "signing_service_id":"kms-service-1",
            "signing_key_reference":"org_secret://org-1/badge-key",
            "verification_method_id":format!("{issuer_did}#badge-key-1"),
            "key_purpose":"vc_jwt_issuer",
            "public_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},
            "issuer_profile":{
                "id":"issuer-profile-1",
                "status":"active",
                "organization_id":"org-1",
                "issuer_did":issuer_did,
                "verification_method_id":format!("{issuer_did}#badge-key-1"),
                "key_purpose":"vc_jwt_issuer"
            },
            "service":{"id":"kms-service-1","algorithm":"ES256"}
        }),
    }
}

#[test]
fn approval_plan_uses_only_the_validated_template_snapshot() {
    let transaction = plan_canvas_award_approval(
        &context(),
        &application(),
        &plan(),
        &snapshot(),
        &seed(),
        now(),
        Duration::from_secs(900),
    )
    .unwrap();
    assert_eq!(transaction.status, CredentialTransactionStatus::Pending);
    assert_eq!(transaction.credential_template_id, "credential-template-1");
    assert_eq!(
        transaction.credential_type.as_deref(),
        Some("OpenBadgeCredential")
    );
    assert_eq!(
        transaction.revocation_profile_id.as_deref(),
        Some("revocation-profile-1")
    );
    assert_eq!(transaction.delivery_mode, "wallet_plus_canvas_mirror");
    assert_eq!(transaction.validity_days, 730);
    assert!(transaction.renewable);
    assert_eq!(transaction.renewal_window_days, 45);
    assert_eq!(transaction.claims["achievement"], "Portable Canvas");
    assert_eq!(
        transaction.claims["_vct"],
        "https://credentials.example/open-badge"
    );
    assert_eq!(
        transaction.wallet_configs,
        [json!({"wallet_id":"wallet-1"})]
    );
    assert_eq!(transaction.issuer_profile_id, None);

    let mut drift = snapshot();
    drift.identity_still_linked = false;
    assert!(plan_canvas_award_approval(
        &context(),
        &application(),
        &plan(),
        &drift,
        &seed(),
        now(),
        Duration::from_secs(900),
    )
    .is_none());
}

struct Repository {
    events: Arc<Mutex<Vec<String>>>,
    snapshot: Option<CanvasAwardApprovalSnapshot>,
    result: Result<(), CanvasAwardCandidateApprovalError>,
}

#[async_trait]
impl CanvasAwardApprovalRepository for Repository {
    async fn load_approval_snapshot(
        &self,
        _context: &CanvasLtiExperienceSessionContext,
        _application: &CanvasLtiBootstrapApplication,
        _plan: &CanvasAwardCandidateMaterializationPlan,
    ) -> Result<Option<CanvasAwardApprovalSnapshot>, CanvasAwardCandidateApprovalError> {
        self.events.lock().unwrap().push("load".to_owned());
        Ok(self.snapshot.clone())
    }

    async fn reserve_issuance(
        &self,
        transaction: &CredentialTransaction,
        _context: &CanvasLtiExperienceSessionContext,
        _plan: &CanvasAwardCandidateMaterializationPlan,
        _snapshot: &CanvasAwardApprovalSnapshot,
    ) -> Result<(), CanvasAwardCandidateApprovalError> {
        self.events.lock().unwrap().push(format!(
            "reserve:{}:{}:{}",
            transaction.id,
            transaction.issuer_profile_id.as_deref().unwrap_or(""),
            transaction.signing_service_id.as_deref().unwrap_or("")
        ));
        self.result.clone()
    }
}

struct Resolver {
    events: Arc<Mutex<Vec<String>>>,
    issuer: IssuerContext,
    error: Option<CredentialIssuanceError>,
}

#[async_trait]
impl IssuerContextResolver for Resolver {
    async fn resolve(
        &self,
        transaction: &CredentialTransaction,
        credential_format: &str,
        force: bool,
    ) -> Result<IssuerContext, CredentialIssuanceError> {
        self.events.lock().unwrap().push(format!(
            "resolve:{}:{credential_format}:{force}",
            transaction.issuer_did.as_deref().unwrap_or("")
        ));
        if let Some(error) = self.error.clone() {
            Err(error)
        } else {
            Ok(self.issuer.clone())
        }
    }
}

struct Seeds;

impl CanvasAwardApprovalSeedGenerator for Seeds {
    fn generate(&self) -> CanvasAwardApprovalSeed {
        seed()
    }
}

struct Clock;

impl CanvasLtiClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        now()
    }
}

fn service(
    events: Arc<Mutex<Vec<String>>>,
    snapshot: Option<CanvasAwardApprovalSnapshot>,
    issuer: IssuerContext,
    resolver_error: Option<CredentialIssuanceError>,
    repository_result: Result<(), CanvasAwardCandidateApprovalError>,
) -> CanvasAwardCandidateApprovalService {
    CanvasAwardCandidateApprovalService::new(
        Arc::new(Repository {
            events: events.clone(),
            snapshot,
            result: repository_result,
        }),
        Arc::new(Resolver {
            events,
            issuer,
            error: resolver_error,
        }),
        Arc::new(Seeds),
        Arc::new(Clock),
        Duration::from_secs(900),
    )
}

#[tokio::test]
async fn approval_resolves_forced_exact_kms_context_before_reservation() {
    let events = Arc::new(Mutex::new(Vec::new()));
    service(events.clone(), Some(snapshot()), issuer(), None, Ok(()))
        .approve_if_ready(&context(), &application(), &plan(), true)
        .await
        .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "load",
            "resolve:did:web:issuer.example:orgs:org-1:dc+sd-jwt:true",
            "reserve:transaction-1:issuer-profile-1:kms-service-1",
        ]
    );

    let denied_events = Arc::new(Mutex::new(Vec::new()));
    service(
        denied_events.clone(),
        Some(snapshot()),
        issuer(),
        None,
        Ok(()),
    )
    .approve_if_ready(&context(), &application(), &plan(), false)
    .await
    .unwrap();
    assert!(denied_events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn approval_separates_readiness_drift_from_dependency_outage() {
    let mut incomplete = issuer();
    incomplete.raw_context["signing_key_reference"] = Value::Null;
    let events = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(
        service(events, Some(snapshot()), incomplete, None, Ok(()))
            .approve_if_ready(&context(), &application(), &plan(), true)
            .await,
        Err(CanvasAwardCandidateApprovalError::ReadinessDrift)
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(
        service(
            events,
            Some(snapshot()),
            issuer(),
            Some(CredentialIssuanceError::RepositoryUnavailable),
            Ok(()),
        )
        .approve_if_ready(&context(), &application(), &plan(), true)
        .await,
        Err(CanvasAwardCandidateApprovalError::Unavailable)
    );
}
