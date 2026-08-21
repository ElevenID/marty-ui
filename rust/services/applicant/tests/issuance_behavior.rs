use chrono::{TimeZone, Utc};
use marty_applicant::{
    issuance::{
        apply_offer, mark_no_active_flow, reconcile_transaction, reserve_attempt, IssuanceOffer,
    },
    Applicant, Application, ClaimState, LifecycleStatus,
};
use serde_json::{json, Map};

fn state() -> (Application, Applicant) {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut applicant = Applicant::new("org-1".into(), "ada@example.com".into(), now);
    applicant.id = "applicant-1".into();
    applicant.status = LifecycleStatus::Approved;
    let application = Application {
        id: "application-1".into(),
        applicant_id: applicant.id.clone(),
        organization_id: "org-1".into(),
        reference_number: Some("APP-20260821-ABC123".into()),
        application_template_id: "template-1".into(),
        credential_template_id: "credential-1".into(),
        status: LifecycleStatus::Approved,
        form_data: Map::new(),
        integration_context: Map::new(),
        system_data: Map::new(),
        required_checks: vec![],
        evidence_requirements: vec![],
        claim_state: ClaimState::NotReady,
        claim_blocker: None,
        created_at: now,
        updated_at: now,
        submitted_at: Some(now),
        reviewed_at: Some(now),
        issued_at: None,
    };
    (application, applicant)
}

#[test]
fn uncertain_retry_reuses_exact_attempt_and_claim_snapshot() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let (mut application, _) = state();
    let claims: Map<String, _> =
        serde_json::from_value(json!({"email":"ada@example.com"})).unwrap();
    let (first_id, first_claims) = reserve_attempt(&mut application, claims, now).unwrap();
    let changed: Map<String, _> =
        serde_json::from_value(json!({"email":"attacker@example.com"})).unwrap();
    let (retry_id, retry_claims) = reserve_attempt(&mut application, changed, now).unwrap();
    assert_eq!(retry_id, first_id);
    assert_eq!(retry_claims, first_claims);
}

#[test]
fn offer_is_not_credentialed_until_transaction_reports_issued() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let (mut application, mut applicant) = state();
    let (attempt, _) = reserve_attempt(&mut application, Map::new(), now).unwrap();
    let offer = IssuanceOffer {
        id: Some("transaction-1".into()),
        credential_offer_uri: Some("openid-credential-offer://offer".into()),
        credential_offer_uris: Map::new(),
        credential_offer_labels: Map::new(),
        expires_at: Some("2026-08-21T12:05:00Z".into()),
        status: "pending".into(),
        flow_instance_id: Some("flow-instance-1".into()),
        flow_definition_id: Some("flow-1".into()),
        source: Some("flow".into()),
    };
    apply_offer(&mut application, &mut applicant, attempt, &offer, now).unwrap();
    assert_eq!(application.status, LifecycleStatus::Offered);
    assert_eq!(application.claim_state, ClaimState::OfferReady);
    assert_eq!(applicant.status, LifecycleStatus::Offered);
    assert!(
        reconcile_transaction(&mut application, &mut applicant, "issued", Some(now), now).unwrap()
    );
    assert_eq!(application.status, LifecycleStatus::Credentialed);
    assert_eq!(application.claim_state, ClaimState::Claimed);
    assert_eq!(applicant.status, LifecycleStatus::Credentialed);
}

#[test]
fn missing_active_flow_persists_stable_issuer_owned_blocker() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let (mut application, _) = state();
    mark_no_active_flow(&mut application, now);
    assert_eq!(application.claim_state, ClaimState::Blocked);
    assert_eq!(
        application.claim_blocker.as_ref().unwrap()["code"],
        "NO_ACTIVE_ISSUANCE_FLOW"
    );
    assert_eq!(
        application.claim_blocker.as_ref().unwrap()["owner"],
        "ISSUER"
    );
}
