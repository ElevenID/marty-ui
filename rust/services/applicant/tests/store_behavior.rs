use chrono::{TimeZone, Utc};
use marty_applicant::{store::StoreDocument, Applicant, Application, ClaimState, LifecycleStatus};
use serde_json::Map;

fn application(id: &str, applicant_id: &str, organization_id: &str) -> Application {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    Application {
        id: id.into(),
        applicant_id: applicant_id.into(),
        organization_id: organization_id.into(),
        reference_number: Some("APP-20260821-ABC123".into()),
        application_template_id: "application-template-1".into(),
        credential_template_id: "credential-template-1".into(),
        status: LifecycleStatus::Draft,
        form_data: Map::new(),
        integration_context: Map::new(),
        system_data: Map::new(),
        required_checks: Vec::new(),
        evidence_requirements: Vec::new(),
        claim_state: ClaimState::NotReady,
        claim_blocker: None,
        created_at: now,
        updated_at: now,
        submitted_at: None,
        reviewed_at: None,
        issued_at: None,
    }
}

#[test]
fn released_json_shape_round_trips_and_queries_remain_tenant_bound() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut first = Applicant::new("org-1".into(), "ada@example.com".into(), now);
    first.id = "applicant-1".into();
    first.user_id = Some("user-1".into());
    let mut second = Applicant::new("org-2".into(), "ada@example.com".into(), now);
    second.id = "applicant-2".into();
    second.user_id = Some("user-1".into());

    let mut store = StoreDocument::default();
    store.save_applicant(first);
    store.save_applicant(second);
    store.save_application(application("application-1", "applicant-1", "org-1"));

    let encoded = store.encode().unwrap();
    let decoded = StoreDocument::decode(&encoded).unwrap();
    assert_eq!(
        decoded.applicant_for_user("user-1", "org-1").unwrap().id,
        "applicant-1"
    );
    assert_eq!(
        decoded.applicant_for_user("user-1", "org-2").unwrap().id,
        "applicant-2"
    );
    assert_eq!(decoded.applications_for_organization("org-1").len(), 1);
    assert!(decoded.applications_for_organization("org-2").is_empty());
}

#[test]
fn saves_replace_existing_identity_instead_of_duplicating() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut applicant = Applicant::new("org-1".into(), "old@example.com".into(), now);
    applicant.id = "applicant-1".into();
    let mut store = StoreDocument::default();
    store.save_applicant(applicant.clone());
    applicant.email = "new@example.com".into();
    store.save_applicant(applicant);
    assert_eq!(store.applicants.len(), 1);
    assert_eq!(
        store.applicant("applicant-1").unwrap().email,
        "new@example.com"
    );
}
