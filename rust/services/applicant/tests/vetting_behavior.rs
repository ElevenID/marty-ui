use chrono::{TimeZone, Utc};
use marty_applicant::{store::StoreDocument, CheckStatus, CheckType, VettingCheck};
use serde_json::{json, Map};

fn check(id: &str, order: i32, check_type: CheckType) -> VettingCheck {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    VettingCheck {
        id: id.into(),
        application_id: "application-1".into(),
        check_type,
        custom_name: None,
        is_required: true,
        order,
        status: CheckStatus::NotStarted,
        config: Map::new(),
        result: Map::new(),
        notes: None,
        performed_by: None,
        external_provider: None,
        webhook_url: None,
        created_at: now,
        updated_at: now,
        started_at: None,
        completed_at: None,
    }
}

#[test]
fn checks_are_ordered_filterable_and_round_trip_all_released_types() {
    let mut store = StoreDocument::default();
    store.save_check(check("check-2", 2, CheckType::DocumentVerification));
    store.save_check(check("check-1", 1, CheckType::IdentityVerification));
    assert_eq!(
        store.checks_for_application("application-1")[0].id,
        "check-1"
    );
    assert_eq!(
        store
            .pending_checks(Some(CheckType::IdentityVerification))
            .len(),
        1
    );

    let encoded = store.encode().unwrap();
    let decoded = StoreDocument::decode(&encoded).unwrap();
    assert_eq!(decoded.checks.len(), 2);
}

#[test]
fn completion_deduplicates_evidence_references_and_records_actor() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut check = check("check-1", 1, CheckType::IdentityVerification);
    check.start(now);
    assert_eq!(check.status, CheckStatus::InProgress);
    check.complete(
        true,
        Some("verified".into()),
        Some("reviewer-1".into()),
        serde_json::from_value(json!({"score": 100})).unwrap(),
        vec![
            "evidence-2".into(),
            "evidence-1".into(),
            "evidence-2".into(),
        ],
        now,
    );
    assert_eq!(check.status, CheckStatus::CompletedPassed);
    assert_eq!(
        check.result["evidence_submission_ids"],
        json!(["evidence-1", "evidence-2"])
    );
    assert_eq!(check.performed_by.as_deref(), Some("reviewer-1"));
}
