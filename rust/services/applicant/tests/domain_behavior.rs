use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, TimeZone, Utc};
use marty_applicant::{
    validate_form_data, ApplicantError, Evidence, EvidenceStatus, EvidenceUpload, FieldDefinition,
    LifecycleStatus, ReviewerLocks, LOCK_TTL_SECONDS, MAX_EVIDENCE_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize)]
struct Behavior {
    http_operations: Vec<Value>,
    lifecycle_statuses: Vec<String>,
    claim_states: Vec<String>,
    evidence_statuses: Vec<String>,
    capabilities: Vec<String>,
    maximum_evidence_bytes: usize,
    reviewer_lock_ttl_seconds: i64,
    removed_legacy_routes_remain_absent: bool,
    failure_behavior: String,
}

fn behavior() -> Behavior {
    serde_json::from_str(include_str!(
        "../../../../contracts/applicant-service-behavior.json"
    ))
    .expect("valid applicant behavior contract")
}

#[test]
fn complete_surface_and_domain_inventory_is_language_neutral() {
    let contract = behavior();
    assert_eq!(contract.http_operations.len(), 32);
    assert_eq!(contract.lifecycle_statuses.len(), 10);
    assert_eq!(contract.claim_states.len(), 5);
    assert_eq!(contract.evidence_statuses.len(), 4);
    assert_eq!(contract.capabilities.len(), 11);
    assert_eq!(contract.maximum_evidence_bytes, MAX_EVIDENCE_BYTES);
    assert_eq!(contract.reviewer_lock_ttl_seconds, LOCK_TTL_SECONDS);
    assert!(contract.removed_legacy_routes_remain_absent);
    assert_eq!(contract.failure_behavior, "fail_closed");
}

#[test]
fn one_shared_lifecycle_preserves_legacy_aliases_and_terminal_states() {
    assert_eq!(
        LifecycleStatus::from_released("pending").unwrap(),
        LifecycleStatus::Submitted
    );
    assert_eq!(
        LifecycleStatus::from_released("in_review").unwrap(),
        LifecycleStatus::UnderReview
    );
    assert_eq!(
        LifecycleStatus::from_released("needs_info").unwrap(),
        LifecycleStatus::PendingInformation
    );
    assert_eq!(
        LifecycleStatus::from_released("issued").unwrap(),
        LifecycleStatus::Credentialed
    );
    assert_eq!(
        LifecycleStatus::from_released("revoked").unwrap(),
        LifecycleStatus::Suspended
    );
    assert_eq!(
        LifecycleStatus::Draft
            .transition(LifecycleStatus::Submitted)
            .unwrap(),
        LifecycleStatus::Submitted
    );
    assert_eq!(
        LifecycleStatus::Submitted
            .transition(LifecycleStatus::Approved)
            .unwrap(),
        LifecycleStatus::Approved
    );
    assert!(matches!(
        LifecycleStatus::Rejected.transition(LifecycleStatus::Submitted),
        Err(ApplicantError::InvalidTransition { .. })
    ));
    assert!(LifecycleStatus::from_released("unknown").is_err());
}

#[test]
fn form_validation_returns_stable_field_failures_and_rejects_unknown_data() {
    let fields: Vec<FieldDefinition> = serde_json::from_value(json!([
        {"field_id":"birth_date","field_type":"date","required":true},
        {"field_id":"score","field_type":"integer","minimum":1,"maximum":10},
        {"field_id":"role","options":[{"value":"member"},{"value":"admin"}]},
        {"field_id":"code","validation_pattern":"^[A-Z]{2}$"}
    ]))
    .unwrap();
    let form: Map<String, Value> = serde_json::from_value(json!({
        "birth_date":"31/12/2000", "score":11, "role":"owner", "code":"x", "extra":true
    }))
    .unwrap();
    let ApplicantError::FieldValidation(errors) = validate_form_data(&form, &fields).unwrap_err()
    else {
        panic!("field validation error")
    };
    assert_eq!(
        errors.iter().map(|error| error.code).collect::<Vec<_>>(),
        vec![
            "INVALID_DATE",
            "ABOVE_MAXIMUM",
            "INVALID_CHOICE",
            "PATTERN_MISMATCH",
            "UNKNOWN_FIELD"
        ]
    );
}

#[test]
fn evidence_is_bounded_hashed_sanitized_and_expires_fail_closed() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let upload = EvidenceUpload {
        application_id: "application-1".into(),
        applicant_id: "applicant-1".into(),
        organization_id: "org-1".into(),
        evidence_requirement_id: "passport".into(),
        evidence_type: "DOCUMENT_SCAN".into(),
        media_type: "application/pdf".into(),
        filename: "folder/passport.pdf".into(),
        content_base64: STANDARD.encode(b"evidence"),
        submitted_by: "user-1".into(),
        captured_at: Some(now),
        expires_at: Some(now + Duration::minutes(1)),
    };
    let mut evidence = Evidence::from_upload(upload, MAX_EVIDENCE_BYTES + 1, now).unwrap();
    assert_eq!(evidence.filename, "passport.pdf");
    assert_eq!(evidence.size_bytes, 8);
    assert_eq!(evidence.sha256.len(), 64);
    evidence.refresh_expiry(now + Duration::minutes(2));
    assert_eq!(evidence.status, EvidenceStatus::Expired);
}

#[test]
fn reviewer_locks_refresh_owner_and_deny_competing_reviewer_until_expiry() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let mut locks = ReviewerLocks::default();
    locks
        .acquire("application-1", "reviewer-1", "One", now)
        .unwrap();
    assert!(matches!(
        locks.acquire("application-1", "reviewer-2", "Two", now),
        Err(ApplicantError::Locked(_))
    ));
    let refreshed = locks
        .acquire(
            "application-1",
            "reviewer-1",
            "One",
            now + Duration::seconds(1),
        )
        .unwrap();
    assert_eq!(
        refreshed.expires_at,
        now + Duration::seconds(1 + LOCK_TTL_SECONDS)
    );
    assert!(locks
        .acquire(
            "application-1",
            "reviewer-2",
            "Two",
            now + Duration::seconds(LOCK_TTL_SECONDS + 2)
        )
        .is_ok());
    assert!(!locks.release(
        "application-1",
        "reviewer-1",
        now + Duration::seconds(LOCK_TTL_SECONDS + 2)
    ));
    assert!(locks.release(
        "application-1",
        "reviewer-2",
        now + Duration::seconds(LOCK_TTL_SECONDS + 2)
    ));
}
