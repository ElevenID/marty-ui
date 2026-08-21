use std::sync::Arc;

use chrono::{DateTime, Utc};
use marty_organization::{
    deserialize_policy_documents, normalize_audit_query, policy_set_ids_to_archive,
    start_from_time_range, validate_policy_documents, AuditQueryInput, CedarPolicyDocument,
    CreatePolicySetCommand, OrganizationApplication, OrganizationApplicationError,
    OrganizationCache, PolicySet, PolicySetStatus, PolicySetType,
};
use mmf_data::MemoryCache;
use mmf_security::{CedarConfig, CedarPolicyValidator};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    cedar_schema: String,
    policy_cases: Vec<PolicyCase>,
    legacy_policy: LegacyPolicy,
    activation_case: ActivationCase,
    audit_now: DateTime<Utc>,
    audit_pagination_cases: Vec<PaginationCase>,
    audit_time_range_cases: Vec<TimeRangeCase>,
}

#[derive(Deserialize)]
struct PolicyCase {
    name: String,
    policies: Vec<CedarPolicyDocument>,
    expected_error: Option<String>,
}

#[derive(Deserialize)]
struct LegacyPolicy {
    source: String,
    expected_policy_id: String,
    expected_effect: String,
}

#[derive(Deserialize)]
struct ActivationCase {
    target_id: Uuid,
    target_type: PolicySetType,
    policy_sets: Vec<ActivationPolicySet>,
    expected_archived_ids: Vec<Uuid>,
}

#[derive(Deserialize)]
struct ActivationPolicySet {
    id: Uuid,
    policy_type: PolicySetType,
    status: PolicySetStatus,
}

#[derive(Deserialize)]
struct PaginationCase {
    name: String,
    page: i64,
    per_page: i64,
    legacy_limit: Option<i64>,
    legacy_offset: i64,
    expected_page: u32,
    expected_per_page: u32,
    expected_offset: u32,
}

#[derive(Deserialize)]
struct TimeRangeCase {
    name: String,
    time_range: String,
    expected_start: Option<DateTime<Utc>>,
    expected_error: Option<String>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-policy-audit-behavior.json"
    )))
    .expect("organization policy/audit fixture must be valid JSON")
}

fn classify_policy_error(errors: &[String]) -> Option<&'static str> {
    let message = errors.first()?;
    if message.starts_with("Policy ") {
        Some("effect_mismatch")
    } else if message.starts_with("Duplicate policy_id") {
        Some("duplicate_policy_id")
    } else if message == "At least one policy must be enabled" {
        Some("no_enabled_policy")
    } else {
        Some("invalid_cedar")
    }
}

#[test]
fn policy_validation_and_legacy_projection_match_shared_behavior() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let validator =
        CedarPolicyValidator::from_human_schema(&fixture.cedar_schema, CedarConfig::default())
            .expect("contract schema must load");
    for case in fixture.policy_cases {
        let errors = validate_policy_documents(&case.policies, &validator);
        assert_eq!(
            classify_policy_error(&errors),
            case.expected_error.as_deref(),
            "{}: {errors:?}",
            case.name
        );
    }
    let legacy = deserialize_policy_documents(&fixture.legacy_policy.source);
    assert_eq!(legacy.len(), 1);
    assert_eq!(
        legacy[0].policy_id,
        fixture.legacy_policy.expected_policy_id
    );
    assert_eq!(legacy[0].effect, fixture.legacy_policy.expected_effect);

    let policy_sets = fixture
        .activation_case
        .policy_sets
        .iter()
        .map(|source| PolicySet {
            id: source.id,
            organization_id: Uuid::nil(),
            name: source.id.to_string(),
            description: None,
            policy_type: source.policy_type,
            status: source.status,
            cedar_policies: "[]".into(),
            cedar_schema_version: "MIP/1.0".into(),
            created_by: None,
            created_at: fixture.audit_now,
            updated_at: fixture.audit_now,
        })
        .collect::<Vec<_>>();
    let target = policy_sets
        .iter()
        .find(|policy_set| policy_set.id == fixture.activation_case.target_id)
        .expect("activation target must exist");
    assert_eq!(target.policy_type, fixture.activation_case.target_type);
    assert_eq!(
        policy_set_ids_to_archive(target, &policy_sets),
        fixture.activation_case.expected_archived_ids
    );
}

#[test]
fn audit_pagination_and_time_ranges_match_shared_behavior() {
    let fixture = fixture();
    for case in fixture.audit_pagination_cases {
        let normalized = normalize_audit_query(
            AuditQueryInput {
                organization_id: Uuid::nil(),
                page: case.page,
                per_page: case.per_page,
                legacy_limit: case.legacy_limit,
                legacy_offset: case.legacy_offset,
                ..AuditQueryInput::default()
            },
            fixture.audit_now,
        )
        .expect(&case.name);
        assert_eq!(normalized.page, case.expected_page, "{}", case.name);
        assert_eq!(normalized.per_page, case.expected_per_page, "{}", case.name);
        assert_eq!(
            normalized.query.offset, case.expected_offset,
            "{}",
            case.name
        );
    }
    for case in fixture.audit_time_range_cases {
        let result = start_from_time_range(Some(&case.time_range), fixture.audit_now);
        assert_eq!(
            result.is_err(),
            case.expected_error.is_some(),
            "{}",
            case.name
        );
        if let Some(expected) = case.expected_start {
            assert_eq!(result.expect(&case.name), Some(expected), "{}", case.name);
        } else if case.expected_error.is_none() {
            assert_eq!(result.expect(&case.name), None, "{}", case.name);
        }
    }
}

#[tokio::test]
async fn policy_mutations_fail_closed_without_the_native_validator() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://contract:contract@127.0.0.1:1/contract")
        .expect("lazy contract pool must compose");
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application = OrganizationApplication::new(
        marty_organization::postgres::PostgresOrganizationStore::new(pool),
        cache,
    )
    .expect("application must compose");
    let error = application
        .create_policy_set(CreatePolicySetCommand {
            organization_id: Uuid::new_v4(),
            name: "fail-closed".into(),
            policies: vec![CedarPolicyDocument {
                policy_id: "allow".into(),
                effect: "permit".into(),
                cedar_text: "permit(principal, action, resource);".into(),
                description: None,
                enabled: true,
            }],
            policy_type: PolicySetType::Custom,
            description: None,
            created_by: None,
            now: Utc::now(),
        })
        .await
        .expect_err("missing native validator must fail before database access");
    assert!(matches!(
        error,
        OrganizationApplicationError::PolicyValidatorUnavailable
    ));
}
