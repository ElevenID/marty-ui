use chrono::{DateTime, Utc};
use marty_organization::{
    plan_organization_creation, plan_organization_update, CreateOrganizationCommand, JoinMechanism,
    Organization, OrganizationApplicationError, OrganizationStatus, OrganizationType,
    UpdateOrganizationPatch,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u32,
    create: CreateCase,
    update: UpdateCase,
    invalid_admission: InvalidAdmission,
}

#[derive(Debug, Deserialize)]
struct CreateCase {
    name: String,
    owner_id: String,
    org_type: OrganizationType,
    display_name: Option<String>,
    description: Option<String>,
    contact_email: Option<String>,
    visibility: String,
    join_mechanism: JoinMechanism,
    requires_approval: bool,
    expected: CreateExpected,
}

#[derive(Debug, Deserialize)]
struct CreateExpected {
    display_name: String,
    slug_prefix: String,
    status: OrganizationStatus,
    plan: String,
    is_discoverable: bool,
    owner_status: marty_organization::MemberStatus,
    permission_count: usize,
}

#[derive(Debug, Deserialize)]
struct UpdateCase {
    fields_set: Vec<String>,
    name: String,
    description: Option<String>,
    contact_phone: String,
    visibility: String,
    join_mechanism: JoinMechanism,
    settings: Map<String, Value>,
    expected_updated_fields: Vec<String>,
    expected_existing_setting: String,
}

#[derive(Debug, Deserialize)]
struct InvalidAdmission {
    visibility: String,
    join_mechanism: JoinMechanism,
    error_code: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-application-behavior.json"
    )))
    .expect("organization application fixture must be valid JSON")
}

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("fixed timestamp")
}

fn existing_organization() -> Organization {
    let mut settings = Map::new();
    settings.insert("existing_setting".into(), json!("preserved"));
    Organization {
        id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            b"marty:organization:application-contract",
        ),
        name: "original-org".into(),
        display_name: Some("Original Organization".into()),
        slug: "original-org-fixed".into(),
        description: Some("remove me".into()),
        org_type: OrganizationType::Startup,
        status: OrganizationStatus::Active,
        owner_id: "owner-subject".into(),
        join_code: None,
        visibility: "PRIVATE".into(),
        join_mechanism: JoinMechanism::Invite,
        requires_approval: false,
        is_discoverable: false,
        contact_email: Some("owner@example.com".into()),
        contact_phone: None,
        website: None,
        plan: "free".into(),
        plan_expires_at: None,
        settings,
        created_at: now(),
        updated_at: now(),
    }
}

#[test]
fn creation_defaults_owner_and_catalog_match_the_language_neutral_contract() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let case = fixture.create;
    let plan = plan_organization_creation(CreateOrganizationCommand {
        name: case.name,
        owner_id: case.owner_id,
        org_type: case.org_type,
        display_name: case.display_name,
        description: case.description,
        contact_email: case.contact_email.clone(),
        visibility: case.visibility,
        join_mechanism: case.join_mechanism,
        requires_approval: case.requires_approval,
        now: now(),
    })
    .expect("valid creation plan");

    assert_eq!(
        plan.organization.display_name.as_deref(),
        Some(case.expected.display_name.as_str())
    );
    assert!(plan
        .organization
        .slug
        .starts_with(&case.expected.slug_prefix));
    assert_eq!(plan.organization.status, case.expected.status);
    assert_eq!(plan.organization.plan, case.expected.plan);
    assert_eq!(
        plan.organization.is_discoverable,
        case.expected.is_discoverable
    );
    assert_eq!(plan.organization.contact_email, case.contact_email);
    assert_eq!(plan.owner.organization_id, plan.organization.id);
    assert_eq!(plan.owner.user_id, plan.organization.owner_id);
    assert_eq!(plan.owner.status, case.expected.owner_status);
    assert_eq!(plan.permissions.len(), case.expected.permission_count);
}

#[test]
fn partial_updates_clear_nullable_fields_merge_settings_and_report_exact_changes() {
    let case = fixture().update;
    assert_eq!(
        case.fields_set,
        [
            "name",
            "description",
            "contact_phone",
            "visibility",
            "join_mechanism",
            "settings"
        ]
    );
    let patch = UpdateOrganizationPatch {
        name: Some(case.name.clone()),
        description: Some(case.description.clone()),
        contact_phone: Some(Some(case.contact_phone.clone())),
        visibility: Some(case.visibility.clone()),
        join_mechanism: Some(case.join_mechanism),
        settings: Some(case.settings),
        ..UpdateOrganizationPatch::default()
    };
    let (updated, fields) =
        plan_organization_update(&existing_organization(), patch, now()).expect("valid update");

    assert_eq!(fields, case.expected_updated_fields);
    assert_eq!(updated.name, case.name);
    assert_eq!(updated.description, None);
    assert_eq!(
        updated.contact_phone.as_deref(),
        Some(case.contact_phone.as_str())
    );
    assert_eq!(updated.visibility, case.visibility);
    assert!(updated.is_discoverable);
    assert_eq!(updated.join_mechanism, JoinMechanism::Open);
    assert_eq!(updated.settings["new_setting"], "enabled");
    assert_eq!(
        updated.settings["existing_setting"],
        case.expected_existing_setting
    );
    assert_eq!(updated.updated_at, now());
}

#[test]
fn empty_updates_and_private_open_admission_fail_closed() {
    assert!(matches!(
        plan_organization_update(
            &existing_organization(),
            UpdateOrganizationPatch::default(),
            now()
        ),
        Err(OrganizationApplicationError::InvalidCommand(_))
    ));

    let invalid = fixture().invalid_admission;
    let error = plan_organization_creation(CreateOrganizationCommand {
        name: "private-open".into(),
        owner_id: "owner-subject".into(),
        org_type: OrganizationType::Startup,
        display_name: None,
        description: None,
        contact_email: None,
        visibility: invalid.visibility,
        join_mechanism: invalid.join_mechanism,
        requires_approval: false,
        now: now(),
    })
    .expect_err("private open admission must fail");
    assert_eq!(error.to_string(), invalid.error_code);
}
