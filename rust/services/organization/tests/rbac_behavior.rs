use chrono::{DateTime, Utc};
use marty_organization::{resolve_replacement_role, OrganizationApplicationError, Role};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    organization_id: Uuid,
    roles: Vec<RoleFixture>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct RoleFixture {
    id: Uuid,
    name: String,
    is_default: bool,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    deleted_role_id: Uuid,
    available_role_ids: Vec<Uuid>,
    has_affected_members: bool,
    requested_replacement_id: Option<Uuid>,
    expected_replacement_id: Option<Uuid>,
    expected_error: Option<String>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-rbac-behavior.json"
    )))
    .expect("organization RBAC fixture must be valid JSON")
}

fn role(source: &RoleFixture, organization_id: Uuid) -> Role {
    let now: DateTime<Utc> = "2026-08-20T12:00:00Z".parse().expect("fixed timestamp");
    Role {
        id: source.id,
        organization_id,
        name: source.name.clone(),
        display_name: Some(source.name.clone()),
        description: None,
        is_system: false,
        is_default_for_new_members: source.is_default,
        permissions: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn replacement_selection_matches_shared_behavior() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let roles = fixture
        .roles
        .iter()
        .map(|source| role(source, fixture.organization_id))
        .collect::<Vec<_>>();

    for case in fixture.cases {
        let available = roles
            .iter()
            .filter(|role| case.available_role_ids.contains(&role.id))
            .cloned()
            .collect::<Vec<_>>();
        let deleted = available
            .iter()
            .find(|role| role.id == case.deleted_role_id)
            .expect("deleted role must be available");
        let result = resolve_replacement_role(
            deleted,
            &available,
            case.requested_replacement_id,
            case.has_affected_members,
        );

        match case.expected_error.as_deref() {
            None => assert_eq!(
                result.expect(&case.name).map(|role| role.id),
                case.expected_replacement_id,
                "{}",
                case.name
            ),
            Some("replacement_role_required") => assert!(
                matches!(
                    result,
                    Err(OrganizationApplicationError::ReplacementRoleRequired)
                ),
                "{}: {result:?}",
                case.name
            ),
            Some("role_not_found") => assert!(
                matches!(result, Err(OrganizationApplicationError::RoleNotFound(_))),
                "{}: {result:?}",
                case.name
            ),
            Some(error) => panic!("unknown expected error {error}"),
        }
    }
}
