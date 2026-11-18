use chrono::{DateTime, Utc};
use marty_organization::{
    evaluate_join_code, plan_direct_member_roles, JoinCode, JoinCodeState, Permission, Role,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    direct_role_cases: Vec<DirectRoleCase>,
    join_code_cases: Vec<JoinCodeCase>,
}

#[derive(Deserialize)]
struct DirectRoleCase {
    name: String,
    grants_marty_admin: bool,
    requested: Option<Vec<String>>,
    current: Vec<String>,
    defaults: Vec<String>,
    expected: Vec<String>,
}

#[derive(Deserialize)]
struct JoinCodeCase {
    name: String,
    is_active: bool,
    expires_at: Option<DateTime<Utc>>,
    max_uses: Option<u32>,
    use_count: u32,
    state: JoinCodeState,
    message: String,
    expired: bool,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-membership-behavior.json"
    )))
    .expect("organization membership fixture must be valid JSON")
}

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("fixed timestamp")
}

fn role(name: &str) -> Role {
    Role {
        id: Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("marty:test-role:{name}").as_bytes(),
        ),
        organization_id: Uuid::nil(),
        name: name.into(),
        display_name: None,
        description: None,
        is_system: true,
        is_default_for_new_members: name == "applicant",
        permissions: Vec::<Permission>::new(),
        created_at: now(),
        updated_at: now(),
    }
}

#[test]
fn direct_member_role_resolution_matches_shared_behavior() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.direct_role_cases {
        let requested = case
            .requested
            .as_ref()
            .map(|names| names.iter().map(|name| role(name)).collect::<Vec<_>>());
        let current = case
            .current
            .iter()
            .map(|name| role(name))
            .collect::<Vec<_>>();
        let defaults = case
            .defaults
            .iter()
            .map(|name| role(name))
            .collect::<Vec<_>>();
        let admin = role("admin");
        let resolved = plan_direct_member_roles(
            case.grants_marty_admin,
            requested.as_deref(),
            &current,
            Some(&admin),
            &defaults,
        )
        .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(
            resolved
                .iter()
                .map(|role| role.name.clone())
                .collect::<Vec<_>>(),
            case.expected,
            "{}",
            case.name
        );
    }
}

#[test]
fn join_code_failure_precedence_and_messages_match_shared_behavior() {
    for case in fixture().join_code_cases {
        let join_code = JoinCode {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            code: "MARTY123".into(),
            created_by: "owner".into(),
            expires_at: case.expires_at,
            max_uses: case.max_uses,
            use_count: case.use_count,
            is_active: case.is_active,
            created_at: now(),
            updated_at: now(),
        };
        let evaluation = evaluate_join_code(&join_code, now());
        assert_eq!(evaluation.state, case.state, "{}", case.name);
        assert_eq!(evaluation.message, case.message, "{}", case.name);
        assert_eq!(evaluation.expired, case.expired, "{}", case.name);
    }
}
