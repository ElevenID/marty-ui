use chrono::{DateTime, Utc};
use marty_organization::{
    authenticate_forwarded_principal, authorize_forwarded_principal, ForwardedPrincipal, Member,
    MemberStatus, OrganizationApplicationError, Permission, Role,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    organization_id: Uuid,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    principal: String,
    user_id: String,
    member_present: bool,
    member_user_id: Option<String>,
    member_organization_id: Option<Uuid>,
    member_status: Option<MemberStatus>,
    member_roles: Vec<String>,
    member_permissions: Vec<String>,
    api_key_id: Option<String>,
    principal_organization_id: Option<Uuid>,
    authorized_permission: Option<String>,
    required_permission: String,
    owner_only: bool,
    expected: String,
    membership_expected: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-authorization-behavior.json"
    )))
    .expect("organization authorization fixture must be valid JSON")
}

fn member(case: &Case, now: DateTime<Utc>) -> Option<Member> {
    if !case.member_present {
        return None;
    }
    let organization_id = case.member_organization_id.expect("member organization");
    let permissions: Vec<Permission> = case
        .member_permissions
        .iter()
        .map(|key| {
            let (resource, action) = key.split_once(':').expect("permission key");
            Permission::new(resource, action)
        })
        .collect();
    let roles = case
        .member_roles
        .iter()
        .map(|name| Role {
            id: Uuid::new_v4(),
            organization_id,
            name: name.clone(),
            display_name: Some(name.clone()),
            description: None,
            is_system: true,
            is_default_for_new_members: false,
            permissions: permissions.clone(),
            created_at: now,
            updated_at: now,
        })
        .collect();
    Some(Member {
        id: Uuid::new_v4(),
        organization_id,
        user_id: case.member_user_id.clone().expect("member user"),
        email: None,
        status: case.member_status.expect("member status"),
        roles,
        invited_by: None,
        invited_at: None,
        joined_at: Some(now),
        created_at: now,
        updated_at: now,
    })
}

fn classify(
    result: &Result<
        marty_organization::OrganizationAuthorizationContext,
        OrganizationApplicationError,
    >,
) -> &'static str {
    match result {
        Ok(_) => "allow",
        Err(OrganizationApplicationError::AuthenticationRequired) => "authentication_required",
        Err(OrganizationApplicationError::MembershipRequired) => "membership_required",
        Err(OrganizationApplicationError::MembershipInactive) => "membership_inactive",
        Err(OrganizationApplicationError::ActionNotAuthorized) => "action_not_authorized",
        Err(error) => panic!("unexpected authorization error: {error}"),
    }
}

#[test]
fn forwarded_user_and_api_key_context_matches_shared_behavior() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    let now: DateTime<Utc> = "2026-08-20T12:00:00Z".parse().expect("fixed timestamp");
    for case in fixture.cases {
        let principal = match case.principal.as_str() {
            "user" => ForwardedPrincipal::User {
                user_id: case.user_id.clone(),
            },
            "api_key" => ForwardedPrincipal::ApiKey {
                user_id: case.user_id.clone(),
                api_key_id: case.api_key_id.clone().expect("API-key ID"),
                organization_id: case
                    .principal_organization_id
                    .expect("API-key organization"),
                authorized_permission: case
                    .authorized_permission
                    .clone()
                    .expect("authorized permission"),
            },
            principal => panic!("unknown principal {principal}"),
        };
        let member = member(&case, now);
        let membership_result =
            authenticate_forwarded_principal(fixture.organization_id, &principal, member.as_ref());
        assert_eq!(
            classify(&membership_result),
            case.membership_expected,
            "{} membership-only",
            case.name
        );
        let result = authorize_forwarded_principal(
            fixture.organization_id,
            &principal,
            &case.required_permission,
            case.owner_only,
            member.as_ref(),
        );
        assert_eq!(classify(&result), case.expected, "{}", case.name);
    }
}
