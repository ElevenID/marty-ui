use chrono::{DateTime, Duration, Utc};
use marty_organization::{
    scim, ApiKey, ApiKeySpec, JoinCode, Member, MemberStatus, Permission, Role,
};
use serde_json::Value;
use uuid::Uuid;

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-domain-behavior.json"
    )))
    .expect("organization domain fixture must be valid JSON")
}

fn fixed_now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z"
        .parse()
        .expect("fixed test timestamp must parse")
}

fn role(name: &str, permission_keys: &[Value], now: DateTime<Utc>) -> Role {
    let permissions = permission_keys
        .iter()
        .map(|value| {
            let key = value.as_str().expect("permission key must be a string");
            let (resource, action) = key
                .split_once(':')
                .expect("permission key must have resource:action form");
            Permission::new(resource, action)
        })
        .collect();
    Role {
        id: Uuid::new_v4(),
        organization_id: Uuid::nil(),
        name: name.to_owned(),
        display_name: None,
        description: None,
        is_system: true,
        is_default_for_new_members: false,
        permissions,
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn slug_behavior_matches_shared_vectors() {
    for case in fixture()["slug_cases"]
        .as_array()
        .expect("slug cases must be an array")
    {
        let slug = marty_organization::Organization::generate_slug(
            case["input"].as_str().expect("slug input must be a string"),
        )
        .expect("valid slug vector must generate a slug");
        assert!(
            slug.starts_with(
                case["expected_prefix"]
                    .as_str()
                    .expect("slug prefix must be a string")
            ),
            "slug case {} produced {slug}",
            case["name"]
        );
        assert_eq!(slug.len(), slug.rfind('-').expect("slug has suffix") + 9);
    }
}

#[test]
fn join_code_generation_and_validity_match_shared_vectors() {
    let fixture = fixture();
    let join_code_fixture = &fixture["join_code"];
    let alphabet = join_code_fixture["alphabet"]
        .as_str()
        .expect("join-code alphabet must be a string");
    for _ in 0..64 {
        let code = JoinCode::generate_code();
        assert_eq!(
            code.len(),
            join_code_fixture["length"]
                .as_u64()
                .expect("join-code length must be numeric") as usize
        );
        assert!(code.chars().all(|character| alphabet.contains(character)));
    }

    let now = fixed_now();
    for case in join_code_fixture["validity_cases"]
        .as_array()
        .expect("validity cases must be an array")
    {
        let expires_at = case["expires_offset_seconds"]
            .as_i64()
            .map(|offset| now + Duration::seconds(offset));
        let join_code = JoinCode {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            code: "ABCDEFGH".to_owned(),
            created_by: "creator".to_owned(),
            expires_at,
            max_uses: case["max_uses"].as_u64().map(|value| value as u32),
            use_count: case["use_count"]
                .as_u64()
                .expect("use count must be numeric") as u32,
            is_active: case["active"].as_bool().expect("active must be boolean"),
            created_at: now,
            updated_at: now,
        };
        assert_eq!(
            join_code.is_valid_at(now),
            case["valid"].as_bool().expect("valid must be boolean"),
            "join-code case {}",
            case["name"]
        );
    }
}

#[test]
fn membership_authorization_matches_shared_vectors() {
    let now = fixed_now();
    for case in fixture()["member_cases"]
        .as_array()
        .expect("member cases must be an array")
    {
        let roles = case["roles"]
            .as_array()
            .expect("roles must be an array")
            .iter()
            .map(|item| {
                role(
                    item["name"].as_str().expect("role name must be a string"),
                    item["permissions"]
                        .as_array()
                        .expect("permissions must be an array"),
                    now,
                )
            })
            .collect();
        let mut member = Member::create(Uuid::new_v4(), "subject", None, MemberStatus::Active, now);
        member.roles = roles;
        assert_eq!(
            member.has_org_console_access(),
            case["has_console_access"]
                .as_bool()
                .expect("console access must be boolean"),
            "member case {}",
            case["name"]
        );
        assert_eq!(
            member.is_owner(),
            case["is_owner"].as_bool().expect("owner must be boolean"),
            "member case {}",
            case["name"]
        );
    }
}

#[test]
fn api_key_scope_and_secret_behavior_match_shared_vectors() {
    let now = fixed_now();
    for case in fixture()["api_key_cases"]
        .as_array()
        .expect("API-key cases must be an array")
    {
        let scopes = case["stored_scopes"]
            .as_array()
            .expect("stored scopes must be an array")
            .iter()
            .map(|value| value.as_str().expect("scope must be a string").to_owned())
            .collect();
        let key = ApiKey::from_raw(
            ApiKeySpec {
                organization_id: Uuid::new_v4(),
                name: "contract-key".to_owned(),
                created_by: "creator".to_owned(),
                scopes: Some(scopes),
                description: None,
                expires_at: None,
                now,
            },
            "mk_test_contract-secret",
        );
        assert!(key.verify("mk_test_contract-secret"));
        assert!(!key.verify("mk_test_wrong-secret"));
        assert_eq!(
            key.has_scope(
                case["query"]
                    .as_str()
                    .expect("query scope must be a string")
            ),
            case["allowed"].as_bool().expect("allowed must be boolean"),
            "API-key case {}",
            case["name"]
        );
    }
}

#[test]
fn scim_helpers_match_shared_vectors() {
    let fixture = fixture();
    for case in fixture["scim"]["pagination_cases"]
        .as_array()
        .expect("pagination cases must be an array")
    {
        let actual = scim::page_bounds(
            case["total"].as_u64().expect("total must be numeric") as usize,
            case["start_index"]
                .as_i64()
                .expect("start index must be numeric"),
            case["count"].as_i64().expect("count must be numeric"),
        );
        assert_eq!(
            actual,
            (
                case["start_offset"]
                    .as_u64()
                    .expect("start offset must be numeric") as usize,
                case["end_offset"]
                    .as_u64()
                    .expect("end offset must be numeric") as usize,
                case["normalized_start"]
                    .as_u64()
                    .expect("normalized start must be numeric") as usize,
            ),
            "pagination case {}",
            case["name"]
        );
    }
    for filter in fixture["scim"]["valid_user_filters"]
        .as_array()
        .expect("valid filters must be an array")
    {
        scim::parse_user_filter(filter.as_str().expect("filter must be a string"))
            .expect("valid filter must parse");
    }
    for filter in fixture["scim"]["invalid_user_filters"]
        .as_array()
        .expect("invalid filters must be an array")
    {
        assert!(
            scim::parse_user_filter(filter.as_str().expect("filter must be a string")).is_err()
        );
    }
    for case in fixture["scim"]["role_slugs"]
        .as_array()
        .expect("role slugs must be an array")
    {
        assert_eq!(
            scim::slugify_role_name(case["input"].as_str().expect("input must be a string")),
            case["expected"]
                .as_str()
                .expect("expected slug must be a string")
        );
    }
}

#[test]
fn frozen_surface_is_unique_and_complete() {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-service-surface.json"
    )))
    .expect("organization surface fixture must be valid JSON");
    let routes = fixture["http_routes"]
        .as_array()
        .expect("HTTP routes must be an array");
    let unique_routes: std::collections::BTreeSet<_> = routes
        .iter()
        .map(|route| route.as_str().expect("route must be a string"))
        .collect();
    assert_eq!(routes.len(), 62);
    assert_eq!(unique_routes.len(), routes.len());
    assert_eq!(
        fixture["grpc_methods"]
            .as_array()
            .expect("gRPC methods must be an array")
            .len(),
        12
    );
    let grpc_methods = fixture["grpc_methods"]
        .as_array()
        .expect("gRPC methods must be an array")
        .iter()
        .map(|method| method.as_str().expect("method must be a string"))
        .collect::<Vec<_>>();
    assert_eq!(grpc_methods, marty_organization::ORGANIZATION_GRPC_METHODS);
    assert_eq!(
        fixture["legacy_python_grpc_gap"]
            .as_array()
            .expect("legacy gap must be an array")
            .len(),
        4
    );
}
