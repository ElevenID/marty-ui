use chrono::{DateTime, Utc};
use marty_organization::{
    apply_console_preference_patch, validate_create_api_key, ApiKeyScopeType,
    ConsoleContextPreference, CreateApiKeyCommand, UpdateConsolePreferencePatch, ViewMode,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    api_key_cases: Vec<ApiKeyCase>,
    preference_cases: Vec<PreferenceCase>,
}

#[derive(Deserialize)]
struct ApiKeyCase {
    name: String,
    scope_type: ApiKeyScopeType,
    deployment_profile_id: Option<Uuid>,
    scopes: Option<Vec<String>>,
    rate_limit: Option<u32>,
    expires_at: Option<DateTime<Utc>>,
    valid: bool,
}

#[derive(Deserialize)]
struct PreferenceCase {
    name: String,
    last_view_mode: Option<ViewMode>,
    last_active_org: ActiveOrgOperation,
    expected_view_mode: ViewMode,
    expected_active_org_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct ActiveOrgOperation {
    operation: String,
    organization_id: Option<Uuid>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-api-preference-behavior.json"
    )))
    .expect("organization API/preference fixture must be valid JSON")
}

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("fixed timestamp")
}

#[test]
fn api_key_scope_and_binding_validation_matches_shared_behavior() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.api_key_cases {
        let result = validate_create_api_key(&CreateApiKeyCommand {
            organization_id: Uuid::new_v4(),
            name: "contract-key".into(),
            created_by: "owner".into(),
            scopes: case.scopes,
            description: None,
            is_test: true,
            scope_type: case.scope_type,
            deployment_profile_id: case.deployment_profile_id,
            rate_limit: case.rate_limit,
            expires_at: case.expires_at,
            now: now(),
        });
        assert_eq!(result.is_ok(), case.valid, "{}: {result:?}", case.name);
    }
}

#[test]
fn preference_omission_clear_and_replace_are_distinct_operations() {
    let active_org = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
    for case in fixture().preference_cases {
        let current = ConsoleContextPreference {
            id: Uuid::new_v4(),
            user_id: "subject".into(),
            last_view_mode: ViewMode::OrgAdmin,
            last_active_org_id: Some(active_org),
            created_at: now(),
            updated_at: now(),
        };
        let last_active_organization_id = match case.last_active_org.operation.as_str() {
            "omitted" => None,
            "clear" => Some(None),
            "set" => Some(Some(
                case.last_active_org.organization_id.expect("set value"),
            )),
            operation => panic!("unknown operation {operation}"),
        };
        let updated = apply_console_preference_patch(
            &current,
            &UpdateConsolePreferencePatch {
                last_view_mode: case.last_view_mode,
                last_active_organization_id,
            },
            now(),
        );
        assert_eq!(
            updated.last_view_mode, case.expected_view_mode,
            "{}",
            case.name
        );
        assert_eq!(
            updated.last_active_org_id, case.expected_active_org_id,
            "{}",
            case.name
        );
    }
}
