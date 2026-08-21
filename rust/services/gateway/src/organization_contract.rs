use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct OrganizationContractError;

const CREATE_FIELDS: &[&str] = &[
    "name",
    "display_name",
    "description",
    "org_type",
    "contact_email",
    "visibility",
    "join_mechanism",
    "requires_approval",
];
const UPDATE_FIELDS: &[&str] = &[
    "organization_id",
    "name",
    "display_name",
    "description",
    "org_type",
    "contact_email",
    "contact_phone",
    "website",
    "visibility",
    "join_mechanism",
    "requires_approval",
];

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, OrganizationContractError> {
    let create = method == "POST" && path == "/v1/organizations";
    let update = matches!(method, "PATCH" | "PUT")
        && path
            .strip_prefix("/v1/organizations/")
            .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'));
    if !create && !update {
        return Ok(None);
    }
    let mut value: Map<String, Value> = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(OrganizationContractError)?;
    let allowed = if create { CREATE_FIELDS } else { UPDATE_FIELDS };
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(OrganizationContractError);
    }
    if create {
        validate_name(value.get("name"))?;
        validate_nonempty(value.get("display_name"), 128)?;
        value.entry("description").or_insert(Value::Null);
        value.entry("org_type").or_insert(json!("startup"));
        value.entry("contact_email").or_insert(Value::Null);
        value.entry("visibility").or_insert(json!("PRIVATE"));
        value.entry("join_mechanism").or_insert(json!("invite"));
        value.entry("requires_approval").or_insert(json!(false));
    } else {
        value.remove("organization_id");
        if value.is_empty() {
            return Err(OrganizationContractError);
        }
        if value.contains_key("name") {
            validate_name(value.get("name"))?;
        }
        if value.contains_key("display_name") && !value["display_name"].is_null() {
            validate_nonempty(value.get("display_name"), 128)?;
        }
    }
    validate_enums(&value)?;
    if value.get("join_mechanism").and_then(Value::as_str) == Some("open")
        && value.get("visibility").and_then(Value::as_str) != Some("PUBLIC")
    {
        return Err(OrganizationContractError);
    }
    serde_json::to_vec(&Value::Object(value))
        .map(Some)
        .map_err(|_| OrganizationContractError)
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationResponse {
    id: String,
    name: String,
    display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    join_code: Option<String>,
    visibility: Visibility,
    owner_id: String,
    status: OrganizationStatus,
    org_type: OrganizationType,
    join_mechanism: JoinMechanism,
    requires_approval: bool,
    is_discoverable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contact_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contact_phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    membership: Option<Membership>,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    roles: Vec<Role>,
    status: MembershipStatus,
    permissions: Vec<String>,
    has_org_console_access: bool,
    is_owner: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    joined_at: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Role {
    id: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Deserialize, Serialize)]
enum Visibility {
    #[serde(rename = "PUBLIC")]
    Public,
    #[serde(rename = "PRIVATE")]
    Private,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum OrganizationStatus {
    Active,
    Suspended,
    Pending,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum OrganizationType {
    Enterprise,
    Startup,
    Individual,
    Government,
    Education,
    Healthcare,
    Financial,
    Other,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum JoinMechanism {
    Open,
    Code,
    Invite,
    Domain,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum MembershipStatus {
    Active,
    Pending,
    Invited,
    Deactivated,
}

pub fn project_response(value: Value, many: bool) -> Result<Value, OrganizationContractError> {
    if many {
        value
            .as_array()
            .ok_or(OrganizationContractError)?
            .iter()
            .cloned()
            .map(|item| {
                serde_json::from_value::<OrganizationResponse>(item)
                    .map_err(|_| OrganizationContractError)
                    .and_then(|item| {
                        serde_json::to_value(item).map_err(|_| OrganizationContractError)
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array)
    } else {
        serde_json::from_value::<OrganizationResponse>(value)
            .map_err(|_| OrganizationContractError)
            .and_then(|item| serde_json::to_value(item).map_err(|_| OrganizationContractError))
    }
}

pub fn response_shape(method: &str, path: &str) -> Option<bool> {
    if method == "GET"
        && matches!(
            path,
            "/v1/organizations" | "/v1/organizations/discover" | "/v1/organizations/mine"
        )
    {
        return Some(true);
    }
    if method == "POST" && path == "/v1/organizations" {
        return Some(false);
    }
    if matches!(method, "GET" | "PATCH" | "PUT")
        && path.strip_prefix("/v1/organizations/").is_some_and(|tail| {
            !tail.is_empty() && !tail.contains('/') && !matches!(tail, "discover" | "mine")
        })
    {
        return Some(false);
    }
    None
}

fn validate_name(value: Option<&Value>) -> Result<(), OrganizationContractError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(OrganizationContractError)?;
    if !(2..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(OrganizationContractError);
    }
    Ok(())
}
fn validate_nonempty(
    value: Option<&Value>,
    maximum: usize,
) -> Result<(), OrganizationContractError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(OrganizationContractError)?;
    if value.is_empty() || value.len() > maximum {
        Err(OrganizationContractError)
    } else {
        Ok(())
    }
}
fn validate_enums(value: &Map<String, Value>) -> Result<(), OrganizationContractError> {
    let sets = [
        (
            "org_type",
            [
                "enterprise",
                "startup",
                "individual",
                "government",
                "education",
                "healthcare",
                "financial",
                "other",
            ]
            .as_slice(),
        ),
        ("visibility", ["PUBLIC", "PRIVATE"].as_slice()),
        (
            "join_mechanism",
            ["open", "code", "invite", "domain"].as_slice(),
        ),
    ];
    for (field, allowed) in sets {
        if let Some(entry) = value.get(field).filter(|entry| !entry.is_null()) {
            if entry.as_str().is_none_or(|entry| !allowed.contains(&entry)) {
                return Err(OrganizationContractError);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        request_cases: Vec<RequestCase>,
        invalid_requests: Vec<RequestCase>,
        valid_response: Value,
        expected_response: Value,
        private_response_field: String,
    }
    #[derive(Deserialize)]
    struct RequestCase {
        name: String,
        method: String,
        path: String,
        input: Value,
        #[serde(default)]
        expected: Value,
    }

    #[test]
    fn language_neutral_organization_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-organization-behavior.json"
        ))
        .expect("organization contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.request_cases {
            let body = serde_json::to_vec(&case.input).expect("fixture");
            let canonical = canonicalize_request(&case.method, &case.path, &body)
                .unwrap_or_else(|_| panic!("{}", case.name))
                .expect("canonical body");
            assert_eq!(
                serde_json::from_slice::<Value>(&canonical).expect("json"),
                case.expected,
                "{}",
                case.name
            );
        }
        for case in contract.invalid_requests {
            assert!(
                canonicalize_request(
                    &case.method,
                    &case.path,
                    &serde_json::to_vec(&case.input).expect("fixture")
                )
                .is_err(),
                "{}",
                case.name
            );
        }
        assert_eq!(
            project_response(contract.valid_response.clone(), false).expect("valid response"),
            contract.expected_response
        );
        let mut private = contract.valid_response;
        private[contract.private_response_field] = json!({"private": true});
        assert!(project_response(private, false).is_err());
    }
}
