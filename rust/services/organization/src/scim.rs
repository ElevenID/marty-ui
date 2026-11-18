use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SERVICE_PROVIDER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const USER_EXTENSION_SCHEMA: &str = "urn:mip:scim:schemas:extension:Organization:2.0:User";
pub const ROLE_EXTENSION_SCHEMA: &str = "urn:mip:scim:schemas:extension:Organization:2.0:Role";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScimError {
    #[error("unsupported SCIM filter syntax")]
    InvalidFilter,
    #[error("group filters require a string value")]
    GroupFilterRequiresString,
    #[error("unsupported filter attribute: {0}")]
    UnsupportedFilterAttribute(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EqualityFilter {
    pub attribute: String,
    pub value: FilterValue,
}

#[must_use]
pub fn page_bounds(total: usize, start_index: i64, count: i64) -> (usize, usize, usize) {
    let normalized_start = start_index.max(1) as usize;
    let normalized_count = count.max(0) as usize;
    let start_offset = normalized_start.saturating_sub(1).min(total);
    let end_offset = if normalized_count == 0 {
        total
    } else {
        start_offset.saturating_add(normalized_count).min(total)
    };
    (start_offset, end_offset, normalized_start)
}

#[must_use]
pub fn list_response(resources: Vec<Value>, total: usize, start_index: usize) -> Value {
    let items_per_page = resources.len();
    json!({
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": items_per_page,
        "Resources": resources,
    })
}

#[must_use]
pub fn error_payload(status: u16, detail: &str, scim_type: Option<&str>) -> Value {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "status": status.to_string(),
        "detail": detail,
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = Value::String(scim_type.to_owned());
    }
    body
}

pub fn parse_equality_filter(filter: &str) -> Result<EqualityFilter, ScimError> {
    let pattern = Regex::new(r#"^\s*([A-Za-z0-9:._\-]+)\s+eq\s+(\".*?\"|true|false)\s*$"#)
        .expect("static regex is valid");
    let captures = pattern.captures(filter).ok_or(ScimError::InvalidFilter)?;
    let attribute = captures[1].to_owned();
    let raw_value = &captures[2];
    let value = match raw_value {
        "true" => FilterValue::Bool(true),
        "false" => FilterValue::Bool(false),
        quoted => FilterValue::String(quoted[1..quoted.len() - 1].to_owned()),
    };
    Ok(EqualityFilter { attribute, value })
}

pub fn parse_user_filter(filter: &str) -> Result<EqualityFilter, ScimError> {
    let parsed = parse_equality_filter(filter)?;
    let accepted = [
        "userName",
        "emails.value",
        "externalId",
        "active",
        concat!(
            "urn:mip:scim:schemas:extension:Organization:2.0:User",
            ":is_owner"
        ),
    ];
    if accepted.contains(&parsed.attribute.as_str()) {
        Ok(parsed)
    } else {
        Err(ScimError::UnsupportedFilterAttribute(parsed.attribute))
    }
}

pub fn parse_group_filter(filter: &str) -> Result<EqualityFilter, ScimError> {
    let parsed = parse_equality_filter(filter)?;
    if !matches!(parsed.value, FilterValue::String(_)) {
        return Err(ScimError::GroupFilterRequiresString);
    }
    let accepted = [
        "displayName",
        concat!(
            "urn:mip:scim:schemas:extension:Organization:2.0:Role",
            ":description"
        ),
    ];
    if accepted.contains(&parsed.attribute.as_str()) {
        Ok(parsed)
    } else {
        Err(ScimError::UnsupportedFilterAttribute(parsed.attribute))
    }
}

#[must_use]
pub fn slugify_role_name(display_name: &str) -> String {
    let pattern = Regex::new("[^a-z0-9]+").expect("static regex is valid");
    let lowercase = display_name.trim().to_lowercase();
    let slug = pattern
        .replace_all(&lowercase, "-")
        .trim_matches('-')
        .to_owned();
    if slug.is_empty() {
        "role".to_owned()
    } else {
        slug
    }
}

#[must_use]
pub fn group_member_remove_id(path: &str) -> Option<String> {
    let pattern =
        Regex::new(r#"^members\[value eq \"([^\"]+)\"\]$"#).expect("static regex is valid");
    pattern
        .captures(path)
        .map(|captures| captures[1].to_owned())
}
