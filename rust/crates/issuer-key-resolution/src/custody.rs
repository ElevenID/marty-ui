use serde_json::Value;

pub const PRIVATE_CUSTODY_FIELDS: &[&str] = &[
    "issuer_algorithm",
    "issuer_key_id",
    "issuer_profile_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_reference",
    "key_name",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "verification_method_id",
];
pub const PRIVATE_JWK_PARAMETERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

pub fn find_private_custody_metadata(value: &Value) -> Option<String> {
    match value {
        Value::Object(values) => {
            let is_jwk = values.keys().any(|name| name.eq_ignore_ascii_case("kty"));
            if is_jwk {
                if let Some(name) = values
                    .keys()
                    .find(|name| contains_case_insensitive(PRIVATE_JWK_PARAMETERS, name))
                {
                    return Some(format!("private JWK parameter '{name}'"));
                }
            }
            for (name, nested) in values {
                if contains_case_insensitive(PRIVATE_CUSTODY_FIELDS, name) {
                    return Some(name.clone());
                }
                if let Some(found) = find_private_custody_metadata(nested) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(find_private_custody_metadata),
        _ => None,
    }
}

pub fn contains_case_insensitive(values: &[&str], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(candidate))
}
