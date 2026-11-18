use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct VerificationFlowContractError;

const REQUEST_FIELDS: &[&str] = &[
    "presentation_policy_id",
    "organization_id",
    "issuer_did",
    "response_type",
    "trust_profile_id",
    "deployment_profile_id",
    "external_reference",
    "callback_url",
    "expiry_minutes",
    "oid4vp_profile",
    "request_transport",
    "request_uri_method",
];

pub fn canonicalize_request(body: &[u8]) -> Result<Value, VerificationFlowContractError> {
    let mut value = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(VerificationFlowContractError)?;
    if value
        .keys()
        .any(|field| !REQUEST_FIELDS.contains(&field.as_str()))
    {
        return Err(VerificationFlowContractError);
    }
    required_string(&value, "organization_id", 1, 255)?;
    let issuer_did = required_string(&value, "issuer_did", 1, 2048)?;
    if !issuer_did.starts_with("did:") {
        return Err(VerificationFlowContractError);
    }
    value.entry("presentation_policy_id").or_insert(Value::Null);
    value.entry("response_type").or_insert(json!("vp_token"));
    value.entry("trust_profile_id").or_insert(Value::Null);
    value.entry("deployment_profile_id").or_insert(Value::Null);
    value.entry("external_reference").or_insert(Value::Null);
    value.entry("callback_url").or_insert(Value::Null);
    value.entry("expiry_minutes").or_insert(json!(15));
    value.entry("oid4vp_profile").or_insert(json!("standard"));
    value
        .entry("request_transport")
        .or_insert(json!("request_uri"));
    value.entry("request_uri_method").or_insert(json!("get"));
    for field in [
        "presentation_policy_id",
        "trust_profile_id",
        "deployment_profile_id",
        "external_reference",
        "callback_url",
    ] {
        optional_string(&value, field)?;
    }
    enum_value(&value, "response_type", &["vp_token", "id_token"])?;
    enum_value(&value, "oid4vp_profile", &["standard", "haip"])?;
    enum_value(
        &value,
        "request_transport",
        &["request_uri", "request_object", "url_query"],
    )?;
    enum_value(&value, "request_uri_method", &["get", "post"])?;
    let expiry = value
        .get("expiry_minutes")
        .and_then(Value::as_u64)
        .ok_or(VerificationFlowContractError)?;
    if !(1..=1440).contains(&expiry) {
        return Err(VerificationFlowContractError);
    }
    let response_type = value["response_type"]
        .as_str()
        .expect("validated response type");
    let transport = value["request_transport"]
        .as_str()
        .expect("validated transport");
    let request_uri_method = value["request_uri_method"]
        .as_str()
        .expect("validated request URI method");
    if response_type == "vp_token"
        && value
            .get("presentation_policy_id")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(VerificationFlowContractError);
    }
    if matches!(transport, "request_object" | "url_query") && request_uri_method != "get" {
        return Err(VerificationFlowContractError);
    }
    if transport == "url_query"
        && (response_type == "id_token" || value["oid4vp_profile"] == "haip")
    {
        return Err(VerificationFlowContractError);
    }
    Ok(Value::Object(value))
}

pub fn project_response(value: Value) -> Result<Value, VerificationFlowContractError> {
    const FIELDS: &[&str] = &[
        "instance_id",
        "request_uri",
        "qr_code_data",
        "presentation_policy_id",
        "nonce",
        "expires_at",
        "status",
    ];
    let source = value.as_object().ok_or(VerificationFlowContractError)?;
    let mut public = Map::new();
    for field in FIELDS {
        let value = source
            .get(*field)
            .and_then(Value::as_str)
            .ok_or(VerificationFlowContractError)?;
        public.insert((*field).into(), Value::String(value.into()));
    }
    Ok(Value::Object(public))
}

pub fn organization_id(value: &Value) -> &str {
    value["organization_id"]
        .as_str()
        .expect("canonical organization")
}

pub fn reference<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn required_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> Result<&'a str, VerificationFlowContractError> {
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(VerificationFlowContractError)?;
    let length = value.chars().count();
    if length < minimum || length > maximum {
        return Err(VerificationFlowContractError);
    }
    Ok(value)
}

fn optional_string(
    value: &Map<String, Value>,
    field: &str,
) -> Result<(), VerificationFlowContractError> {
    if value
        .get(field)
        .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(VerificationFlowContractError);
    }
    Ok(())
}

fn enum_value(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), VerificationFlowContractError> {
    if value
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| !allowed.contains(&value))
    {
        return Err(VerificationFlowContractError);
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
        valid_request: Value,
        expected_request: Value,
        invalid_requests: Vec<Value>,
        internal_response: Value,
        expected_response: Value,
    }

    #[test]
    fn language_neutral_verification_flow_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-verification-flow-behavior.json"
        ))
        .expect("verification flow contract");
        assert_eq!(contract.schema_version, 1);
        assert_eq!(
            canonicalize_request(&serde_json::to_vec(&contract.valid_request).expect("fixture"))
                .expect("valid request"),
            contract.expected_request
        );
        for invalid in contract.invalid_requests {
            assert!(canonicalize_request(&serde_json::to_vec(&invalid).expect("fixture")).is_err());
        }
        assert_eq!(
            project_response(contract.internal_response).expect("valid response"),
            contract.expected_response
        );
    }
}
