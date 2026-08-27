use std::collections::BTreeSet;

use serde_json::{Map, Value};

#[derive(Debug)]
pub struct CredentialTemplateContractError;

const PUBLIC_FIELDS: &[&str] = &[
    "id",
    "organization_id",
    "name",
    "description",
    "status",
    "credential_type",
    "compliance_profile_id",
    "vct",
    "doctype",
    "credential_payload_format",
    "issuance_protocol",
    "application_template_id",
    "trust_profile_id",
    "revocation_profile_id",
    "claims",
    "validity_rules",
    "issuer_did",
    "privacy_posture",
    "created_at",
    "updated_at",
];
const CREATE_FIELDS: &[&str] = &[
    "organization_id",
    "name",
    "description",
    "credential_type",
    "vct",
    "doctype",
    "claims",
    "privacy_posture",
    "selective_disclosure_fields",
    "supported_formats",
    "application_template_id",
    "compliance_profile_id",
    "trust_profile_id",
    "revocation_profile_id",
    "validity_rules",
    "issuer_did",
    "derived_attributes",
    "display_style",
    "zk_predicate_claims",
    "schema_uri",
    "credential_payload_format",
    "issuance_protocol",
];

pub fn canonicalize_create(body: &[u8]) -> Result<Value, CredentialTemplateContractError> {
    let mut value = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(CredentialTemplateContractError)?;
    if value
        .keys()
        .any(|key| !CREATE_FIELDS.contains(&key.as_str()))
    {
        return Err(CredentialTemplateContractError);
    }
    for field in [
        "organization_id",
        "name",
        "credential_type",
        "compliance_profile_id",
        "issuer_did",
    ] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|entry| entry.is_empty())
        {
            return Err(CredentialTemplateContractError);
        }
    }
    if !value["issuer_did"]
        .as_str()
        .is_some_and(|did| did.starts_with("did:") && did.len() <= 2048)
    {
        return Err(CredentialTemplateContractError);
    }
    value.entry("claims").or_insert(Value::Array(Vec::new()));
    value
        .entry("privacy_posture")
        .or_insert(Value::String("selective_disclosure".into()));
    value
        .entry("selective_disclosure_fields")
        .or_insert(Value::Array(Vec::new()));
    value
        .entry("supported_formats")
        .or_insert(Value::Array(vec![Value::String("sd_jwt_vc".into())]));
    value
        .entry("derived_attributes")
        .or_insert(Value::Array(Vec::new()));
    value
        .entry("zk_predicate_claims")
        .or_insert(Value::Array(Vec::new()));
    let mut formats = value
        .get("supported_formats")
        .and_then(Value::as_array)
        .ok_or(CredentialTemplateContractError)?
        .iter()
        .filter_map(Value::as_str)
        .map(|value| value.to_ascii_lowercase().replace('-', "_"))
        .collect::<BTreeSet<_>>();
    if let Some(format) = value
        .get("credential_payload_format")
        .and_then(Value::as_str)
    {
        formats.insert(format.to_ascii_lowercase().replace('-', "_"));
    }
    if formats.iter().any(|format| {
        matches!(
            format.as_str(),
            "mdoc" | "mso_mdoc" | "iso_mdoc" | "zk_mdoc"
        )
    }) && value
        .get("doctype")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(CredentialTemplateContractError);
    }
    if formats.iter().any(|format| {
        matches!(
            format.as_str(),
            "sd_jwt_vc" | "dc+sd_jwt" | "vc+sd_jwt" | "w3c_vcdm_v2_sd_jwt" | "ietf_sd_jwt_vc"
        )
    }) && value
        .get("vct")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(CredentialTemplateContractError);
    }
    let claims = internal_claims(value.get("claims").ok_or(CredentialTemplateContractError)?)?;
    value.insert("claims".into(), claims);
    Ok(Value::Object(value))
}

pub fn internal_claims(value: &Value) -> Result<Value, CredentialTemplateContractError> {
    let claims = value.as_array().ok_or(CredentialTemplateContractError)?;
    let mut names = BTreeSet::new();
    let mut output = Vec::with_capacity(claims.len());
    for claim in claims {
        let mut claim = claim
            .as_object()
            .cloned()
            .ok_or(CredentialTemplateContractError)?;
        let name = claim
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or(CredentialTemplateContractError)?
            .to_owned();
        if !names.insert(name.clone()) {
            return Err(CredentialTemplateContractError);
        }
        let display = claim
            .remove("display")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        if let Some(label) = display.get("label").filter(|value| value.is_string()) {
            claim.insert("display_name".into(), label.clone());
        }
        if let Some(icon) = display.get("icon").filter(|value| value.is_string()) {
            claim.insert("display_icon".into(), icon.clone());
        }
        if !claim.contains_key("claim_type") {
            if let Some(kind) = claim.remove("type").filter(|value| value.is_string()) {
                claim.insert("claim_type".into(), kind);
            }
        } else {
            claim.remove("type");
        }
        if claim
            .get("derived_from")
            .is_some_and(|value| !value.is_null())
        {
            claim.insert("derivable".into(), Value::Bool(true));
        }
        if let Some(namespace) = claim.remove("namespace").filter(|value| value.is_string()) {
            claim.insert("mdoc_namespace".into(), namespace);
            if !claim.contains_key("mdoc_element_identifier") {
                claim.insert("mdoc_element_identifier".into(), Value::String(name));
            }
        }
        output.push(Value::Object(claim));
    }
    for claim in &output {
        if let Some(source) = claim.get("derived_from").and_then(Value::as_str) {
            if !names.contains(source) {
                return Err(CredentialTemplateContractError);
            }
        }
    }
    Ok(Value::Array(output))
}

pub fn canonicalize_update(body: &[u8]) -> Result<Vec<u8>, CredentialTemplateContractError> {
    let mut value = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or(CredentialTemplateContractError)?;
    if let Some(claims) = value.get("claims").cloned() {
        value.insert("claims".into(), internal_claims(&claims)?);
    }
    serde_json::to_vec(&value).map_err(|_| CredentialTemplateContractError)
}

pub fn public_response(value: Value) -> Result<Value, CredentialTemplateContractError> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(public_template)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(value) => public_template(Value::Object(value)),
        _ => Err(CredentialTemplateContractError),
    }
}

fn public_template(value: Value) -> Result<Value, CredentialTemplateContractError> {
    let value = value.as_object().ok_or(CredentialTemplateContractError)?;
    let mut public = value
        .iter()
        .filter(|(key, _)| PUBLIC_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    if let Some(claims) = public.get("claims").and_then(Value::as_array) {
        let claims = claims
            .iter()
            .map(public_claim)
            .collect::<Result<Vec<_>, _>>()?;
        public.insert("claims".into(), Value::Array(claims));
    }
    Ok(Value::Object(public))
}

fn public_claim(value: &Value) -> Result<Value, CredentialTemplateContractError> {
    let mut claim = value
        .as_object()
        .cloned()
        .ok_or(CredentialTemplateContractError)?;
    if !claim.contains_key("type") {
        if let Some(kind) = claim
            .remove("claim_type")
            .and_then(|value| value.as_str().map(str::to_uppercase))
        {
            claim.insert("type".into(), Value::String(kind));
        }
    } else {
        claim.remove("claim_type");
    }
    let display_name = claim.remove("display_name");
    let display_icon = claim.remove("display_icon");
    let mut display = claim
        .remove("display")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    if !display.contains_key("label") {
        if let Some(value) = display_name.filter(Value::is_string) {
            display.insert("label".into(), value);
        }
    }
    if !display.contains_key("icon") {
        if let Some(value) = display_icon.filter(Value::is_string) {
            display.insert("icon".into(), value);
        }
    }
    if !display.is_empty() {
        claim.insert("display".into(), Value::Object(display));
    }
    if !claim.contains_key("namespace") {
        if let Some(namespace) = claim.remove("mdoc_namespace").filter(Value::is_string) {
            claim.insert("namespace".into(), namespace);
        }
    } else {
        claim.remove("mdoc_namespace");
    }
    Ok(Value::Object(claim))
}

pub fn response_route(method: &str, path: &str) -> bool {
    path.starts_with("/v1/credential-templates")
        && !matches!(method, "DELETE")
        && !path.ends_with("/wallet-compatibility")
        && !path.ends_with("/application-template")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        create_input: Value,
        expected_create_internal: Value,
        public_claims: Value,
        expected_internal_claims: Value,
        internal_response: Value,
        expected_public_response: Value,
    }
    #[test]
    fn language_neutral_credential_template_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-credential-template-behavior.json"
        ))
        .expect("template contract");
        assert_eq!(contract.schema_version, 1);
        let create_body = serde_json::to_vec(&contract.create_input).expect("create JSON");
        assert_eq!(
            canonicalize_create(&create_body).expect("create request"),
            contract.expected_create_internal
        );
        assert_eq!(
            internal_claims(&contract.public_claims).expect("claims"),
            contract.expected_internal_claims
        );
        assert_eq!(
            public_response(contract.internal_response).expect("response"),
            contract.expected_public_response
        );
    }
}
