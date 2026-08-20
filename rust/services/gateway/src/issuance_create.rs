use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct IssuanceCreateError(pub &'static str);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceCreate {
    pub organization_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_client: Option<AuthorizedClient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default = "empty_object")]
    pub claims: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_subject: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_document: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedClient {
    pub client_id: String,
    pub jwks: AuthorizedClientJwks,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedClientJwks {
    pub keys: Vec<AuthorizedClientJwk>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedClientJwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    pub y: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

impl IssuanceCreate {
    pub fn parse(value: Value) -> Result<Self, IssuanceCreateError> {
        let request: Self = serde_json::from_value(value)
            .map_err(|_| IssuanceCreateError("Issuance request is outside the public contract"))?;
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), IssuanceCreateError> {
        required(&self.organization_id, 255, "organization_id is required")?;
        optional_id(&self.credential_template_id, 255)?;
        optional_id(&self.application_id, 255)?;
        optional_did(&self.issuer_did)?;
        optional_did(&self.subject_did)?;
        optional_did(&self.holder_did)?;
        if self.credential_template_id.is_none() && self.issuer_did.is_none() {
            return Err(IssuanceCreateError(
                "credential_template_id or issuer_did is required",
            ));
        }
        let claims = self
            .claims
            .as_object()
            .ok_or(IssuanceCreateError("claims must be an object"))?;
        for field in RESERVED_CLAIMS {
            if claims.contains_key(*field) {
                return Err(IssuanceCreateError("claims contains a reserved field"));
            }
        }
        if let Some(document) = &self.credential_document {
            if !claims.is_empty() || self.credential_subject.is_some() {
                return Err(IssuanceCreateError(
                    "credential_document cannot be combined with claims or credential_subject",
                ));
            }
            validate_document(document)?;
        } else if let Some(subject) = &self.credential_subject {
            if !claims.is_empty() {
                return Err(IssuanceCreateError(
                    "credential_subject cannot be combined with claims",
                ));
            }
            validate_subjects(subject)?;
        }
        if let Some(client) = &self.authorized_client {
            client.validate()?;
        }
        Ok(())
    }

    pub fn select_issuer_did(&self, template: &Value) -> Result<String, IssuanceCreateError> {
        let template_did = clean_string(template.get("issuer_did"));
        if self.credential_template_id.is_some() {
            let template_did = template_did.ok_or(IssuanceCreateError(
                "credential template must contain issuer_did",
            ))?;
            if self
                .issuer_did
                .as_deref()
                .is_some_and(|did| did != template_did)
            {
                return Err(IssuanceCreateError(
                    "issuer_did cannot override the credential template issuer DID",
                ));
            }
            return Ok(template_did.into());
        }
        self.issuer_did
            .clone()
            .ok_or(IssuanceCreateError("issuer_did is required"))
    }

    pub fn credential_format(&self, template: &Value) -> Option<String> {
        clean_string(template.get("credential_payload_format"))
            .and_then(public_format)
            .or_else(|| {
                template
                    .get("supported_formats")
                    .and_then(Value::as_array)
                    .map(|formats| {
                        formats
                            .iter()
                            .filter_map(Value::as_str)
                            .filter_map(public_format)
                            .collect::<BTreeSet<_>>()
                    })
                    .filter(|formats| formats.len() == 1)
                    .and_then(|formats| formats.into_iter().next())
            })
            .or_else(|| {
                self.claims
                    .get("credential_format")
                    .and_then(Value::as_str)
                    .and_then(public_format)
            })
    }

    pub fn registration(&self) -> Option<Value> {
        self.authorized_client.as_ref().map(|client| {
            json!({
                "organization_id": self.organization_id,
                "client_id": client.client_id,
                "jwks": client.jwks,
                "redirect_uris": [],
                "active": true
            })
        })
    }

    pub fn downstream(mut self, issuer_did: String) -> Result<Value, IssuanceCreateError> {
        let authorized_client_id = self.authorized_client.take().map(|client| client.client_id);
        let mut value = serde_json::to_value(self)
            .map_err(|_| IssuanceCreateError("Issuance request could not be serialized"))?;
        value["issuer_did"] = Value::String(issuer_did);
        if value
            .get("claims")
            .is_some_and(|claims| claims == &json!({}))
        {
            value
                .as_object_mut()
                .expect("serialized struct")
                .remove("claims");
        }
        if let Some(client_id) = authorized_client_id {
            value["authorized_client_id"] = Value::String(client_id);
        }
        Ok(value)
    }
}

impl AuthorizedClient {
    fn validate(&self) -> Result<(), IssuanceCreateError> {
        required(
            &self.client_id,
            512,
            "authorized_client.client_id is required",
        )?;
        if self.jwks.keys.is_empty() {
            return Err(IssuanceCreateError(
                "authorized_client.jwks.keys is required",
            ));
        }
        let mut kids = BTreeSet::new();
        for key in &self.jwks.keys {
            if key.kty != "EC"
                || key.crv != "P-256"
                || key.alg.as_deref().is_some_and(|alg| alg != "ES256")
                || key.r#use.as_deref().is_some_and(|value| value != "sig")
                || key
                    .key_ops
                    .as_ref()
                    .is_some_and(|ops| ops.as_slice() != ["verify"])
                || !base64url_coordinate(&key.x)
                || !base64url_coordinate(&key.y)
            {
                return Err(IssuanceCreateError(
                    "authorized_client.jwks must contain public ES256 keys only",
                ));
            }
            required(&key.kid, 256, "authorized_client key id is required")?;
            if !kids.insert(&key.kid) {
                return Err(IssuanceCreateError(
                    "authorized_client key ids must be unique",
                ));
            }
        }
        Ok(())
    }
}

const RESERVED_CLAIMS: &[&str] = &[
    "issuer_profile_id",
    "issuer_key_id",
    "issuer_algorithm",
    "key_access_mode",
    "verification_method_id",
    "signing_service_id",
    "signing_key_reference",
    "key_reference",
    "kms_provider",
    "provider",
    "key_name",
    "key_version",
    "transit_mount",
    "_application_id",
    "_credential_subject",
    "_credential_document",
];

fn empty_object() -> Value {
    json!({})
}

fn required(value: &str, maximum: usize, error: &'static str) -> Result<(), IssuanceCreateError> {
    if value.is_empty() || value.len() > maximum {
        Err(IssuanceCreateError(error))
    } else {
        Ok(())
    }
}

fn optional_id(value: &Option<String>, maximum: usize) -> Result<(), IssuanceCreateError> {
    value.as_deref().map_or(Ok(()), |value| {
        required(value, maximum, "identifier is invalid")
    })
}

fn optional_did(value: &Option<String>) -> Result<(), IssuanceCreateError> {
    if value
        .as_deref()
        .is_some_and(|did| !did.starts_with("did:") || did.len() > 2048)
    {
        Err(IssuanceCreateError("DID is invalid"))
    } else {
        Ok(())
    }
}

fn validate_document(document: &Map<String, Value>) -> Result<(), IssuanceCreateError> {
    if document.is_empty() || document.contains_key("proof") {
        return Err(IssuanceCreateError(
            "credential_document must be a non-empty unsigned object",
        ));
    }
    if document
        .get("@context")
        .and_then(Value::as_array)
        .and_then(|v| v.first())
        .and_then(Value::as_str)
        != Some("https://www.w3.org/ns/credentials/v2")
    {
        return Err(IssuanceCreateError(
            "credential_document must use the VCDM v2 context",
        ));
    }
    let types = document
        .get("type")
        .map(|value| {
            value
                .as_array()
                .map_or_else(|| vec![value], |v| v.iter().collect())
        })
        .unwrap_or_default();
    if !types
        .iter()
        .any(|value| value.as_str() == Some("VerifiableCredential"))
    {
        return Err(IssuanceCreateError(
            "credential_document type must include VerifiableCredential",
        ));
    }
    validate_subjects(
        document
            .get("credentialSubject")
            .ok_or(IssuanceCreateError("credentialSubject is required"))?,
    )
}

fn validate_subjects(value: &Value) -> Result<(), IssuanceCreateError> {
    let subjects = value
        .as_array()
        .map_or_else(|| vec![value], |values| values.iter().collect());
    if subjects.is_empty()
        || subjects
            .iter()
            .any(|subject| subject.as_object().is_none_or(Map::is_empty))
    {
        Err(IssuanceCreateError(
            "credential subject must contain non-empty objects",
        ))
    } else {
        Ok(())
    }
}

fn clean_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn public_format(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    Some(
        match value.as_str() {
            "w3c_vcdm_v2_sd_jwt" | "ietf_sd_jwt" | "sd_jwt_vc" | "vc+sd_jwt" | "vc+sd-jwt"
            | "dc+sd_jwt" | "dc+sd-jwt" => "dc+sd-jwt",
            "w3c_vcdm_v2_jwt_vc" | "vc_jwt" | "jwt_vc" | "jwt_vc_json" => "jwt_vc_json",
            "w3c_vcdm_v2_di" | "json_ld" | "json-ld" | "ldp_vc" => "ldp_vc",
            "mdoc" | "mso_mdoc" => "mso_mdoc",
            other => other,
        }
        .into(),
    )
}

fn base64url_coordinate(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        valid_cases: Vec<ValidCase>,
        invalid_cases: Vec<InvalidCase>,
    }

    #[derive(Deserialize)]
    struct ValidCase {
        name: String,
        input: Value,
        resolved_issuer_did: String,
        expected_downstream: Value,
        expected_registration: Option<Value>,
    }

    #[derive(Deserialize)]
    struct InvalidCase {
        name: String,
        input: Value,
    }

    #[test]
    fn language_neutral_issuance_create_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-issuance-create-behavior.json"
        ))
        .expect("issuance create contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.valid_cases {
            let input = IssuanceCreate::parse(case.input)
                .unwrap_or_else(|_| panic!("valid request: {}", case.name));
            assert_eq!(
                input.registration(),
                case.expected_registration,
                "{}",
                case.name
            );
            assert_eq!(
                input
                    .downstream(case.resolved_issuer_did)
                    .expect("downstream request"),
                case.expected_downstream,
                "{}",
                case.name
            );
        }
        for case in contract.invalid_cases {
            assert!(IssuanceCreate::parse(case.input).is_err(), "{}", case.name);
        }
    }
}
