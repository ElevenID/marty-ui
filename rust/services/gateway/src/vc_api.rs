//! Deterministic W3C VC-API compatibility transformations.
//!
//! Cryptographic verification and issuance remain in their canonical Rust
//! services. These functions only adapt public VC-API representations to and
//! from Marty's ordinary service contracts.

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use url::Url;

const VCDM_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
const PRE_AUTH_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiableField {
    Credential,
    Presentation,
}

impl VerifiableField {
    fn envelope_type(self) -> &'static str {
        match self {
            Self::Credential => "EnvelopedVerifiableCredential",
            Self::Presentation => "EnvelopedVerifiablePresentation",
        }
    }

    fn media_types(self) -> &'static [&'static str] {
        match self {
            Self::Credential => &["application/vc+jwt", "application/jwt"],
            Self::Presentation => &["application/vp+jwt", "application/jwt"],
        }
    }
}

impl TryFrom<&str> for VerifiableField {
    type Error = VcApiAdapterError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "verifiableCredential" => Ok(Self::Credential),
            "verifiablePresentation" => Ok(Self::Presentation),
            _ => Err(VcApiAdapterError::UnsupportedSerialization),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VcApiAdapterError {
    #[error("unsupported_serialization")]
    UnsupportedSerialization,
    #[error("invalid_envelope")]
    InvalidEnvelope,
    #[error("invalid_policy_response")]
    InvalidPolicyResponse,
    #[error("invalid_issued_credential")]
    InvalidIssuedCredential,
    #[error("{0}")]
    InvalidOffer(String),
}

impl VcApiAdapterError {
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::UnsupportedSerialization => "unsupported_serialization",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::InvalidPolicyResponse => "invalid_policy_response",
            Self::InvalidIssuedCredential => "invalid_issued_credential",
            Self::InvalidOffer(message) => message,
        }
    }
}

pub fn adapt_verifiable(value: &Value, field: VerifiableField) -> Result<Value, VcApiAdapterError> {
    if value.as_str().is_some_and(|token| !token.trim().is_empty()) {
        return Ok(value.clone());
    }
    let object = value
        .as_object()
        .ok_or(VcApiAdapterError::UnsupportedSerialization)?;
    if has_data_integrity_proof(object) {
        return Ok(value.clone());
    }
    extract_jose_envelope(object, field).map(Value::String)
}

fn has_data_integrity_proof(object: &Map<String, Value>) -> bool {
    let Some(proof) = object.get("proof") else {
        return false;
    };
    proof
        .as_array()
        .map_or_else(|| vec![proof], |values| values.iter().collect())
        .into_iter()
        .any(|item| {
            item.as_object()
                .and_then(|proof| proof.get("type"))
                .and_then(Value::as_str)
                == Some("DataIntegrityProof")
        })
}

fn extract_jose_envelope(
    object: &Map<String, Value>,
    field: VerifiableField,
) -> Result<String, VcApiAdapterError> {
    let context_valid = match object.get("@context") {
        Some(Value::String(value)) => value == VCDM_V2_CONTEXT,
        Some(Value::Array(values)) => {
            values.first().and_then(Value::as_str) == Some(VCDM_V2_CONTEXT)
        }
        _ => false,
    };
    let type_valid = match object.get("type") {
        Some(Value::String(value)) => value == field.envelope_type(),
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some(field.envelope_type())),
        _ => false,
    };
    let identifier = object.get("id").and_then(Value::as_str);
    if !context_valid || !type_valid || identifier.is_none() {
        return Err(VcApiAdapterError::UnsupportedSerialization);
    }
    let identifier = identifier.expect("checked above");
    let Some((media_type, token)) = identifier
        .strip_prefix("data:")
        .and_then(|value| value.split_once(','))
    else {
        return Err(VcApiAdapterError::InvalidEnvelope);
    };
    let media_type = percent_decode_ascii(media_type)?.to_ascii_lowercase();
    if !field.media_types().contains(&media_type.as_str()) {
        return Err(VcApiAdapterError::UnsupportedSerialization);
    }
    let token = percent_decode_ascii(token)?;
    if token.split('.').count() != 3 || token.split('.').any(str::is_empty) {
        return Err(VcApiAdapterError::InvalidEnvelope);
    }
    Ok(token)
}

fn percent_decode_ascii(value: &str) -> Result<String, VcApiAdapterError> {
    let decoded = percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| VcApiAdapterError::InvalidEnvelope)?;
    decoded
        .is_ascii()
        .then(|| decoded.into_owned())
        .ok_or(VcApiAdapterError::InvalidEnvelope)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfferSelection {
    pub credential_configuration_id: String,
    pub pre_authorized_code: String,
}

pub fn parse_inline_credential_offer(
    offer_uri: &str,
    expected_issuer: &str,
) -> Result<OfferSelection, VcApiAdapterError> {
    if offer_uri.is_empty() {
        return Err(invalid_offer("credential_offer_uri is missing"));
    }
    let url = Url::parse(offer_uri)
        .map_err(|_| invalid_offer("credential_offer_uri contains invalid JSON"))?;
    let offers = url
        .query_pairs()
        .filter(|(name, _)| name == "credential_offer")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    if offers.len() != 1 {
        return Err(invalid_offer(
            "credential_offer_uri must contain one inline credential_offer",
        ));
    }
    let offer: Value = serde_json::from_str(&offers[0])
        .map_err(|_| invalid_offer("credential_offer_uri contains invalid JSON"))?;
    let object = offer.as_object().ok_or_else(|| {
        invalid_offer("credential offer issuer does not match the selected organization")
    })?;
    if object.get("credential_issuer").and_then(Value::as_str) != Some(expected_issuer) {
        return Err(invalid_offer(
            "credential offer issuer does not match the selected organization",
        ));
    }
    let configurations = object
        .get("credential_configuration_ids")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_offer("credential offer must select exactly one configuration"))?;
    let code = object
        .get("grants")
        .and_then(Value::as_object)
        .and_then(|grants| grants.get(PRE_AUTH_GRANT))
        .and_then(Value::as_object)
        .and_then(|grant| grant.get("pre-authorized_code"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_offer("credential offer has no pre-authorized code"))?;
    Ok(OfferSelection {
        credential_configuration_id: configurations.into(),
        pre_authorized_code: code.into(),
    })
}

fn invalid_offer(message: &str) -> VcApiAdapterError {
    VcApiAdapterError::InvalidOffer(message.into())
}

#[must_use]
pub fn credential_issuer_id(credential: &Value) -> Option<&str> {
    let issuer = credential.as_object()?.get("issuer")?;
    issuer
        .as_str()
        .or_else(|| issuer.as_object()?.get("id")?.as_str())
}

#[must_use]
pub fn evaluation_request(token: Value, options: &Value) -> Value {
    json!({
        "vp_token": token,
        "nonce": options.get("challenge").cloned().unwrap_or(Value::Null),
        "audience": options.get("domain").cloned().unwrap_or(Value::Null)
    })
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AdaptedResponse {
    pub status: u16,
    pub body: Value,
}

pub fn adapt_evaluation(evaluation: &Value) -> Result<AdaptedResponse, VcApiAdapterError> {
    let object = evaluation
        .as_object()
        .ok_or(VcApiAdapterError::InvalidPolicyResponse)?;
    if object.get("decision").and_then(Value::as_str) == Some("allow")
        && object.get("result").and_then(Value::as_str) == Some("passed")
    {
        Ok(AdaptedResponse {
            status: 200,
            body: json!({"verified": true, "results": evaluation, "problemDetails": []}),
        })
    } else {
        Ok(AdaptedResponse {
            status: 422,
            body: json!({"verified": false, "errors": ["verification_failed"]}),
        })
    }
}

pub fn issued_data_integrity_credential<'a>(
    response: &'a Value,
    issuer_did: &str,
) -> Result<&'a Value, VcApiAdapterError> {
    let credentials = response
        .get("credentials")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or(VcApiAdapterError::InvalidIssuedCredential)?;
    let result = credentials[0]
        .as_object()
        .ok_or(VcApiAdapterError::InvalidIssuedCredential)?;
    if result.get("format").and_then(Value::as_str) != Some("ldp_vc") {
        return Err(VcApiAdapterError::InvalidIssuedCredential);
    }
    let document = result
        .get("credential")
        .filter(|value| value.is_object())
        .ok_or(VcApiAdapterError::InvalidIssuedCredential)?;
    let proof = document
        .get("proof")
        .and_then(Value::as_object)
        .ok_or(VcApiAdapterError::InvalidIssuedCredential)?;
    if credential_issuer_id(document) != Some(issuer_did)
        || proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof")
        || proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-rdfc-2022")
    {
        return Err(VcApiAdapterError::InvalidIssuedCredential);
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        serialization: Vec<SerializationCase>,
        offers: Vec<OfferCase>,
        evaluations: Vec<EvaluationCase>,
        issued_credentials: Vec<IssuedCredentialCase>,
    }

    #[derive(Deserialize)]
    struct SerializationCase {
        field: String,
        input: Value,
        expected: Option<Value>,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    struct OfferCase {
        uri: String,
        expected_issuer: String,
        configuration_id: Option<String>,
        pre_authorized_code: Option<String>,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    struct EvaluationCase {
        input: Value,
        status: u16,
        output: Option<Value>,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    struct IssuedCredentialCase {
        issuer_did: String,
        input: Value,
        expected_issuer: Option<String>,
        error: Option<String>,
    }

    fn contract() -> Contract {
        serde_json::from_str(include_str!(
            "../../../../contracts/vc-api-adapter-behavior.json"
        ))
        .expect("valid VC-API contract")
    }

    #[test]
    fn language_neutral_vc_api_adapter_contract() {
        let contract = contract();
        assert_eq!(contract.schema_version, 1);
        for case in contract.serialization {
            let result = adapt_verifiable(
                &case.input,
                VerifiableField::try_from(case.field.as_str()).expect("field"),
            );
            match case.error {
                Some(error) => assert_eq!(result.expect_err("error").code(), error),
                None => assert_eq!(result.expect("adapted"), case.expected.expect("expected")),
            }
        }
        for case in contract.offers {
            let result = parse_inline_credential_offer(&case.uri, &case.expected_issuer);
            match case.error {
                Some(error) => assert_eq!(result.expect_err("error").code(), error),
                None => {
                    let result = result.expect("offer");
                    assert_eq!(
                        Some(result.credential_configuration_id),
                        case.configuration_id
                    );
                    assert_eq!(Some(result.pre_authorized_code), case.pre_authorized_code);
                }
            }
        }
        for case in contract.evaluations {
            let result = adapt_evaluation(&case.input);
            match case.error {
                Some(error) => assert_eq!(result.expect_err("error").code(), error),
                None => {
                    let result = result.expect("evaluation");
                    assert_eq!(result.status, case.status);
                    assert_eq!(Some(result.body), case.output);
                }
            }
        }
        for case in contract.issued_credentials {
            let result = issued_data_integrity_credential(&case.input, &case.issuer_did);
            match case.error {
                Some(error) => assert_eq!(result.expect_err("error").code(), error),
                None => assert_eq!(
                    result
                        .expect("credential")
                        .get("issuer")
                        .and_then(Value::as_str),
                    case.expected_issuer.as_deref()
                ),
            }
        }
    }

    #[test]
    fn issuer_identifier_accepts_both_vcdm_shapes() {
        assert_eq!(
            credential_issuer_id(&json!({"issuer": "did:example:1"})),
            Some("did:example:1")
        );
        assert_eq!(
            credential_issuer_id(&json!({"issuer": {"id": "did:example:2"}})),
            Some("did:example:2")
        );
        assert_eq!(credential_issuer_id(&json!({"issuer": 42})), None);
    }
}
