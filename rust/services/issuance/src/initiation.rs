use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const IDEMPOTENCY_KEY_PREFIX: &str = "marty:issuance-idempotency-key:v1:";
const IDEMPOTENCY_REQUEST_PREFIX: &str = "marty:issuance-initiate-request:v1:";
const RESERVED_CLAIMS: &[&str] = &[
    "_application_id",
    "_credential_subject",
    "_credential_document",
];
const VCDM_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitiationRequest {
    pub organization_id: String,
    pub issuer_did: String,
    #[serde(default)]
    pub credential_template_id: Option<String>,
    #[serde(default)]
    pub application_id: Option<String>,
    #[serde(default)]
    pub applicant_id: Option<String>,
    #[serde(default)]
    pub subject_did: Option<String>,
    #[serde(default)]
    pub holder_did: Option<String>,
    #[serde(default)]
    pub authorized_client_id: Option<String>,
    #[serde(default = "default_delivery_mode")]
    pub delivery_mode: String,
    /// `None` distinguishes omission from an explicitly supplied empty object,
    /// matching the Python model's exclusivity checks.
    #[serde(default)]
    pub claims: Option<Map<String, Value>>,
    #[serde(default)]
    pub credential_subject: Option<Value>,
    #[serde(default)]
    pub credential_document: Option<Value>,
}

impl InitiationRequest {
    pub fn validate(&self) -> Result<(), InitiationError> {
        if self.issuer_did.is_empty() {
            return Err(InitiationError::IssuerDidRequired);
        }
        normalize_delivery_mode(&self.delivery_mode)?;
        if let Some(claims) = &self.claims {
            if let Some(field) = RESERVED_CLAIMS
                .iter()
                .find(|field| claims.contains_key(**field))
            {
                return Err(InitiationError::ReservedClaim((*field).to_owned()));
            }
        }
        if self.credential_subject.is_some() && self.claims.is_some() {
            return Err(InitiationError::CredentialSubjectWithClaims);
        }
        if self.credential_document.is_some()
            && (self.claims.is_some() || self.credential_subject.is_some())
        {
            return Err(InitiationError::CredentialDocumentWithClaims);
        }
        if let Some(subject) = &self.credential_subject {
            validate_subject(subject)?;
        }
        if let Some(document) = &self.credential_document {
            validate_credential_document(document, &self.issuer_did)?;
        }
        Ok(())
    }

    pub fn normalized_delivery_mode(&self) -> Result<String, InitiationError> {
        normalize_delivery_mode(&self.delivery_mode)
    }

    pub fn semantic_payload(&self) -> Result<Value, InitiationError> {
        self.validate()?;
        Ok(serde_json::json!({
            "organization_id": self.organization_id,
            "credential_template_id": optional_string(&self.credential_template_id),
            "application_id": optional_string(&self.application_id),
            "applicant_id": optional_string(&self.applicant_id),
            "subject_did": optional_string(&self.subject_did),
            "holder_did": optional_string(&self.holder_did),
            "issuer_did": self.issuer_did,
            "authorized_client_id": optional_string(&self.authorized_client_id),
            "delivery_mode": self.normalized_delivery_mode()?,
            "claims": self.claims.clone().unwrap_or_default(),
            "credential_subject": self.credential_subject.clone(),
            "credential_document": self.credential_document.clone(),
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyBinding {
    pub key_hash: String,
    pub request_hash: String,
}

pub fn idempotency_binding(
    raw_key: Option<&str>,
    request: &InitiationRequest,
) -> Result<Option<IdempotencyBinding>, InitiationError> {
    let Some(key) = normalize_idempotency_key(raw_key)? else {
        return Ok(None);
    };
    let semantic_payload = request.semantic_payload()?;
    Ok(Some(IdempotencyBinding {
        key_hash: sha256(format!("{IDEMPOTENCY_KEY_PREFIX}{key}")),
        request_hash: sha256(format!(
            "{IDEMPOTENCY_REQUEST_PREFIX}{}",
            canonical_json(&semantic_payload)?
        )),
    }))
}

pub fn normalize_idempotency_key(value: Option<&str>) -> Result<Option<String>, InitiationError> {
    let raw = value.unwrap_or_default();
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Ok(None);
    }
    if raw != normalized {
        return Err(InitiationError::IdempotencyWhitespace);
    }
    let allowed = normalized
        .bytes()
        .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b':' | b'-'));
    if !allowed || normalized.len() > 128 {
        return Err(InitiationError::InvalidIdempotencyKey);
    }
    Ok(Some(normalized.to_owned()))
}

pub fn normalize_delivery_mode(value: &str) -> Result<String, InitiationError> {
    let normalized = value.trim();
    let normalized = if normalized.is_empty() {
        "wallet_only"
    } else {
        normalized
    };
    if !matches!(normalized, "wallet_only" | "wallet_plus_canvas_mirror") {
        return Err(InitiationError::InvalidDeliveryMode(normalized.to_owned()));
    }
    Ok(normalized.to_owned())
}

fn default_delivery_mode() -> String {
    "wallet_only".to_owned()
}

fn optional_string(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or_default()
}

fn validate_credential_document(document: &Value, issuer_did: &str) -> Result<(), InitiationError> {
    let document = document
        .as_object()
        .filter(|document| !document.is_empty())
        .ok_or(InitiationError::InvalidCredentialDocument)?;
    if document.contains_key("proof") {
        return Err(InitiationError::CredentialDocumentSigned);
    }
    let valid_context = document
        .get("@context")
        .and_then(Value::as_array)
        .and_then(|context| context.first())
        .and_then(Value::as_str)
        == Some(VCDM_V2_CONTEXT);
    if !valid_context {
        return Err(InitiationError::InvalidCredentialDocument);
    }
    let has_vc_type = match document.get("type") {
        Some(Value::String(value)) => value == "VerifiableCredential",
        Some(Value::Array(values)) => values
            .iter()
            .any(|value| value.as_str() == Some("VerifiableCredential")),
        _ => false,
    };
    if !has_vc_type {
        return Err(InitiationError::InvalidCredentialDocument);
    }
    validate_subject(
        document
            .get("credentialSubject")
            .ok_or(InitiationError::InvalidCredentialDocument)?,
    )
    .map_err(|_| InitiationError::InvalidCredentialDocument)?;
    if document.get("issuer").and_then(identifier) != Some(issuer_did) {
        return Err(InitiationError::CredentialDocumentIssuerMismatch);
    }
    Ok(())
}

fn validate_subject(subject: &Value) -> Result<(), InitiationError> {
    match subject {
        Value::Object(value) if !value.is_empty() => Ok(()),
        Value::Array(values)
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_object().is_some_and(|subject| !subject.is_empty())) =>
        {
            Ok(())
        }
        _ => Err(InitiationError::InvalidCredentialSubject),
    }
}

fn identifier(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("id")?.as_str())
}

fn canonical_json(value: &Value) -> Result<String, InitiationError> {
    serde_json::to_string(&canonicalize(value)).map_err(|_| InitiationError::Canonicalization)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut fields = object.iter().collect::<Vec<_>>();
            fields.sort_unstable_by_key(|(name, _)| *name);
            Value::Object(
                fields
                    .into_iter()
                    .map(|(name, value)| (name.clone(), canonicalize(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn sha256(value: String) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationError {
    #[error("issuer_did is required")]
    IssuerDidRequired,
    #[error("{0} is reserved for internal use")]
    ReservedClaim(String),
    #[error("credential_subject cannot be combined with claims")]
    CredentialSubjectWithClaims,
    #[error("credential_document cannot be combined with claims or credential_subject")]
    CredentialDocumentWithClaims,
    #[error("credential_subject must be a non-empty object or list of non-empty objects")]
    InvalidCredentialSubject,
    #[error("credential_document failed VCDM validation")]
    InvalidCredentialDocument,
    #[error("credential_document must be unsigned")]
    CredentialDocumentSigned,
    #[error("credential_document issuer must match the resolved issuer_did")]
    CredentialDocumentIssuerMismatch,
    #[error("idempotency key must not contain surrounding whitespace")]
    IdempotencyWhitespace,
    #[error("idempotency key must contain 1-128 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidIdempotencyKey,
    #[error(
        "Invalid delivery_mode '{0}'. Must be one of ['wallet_only', 'wallet_plus_canvas_mirror']"
    )]
    InvalidDeliveryMode(String),
    #[error("issuance request could not be canonicalized")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InitiationRequest {
        serde_json::from_value(serde_json::json!({
            "organization_id": "org-1",
            "credential_template_id": "template-1",
            "application_id": "application-1",
            "applicant_id": "applicant-1",
            "subject_did": "did:key:z6MkHolder",
            "issuer_did": "did:web:issuer.example",
            "authorized_client_id": "client-1",
            "delivery_mode": "wallet_plus_canvas_mirror",
            "claims": {"profile": {"level": 2}, "roles": ["student", "member"]}
        }))
        .expect("valid initiation request")
    }

    #[test]
    fn idempotency_vector_matches_the_language_neutral_contract() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-initiation.json"
        ))
        .expect("valid initiation contract");
        let vector = &contract["idempotency"]["vector"];
        let request: InitiationRequest =
            serde_json::from_value(vector["request"].clone()).expect("valid vector request");
        let binding = idempotency_binding(vector["key"].as_str(), &request)
            .expect("valid idempotency binding")
            .expect("binding is present");

        assert_eq!(binding.key_hash, vector["key_hash"]);
        assert_eq!(binding.request_hash, vector["request_hash"]);
        assert_eq!(request.semantic_payload().unwrap(), vector["request"]);
    }

    #[test]
    fn nested_claim_order_does_not_change_the_request_hash() {
        let first = request();
        let mut second = request();
        second.claims = Some(
            serde_json::from_value(serde_json::json!({
                "roles": ["student", "member"],
                "profile": {"level": 2}
            }))
            .unwrap(),
        );
        assert_eq!(
            idempotency_binding(Some("same"), &first).unwrap(),
            idempotency_binding(Some("same"), &second).unwrap()
        );
    }

    #[test]
    fn strict_request_and_explicit_subject_rules_match_the_contract() {
        let unknown = serde_json::from_value::<InitiationRequest>(serde_json::json!({
            "organization_id": "org-1",
            "issuer_did": "did:web:issuer.example",
            "unknown": true
        }));
        assert!(unknown.is_err());

        let mut explicit_subject = request();
        explicit_subject.credential_subject = Some(serde_json::json!({"name": "Ada"}));
        assert_eq!(
            explicit_subject.validate(),
            Err(InitiationError::CredentialSubjectWithClaims)
        );
        explicit_subject.claims = None;
        assert_eq!(explicit_subject.validate(), Ok(()));

        explicit_subject.credential_subject = Some(serde_json::json!([]));
        assert_eq!(
            explicit_subject.validate(),
            Err(InitiationError::InvalidCredentialSubject)
        );
    }

    #[test]
    fn unsigned_matching_vcdm_document_is_accepted_and_signed_or_foreign_is_rejected() {
        let document = serde_json::json!({
            "@context": [VCDM_V2_CONTEXT],
            "type": ["VerifiableCredential", "EmployeeCredential"],
            "issuer": {"id": "did:web:issuer.example"},
            "credentialSubject": [{"id": "did:example:subject", "employeeNumber": "E-1"}]
        });
        let mut request = request();
        request.claims = None;
        request.credential_document = Some(document.clone());
        assert_eq!(request.validate(), Ok(()));

        let mut signed = document.clone();
        signed
            .as_object_mut()
            .unwrap()
            .insert("proof".to_owned(), serde_json::json!({}));
        request.credential_document = Some(signed);
        assert_eq!(
            request.validate(),
            Err(InitiationError::CredentialDocumentSigned)
        );

        let mut foreign = document;
        foreign.as_object_mut().unwrap().insert(
            "issuer".to_owned(),
            Value::String("did:web:other.example".to_owned()),
        );
        request.credential_document = Some(foreign);
        assert_eq!(
            request.validate(),
            Err(InitiationError::CredentialDocumentIssuerMismatch)
        );
    }

    #[test]
    fn key_and_delivery_normalization_are_exact() {
        assert_eq!(normalize_idempotency_key(None), Ok(None));
        assert_eq!(normalize_idempotency_key(Some("")), Ok(None));
        assert_eq!(
            normalize_idempotency_key(Some(" padded")),
            Err(InitiationError::IdempotencyWhitespace)
        );
        assert_eq!(
            normalize_idempotency_key(Some("contains a space")),
            Err(InitiationError::InvalidIdempotencyKey)
        );
        assert_eq!(normalize_delivery_mode("  ").unwrap(), "wallet_only");
        assert_eq!(
            normalize_delivery_mode("direct-kms"),
            Err(InitiationError::InvalidDeliveryMode(
                "direct-kms".to_owned()
            ))
        );
    }
}
