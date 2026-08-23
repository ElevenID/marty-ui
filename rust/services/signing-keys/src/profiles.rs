//! Canonical issuer-profile validation, selection, and persistence.

use chrono::{SecondsFormat, Utc};
use marty_crypto::certificate::load_certificate_pem;
use redis::{aio::ConnectionManager, AsyncCommands};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

const PROFILE_STATUSES: &[&str] = &["draft", "active", "revoked"];
const ISSUER_MODES: &[&str] = &["org_managed", "elevenid_managed", "elevenid_alias_for_org"];
const ATTESTATION_MODES: &[&str] = &["disabled", "optional", "required"];
const STATUS_POLICIES: &[&str] = &["disabled", "if_present", "required"];
const ALGORITHMS: &[&str] = &["ES256", "ES384", "RS256", "EdDSA"];
const KEY_PURPOSES: &[&str] = &[
    "vc_jwt_issuer",
    "mdoc_dsc",
    "x509_doc_signer",
    "holder_binding",
    "presentation_signing",
    "oid4vp_request_signing",
    "vdsnc_signing",
    "csca",
    "jwks_signing",
    "lti_tool_signing",
];
const PROTOCOL_FORMATS: &[&str] = &[
    "MDOC",
    "SD_JWT_VC",
    "VC_JWT",
    "JSON_LD",
    "ZK_MDOC",
    "ICAO_EMRTD",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("issuer profile storage is unavailable: {0}")]
    Storage(String),
    #[error("stored issuer profile document is malformed: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
pub struct ProfileStore {
    connection: ConnectionManager,
}

impl ProfileStore {
    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    pub async fn list(&self, organization_id: &str) -> Result<Value, ProfileError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(storage_key(organization_id))
            .await
            .map_err(|error| ProfileError::Storage(error.to_string()))?;
        let document = match payload {
            Some(payload) => serde_json::from_str::<Value>(&payload)
                .map_err(|error| ProfileError::Corrupt(error.to_string()))?,
            None => json!({"profiles": []}),
        };
        validate_document(&document)?;
        validate_scoped_document(&document, organization_id)?;
        Ok(document)
    }

    pub async fn get(
        &self,
        organization_id: &str,
        profile_id: &str,
    ) -> Result<Value, ProfileError> {
        self.list(organization_id)
            .await?
            .get("profiles")
            .and_then(Value::as_array)
            .and_then(|profiles| {
                profiles
                    .iter()
                    .find(|profile| profile.get("id").and_then(Value::as_str) == Some(profile_id))
            })
            .cloned()
            .ok_or_else(|| ProfileError::NotFound("Issuer profile not found.".to_string()))
    }

    pub async fn put(
        &self,
        organization_id: &str,
        profile_id: &str,
        profile: Value,
    ) -> Result<Value, ProfileError> {
        validate_stored_profile(&profile, organization_id, Some(profile_id))?;
        let mut document = self.list(organization_id).await?;
        let profiles = document["profiles"]
            .as_array_mut()
            .expect("validated profile array");
        if let Some(existing) = profiles
            .iter_mut()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(profile_id))
        {
            *existing = profile.clone();
        } else {
            profiles.push(profile.clone());
        }
        self.save(organization_id, &document).await?;
        Ok(profile)
    }

    pub async fn delete(
        &self,
        organization_id: &str,
        profile_id: &str,
    ) -> Result<(), ProfileError> {
        let mut document = self.list(organization_id).await?;
        let profiles = document["profiles"]
            .as_array_mut()
            .expect("validated profile array");
        let original = profiles.len();
        profiles.retain(|profile| profile.get("id").and_then(Value::as_str) != Some(profile_id));
        if profiles.len() == original {
            return Err(ProfileError::NotFound(
                "Issuer profile not found.".to_string(),
            ));
        }
        self.save(organization_id, &document).await
    }

    pub async fn find(
        &self,
        organization_id: &str,
        request: FindProfilesRequest,
    ) -> Result<Vec<Value>, ProfileError> {
        validate_find_request(&request)?;
        let document = self.list(organization_id).await?;
        Ok(find_profiles(
            document["profiles"]
                .as_array()
                .expect("validated profile array"),
            organization_id,
            &request,
        ))
    }

    pub async fn find_duplicate(
        &self,
        organization_id: &str,
        request: DuplicateProfileRequest,
    ) -> Result<DuplicateProfileResponse, ProfileError> {
        let document = self.list(organization_id).await?;
        duplicate_profile(
            document["profiles"]
                .as_array()
                .expect("validated profile array"),
            &request,
        )
    }

    async fn save(&self, organization_id: &str, document: &Value) -> Result<(), ProfileError> {
        validate_document(document)?;
        let payload = serde_json::to_string(document)
            .map_err(|error| ProfileError::Corrupt(error.to_string()))?;
        let mut connection = self.connection.clone();
        connection
            .set::<_, _, ()>(storage_key(organization_id), payload)
            .await
            .map_err(|error| ProfileError::Storage(error.to_string()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeProfileRequest {
    pub body: Value,
    #[serde(default)]
    pub existing: Option<Value>,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidateBindingRequest {
    pub profile: Value,
    pub service: Value,
    pub registry: Value,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FindProfilesRequest {
    #[serde(default)]
    pub active_only: bool,
    #[serde(default)]
    pub issuer_did: Option<String>,
    #[serde(default)]
    pub issuer_mode: Option<String>,
    #[serde(default)]
    pub key_purpose: Option<String>,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub wire_credential_format: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub allow_missing_algorithm: bool,
    #[serde(default)]
    pub require_signing_service: bool,
    #[serde(default)]
    pub require_signing_key_reference: bool,
    #[serde(default)]
    pub require_public_identity: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DuplicateProfileRequest {
    pub profile: Value,
    #[serde(default)]
    pub service_key_reference: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustodyFormatRequest {
    pub credential_format: String,
    pub key_purpose: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CustodyFormatResponse {
    pub wire_format: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DuplicateProfileResponse {
    pub profile: Option<Value>,
    pub found: bool,
}

pub fn normalize_profile(
    organization_id: &str,
    request: NormalizeProfileRequest,
) -> Result<Value, ProfileError> {
    let body = object(&request.body, "issuer profile body must be an object")?;
    let existing = request
        .existing
        .as_ref()
        .map(|value| object(value, "existing issuer profile must be an object"))
        .transpose()?;
    let field = |name: &str| {
        body.get(name)
            .or_else(|| existing.and_then(|item| item.get(name)))
    };
    let string_field = |name: &str, default: &str| {
        field(name)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string()
    };
    let status = string_field("status", "draft");
    allowed("status", &status, PROFILE_STATUSES)?;
    let issuer_did = string_field("issuer_did", "");
    if issuer_did.is_empty() {
        return Err(ProfileError::Invalid("issuer_did is required.".to_string()));
    }
    if !issuer_did.starts_with("did:") {
        return Err(ProfileError::Invalid(
            "issuer_did must be a DID string.".to_string(),
        ));
    }
    let signing_service_id = string_field("signing_service_id", "");
    if signing_service_id.is_empty() {
        return Err(ProfileError::Invalid(
            "signing_service_id is required.".to_string(),
        ));
    }
    let key_purpose = string_field("key_purpose", "vc_jwt_issuer");
    allowed("key_purpose", &key_purpose, KEY_PURPOSES)?;
    let algorithm = string_field("algorithm", "");
    if !algorithm.is_empty() {
        allowed("algorithm", &algorithm, ALGORITHMS)?;
    }
    let credential_format = string_field("credential_format", "");
    if !credential_format.is_empty() {
        allowed(
            "protocol credential_format",
            &credential_format,
            PROTOCOL_FORMATS,
        )?;
    }
    let issuer_mode = string_field("issuer_mode", "org_managed");
    allowed("issuer_mode", &issuer_mode, ISSUER_MODES)?;
    let policy = normalize_attestation_policy(field("key_attestation_policy"))?;
    let now = request.now.unwrap_or_else(now_iso);
    let id = request
        .profile_id
        .or_else(|| existing.and_then(|profile| string(profile, "id")))
        .unwrap_or_else(|| format!("ip-{}", &Uuid::new_v4().simple().to_string()[..16]));
    Ok(json!({
        "id": id,
        "organization_id": organization_id,
        "name": string_field("name", ""),
        "issuer_mode": issuer_mode,
        "issuer_did": issuer_did,
        "signing_service_id": signing_service_id,
        "signing_key_reference": string_field("signing_key_reference", ""),
        "verification_method_id": string_field("verification_method_id", ""),
        "key_purpose": key_purpose,
        "credential_format": credential_format,
        "algorithm": algorithm,
        "key_attestation_policy": policy,
        "status": status,
        "created_at": existing
            .and_then(|profile| string(profile, "created_at"))
            .unwrap_or_else(|| now.clone()),
        "updated_at": now,
    }))
}

pub fn validate_binding(request: &ValidateBindingRequest) -> Result<(), ProfileError> {
    let profile = object(&request.profile, "profile must be an object")?;
    let service = object(&request.service, "service must be an object")?;
    let service_id = string(service, "id").unwrap_or_default();
    let purpose = string(profile, "key_purpose").unwrap_or_else(|| "vc_jwt_issuer".to_string());
    let algorithm = string(profile, "algorithm").unwrap_or_default();
    let service_purposes = strings(service.get("key_purposes"));
    if !service_purposes.is_empty() && !service_purposes.contains(&purpose) {
        return Err(ProfileError::Invalid(format!(
            "Signing service '{service_id}' is not configured for key_purpose '{purpose}'."
        )));
    }
    let service_algorithms = strings(service.get("algorithms"));
    if !algorithm.is_empty()
        && !service_algorithms.is_empty()
        && !service_algorithms.contains(&algorithm)
    {
        return Err(ProfileError::Invalid(format!(
            "Signing service '{service_id}' does not support algorithm '{algorithm}'."
        )));
    }
    let key_reference = string(profile, "signing_key_reference").unwrap_or_default();
    if service_id.is_empty() || key_reference.is_empty() {
        return Err(ProfileError::Invalid(
            "Issuer profiles require an explicit signing key reference.".to_string(),
        ));
    }
    let reference_purposes = request.registry["key_reference_purposes"][&service_id]
        [&key_reference]
        .as_array()
        .map(|values| strings(Some(&Value::Array(values.clone()))))
        .unwrap_or_default();
    if reference_purposes.contains(&"lti_tool_signing".to_string()) && purpose != "lti_tool_signing"
    {
        return Err(ProfileError::Invalid(format!(
            "Key reference '{key_reference}' is reserved for LTI tool signing and cannot be assigned to an issuer profile."
        )));
    }
    if purpose == "lti_tool_signing"
        && !reference_purposes.is_empty()
        && reference_purposes != ["lti_tool_signing"]
    {
        return Err(ProfileError::Invalid(format!(
            "Key reference '{key_reference}' must be registered exclusively for lti_tool_signing."
        )));
    }
    if !reference_purposes.is_empty() && !reference_purposes.contains(&purpose) {
        return Err(ProfileError::Invalid(format!(
            "Key reference '{key_reference}' is not registered for issuer key_purpose '{purpose}'."
        )));
    }
    Ok(())
}

pub fn normalize_attestation_policy(value: Option<&Value>) -> Result<Value, ProfileError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(default_policy());
    };
    let policy = object(value, "key_attestation_policy must be an object.")?;
    let mode = string(policy, "mode").unwrap_or_else(|| "disabled".to_string());
    allowed("key attestation mode", &mode, ATTESTATION_MODES)?;
    let status_validation =
        string(policy, "status_validation").unwrap_or_else(|| "required".to_string());
    allowed(
        "key attestation status_validation",
        &status_validation,
        STATUS_POLICIES,
    )?;
    let roots = required_string_list(policy, "trusted_root_certificates_pem")?;
    let algorithms = required_string_list(policy, "allowed_algorithms")?;
    supported_algorithms("key attestation", &algorithms)?;
    if mode != "disabled" && (roots.is_empty() || algorithms.is_empty()) {
        return Err(ProfileError::Invalid(
            "Enabled key attestation policy requires trusted roots and allowed algorithms."
                .to_string(),
        ));
    }
    let status_roots = required_string_list(policy, "status_list_trusted_root_certificates_pem")?;
    let tls_roots = required_string_list(policy, "status_list_tls_ca_certificates_pem")?;
    for certificate in roots.iter().chain(&status_roots).chain(&tls_roots) {
        load_certificate_pem(certificate).map_err(|_| {
            ProfileError::Invalid(
                "key_attestation_policy contains an invalid trusted root certificate.".to_string(),
            )
        })?;
    }
    let max_age = bounded_integer(policy, "max_age_seconds", 300, 1, 86_400)?;
    let require_nonce = boolean(policy, "require_nonce", true)?;
    let status_algorithms = required_string_list(policy, "status_list_allowed_algorithms")?;
    supported_algorithms("status-list", &status_algorithms)?;
    let status_max_age =
        bounded_integer(policy, "status_list_max_age_seconds", 86_400, 1, 604_800)?;
    let allow_private_hosts = boolean(policy, "status_list_allow_private_hosts", false)?;
    let origins = required_string_list(policy, "status_list_allowed_origins")?
        .into_iter()
        .map(|origin| normalize_origin(&origin))
        .collect::<Result<Vec<_>, _>>()?;
    if mode != "disabled" && status_validation != "disabled" && origins.is_empty() {
        return Err(ProfileError::Invalid(
            "Enabled key attestation status validation requires at least one status-list allowed origin."
                .to_string(),
        ));
    }
    Ok(json!({
        "mode": mode,
        "trusted_root_certificates_pem": roots,
        "allowed_algorithms": algorithms,
        "required_key_storage": required_string_list(policy, "required_key_storage")?,
        "required_user_authentication": required_string_list(policy, "required_user_authentication")?,
        "max_age_seconds": max_age,
        "require_nonce": require_nonce,
        "status_validation": status_validation,
        "status_list_allowed_origins": origins,
        "status_list_trusted_root_certificates_pem": status_roots,
        "status_list_allowed_algorithms": status_algorithms,
        "status_list_max_age_seconds": status_max_age,
        "status_list_allow_private_hosts": allow_private_hosts,
        "status_list_tls_ca_certificates_pem": tls_roots,
    }))
}

pub fn duplicate_profile(
    profiles: &[Value],
    request: &DuplicateProfileRequest,
) -> Result<DuplicateProfileResponse, ProfileError> {
    let profile = object(&request.profile, "profile must be an object")?;
    let requested_reference = string(profile, "signing_key_reference").unwrap_or_default();
    let found = profiles.iter().find(|candidate| {
        candidate.as_object().is_some_and(|candidate| {
            string(candidate, "status").as_deref() != Some("revoked")
                && same(candidate, profile, "issuer_did")
                && same(candidate, profile, "signing_service_id")
                && (string(candidate, "signing_key_reference")
                    .filter(|value| !value.is_empty())
                    .or_else(|| request.service_key_reference.clone())
                    .unwrap_or_default()
                    == requested_reference)
                && string(candidate, "key_purpose")
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "vc_jwt_issuer".to_string())
                    == string(profile, "key_purpose")
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "vc_jwt_issuer".to_string())
                && optional_match(candidate, profile, "credential_format")
                && optional_algorithm_match(candidate, profile)
        })
    });
    let Some(found) = found else {
        return Ok(DuplicateProfileResponse {
            profile: None,
            found: false,
        });
    };
    let mut repaired = found.clone();
    let repaired_object = repaired.as_object_mut().expect("matched profile object");
    for field in [
        "signing_key_reference",
        "key_purpose",
        "credential_format",
        "algorithm",
        "name",
    ] {
        if string(repaired_object, field).is_none_or(|value| value.is_empty()) {
            if let Some(value) = profile.get(field).filter(|value| !value.is_null()) {
                repaired_object.insert(field.to_string(), value.clone());
            }
        }
    }
    if string(profile, "status").as_deref() == Some("active")
        && string(repaired_object, "status").as_deref() != Some("active")
    {
        repaired_object.insert("status".to_string(), Value::String("active".to_string()));
    }
    Ok(DuplicateProfileResponse {
        profile: Some(repaired),
        found: true,
    })
}

pub fn find_profiles(
    profiles: &[Value],
    organization_id: &str,
    request: &FindProfilesRequest,
) -> Vec<Value> {
    profiles
        .iter()
        .filter(|profile| {
            let Some(profile) = profile.as_object() else {
                return false;
            };
            string(profile, "organization_id").as_deref() == Some(organization_id)
                && (!request.active_only
                    || string(profile, "status")
                        .is_some_and(|status| status.eq_ignore_ascii_case("active")))
                && request
                    .issuer_did
                    .as_ref()
                    .is_none_or(|value| string(profile, "issuer_did").as_ref() == Some(value))
                && request.issuer_mode.as_ref().is_none_or(|value| {
                    string(profile, "issuer_mode")
                        .filter(|mode| !mode.trim().is_empty())
                        .unwrap_or_else(|| "org_managed".to_string())
                        == *value
                })
                && request.key_purpose.as_ref().is_none_or(|value| {
                    string(profile, "key_purpose")
                        .filter(|purpose| !purpose.trim().is_empty())
                        .unwrap_or_else(|| "vc_jwt_issuer".to_string())
                        == *value
                })
                && request.credential_format.as_ref().is_none_or(|value| {
                    string(profile, "credential_format").as_ref() == Some(value)
                })
                && request
                    .wire_credential_format
                    .as_ref()
                    .is_none_or(|value| profile_wire_format(profile).as_ref() == Some(value))
                && request.algorithm.as_ref().is_none_or(|value| {
                    let stored = string(profile, "algorithm").unwrap_or_default();
                    (request.allow_missing_algorithm && stored.trim().is_empty())
                        || canonical_algorithm(Some(&stored)) == *value
                })
                && (!request.require_signing_service
                    || string(profile, "signing_service_id").is_some_and(|value| !value.is_empty()))
                && (!request.require_signing_key_reference
                    || string(profile, "signing_key_reference")
                        .is_some_and(|value| !value.is_empty()))
                && (!request.require_public_identity || is_public_identity(profile))
        })
        .cloned()
        .collect()
}

pub fn custody_format(
    request: &CustodyFormatRequest,
) -> Result<CustodyFormatResponse, ProfileError> {
    let purpose_format = match request.key_purpose.as_str() {
        "oid4vp_request_signing" => Some("oauth-authz-req+jwt"),
        "lti_tool_signing" => Some("lti_tool_jwt"),
        "vdsnc_signing" | "csca" => Some("mso_mdoc"),
        _ => None,
    };
    let wire_format = purpose_format
        .map(str::to_string)
        .or_else(|| protocol_wire_format(&request.credential_format))
        .ok_or_else(|| {
            ProfileError::Invalid(format!(
                "Unsupported credential_format '{}'.",
                request.credential_format
            ))
        })?;
    Ok(CustodyFormatResponse { wire_format })
}

fn validate_find_request(request: &FindProfilesRequest) -> Result<(), ProfileError> {
    if let Some(mode) = &request.issuer_mode {
        allowed("issuer_mode", mode, ISSUER_MODES)?;
    }
    if let Some(purpose) = &request.key_purpose {
        allowed("key_purpose", purpose, KEY_PURPOSES)?;
    }
    if let Some(format) = &request.credential_format {
        allowed("protocol credential_format", format, PROTOCOL_FORMATS)?;
    }
    if let Some(algorithm) = &request.algorithm {
        allowed("algorithm", algorithm, ALGORITHMS)?;
    }
    Ok(())
}

fn is_public_identity(profile: &Map<String, Value>) -> bool {
    string(profile, "issuer_did").is_some_and(|value| value.starts_with("did:"))
        && string(profile, "credential_format")
            .is_some_and(|value| PROTOCOL_FORMATS.contains(&value.to_ascii_uppercase().as_str()))
        && string(profile, "algorithm")
            .is_some_and(|value| ALGORITHMS.contains(&canonical_algorithm(Some(&value)).as_str()))
}

fn profile_wire_format(profile: &Map<String, Value>) -> Option<String> {
    let purpose = string(profile, "key_purpose")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "vc_jwt_issuer".to_string());
    let purpose_format = match purpose.as_str() {
        "oid4vp_request_signing" => Some("oauth-authz-req+jwt"),
        "lti_tool_signing" => Some("lti_tool_jwt"),
        "vdsnc_signing" => Some("mso_mdoc"),
        "csca" => Some("mso_mdoc"),
        _ => None,
    };
    purpose_format
        .map(str::to_string)
        .or_else(|| protocol_wire_format(&string(profile, "credential_format")?))
}

fn protocol_wire_format(protocol_format: &str) -> Option<String> {
    match protocol_format
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "mdoc" | "mso_mdoc" => Some("mso_mdoc".to_string()),
        "sd_jwt_vc" | "dc+sd_jwt" | "vc+sd_jwt" => Some("dc+sd-jwt".to_string()),
        "vc_jwt" | "jwt_vc" | "jwt_vc_json" => Some("jwt_vc_json".to_string()),
        "json_ld" | "ldp_vc" => Some("ldp_vc".to_string()),
        "zk_mdoc" => Some("zk_mdoc".to_string()),
        "icao_emrtd" => Some("icao_emrtd".to_string()),
        "vds_nc" => Some("vds_nc".to_string()),
        _ => None,
    }
}

fn validate_document(document: &Value) -> Result<(), ProfileError> {
    let profiles = document
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| ProfileError::Corrupt("profiles must be an array".to_string()))?;
    if profiles.iter().any(|profile| !profile.is_object()) {
        return Err(ProfileError::Corrupt(
            "profiles must contain only objects".to_string(),
        ));
    }
    Ok(())
}

fn validate_scoped_document(document: &Value, organization_id: &str) -> Result<(), ProfileError> {
    for profile in document["profiles"]
        .as_array()
        .expect("validated profile array")
    {
        if profile.get("organization_id").and_then(Value::as_str) != Some(organization_id) {
            return Err(ProfileError::Corrupt(
                "profile organization does not match its storage scope".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_stored_profile(
    profile: &Value,
    organization_id: &str,
    profile_id: Option<&str>,
) -> Result<(), ProfileError> {
    let profile = object(profile, "profile must be an object")?;
    if string(profile, "organization_id").as_deref() != Some(organization_id) {
        return Err(ProfileError::Invalid(
            "Issuer profile organization does not match its storage scope.".to_string(),
        ));
    }
    if profile_id.is_some_and(|id| string(profile, "id").as_deref() != Some(id)) {
        return Err(ProfileError::Invalid(
            "Issuer profile ID does not match its storage key.".to_string(),
        ));
    }
    Ok(())
}

fn default_policy() -> Value {
    json!({
        "mode": "disabled",
        "trusted_root_certificates_pem": [],
        "allowed_algorithms": [],
        "required_key_storage": [],
        "required_user_authentication": [],
        "max_age_seconds": 300,
        "require_nonce": true,
        "status_validation": "required",
        "status_list_allowed_origins": [],
        "status_list_trusted_root_certificates_pem": [],
        "status_list_allowed_algorithms": [],
        "status_list_max_age_seconds": 86400,
        "status_list_allow_private_hosts": false,
        "status_list_tls_ca_certificates_pem": [],
    })
}

fn allowed(name: &str, value: &str, allowed: &[&str]) -> Result<(), ProfileError> {
    if allowed.contains(&value) {
        return Ok(());
    }
    Err(ProfileError::Invalid(format!(
        "Invalid {name} '{value}'. Must be one of {allowed:?}."
    )))
}

fn supported_algorithms(name: &str, algorithms: &[String]) -> Result<(), ProfileError> {
    let unsupported = algorithms
        .iter()
        .filter(|algorithm| !ALGORITHMS.contains(&algorithm.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Invalid(format!(
            "Unsupported {name} algorithms: {unsupported:?}."
        )))
    }
}

fn required_string_list(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, ProfileError> {
    let Some(value) = object.get(name) else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        ProfileError::Invalid(format!(
            "key_attestation_policy.{name} must be an array of non-empty strings."
        ))
    })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    ProfileError::Invalid(format!(
                        "key_attestation_policy.{name} must be an array of non-empty strings."
                    ))
                })
        })
        .collect()
}

fn bounded_integer(
    object: &Map<String, Value>,
    name: &str,
    default: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64, ProfileError> {
    let value = object.get(name).map_or(Some(default), Value::as_i64);
    value
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .ok_or_else(|| {
            ProfileError::Invalid(format!(
                "key_attestation_policy.{name} must be from {minimum} through {maximum}."
            ))
        })
}

fn boolean(object: &Map<String, Value>, name: &str, default: bool) -> Result<bool, ProfileError> {
    object
        .get(name)
        .map_or(Some(default), Value::as_bool)
        .ok_or_else(|| {
            ProfileError::Invalid(format!("key_attestation_policy.{name} must be a boolean."))
        })
}

fn normalize_origin(origin: &str) -> Result<String, ProfileError> {
    let parsed = Url::parse(origin).map_err(|_| invalid_origin())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid_origin());
    }
    let host = parsed.host_str().expect("validated host").to_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Ok(match parsed.port() {
        Some(port) if port != 443 => format!("https://{host}:{port}"),
        _ => format!("https://{host}"),
    })
}

fn invalid_origin() -> ProfileError {
    ProfileError::Invalid(
        "key_attestation_policy.status_list_allowed_origins must contain HTTPS origins without paths or credentials."
            .to_string(),
    )
}

fn object<'a>(value: &'a Value, message: &str) -> Result<&'a Map<String, Value>, ProfileError> {
    value
        .as_object()
        .ok_or_else(|| ProfileError::Invalid(message.to_string()))
}

fn string(object: &Map<String, Value>, name: &str) -> Option<String> {
    object.get(name).and_then(Value::as_str).map(str::to_string)
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn same(left: &Map<String, Value>, right: &Map<String, Value>, field: &str) -> bool {
    left.get(field) == right.get(field)
}

fn optional_match(left: &Map<String, Value>, right: &Map<String, Value>, field: &str) -> bool {
    string(left, field).is_none_or(|value| value.is_empty()) || left.get(field) == right.get(field)
}

fn optional_algorithm_match(left: &Map<String, Value>, right: &Map<String, Value>) -> bool {
    let candidate = string(left, "algorithm").unwrap_or_default();
    candidate.is_empty()
        || canonical_algorithm(Some(&candidate))
            == canonical_algorithm(string(right, "algorithm").as_deref())
}

fn canonical_algorithm(value: Option<&str>) -> String {
    let value = value.unwrap_or("ES256");
    ALGORITHMS
        .iter()
        .find(|algorithm| algorithm.eq_ignore_ascii_case(value))
        .copied()
        .unwrap_or(value)
        .to_string()
}

pub fn storage_key(organization_id: &str) -> String {
    format!("org:{organization_id}:issuer-profiles")
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}
