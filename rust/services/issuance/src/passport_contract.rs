//! Frozen physical-document HTTP shapes. The source reference is Credentials
//! `physical_document_routes.py` at the commit pinned in the native contract.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use num_bigint::BigUint;
use serde::{
    de::{IgnoredAny, MapAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::{json, Map, Value};

use crate::{
    passport_artifact::PassportSensitiveArtifact, passport_bureau::DocumentType,
    passport_repository::PassportJob,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassportApplicationRequest {
    pub organization_id: String,
    pub flow_execution_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub delivery_destination_profile_id: String,
    #[serde(default = "default_document_type")]
    pub document_type: DocumentType,
    pub country_code: String,
    pub applicant: Map<String, Value>,
    pub mrz: BTreeMap<String, String>,
    pub data_groups: BTreeMap<String, String>,
}

const fn default_document_type() -> DocumentType {
    DocumentType::TD3
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PassportRequestError {
    #[error("delivery_destination_profile_id exceeds 128 characters")]
    DestinationTooLong,
    #[error("country_code must contain three uppercase ASCII letters")]
    InvalidCountryCode,
    #[error("DG1 and DG2 are required")]
    MissingDataGroups,
    #[error("invalid data group name")]
    InvalidDataGroupName,
    #[error("data group content must be strict base64")]
    InvalidDataGroupContent,
}

impl PassportApplicationRequest {
    /// Reproduce the released Pydantic request boundary before reading a job or key.
    pub fn from_python_value(input: &Value, field_order: Option<&[String]>) -> Result<Self, Value> {
        if input.is_null() {
            return Err(json!({"detail": [{
                "type": "missing", "loc": ["body"], "msg": "Field required", "input": null,
            }]}));
        }
        let Some(fields) = input.as_object() else {
            return Err(json!({"detail": [{
                "type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": input,
            }]}));
        };
        let mut errors = Vec::new();
        for name in [
            "organization_id",
            "flow_execution_id",
            "application_template_id",
            "credential_template_id",
        ] {
            string_field(fields, name, &mut errors);
        }
        if let Some(destination) =
            string_field(fields, "delivery_destination_profile_id", &mut errors)
        {
            if destination.chars().count() > 128 {
                errors.push(json!({
                    "type": "string_too_long", "loc": ["body", "delivery_destination_profile_id"],
                    "msg": "String should have at most 128 characters", "input": destination,
                    "ctx": {"max_length": 128},
                }));
            }
        }
        if let Some(value) = fields.get("document_type") {
            if !matches!(value.as_str(), Some("TD1" | "TD2" | "TD3")) {
                errors.push(json!({
                    "type": "literal_error", "loc": ["body", "document_type"],
                    "msg": "Input should be 'TD1', 'TD2' or 'TD3'", "input": value,
                    "ctx": {"expected": "'TD1', 'TD2' or 'TD3'"},
                }));
            }
        }
        if let Some(country) = string_field(fields, "country_code", &mut errors) {
            if !valid_country_code(country) {
                errors.push(json!({
                    "type": "string_pattern_mismatch", "loc": ["body", "country_code"],
                    "msg": "String should match pattern '^[A-Z]{3}$'", "input": country,
                    "ctx": {"pattern": "^[A-Z]{3}$"},
                }));
            }
        }
        dictionary_field(fields, "applicant", &mut errors);
        string_dictionary_field(fields, "mrz", &mut errors);
        if let Some(groups) = string_dictionary_field(fields, "data_groups", &mut errors) {
            let problem = if !groups.contains_key("DG1") || !groups.contains_key("DG2") {
                Some("DG1 and DG2 are required".to_owned())
            } else {
                groups.iter().find_map(|(name, content)| {
                    if !valid_data_group_name(name) {
                        return Some(format!("Invalid data group name: {name}"));
                    }
                    STANDARD
                        .decode(content.as_str().expect("validated string dictionary"))
                        .err()
                        .map(|_| "Only base64 data is allowed".to_owned())
                })
            };
            if let Some(problem) = problem {
                errors.push(json!({
                    "type": "value_error", "loc": ["body", "data_groups"],
                    "msg": format!("Value error, {problem}"), "input": fields["data_groups"],
                    "ctx": {"error": {}},
                }));
            }
        }
        let names = field_order.map_or_else(
            || fields.keys().cloned().collect::<Vec<_>>(),
            <[String]>::to_vec,
        );
        let mut seen = BTreeSet::new();
        for name in names {
            if !matches!(
                name.as_str(),
                "organization_id"
                    | "flow_execution_id"
                    | "application_template_id"
                    | "credential_template_id"
                    | "delivery_destination_profile_id"
                    | "document_type"
                    | "country_code"
                    | "applicant"
                    | "mrz"
                    | "data_groups"
            ) && seen.insert(name.clone())
            {
                if let Some(value) = fields.get(&name) {
                    errors.push(json!({
                        "type": "extra_forbidden", "loc": ["body", name],
                        "msg": "Extra inputs are not permitted", "input": value,
                    }));
                }
            }
        }
        if !errors.is_empty() {
            return Err(json!({"detail": errors}));
        }
        serde_json::from_value(input.clone())
            .map_err(|_| json!({"detail": "Physical document request validation failed"}))
    }

    pub fn validate(&self) -> Result<(), PassportRequestError> {
        if self.delivery_destination_profile_id.chars().count() > 128 {
            return Err(PassportRequestError::DestinationTooLong);
        }
        if !valid_country_code(&self.country_code) {
            return Err(PassportRequestError::InvalidCountryCode);
        }
        if !self.data_groups.contains_key("DG1") || !self.data_groups.contains_key("DG2") {
            return Err(PassportRequestError::MissingDataGroups);
        }
        for (name, content) in &self.data_groups {
            if !valid_data_group_name(name) {
                return Err(PassportRequestError::InvalidDataGroupName);
            }
            STANDARD
                .decode(content)
                .map_err(|_| PassportRequestError::InvalidDataGroupContent)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn sensitive_artifact(&self) -> PassportSensitiveArtifact {
        PassportSensitiveArtifact {
            applicant: Value::Object(self.applicant.clone()),
            mrz: self.mrz.clone(),
            data_groups: self.data_groups.clone(),
        }
    }
}

fn valid_country_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_data_group_name(name: &str) -> bool {
    name.strip_prefix("DG")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(python_is_digit))
}

fn string_field<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<&'a str> {
    match fields.get(name) {
        None => errors.push(json!({
            "type": "missing", "loc": ["body", name], "msg": "Field required",
            "input": fields,
        })),
        Some(value) if !value.is_string() => errors.push(json!({
            "type": "string_type", "loc": ["body", name],
            "msg": "Input should be a valid string", "input": value,
        })),
        Some(value) => return value.as_str(),
    }
    None
}

fn dictionary_field<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<&'a Map<String, Value>> {
    match fields.get(name) {
        None => errors.push(json!({
            "type": "missing", "loc": ["body", name], "msg": "Field required",
            "input": fields,
        })),
        Some(value) if !value.is_object() => errors.push(json!({
            "type": "dict_type", "loc": ["body", name],
            "msg": "Input should be a valid dictionary", "input": value,
        })),
        Some(value) => return value.as_object(),
    }
    None
}

fn string_dictionary_field<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    errors: &mut Vec<Value>,
) -> Option<&'a Map<String, Value>> {
    let values = dictionary_field(fields, name, errors)?;
    let mut all_strings = true;
    for (key, value) in values {
        if !value.is_string() {
            errors.push(json!({
                "type": "string_type", "loc": ["body", name, key],
                "msg": "Input should be a valid string", "input": value,
            }));
            all_strings = false;
        }
    }
    all_strings.then_some(values)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityResultRequest {
    pub passed: bool,
    #[serde(default)]
    pub failure_codes: Vec<String>,
}

impl QualityResultRequest {
    /// Reproduce the captured released Pydantic quality boundary before the job is read.
    pub fn from_python_value(input: &Value, field_order: Option<&[String]>) -> Result<Self, Value> {
        if input.is_null() {
            return Err(json!({"detail": [{
                "type": "missing", "loc": ["body"],
                "msg": "Field required", "input": null,
            }]}));
        }
        let Some(fields) = input.as_object() else {
            return Err(json!({"detail": [{
                "type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid dictionary or object to extract fields from",
                "input": input,
            }]}));
        };
        let mut errors = Vec::new();
        let passed = match fields.get("passed") {
            None => {
                errors.push(json!({
                    "type": "missing", "loc": ["body", "passed"],
                    "msg": "Field required", "input": input,
                }));
                None
            }
            Some(value) => match python_bool(value) {
                Some(passed) => Some(passed),
                None => {
                    let (kind, message) =
                        if value.is_null() || value.is_array() || value.is_object() {
                            ("bool_type", "Input should be a valid boolean")
                        } else {
                            (
                                "bool_parsing",
                                "Input should be a valid boolean, unable to interpret input",
                            )
                        };
                    errors.push(json!({
                        "type": kind, "loc": ["body", "passed"],
                        "msg": message, "input": value,
                    }));
                    None
                }
            },
        };
        let failure_codes = match fields.get("failure_codes") {
            None => Some(Vec::new()),
            Some(Value::Array(values)) => {
                let mut codes = Vec::with_capacity(values.len());
                for (index, value) in values.iter().enumerate() {
                    if let Some(code) = value.as_str() {
                        codes.push(code.to_owned());
                    } else {
                        errors.push(json!({
                            "type": "string_type", "loc": ["body", "failure_codes", index],
                            "msg": "Input should be a valid string", "input": value,
                        }));
                    }
                }
                Some(codes)
            }
            Some(value) => {
                errors.push(json!({
                    "type": "list_type", "loc": ["body", "failure_codes"],
                    "msg": "Input should be a valid list", "input": value,
                }));
                None
            }
        };
        let names = field_order.map_or_else(
            || fields.keys().cloned().collect::<Vec<_>>(),
            <[String]>::to_vec,
        );
        let mut seen = BTreeSet::new();
        for name in names {
            if name != "passed" && name != "failure_codes" && seen.insert(name.clone()) {
                let Some(value) = fields.get(&name) else {
                    continue;
                };
                errors.push(json!({
                    "type": "extra_forbidden", "loc": ["body", name],
                    "msg": "Extra inputs are not permitted", "input": value,
                }));
            }
        }
        if !errors.is_empty() {
            return Err(json!({"detail": errors}));
        }
        Ok(Self {
            passed: passed.expect("validated passed field"),
            failure_codes: failure_codes.expect("validated failure code list"),
        })
    }
}

/// Preserve the submitted order of extra fields for Pydantic error arrays.
pub fn json_field_order(body: &[u8]) -> Vec<String> {
    struct OrderedKeys(Vec<String>);
    impl<'de> Deserialize<'de> for OrderedKeys {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Keys;
            impl<'de> Visitor<'de> for Keys {
                type Value = OrderedKeys;
                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a quality-result JSON object")
                }
                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                    let mut names = Vec::new();
                    while let Some((name, _)) = map.next_entry::<String, IgnoredAny>()? {
                        names.push(name);
                    }
                    Ok(OrderedKeys(names))
                }
            }
            deserializer.deserialize_map(Keys)
        }
    }
    serde_json::from_slice::<OrderedKeys>(body).map_or_else(|_| Vec::new(), |value| value.0)
}

fn python_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) if value.as_i64() == Some(0) || value.as_f64() == Some(0.0) => {
            Some(false)
        }
        Value::Number(value) if value.as_i64() == Some(1) || value.as_f64() == Some(1.0) => {
            Some(true)
        }
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
            "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

/// Exactly the Python `_safe_response` projection; no ciphertext or applicant
/// material is reachable through this type.
#[derive(Serialize)]
pub struct PassportSafeResponse<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
    pub flow_execution_id: &'a str,
    pub application_id: &'a str,
    pub credential_template_id: &'a str,
    pub delivery_destination_profile_id: &'a str,
    pub document_type: &'a str,
    pub country_code: &'a str,
    pub secure_artifact_reference: &'a str,
    pub bureau_job_id: Option<&'a str>,
    pub tracking_number: Option<&'a str>,
    pub status: &'a str,
    pub quality_result: Option<&'a Value>,
    pub error_code: Option<&'a str>,
    pub error_message: Option<&'a str>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl<'a> From<&'a PassportJob> for PassportSafeResponse<'a> {
    fn from(job: &'a PassportJob) -> Self {
        Self {
            id: &job.id,
            organization_id: &job.organization_id,
            flow_execution_id: &job.flow_execution_id,
            application_id: &job.application_id,
            credential_template_id: &job.credential_template_id,
            delivery_destination_profile_id: &job.delivery_destination_profile_id,
            document_type: &job.document_type,
            country_code: &job.country_code,
            secure_artifact_reference: &job.secure_artifact_reference,
            bureau_job_id: job.bureau_job_id.as_deref(),
            tracking_number: job.tracking_number.as_deref(),
            status: &job.status,
            quality_result: job.quality_result.as_ref(),
            error_code: job.error_code.as_deref(),
            error_message: job.error_message.as_deref(),
            submitted_at: job.submitted_at,
            completed_at: job.completed_at,
            created_at: job.created_at,
            updated_at: job.updated_at,
        }
    }
}

impl PassportSensitiveArtifact {
    pub fn numbered_data_groups(&self) -> Result<BTreeMap<BigUint, String>, PassportRequestError> {
        let mut numbered = BTreeMap::new();
        for (name, content) in &self.data_groups {
            let digits = name
                .strip_prefix("DG")
                .ok_or(PassportRequestError::InvalidDataGroupName)?;
            let normalized = digits
                .chars()
                .map(python_decimal_digit)
                .map(|digit| digit.map(|value| char::from(b'0' + value)))
                .collect::<Option<String>>()
                .ok_or(PassportRequestError::InvalidDataGroupName)?;
            let number = BigUint::parse_bytes(normalized.as_bytes(), 10)
                .ok_or(PassportRequestError::InvalidDataGroupName)?;
            numbered.insert(number, content.clone());
        }
        Ok(numbered)
    }
}

// Frozen from the released Python runtime's Unicode 15.0 `str.isdigit` and
// `unicodedata.decimal` behavior. Each decimal block contains digits 0..9.
const DECIMAL_ZEROES: &[u32] = &[
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x11f50, 0x16a60, 0x16ac0,
    0x16b50, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e950,
    0x1fbf0,
];

const NONDECIMAL_DIGIT_RANGES: &[(u32, u32)] = &[
    (0xb2, 0xb3),
    (0xb9, 0xb9),
    (0x1369, 0x1371),
    (0x19da, 0x19da),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247c),
    (0x2488, 0x2490),
    (0x24ea, 0x24ea),
    (0x24f5, 0x24fd),
    (0x24ff, 0x24ff),
    (0x2776, 0x277e),
    (0x2780, 0x2788),
    (0x278a, 0x2792),
    (0x10a40, 0x10a43),
    (0x10e60, 0x10e68),
    (0x11052, 0x1105a),
    (0x1f100, 0x1f10a),
];

fn python_decimal_digit(character: char) -> Option<u8> {
    let codepoint = u32::from(character);
    let index = DECIMAL_ZEROES
        .partition_point(|zero| *zero <= codepoint)
        .checked_sub(1)?;
    let value = codepoint - DECIMAL_ZEROES[index];
    (value < 10).then_some(value as u8)
}

fn python_is_digit(character: char) -> bool {
    python_decimal_digit(character).is_some()
        || NONDECIMAL_DIGIT_RANGES
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&u32::from(character)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn application() -> Value {
        json!({
            "organization_id": "org-1", "flow_execution_id": "flow-1",
            "application_template_id": "template-1", "credential_template_id": "credential-1",
            "delivery_destination_profile_id": "destination-1", "country_code": "USA",
            "applicant": {"name": "Sensitive Name"},
            "mrz": {"line_1": "SENSITIVE MRZ"},
            "data_groups": {"DG1": "YQ==", "DG2": "Yg=="}
        })
    }

    #[test]
    fn application_defaults_and_validation_match_frozen_request() {
        let request: PassportApplicationRequest = serde_json::from_value(application()).unwrap();
        assert_eq!(request.document_type, DocumentType::TD3);
        request.validate().unwrap();
        assert_eq!(request.sensitive_artifact().data_groups.len(), 2);
        let numbered = request.sensitive_artifact().numbered_data_groups().unwrap();
        assert_eq!(
            numbered.get(&BigUint::from(1u8)).map(String::as_str),
            Some("YQ==")
        );
    }

    #[test]
    fn application_rejects_unknown_and_invalid_frozen_fields() {
        let mut value = application();
        value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<PassportApplicationRequest>(value).is_err());
        let mut value = application();
        value["document_type"] = json!("TD4");
        assert!(serde_json::from_value::<PassportApplicationRequest>(value).is_err());
        for (field, replacement, error) in [
            (
                "country_code",
                json!("usA"),
                PassportRequestError::InvalidCountryCode,
            ),
            (
                "delivery_destination_profile_id",
                json!("x".repeat(129)),
                PassportRequestError::DestinationTooLong,
            ),
            (
                "data_groups",
                json!({"DG1": "YQ=="}),
                PassportRequestError::MissingDataGroups,
            ),
            (
                "data_groups",
                json!({"DG1": "YQ==", "DG2": "Yg==", "DGx": "Yw=="}),
                PassportRequestError::InvalidDataGroupName,
            ),
            (
                "data_groups",
                json!({"DG1": "YQ==", "DG2": "***"}),
                PassportRequestError::InvalidDataGroupContent,
            ),
        ] {
            let mut value = application();
            value[field] = replacement;
            let request: PassportApplicationRequest = serde_json::from_value(value).unwrap();
            assert_eq!(request.validate(), Err(error));
        }
        let mut value = application();
        value["data_groups"]["DG999999999999999999999999999999999999999999"] = json!("Yw==");
        let request: PassportApplicationRequest = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        assert!(request
            .sensitive_artifact()
            .numbered_data_groups()
            .unwrap()
            .contains_key(
                &BigUint::parse_bytes(b"999999999999999999999999999999999999999999", 10).unwrap()
            ));
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let unicode = &frozen["unicode_data_group_digit_observation"];
        let mut value = application();
        for (name, _) in unicode["accepted_decimal_names"].as_object().unwrap() {
            value["data_groups"][name] = json!("Yw==");
        }
        let request: PassportApplicationRequest = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        let numbered = request.sensitive_artifact().numbered_data_groups().unwrap();
        for (_, number) in unicode["accepted_decimal_names"].as_object().unwrap() {
            let number = BigUint::parse_bytes(number.as_str().unwrap().as_bytes(), 10).unwrap();
            assert_eq!(numbered.get(&number).map(String::as_str), Some("Yw=="));
        }
        let mut value = application();
        value["data_groups"][unicode["accepted_nondecimal_name"].as_str().unwrap()] = json!("Yw==");
        let request: PassportApplicationRequest = serde_json::from_value(value).unwrap();
        request.validate().unwrap();
        assert!(request.sensitive_artifact().numbered_data_groups().is_err());
    }

    #[test]
    fn digit_tables_match_released_python_unicode_codepoints_and_values() {
        use sha2::{Digest, Sha256};

        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let unicode = &frozen["unicode_data_group_digit_observation"];
        assert_eq!(unicode["python_unicode_version"], "15.0.0");
        let mut digits = 0;
        let mut decimals = 0;
        let mut digit_codepoints = Sha256::new();
        let mut decimal_codepoints = Sha256::new();
        let mut decimal_values = Sha256::new();
        for codepoint in 0_u32..=0x10ffff {
            let Some(character) = char::from_u32(codepoint) else {
                continue;
            };
            if python_is_digit(character) {
                digits += 1;
                digit_codepoints.update(codepoint.to_be_bytes());
            }
            if let Some(value) = python_decimal_digit(character) {
                decimals += 1;
                decimal_codepoints.update(codepoint.to_be_bytes());
                decimal_values.update(codepoint.to_be_bytes());
                decimal_values.update([value]);
            }
        }
        assert_eq!(
            digits,
            unicode["python_isdigit_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            decimals,
            unicode["python_decimal_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            format!("{:x}", digit_codepoints.finalize()),
            unicode["python_isdigit_codepoints_sha256_be_u32"]
        );
        assert_eq!(
            format!("{:x}", decimal_codepoints.finalize()),
            unicode["python_decimal_codepoints_sha256_be_u32"]
        );
        assert_eq!(
            format!("{:x}", decimal_values.finalize()),
            unicode["python_decimal_values_sha256_be_u32_u8"]
        );
    }

    #[test]
    fn quality_model_defaults_and_rejects_extras() {
        let quality: QualityResultRequest =
            serde_json::from_value(json!({"passed": true})).unwrap();
        assert!(quality.passed);
        assert!(quality.failure_codes.is_empty());
        assert!(serde_json::from_value::<QualityResultRequest>(
            json!({"passed": true, "extra": 1})
        )
        .is_err());
        for (input, expected) in [
            (json!(true), true),
            (json!(false), false),
            (json!(1), true),
            (json!(0), false),
            (json!("true"), true),
            (json!("off"), false),
        ] {
            let parsed =
                QualityResultRequest::from_python_value(&json!({"passed": input}), None).unwrap();
            assert_eq!(parsed.passed, expected);
        }
    }

    #[test]
    fn safe_projection_has_only_the_frozen_public_fields() {
        let now = Utc::now();
        let job = PassportJob {
            id: "job-1".into(),
            organization_id: "org-1".into(),
            flow_execution_id: "flow-1".into(),
            application_id: "application-1".into(),
            application_template_id: "secret-template".into(),
            credential_template_id: "credential-1".into(),
            revocation_profile_id: Some("secret-revocation".into()),
            delivery_destination_profile_id: "destination-1".into(),
            document_type: "TD3".into(),
            country_code: "USA".into(),
            secure_artifact_ciphertext: "secret-ciphertext".into(),
            secure_artifact_reference: "physical-artifact://job-1".into(),
            sod_sha256: Some("secret-sod".into()),
            bureau_job_id: None,
            tracking_number: None,
            status: "DRAFT".into(),
            quality_result: None,
            error_code: None,
            error_message: None,
            submitted_at: None,
            completed_at: None,
            created_at: now,
            updated_at: now,
        };
        let serialized = serde_json::to_value(PassportSafeResponse::from(&job)).unwrap();
        let frozen: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let expected = frozen["safe_job_response_fields"].as_array().unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), expected.len());
        for field in expected {
            let field = field.as_str().unwrap();
            assert!(serialized.get(field).is_some(), "missing {field}");
        }
        for secret in [
            "secret-ciphertext",
            "secret-template",
            "secret-revocation",
            "secret-sod",
        ] {
            assert!(!serialized.to_string().contains(secret));
        }
    }
}
