//! Frozen physical-document HTTP shapes. The source reference is Credentials
//! `physical_document_routes.py` at the commit pinned in the native contract.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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
    #[error("data group number exceeds the native signer range")]
    DataGroupNumberOutOfRange,
    #[error("data group content must be strict base64")]
    InvalidDataGroupContent,
}

impl PassportApplicationRequest {
    pub fn validate(&self) -> Result<(), PassportRequestError> {
        if self.delivery_destination_profile_id.chars().count() > 128 {
            return Err(PassportRequestError::DestinationTooLong);
        }
        if self.country_code.len() != 3
            || !self
                .country_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(PassportRequestError::InvalidCountryCode);
        }
        if !self.data_groups.contains_key("DG1") || !self.data_groups.contains_key("DG2") {
            return Err(PassportRequestError::MissingDataGroups);
        }
        for (name, content) in &self.data_groups {
            let digits = name
                .strip_prefix("DG")
                .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(PassportRequestError::InvalidDataGroupName)?;
            digits
                .parse::<u16>()
                .map_err(|_| PassportRequestError::DataGroupNumberOutOfRange)?;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityResultRequest {
    pub passed: bool,
    #[serde(default)]
    pub failure_codes: Vec<String>,
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
    pub fn numbered_data_groups(&self) -> Result<BTreeMap<u16, String>, PassportRequestError> {
        let mut numbered = BTreeMap::new();
        for (name, content) in &self.data_groups {
            let digits = name
                .strip_prefix("DG")
                .ok_or(PassportRequestError::InvalidDataGroupName)?;
            let number = digits
                .parse::<u16>()
                .map_err(|_| PassportRequestError::DataGroupNumberOutOfRange)?;
            numbered.insert(number, content.clone());
        }
        Ok(numbered)
    }
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
        assert_eq!(numbered.get(&1).map(String::as_str), Some("YQ=="));
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
            (
                "data_groups",
                json!({"DG1": "YQ==", "DG2": "Yg==", "DG65536": "Yw=="}),
                PassportRequestError::DataGroupNumberOutOfRange,
            ),
        ] {
            let mut value = application();
            value[field] = replacement;
            let request: PassportApplicationRequest = serde_json::from_value(value).unwrap();
            assert_eq!(request.validate(), Err(error));
        }
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
