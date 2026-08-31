use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

const DEFAULT_SESSION_DURATION_SECONDS: u64 = 600;
const MIN_SESSION_DURATION_SECONDS: u64 = 30;
const MAX_SESSION_DURATION_SECONDS: u64 = 3_600;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<Map<String, Value>>,
    #[serde(default)]
    pub format: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub verifier_did: String,
    pub presentation_definition: PresentationDefinition,
    #[serde(default = "default_session_duration_seconds")]
    pub session_duration_seconds: u64,
}

impl CreateSessionRequest {
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        if !(MIN_SESSION_DURATION_SECONDS..=MAX_SESSION_DURATION_SECONDS)
            .contains(&self.session_duration_seconds)
        {
            return Err(RequestValidationError::SessionDuration);
        }
        Ok(())
    }
}

const fn default_session_duration_seconds() -> u64 {
    DEFAULT_SESSION_DURATION_SECONDS
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SessionResponse {
    pub id: String,
    pub organization_id: String,
    pub verifier_did: String,
    pub status: String,
    pub request_uri: String,
    pub nonce: String,
    pub expires_at: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubmitPresentationRequest {
    pub presentation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum PresentationPayload {
    Object(Map<String, Value>),
    String(String),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyDirectRequest {
    pub presentation: PresentationPayload,
    pub presentation_definition: PresentationDefinition,
    pub verifier_did: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifyVdsNcRequest {
    pub barcode: String,
    pub issuer_did: String,
    #[serde(default)]
    pub verification_method_id: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RequestValidationError {
    #[error("session_duration_seconds must be between 30 and 3600")]
    SessionDuration,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ClaimResult {
    pub claim_name: String,
    pub required: bool,
    pub present: bool,
    pub satisfies_predicate: bool,
    pub result: String,
}

/// Compatibility projection derived only from a canonical Core result.
///
/// The legacy convenience fields cannot assert success independently of the
/// canonical result. Missing or inconsistent evidence therefore fails closed.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct VerificationResult {
    pub canonical_result: Option<Value>,
    pub processing_status: String,
    pub decision: String,
    pub decision_code: String,
    pub valid: bool,
    pub overall_result: String,
    pub claim_results: Vec<ClaimResult>,
    pub trust_chain_valid: bool,
    pub revocation_checked: bool,
    pub revocation_status: Option<String>,
    pub evaluated_at: Option<String>,
    pub verifier_nonce: Option<String>,
    pub flow_instance_id: Option<String>,
    pub policy_id: Option<String>,
    pub verified_claims: Option<Map<String, Value>>,
    pub verification_method: Option<String>,
    pub error: Option<String>,
    pub verified_at: Option<String>,
}

impl VerificationResult {
    #[must_use]
    pub fn from_canonical(
        canonical_result: Option<Value>,
        verification_method: Option<String>,
        error: Option<String>,
    ) -> Self {
        let Some(canonical) = canonical_result else {
            return Self::unavailable(verification_method, error);
        };
        let processing_status = string_field(&canonical, "processing_status", "UNAVAILABLE");
        let decision = string_field(&canonical, "decision", "INDETERMINATE");
        let decision_code = string_field(&canonical, "decision_code", "PROCESSING_NOT_COMPLETED");
        let valid = canonical.get("valid") == Some(&Value::Bool(true)) && decision == "PASS";
        let trust = check(&canonical, "issuer.trust");
        let status = check(&canonical, "credential.status");
        let trust_chain_valid = trust
            .and_then(|value| value.get("outcome"))
            .and_then(Value::as_str)
            == Some("PASSED");
        let revocation_checked = matches!(
            status
                .and_then(|value| value.get("outcome"))
                .and_then(Value::as_str),
            Some("PASSED" | "FAILED" | "ERROR")
        );
        let revocation_status = match status.and_then(|value| value.get("code")) {
            Some(Value::String(code)) if code == "CREDENTIAL_STATUS_VALID" => "VALID",
            Some(Value::String(code)) if code == "CREDENTIAL_STATUS_REVOKED" => "REVOKED",
            _ => "UNKNOWN",
        };
        let evaluated_at = optional_string(&canonical, "evaluated_at");
        let policy_id = canonical
            .get("policy")
            .and_then(Value::as_object)
            .and_then(|policy| policy.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self {
            canonical_result: Some(canonical),
            processing_status,
            overall_result: decision.clone(),
            decision,
            decision_code,
            valid,
            claim_results: Vec::new(),
            trust_chain_valid,
            revocation_checked,
            revocation_status: Some(revocation_status.into()),
            evaluated_at: evaluated_at.clone(),
            verifier_nonce: None,
            flow_instance_id: None,
            policy_id,
            verified_claims: None,
            verification_method,
            error: if valid {
                None
            } else {
                Some(error.unwrap_or_else(|| "Canonical verification did not pass".into()))
            },
            verified_at: valid.then_some(evaluated_at).flatten(),
        }
    }

    fn unavailable(verification_method: Option<String>, error: Option<String>) -> Self {
        Self {
            canonical_result: None,
            processing_status: "UNAVAILABLE".into(),
            decision: "INDETERMINATE".into(),
            decision_code: "PROCESSING_NOT_COMPLETED".into(),
            valid: false,
            overall_result: "INDETERMINATE".into(),
            claim_results: Vec::new(),
            trust_chain_valid: false,
            revocation_checked: false,
            revocation_status: None,
            evaluated_at: None,
            verifier_nonce: None,
            flow_instance_id: None,
            policy_id: None,
            verified_claims: None,
            verification_method,
            error: Some(error.unwrap_or_else(|| {
                "Legacy verification evidence has no canonical provenance".into()
            })),
            verified_at: None,
        }
    }
}

fn string_field(value: &Value, name: &str, default: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .into()
}

fn optional_string(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn check<'a>(canonical: &'a Value, check_id: &str) -> Option<&'a Map<String, Value>> {
    canonical
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks.iter().find_map(|check| {
                let check = check.as_object()?;
                (check.get("check_id").and_then(Value::as_str) == Some(check_id)).then_some(check)
            })
        })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_models_reject_unknown_fields_and_enforce_duration_bounds() {
        let request: CreateSessionRequest = serde_json::from_value(json!({
            "verifier_did": "did:web:verifier.example",
            "presentation_definition": {"id": "pd-1", "input_descriptors": []}
        }))
        .unwrap();
        assert_eq!(request.session_duration_seconds, 600);
        request.validate().unwrap();

        for duration in [29, 3_601] {
            let mut request = request.clone();
            request.session_duration_seconds = duration;
            assert_eq!(
                request.validate(),
                Err(RequestValidationError::SessionDuration)
            );
        }
        assert!(serde_json::from_value::<CreateSessionRequest>(json!({
            "verifier_did": "did:web:verifier.example",
            "presentation_definition": {"id": "pd-1", "input_descriptors": []},
            "unexpected": true
        }))
        .is_err());
    }

    #[test]
    fn direct_presentation_accepts_only_an_object_or_string() {
        let base = json!({
            "presentation_definition": {"id": "pd-1", "input_descriptors": []},
            "verifier_did": "did:web:verifier.example"
        });
        for presentation in [json!({"vp": "value"}), json!("jwt.value")] {
            let mut request = base.clone();
            request["presentation"] = presentation;
            serde_json::from_value::<VerifyDirectRequest>(request).unwrap();
        }
        let mut invalid = base;
        invalid["presentation"] = json!(true);
        assert!(serde_json::from_value::<VerifyDirectRequest>(invalid).is_err());
    }

    #[test]
    fn absent_canonical_result_is_always_fail_closed() {
        let result = VerificationResult::from_canonical(
            None,
            Some("jwt".into()),
            Some("adapter claimed success without provenance".into()),
        );
        assert!(!result.valid);
        assert_eq!(result.processing_status, "UNAVAILABLE");
        assert_eq!(result.decision, "INDETERMINATE");
        assert_eq!(result.verified_at, None);
    }

    #[test]
    fn canonical_pass_projects_trust_status_and_timestamps() {
        let result = VerificationResult::from_canonical(
            Some(json!({
                "processing_status": "COMPLETED",
                "decision": "PASS",
                "decision_code": "ALL_REQUIRED_CHECKS_PASSED",
                "valid": true,
                "evaluated_at": "2026-08-30T12:00:00Z",
                "policy": {"id": "policy:employee"},
                "checks": [
                    {"check_id": "issuer.trust", "outcome": "PASSED"},
                    {"check_id": "credential.status", "outcome": "PASSED", "code": "CREDENTIAL_STATUS_VALID"}
                ]
            })),
            Some("vds_nc".into()),
            None,
        );
        assert!(result.valid);
        assert!(result.trust_chain_valid);
        assert!(result.revocation_checked);
        assert_eq!(result.revocation_status.as_deref(), Some("VALID"));
        assert_eq!(result.policy_id.as_deref(), Some("policy:employee"));
        assert_eq!(result.verified_at, result.evaluated_at);
        assert_eq!(result.error, None);
    }

    #[test]
    fn inconsistent_canonical_success_cannot_escape_fail_closed_projection() {
        let result = VerificationResult::from_canonical(
            Some(json!({
                "processing_status": "COMPLETED",
                "decision": "FAIL",
                "decision_code": "REQUIRED_CHECK_FAILED",
                "valid": true
            })),
            None,
            None,
        );
        assert!(!result.valid);
        assert_eq!(result.overall_result, "FAIL");
        assert_eq!(
            result.error.as_deref(),
            Some("Canonical verification did not pass")
        );
    }
}
