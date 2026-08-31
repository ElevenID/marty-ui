use marty_verification::verification::VerificationDecisionResult as CoreVerificationResult;
use serde::de::Error as DeserializeError;
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
    pub session_duration_seconds: SessionDurationSeconds,
}

const fn default_session_duration_seconds() -> SessionDurationSeconds {
    SessionDurationSeconds(DEFAULT_SESSION_DURATION_SECONDS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SessionDurationSeconds(u64);

impl SessionDurationSeconds {
    pub fn new(value: u64) -> Result<Self, RequestValidationError> {
        if (MIN_SESSION_DURATION_SECONDS..=MAX_SESSION_DURATION_SECONDS).contains(&value) {
            Ok(Self(value))
        } else {
            Err(RequestValidationError::SessionDuration)
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SessionDurationSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let integer = match value {
            Value::Number(number) => number.as_u64().or_else(|| {
                let float = number.as_f64()?;
                (float.is_finite() && float.fract() == 0.0 && float >= 0.0).then_some(float as u64)
            }),
            Value::String(value) => value.trim().parse().ok(),
            _ => None,
        }
        .ok_or_else(|| D::Error::custom("session_duration_seconds must be an integer"))?;
        Self::new(integer).map_err(D::Error::custom)
    }
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
    canonical_result: Option<Value>,
    processing_status: String,
    decision: String,
    decision_code: String,
    valid: bool,
    overall_result: String,
    claim_results: Vec<ClaimResult>,
    trust_chain_valid: bool,
    revocation_checked: bool,
    revocation_status: Option<String>,
    evaluated_at: Option<String>,
    verifier_nonce: Option<String>,
    flow_instance_id: Option<String>,
    policy_id: Option<String>,
    verified_claims: Option<Map<String, Value>>,
    verification_method: Option<String>,
    error: Option<String>,
    verified_at: Option<String>,
}

impl VerificationResult {
    #[must_use]
    pub fn from_canonical(
        canonical_result: Option<&CoreVerificationResult>,
        verification_method: Option<String>,
        error: Option<String>,
    ) -> Self {
        let Some(canonical_result) = canonical_result else {
            return Self::unavailable(verification_method, error);
        };
        let canonical = serde_json::to_value(canonical_result)
            .expect("Core VerificationDecisionResult serialization is infallible");
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

    #[must_use]
    pub fn canonical_result(&self) -> Option<&Value> {
        self.canonical_result.as_ref()
    }

    #[must_use]
    pub fn processing_status(&self) -> &str {
        &self.processing_status
    }

    #[must_use]
    pub fn decision(&self) -> &str {
        &self.decision
    }

    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.valid
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[must_use]
    pub fn verified_at(&self) -> Option<&str> {
        self.verified_at.as_deref()
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
    use marty_verification::verification::{
        build_verification_decision_result, VerificationCheckCategory, VerificationCheckOutcome,
        VerificationCheckResult, VerificationComponentVersion, VerificationContextMode,
        VerificationDecisionContext, VerificationDecisionResultInput, VerificationProcessingStatus,
        VerificationProfileReference,
    };
    use serde_json::json;

    use super::*;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn canonical_input(status: VerificationProcessingStatus) -> VerificationDecisionResultInput {
        VerificationDecisionResultInput {
            verification_id: "verification:compat-001".into(),
            context: VerificationDecisionContext {
                mode: VerificationContextMode::Online,
                verifier_id: "did:web:verifier.example".into(),
                organization_id: Some("123e4567-e89b-42d3-a456-426614174000".into()),
                transaction_id: Some("transaction:compat-001".into()),
                audience: Some("did:web:verifier.example".into()),
                offline_profile_id: None,
            },
            processing_status: status,
            evaluated_at: "2026-08-30T12:00:00Z".into(),
            input_digest: DIGEST.into(),
            evidence_digest: DIGEST.into(),
            policy: VerificationProfileReference {
                id: "policy:employee".into(),
                version: "1.0.0".into(),
                content_digest: DIGEST.into(),
            },
            trust_profile: VerificationProfileReference {
                id: "trust:employee".into(),
                version: "1.0.0".into(),
                content_digest: DIGEST.into(),
            },
            components: vec![VerificationComponentVersion {
                component_id: "marty-core".into(),
                version: "0.1.61".into(),
                artifact_digest: DIGEST.into(),
                adapter_id: Some("verification-service".into()),
                adapter_version: Some("1.0.0".into()),
            }],
            checks: vec![
                VerificationCheckResult {
                    check_id: "issuer.trust".into(),
                    category: VerificationCheckCategory::IssuerTrust,
                    required: true,
                    outcome: VerificationCheckOutcome::Passed,
                    code: "ISSUER_TRUSTED".into(),
                    component_id: "marty-core".into(),
                    evaluated_at: "2026-08-30T12:00:00Z".into(),
                    evidence_refs: vec![
                        "urn:marty:evidence:123e4567-e89b-42d3-a456-426614174001".into()
                    ],
                },
                VerificationCheckResult {
                    check_id: "credential.status".into(),
                    category: VerificationCheckCategory::Status,
                    required: true,
                    outcome: VerificationCheckOutcome::Passed,
                    code: "CREDENTIAL_STATUS_VALID".into(),
                    component_id: "marty-core".into(),
                    evaluated_at: "2026-08-30T12:00:00Z".into(),
                    evidence_refs: vec![
                        "urn:marty:evidence:123e4567-e89b-42d3-a456-426614174002".into()
                    ],
                },
            ],
        }
    }

    #[test]
    fn request_models_reject_unknown_fields_and_enforce_duration_bounds() {
        let request: CreateSessionRequest = serde_json::from_value(json!({
            "verifier_did": "did:web:verifier.example",
            "presentation_definition": {"id": "pd-1", "input_descriptors": []}
        }))
        .unwrap();
        assert_eq!(request.session_duration_seconds.get(), 600);

        for duration in [json!(29), json!(3_601)] {
            assert!(serde_json::from_value::<CreateSessionRequest>(json!({
                "verifier_did": "did:web:verifier.example",
                "presentation_definition": {"id": "pd-1", "input_descriptors": []},
                "session_duration_seconds": duration
            }))
            .is_err());
        }
        assert!(serde_json::from_value::<CreateSessionRequest>(json!({
            "verifier_did": "did:web:verifier.example",
            "presentation_definition": {"id": "pd-1", "input_descriptors": []},
            "unexpected": true
        }))
        .is_err());
    }

    #[test]
    fn duration_ingress_matches_released_pydantic_coercion() {
        let cases = [
            (json!("600"), Some(600)),
            (json!(600.0), Some(600)),
            (json!(600.5), None),
            (json!(true), None),
            (json!(30), Some(30)),
            (json!(3_600), Some(3_600)),
            (json!(29), None),
            (json!(3_601), None),
        ];
        for (duration, expected) in cases {
            let parsed = serde_json::from_value::<CreateSessionRequest>(json!({
                "verifier_did": "did:web:verifier.example",
                "presentation_definition": {"id": "pd-1", "input_descriptors": []},
                "session_duration_seconds": duration
            }));
            assert_eq!(
                parsed
                    .ok()
                    .map(|request| request.session_duration_seconds.get()),
                expected
            );
        }
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
        assert!(!result.is_valid());
        assert_eq!(result.processing_status(), "UNAVAILABLE");
        assert_eq!(result.decision(), "INDETERMINATE");
        assert_eq!(result.verified_at(), None);
    }

    #[test]
    fn canonical_pass_projects_trust_status_and_timestamps() {
        let canonical = build_verification_decision_result(canonical_input(
            VerificationProcessingStatus::Completed,
        ))
        .unwrap();
        let result =
            VerificationResult::from_canonical(Some(&canonical), Some("vds_nc".into()), None);
        assert!(result.is_valid());
        assert!(result.trust_chain_valid);
        assert!(result.revocation_checked);
        assert_eq!(result.revocation_status.as_deref(), Some("VALID"));
        assert_eq!(result.policy_id.as_deref(), Some("policy:employee"));
        assert_eq!(result.verified_at, result.evaluated_at);
        assert_eq!(result.error(), None);
    }

    #[test]
    fn incomplete_or_tampered_inputs_never_reach_the_projection() {
        assert!(
            serde_json::from_value::<VerificationDecisionResultInput>(json!({
                "decision": "PASS",
                "valid": true
            }))
            .is_err()
        );
        let mut tampered = canonical_input(VerificationProcessingStatus::Completed);
        tampered.evidence_digest = "tampered".into();
        assert!(build_verification_decision_result(tampered).is_err());
        let mut incomplete = canonical_input(VerificationProcessingStatus::Completed);
        incomplete.components.clear();
        assert!(build_verification_decision_result(incomplete).is_err());
    }

    #[test]
    fn core_reducer_prevents_contradictory_processing_success() {
        let canonical = build_verification_decision_result(canonical_input(
            VerificationProcessingStatus::Unavailable,
        ))
        .unwrap();
        let result = VerificationResult::from_canonical(Some(&canonical), None, None);
        assert!(!result.is_valid());
        assert_eq!(result.processing_status(), "UNAVAILABLE");
        assert_eq!(result.decision(), "INDETERMINATE");
        assert_eq!(result.error(), Some("Canonical verification did not pass"));
    }
}
