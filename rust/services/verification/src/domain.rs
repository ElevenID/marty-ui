use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const SESSION_TTL_SECONDS: u64 = 60 * 60;
pub const SUBMISSION_LEASE_SECONDS: i64 = 30;
pub const SUBMISSION_CAS_RETRIES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Pending,
    Completed,
    Expired,
    Failed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VerificationSession {
    pub session_id: String,
    pub flow_id: String,
    pub flow_instance_id: String,
    pub organization_id: String,
    #[serde(default)]
    pub evaluation_principal_id: String,
    #[serde(default)]
    pub presentation_policy_id: Option<String>,
    #[serde(default = "default_response_type")]
    pub response_type: String,
    #[serde(default)]
    pub trust_profile_id: Option<String>,
    #[serde(default)]
    pub deployment_profile_id: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default)]
    pub purpose: String,
    pub nonce: String,
    #[serde(default)]
    pub holder_id: Option<String>,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub decision_reason: String,
    #[serde(default)]
    pub verified_claims: BTreeMap<String, Value>,
    #[serde(default)]
    pub credential_results: Vec<Value>,
    #[serde(default)]
    pub holder_binding_evidence: Option<Value>,
    #[serde(default)]
    pub inspection_performed: bool,
    #[serde(default)]
    pub inspection_result: String,
    #[serde(default)]
    pub inspection_result_sha256: Option<String>,
    #[serde(default)]
    pub vp_token_sha256: Option<String>,
    #[serde(default)]
    pub processing_token: Option<String>,
    #[serde(default)]
    pub processing_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub total_requirements: i32,
    #[serde(default)]
    pub satisfied_requirements: i32,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default, skip_serializing)]
    pub vp_token: Option<String>,
}

fn default_response_type() -> String {
    "vp_token".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartVerificationRequest {
    pub organization_id: String,
    #[serde(default)]
    pub presentation_policy_id: Option<String>,
    #[serde(default = "default_response_type")]
    pub response_type: String,
    #[serde(default)]
    pub trust_profile_id: Option<String>,
    #[serde(default)]
    pub deployment_profile_id: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
    #[serde(default = "default_expiry_minutes")]
    pub expiry_minutes: i32,
    #[serde(default)]
    pub purpose: String,
}

const fn default_expiry_minutes() -> i32 {
    15
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitVerificationRequest {
    pub vp_token: String,
    #[serde(default)]
    pub presentation_submission: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluateRequest {
    pub vp_token: String,
    pub presentation_policy_id: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub context: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZkpSubmitRequest {
    #[serde(default)]
    pub vp_token: Option<String>,
    #[serde(default)]
    pub proof: Option<String>,
    #[serde(default)]
    pub presentation_policy_id: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EvaluationResult {
    pub result: String,
    pub decision: String,
    pub decision_reason: String,
    pub verified_claims: BTreeMap<String, Value>,
    pub credential_results: Vec<Value>,
    pub holder_binding_evidence: Option<Value>,
    pub total_requirements: i32,
    pub satisfied_requirements: i32,
    pub evaluation_timestamp: String,
    pub nonce: String,
}

impl EvaluationResult {
    #[must_use]
    pub fn as_value(&self) -> Value {
        json!({
            "result": self.result,
            "decision": self.decision,
            "decision_reason": self.decision_reason,
            "verified_claims": self.verified_claims,
            "credential_results": self.credential_results,
            "total_requirements": self.total_requirements,
            "satisfied_requirements": self.satisfied_requirements,
            "evaluation_timestamp": self.evaluation_timestamp,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SubmissionOutcome {
    Claimed,
    Committed,
    Duplicate,
    Busy,
    Conflict,
    Expired,
    Missing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SubmissionTransition {
    pub outcome: SubmissionOutcome,
    pub session: Option<VerificationSession>,
    pub token: Option<String>,
}

impl SubmissionTransition {
    #[must_use]
    pub const fn new(outcome: SubmissionOutcome) -> Self {
        Self {
            outcome,
            session: None,
            token: None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VerificationError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Gone(String),
    #[error("{0}")]
    Dependency(String),
    #[error("{0}")]
    Coordination(String),
    #[error("{0}")]
    Internal(String),
}

impl VerificationSession {
    pub fn new(
        request: &StartVerificationRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, VerificationError> {
        let expires_at = now
            .checked_add_signed(Duration::minutes(i64::from(request.expiry_minutes)))
            .ok_or_else(|| VerificationError::BadRequest("invalid expiry_minutes".into()))?;
        let session_id = Uuid::new_v4().to_string();
        Ok(Self {
            session_id: session_id.clone(),
            flow_id: Uuid::new_v4().to_string(),
            flow_instance_id: session_id,
            organization_id: request.organization_id.clone(),
            evaluation_principal_id: String::new(),
            presentation_policy_id: request.presentation_policy_id.clone(),
            response_type: request.response_type.clone(),
            trust_profile_id: request.trust_profile_id.clone(),
            deployment_profile_id: request.deployment_profile_id.clone(),
            external_reference: request.external_reference.clone(),
            callback_url: None,
            purpose: request.purpose.clone(),
            nonce: random_token(16),
            holder_id: None,
            status: SessionStatus::Pending,
            created_at: now,
            updated_at: now,
            expires_at,
            result: None,
            decision: None,
            decision_reason: String::new(),
            verified_claims: BTreeMap::new(),
            credential_results: Vec::new(),
            holder_binding_evidence: None,
            inspection_performed: false,
            inspection_result: String::new(),
            inspection_result_sha256: None,
            vp_token_sha256: None,
            processing_token: None,
            processing_expires_at: None,
            total_requirements: 0,
            satisfied_requirements: 0,
            completed_at: None,
            error: None,
            vp_token: None,
        })
    }

    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }

    pub fn minimize_terminal(&mut self) {
        if self.status == SessionStatus::Pending {
            return;
        }
        self.callback_url = None;
        self.evaluation_principal_id.clear();
        self.processing_token = None;
        self.processing_expires_at = None;
        if self.vp_token_sha256.is_none() {
            self.vp_token_sha256 = self.vp_token.as_deref().map(sha256_text);
        }
        self.vp_token = None;
        self.verified_claims = minimize_verified_claims(&self.verified_claims);
        self.credential_results = minimize_credential_results(&self.credential_results);
        if !(self.inspection_result.is_empty()
            || self.inspection_result_sha256.is_some()
                && safe_inspection_results().contains(self.inspection_result.as_str()))
        {
            let (result, digest) = minimize_inspection_result(&self.inspection_result);
            self.inspection_result = result;
            self.inspection_result_sha256 = digest;
        }
    }

    #[must_use]
    pub fn protocol_value(&self) -> Value {
        let mut fields = Map::from_iter([
            ("id".into(), json!(self.session_id)),
            ("flow_id".into(), json!(self.flow_id)),
            ("flow_instance_id".into(), json!(self.flow_instance_id)),
            ("verifier_nonce".into(), json!(self.nonce)),
            ("status".into(), json!(self.protocol_status())),
            ("expires_at".into(), json!(self.expires_at.to_rfc3339())),
            ("created_at".into(), json!(self.created_at.to_rfc3339())),
            ("updated_at".into(), json!(self.updated_at.to_rfc3339())),
        ]);
        insert_optional(
            &mut fields,
            "presentation_policy_id",
            self.presentation_policy_id
                .as_ref()
                .map(|value| json!(value)),
        );
        insert_optional(
            &mut fields,
            "deployment_profile_id",
            self.deployment_profile_id
                .as_ref()
                .map(|value| json!(value)),
        );
        insert_optional(
            &mut fields,
            "holder_id",
            self.holder_id.as_ref().map(|value| json!(value)),
        );
        insert_optional(&mut fields, "result", self.protocol_result());
        insert_optional(
            &mut fields,
            "completed_at",
            self.completed_at.map(|value| json!(value.to_rfc3339())),
        );
        insert_optional(
            &mut fields,
            "error",
            self.error.as_ref().map(|value| json!(value)),
        );
        Value::Object(fields)
    }

    #[must_use]
    pub const fn protocol_status(&self) -> &'static str {
        match self.status {
            SessionStatus::Pending => "PENDING",
            SessionStatus::Completed => "PASSED",
            SessionStatus::Expired => "EXPIRED",
            SessionStatus::Failed => "FAILED",
        }
    }

    fn protocol_result(&self) -> Option<Value> {
        if self.completed_at.is_none() && self.result.is_none() {
            return None;
        }
        let passed =
            self.result.as_deref() == Some("passed") && self.status != SessionStatus::Failed;
        let mut result = Map::from_iter([("passed".into(), json!(passed))]);
        let claims = self.verified_claims.keys().cloned().collect::<Vec<_>>();
        if !claims.is_empty() {
            result.insert("claims_satisfied".into(), json!(claims));
        }
        let missing = collect_claims_missing(&self.credential_results);
        if !missing.is_empty() {
            result.insert("claims_missing".into(), json!(missing));
        }
        if let Some(decision) = &self.decision {
            result.insert("trust_validated".into(), json!(decision == "allow"));
        }
        if let Some(checked) = derive_revocation_checked(&self.credential_results) {
            result.insert("revocation_checked".into(), json!(checked));
        }
        if let Some(evidence) = &self.holder_binding_evidence {
            result.insert("holder_binding_evidence".into(), evidence.clone());
        }
        let reason = if self.decision_reason.is_empty() {
            self.error.as_deref().unwrap_or_default()
        } else {
            &self.decision_reason
        };
        if !passed && !reason.is_empty() {
            result.insert("failure_reason".into(), json!(reason));
        }
        Some(Value::Object(result))
    }
}

fn insert_optional(fields: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        fields.insert(key.into(), value);
    }
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

#[must_use]
pub fn sha256_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn minimize_verified_claims(claims: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    claims
        .keys()
        .filter(|name| !name.is_empty())
        .map(|name| (name.clone(), Value::Bool(true)))
        .collect()
}

fn minimize_credential_results(results: &[Value]) -> Vec<Value> {
    const SCALARS: &[&str] = &[
        "credential_template_id",
        "credential_type",
        "credential_format",
        "satisfied",
        "issuer_did",
        "signature_valid",
        "trust_validated",
        "revocation_checked",
        "revocation_validated",
        "revocation_status_checked",
        "holder_binding_validated",
    ];
    const LISTS: &[&str] = &["claims_missing", "claims_satisfied"];
    results
        .iter()
        .filter_map(Value::as_object)
        .map(|source| {
            let mut projected = Map::new();
            for key in SCALARS {
                if source.get(*key).is_some_and(|value| {
                    value.is_string() || value.is_boolean() || value.is_number()
                }) {
                    projected.insert((*key).into(), source[*key].clone());
                }
            }
            for key in LISTS {
                if let Some(values) = source.get(*key).and_then(Value::as_array) {
                    projected.insert(
                        (*key).into(),
                        Value::Array(
                            values
                                .iter()
                                .filter_map(nonempty_string)
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                }
            }
            if let Some(claims) = source.get("claim_results").and_then(Value::as_array) {
                let claims = claims
                    .iter()
                    .filter_map(minimize_claim_result)
                    .collect::<Vec<_>>();
                if !claims.is_empty() {
                    projected.insert("claim_results".into(), Value::Array(claims));
                }
            }
            Value::Object(projected)
        })
        .collect()
}

fn minimize_claim_result(value: &Value) -> Option<Value> {
    let source = value.as_object()?;
    let mut result = Map::new();
    for key in ["claim_name", "satisfied"] {
        if source
            .get(key)
            .is_some_and(|value| value.is_string() || value.is_boolean())
        {
            result.insert(key.into(), source[key].clone());
        }
    }
    if let Some(constraints) = source.get("constraint_results").and_then(Value::as_array) {
        let minimized = constraints
            .iter()
            .filter_map(|constraint| {
                let source = constraint.as_object()?;
                let projected = ["constraint_type", "passed", "satisfied"]
                    .into_iter()
                    .filter_map(|key| {
                        source
                            .get(key)
                            .filter(|value| value.is_string() || value.is_boolean())
                            .map(|value| (key.into(), value.clone()))
                    })
                    .collect::<Map<_, _>>();
                (!projected.is_empty()).then_some(Value::Object(projected))
            })
            .collect::<Vec<_>>();
        if !minimized.is_empty() {
            result.insert("constraint_results".into(), Value::Array(minimized));
        }
    }
    (!result.is_empty()).then_some(Value::Object(result))
}

fn nonempty_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Null => None,
        value => {
            let value = value.to_string();
            (!value.is_empty()).then_some(value)
        }
    }
}

fn safe_inspection_results() -> BTreeSet<&'static str> {
    [
        "error",
        "failed",
        "invalid",
        "ok",
        "passed",
        "recorded",
        "unavailable",
        "unsupported",
        "unverified",
        "valid",
        "verified",
    ]
    .into_iter()
    .collect()
}

fn minimize_inspection_result(raw: &str) -> (String, Option<String>) {
    if raw.is_empty() {
        return (String::new(), None);
    }
    let digest = sha256_text(raw);
    let mut normalized = raw.trim().to_ascii_lowercase();
    if let Ok(Value::Object(object)) = serde_json::from_str::<Value>(raw) {
        for key in ["result", "status", "decision"] {
            if let Some(candidate) = object
                .get(key)
                .and_then(Value::as_str)
                .map(|value| value.trim().to_ascii_lowercase())
            {
                if safe_inspection_results().contains(candidate.as_str()) {
                    normalized = candidate;
                    break;
                }
            }
        }
    }
    let safe = if safe_inspection_results().contains(normalized.as_str()) {
        normalized
    } else {
        "recorded".into()
    };
    (safe, Some(digest))
}

fn collect_claims_missing(results: &[Value]) -> Vec<String> {
    results
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|result| {
            ["claims_missing", "missing_claims", "unsatisfied_claims"]
                .into_iter()
                .flat_map(|key| {
                    result
                        .get(key)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                })
                .filter_map(nonempty_string)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn derive_revocation_checked(results: &[Value]) -> Option<bool> {
    for result in results.iter().filter_map(Value::as_object) {
        for key in [
            "revocation_checked",
            "revocation_validated",
            "revocation_status_checked",
        ] {
            if let Some(value) = result.get(key) {
                return Some(value.as_bool().unwrap_or(!value.is_null()));
            }
        }
    }
    None
}

#[must_use]
pub fn normalize_holder_binding(evaluation: &Value) -> Option<Value> {
    let object = evaluation.as_object()?;
    let raw = object
        .get("holder_binding_evidence")
        .and_then(Value::as_object)
        .cloned()
        .or_else(|| {
            object.get("holder_binding_validated").map(|validated| {
                Map::from_iter([
                    (
                        "required".into(),
                        object
                            .get("holder_binding_required")
                            .cloned()
                            .unwrap_or(Value::Bool(true)),
                    ),
                    ("validated".into(), validated.clone()),
                ])
            })
        })?;
    let mut evidence = Map::from_iter([
        (
            "required".into(),
            Value::Bool(
                raw.get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        (
            "validated".into(),
            Value::Bool(
                raw.get("validated")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
    ]);
    for key in [
        "binding_method",
        "proof_profile",
        "challenge_validated",
        "audience_validated",
        "replay_checked",
        "proof_age_seconds",
        "failure_reason",
    ] {
        if let Some(value) = raw.get(key).filter(|value| !value.is_null()) {
            evidence.insert(key.into(), value.clone());
        }
    }
    Some(Value::Object(evidence))
}
