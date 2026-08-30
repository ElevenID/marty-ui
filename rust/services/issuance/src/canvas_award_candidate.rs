use std::{collections::BTreeMap, fmt, time::Duration};

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    canvas_issuance_guard::{binding_readiness_is_current, validated_requirements},
    canvas_lti_bootstrap::CanvasLtiBootstrapApplication,
    canvas_lti_experience::{
        lti_subject, python_string, python_truthy, signed_canvas_identifier,
        CanvasLtiExperienceSessionContext,
    },
    canvas_lti_launch::feature_enabled,
};

const REDACTED: &str = "[REDACTED]";

#[derive(Clone, PartialEq)]
pub struct CanvasAwardCandidate {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub binding_id: String,
    pub learner_identity_id: Option<String>,
    pub canvas_user_id: Option<String>,
    pub lti_subject: Option<String>,
    pub state: String,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasAwardCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasAwardCandidate")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("platform_id", &self.platform_id)
            .field("binding_id", &self.binding_id)
            .field("learner_identity_id", &REDACTED)
            .field("canvas_user_id", &REDACTED)
            .field("lti_subject", &REDACTED)
            .field("state", &self.state)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct CanvasCandidateObservation {
    pub id: String,
    pub requirement_id: String,
    pub assertion: Value,
    pub verification: Value,
    pub payload_hash: String,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasCandidateObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasCandidateObservation")
            .field("id", &self.id)
            .field("requirement_id", &self.requirement_id)
            .field("assertion", &REDACTED)
            .field("verification", &REDACTED)
            .field("payload_hash", &self.payload_hash)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasLinkedIdentity {
    pub id: String,
    pub lti_subject: String,
    pub canvas_user_id: Option<String>,
    pub status: String,
}

impl fmt::Debug for CanvasLinkedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasLinkedIdentity")
            .field("id", &self.id)
            .field("lti_subject", &REDACTED)
            .field("canvas_user_id", &REDACTED)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CanvasIdentityJoin<'a> {
    pub by_subject: Option<&'a CanvasLinkedIdentity>,
    pub by_canvas_user: Option<&'a CanvasLinkedIdentity>,
}

#[derive(Clone, PartialEq)]
pub struct CanvasAwardCandidateMaterializationPlan {
    pub candidate_id: String,
    pub lti_subject: Option<String>,
    pub canvas_user_id: Option<String>,
    pub learner_identity_id: Option<String>,
    pub facts: Vec<Value>,
    pub application_canvas_patch: Map<String, Value>,
    pub materialized_at: DateTime<Utc>,
}

impl fmt::Debug for CanvasAwardCandidateMaterializationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanvasAwardCandidateMaterializationPlan")
            .field("candidate_id", &self.candidate_id)
            .field("lti_subject", &REDACTED)
            .field("canvas_user_id", &REDACTED)
            .field("learner_identity_id", &REDACTED)
            .field("facts", &REDACTED)
            .field("application_canvas_patch", &REDACTED)
            .field("materialized_at", &self.materialized_at)
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn plan_canvas_award_candidate_materialization<F>(
    context: &CanvasLtiExperienceSessionContext,
    application: &CanvasLtiBootstrapApplication,
    binding: &Map<String, Value>,
    candidates: &[CanvasAwardCandidate],
    identities: CanvasIdentityJoin<'_>,
    observations: &[CanvasCandidateObservation],
    now: DateTime<Utc>,
    evidence_max_age: Duration,
    mut next_fact_id: F,
) -> Option<CanvasAwardCandidateMaterializationPlan>
where
    F: FnMut() -> String,
{
    let binding_id = context.canvas_program_binding_id.as_deref()?;
    let subject = lti_subject(&context.verified_launch);
    let canvas_user_id = signed_canvas_identifier(&context.verified_launch, "canvas_user_id");
    let linked_identity =
        exact_linked_identity(subject.as_deref(), canvas_user_id.as_deref(), identities);
    let candidate = candidates.iter().find(|candidate| {
        candidate.organization_id == application.organization_id
            && candidate.platform_id == context.canvas_platform_id
            && candidate.binding_id == binding_id
            && matches!(candidate.state.as_str(), "pending_claim" | "eligible")
            && candidate_matches_launch(
                candidate,
                subject.as_deref(),
                canvas_user_id.as_deref(),
                linked_identity,
            )
    })?;
    if !is_fresh(candidate.observed_at, now, evidence_max_age) {
        return None;
    }
    let requirements = validated_requirements(binding).ok()?;
    let observations_by_requirement = observations
        .iter()
        .map(|observation| (observation.requirement_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    if requirements.iter().any(|requirement| {
        requirement.get("required").and_then(Value::as_bool) != Some(false)
            && observations_by_requirement
                .get(requirement_id(requirement).as_str())
                .is_none_or(|observation| {
                    !observation_is_fresh_and_verified(observation, now, evidence_max_age)
                        || !observation_satisfies(requirement, observation)
                })
    }) {
        return None;
    }
    let current_observations = observations
        .iter()
        .filter(|observation| observation_is_fresh_and_verified(observation, now, evidence_max_age))
        .collect::<Vec<_>>();
    if current_observations.is_empty() {
        return None;
    }
    let subject_id = subject
        .as_deref()
        .or(candidate.lti_subject.as_deref())
        .or(candidate.canvas_user_id.as_deref())
        .unwrap_or_default();
    let requirements_by_id = requirements
        .iter()
        .map(|requirement| (requirement_id(requirement), requirement))
        .collect::<BTreeMap<_, _>>();
    let facts = current_observations
        .into_iter()
        .filter_map(|observation| {
            let requirement = requirements_by_id.get(&observation.requirement_id)?;
            Some(authoritative_fact(
                next_fact_id(),
                application,
                context,
                binding_id,
                subject_id,
                requirement,
                observation,
                now,
            ))
        })
        .collect();
    let mut application_canvas_patch = Map::new();
    application_canvas_patch.insert(
        "canvas_award_candidate_id".to_owned(),
        Value::String(candidate.id.clone()),
    );
    application_canvas_patch.insert(
        "candidate_materialized_at".to_owned(),
        Value::String(now.to_rfc3339_opts(SecondsFormat::AutoSi, false)),
    );
    let materialized_canvas_user_id = canvas_user_id.or_else(|| candidate.canvas_user_id.clone());
    let materialized_learner_identity_id = if materialized_canvas_user_id.is_some() {
        linked_identity
            .map(|identity| identity.id.clone())
            .or_else(|| candidate.learner_identity_id.clone())
    } else {
        candidate.learner_identity_id.clone()
    };
    Some(CanvasAwardCandidateMaterializationPlan {
        candidate_id: candidate.id.clone(),
        lti_subject: subject.or_else(|| candidate.lti_subject.clone()),
        canvas_user_id: materialized_canvas_user_id,
        learner_identity_id: materialized_learner_identity_id,
        facts,
        application_canvas_patch,
        materialized_at: now,
    })
}

pub fn canvas_auto_approval_ready(
    binding: &Map<String, Value>,
    now: DateTime<Utc>,
    readiness_max_age: Duration,
) -> bool {
    binding
        .get("auto_approve_on_evidence")
        .and_then(Value::as_bool)
        == Some(true)
        && binding.get("enabled").and_then(Value::as_bool) == Some(true)
        && feature_enabled(
            binding.get("feature_flags").unwrap_or(&Value::Null),
            "enable_canvas_evidence",
        )
        && binding_readiness_is_current(binding, readiness_max_age, now)
}

fn exact_linked_identity<'a>(
    subject: Option<&str>,
    canvas_user_id: Option<&str>,
    identities: CanvasIdentityJoin<'a>,
) -> Option<&'a CanvasLinkedIdentity> {
    let (subject, canvas_user_id, by_subject, by_canvas_user) = (
        subject?,
        canvas_user_id?,
        identities.by_subject?,
        identities.by_canvas_user?,
    );
    (by_subject.id == by_canvas_user.id
        && by_subject.status == "linked"
        && by_subject.lti_subject == subject
        && by_subject.canvas_user_id.as_deref() == Some(canvas_user_id))
    .then_some(by_subject)
}

fn candidate_matches_launch(
    candidate: &CanvasAwardCandidate,
    subject: Option<&str>,
    _canvas_user_id: Option<&str>,
    linked_identity: Option<&CanvasLinkedIdentity>,
) -> bool {
    if let Some(candidate_user_id) = candidate
        .canvas_user_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return linked_identity.is_some_and(|identity| {
            identity.canvas_user_id.as_deref().map(str::trim) == Some(candidate_user_id)
                && candidate
                    .lti_subject
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none_or(|candidate_subject| Some(candidate_subject) == subject)
                && candidate
                    .learner_identity_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none_or(|identity_id| identity_id == identity.id)
        });
    }
    subject.is_some_and(|subject| candidate.lti_subject.as_deref() == Some(subject))
}

fn observation_is_fresh_and_verified(
    observation: &CanvasCandidateObservation,
    now: DateTime<Utc>,
    max_age: Duration,
) -> bool {
    text(
        observation
            .verification
            .get("status")
            .unwrap_or(&Value::Null),
    )
    .eq_ignore_ascii_case("VERIFIED")
        && is_fresh(observation.observed_at, now, max_age)
}

fn is_fresh(observed_at: DateTime<Utc>, now: DateTime<Utc>, max_age: Duration) -> bool {
    if max_age.is_zero() {
        return false;
    }
    let age = now.signed_duration_since(observed_at).num_seconds();
    age >= 0 && u64::try_from(age).is_ok_and(|age| age <= max_age.as_secs())
}

fn observation_satisfies(requirement: &Value, observation: &CanvasCandidateObservation) -> bool {
    let pass_rule = requirement.get("pass_rule").and_then(Value::as_object);
    if let Some(minimum) = pass_rule
        .and_then(|rule| rule.get("min_score_percent"))
        .and_then(Value::as_f64)
    {
        return python_number(observation.assertion.get("score_percent"))
            .is_some_and(|score| score >= minimum);
    }
    pass_rule
        .and_then(|rule| rule.get("completed"))
        .and_then(Value::as_bool)
        == Some(true)
        && observation
            .assertion
            .get("completed")
            .and_then(Value::as_bool)
            == Some(true)
}

#[allow(clippy::too_many_arguments)]
fn authoritative_fact(
    id: String,
    application: &CanvasLtiBootstrapApplication,
    context: &CanvasLtiExperienceSessionContext,
    binding_id: &str,
    subject_id: &str,
    requirement: &Value,
    observation: &CanvasCandidateObservation,
    created_at: DateTime<Utc>,
) -> Value {
    let source = requirement.get("source").cloned().unwrap_or(Value::Null);
    let fact_type = requirement.get("fact_type").cloned().unwrap_or(Value::Null);
    let scope = requirement
        .get("scope")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let normalized = json!({
        "requirement_id": requirement_id(requirement),
        "source": source,
        "fact_type": fact_type,
        "scope": scope,
        "assertion": observation.assertion,
        "payload": {
            "candidate_observation_id": observation.id,
            "candidate_payload_hash": observation.payload_hash,
        },
    });
    let canonical = canonical_json(&normalized);
    let payload_hash = sha256_hex(canonical.as_bytes());
    let event_material = format!("canvas:{}:{canonical}", text(&source));
    let provider_event_id =
        Uuid::new_v5(&Uuid::NAMESPACE_URL, event_material.as_bytes()).to_string();
    let logical_material = format!(
        "{}:{binding_id}:{}:{}:{subject_id}",
        context.canvas_platform_id,
        application.id,
        requirement_id(requirement)
    );
    let verification_method = observation
        .verification
        .get("method")
        .filter(|value| python_truthy(value))
        .and_then(python_string)
        .unwrap_or_else(|| "CANVAS_BACKGROUND_AUTHORITATIVE_READ".to_owned());
    json!({
        "id": id,
        "organization_id": application.organization_id,
        "application_id": application.id,
        "subject_id": subject_id,
        "provider": "canvas",
        "fact_type": fact_type,
        "scope": scope,
        "assertion": observation.assertion,
        "verification": {"status": "VERIFIED", "method": verification_method},
        "source": {"source": source, "provider_event_id": provider_event_id},
        "requirement_id": requirement_id(requirement),
        "logical_key": sha256_hex(logical_material.as_bytes()),
        "source_revision": payload_hash,
        "payload_hash": payload_hash,
        "observed_at": observation.observed_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
        "effective_at": observation.observed_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
        "created_at": created_at.to_rfc3339_opts(SecondsFormat::AutoSi, false),
    })
}

fn requirement_id(requirement: &Value) -> String {
    requirement
        .get("requirement_id")
        .map(text)
        .unwrap_or_default()
}

fn python_number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Bool(_) | Value::Null | Value::Array(_) | Value::Object(_) => None,
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
    }
}

fn text(value: &Value) -> String {
    python_string(value).unwrap_or_default().trim().to_owned()
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => python_json_string(value),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(name, value)| format!(
                    "{}:{}",
                    python_json_string(name),
                    canonical_json(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn python_json_string(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{0008}' => encoded.push_str("\\b"),
            '\u{000c}' => encoded.push_str("\\f"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => encoded.push_str(&format!("\\u{:04x}", character as u32)),
            '\u{0020}'..='\u{007f}' => encoded.push(character),
            character if (character as u32) <= 0xffff => {
                encoded.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => {
                let codepoint = character as u32 - 0x1_0000;
                let high = 0xd800 + (codepoint >> 10);
                let low = 0xdc00 + (codepoint & 0x03ff);
                encoded.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        }
    }
    encoded.push('"');
    encoded
}
