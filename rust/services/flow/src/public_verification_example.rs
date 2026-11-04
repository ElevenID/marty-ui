//! Governed synthetic specimens and bounded, recoverable example execution.
use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::wallet::{ParsedPresentationRequest, WalletEngine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    DemoCredentialProfile, FlowInstanceRecord, PublicVerificationCatalogError,
    PublicVerificationSessionError, VerificationSubmissionInput,
};

/// Operator-owned signed synthetic input. Deliberately has no Debug impl.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationExampleConfig {
    pub id: String,
    pub scenario_id: String,
    pub label: String,
    pub description: String,
    pub profile: DemoCredentialProfile,
    pub credential: String,
}

#[derive(Debug, Serialize)]
pub struct PublicVerificationExampleView<'a> {
    pub id: &'a str,
    pub scenario_id: &'a str,
    pub label: &'a str,
    pub description: &'a str,
}

impl PublicVerificationExampleConfig {
    pub(crate) fn public_view(&self) -> PublicVerificationExampleView<'_> {
        PublicVerificationExampleView {
            id: &self.id,
            scenario_id: &self.scenario_id,
            label: &self.label,
            description: &self.description,
        }
    }
}

pub(crate) fn validate_examples(
    examples: &[PublicVerificationExampleConfig],
    scenarios: &BTreeSet<&String>,
) -> Result<(), PublicVerificationCatalogError> {
    use crate::public_verification_catalog::{bounded_text, slug};
    let mut ids = BTreeSet::new();
    if examples.len() > 16 {
        return Err(PublicVerificationCatalogError::InvalidConfiguration);
    }
    for example in examples {
        if !slug(&example.id)
            || !ids.insert(&example.id)
            || !scenarios.contains(&example.scenario_id)
            || !bounded_text(&example.label, 120)
            || !bounded_text(&example.description, 400)
            || !bounded_text(&example.profile.credential_template_id, 128)
            || !bounded_text(&example.profile.issuer_did, 512)
            || !example.profile.issuer_did.starts_with("did:")
            || !bounded_text(&example.profile.vct, 512)
            || example.credential.len() > 16_384
            || !example.credential.ends_with('~')
            || example
                .credential
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            || example
                .credential
                .split('~')
                .next()
                .is_none_or(|jwt| jwt.split('.').count() != 3)
        {
            return Err(PublicVerificationCatalogError::InvalidConfiguration);
        }
    }
    Ok(())
}

pub(crate) const EXAMPLE_OPERATION: &str = "_marty_public_verification_example";
const LEASE_SECONDS: i64 = 90;
// Bounds KMS work per admitted session even if dependencies repeatedly fail.
const MAX_ATTEMPTS: u8 = 3;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExampleOperation {
    owner: Uuid,
    lease_expires_at: DateTime<Utc>,
    attempts: u8,
    input_rejected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicVerificationExampleStatus {
    Running,
    InputRejected,
    RetryAvailable,
    RetryExhausted,
}

fn operation(
    instance: &FlowInstanceRecord,
) -> Result<Option<ExampleOperation>, PublicVerificationSessionError> {
    instance
        .context
        .get(EXAMPLE_OPERATION)
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|_| PublicVerificationSessionError::InvalidState)
        })
        .transpose()
}

pub(crate) fn example_status(
    instance: &FlowInstanceRecord,
) -> Result<Option<PublicVerificationExampleStatus>, PublicVerificationSessionError> {
    if instance.status.is_terminal() {
        return Ok(None);
    }
    Ok(operation(instance)?.map(|op| {
        if op.input_rejected {
            PublicVerificationExampleStatus::InputRejected
        } else if op.attempts >= MAX_ATTEMPTS && op.lease_expires_at <= Utc::now() {
            PublicVerificationExampleStatus::RetryExhausted
        } else if op.lease_expires_at <= Utc::now() {
            PublicVerificationExampleStatus::RetryAvailable
        } else {
            PublicVerificationExampleStatus::Running
        }
    }))
}

/// Prepare a snapshot-bound CAS lease. No transaction/connection is held while
/// calling KMS or the policy owner. The original instance expiry never moves.
pub(crate) fn claim_example(
    instance: &FlowInstanceRecord,
    now: DateTime<Utc>,
) -> Result<Option<(FlowInstanceRecord, Uuid)>, PublicVerificationSessionError> {
    if instance.status.is_terminal() || instance.expires_at.is_none_or(|expiry| now >= expiry) {
        return Ok(None);
    }
    let old = operation(instance)?;
    if old.as_ref().is_some_and(|op| {
        op.input_rejected || op.lease_expires_at > now || op.attempts >= MAX_ATTEMPTS
    }) {
        return Ok(None);
    }
    let owner = Uuid::new_v4();
    let op = ExampleOperation {
        owner,
        lease_expires_at: now + Duration::seconds(LEASE_SECONDS),
        attempts: old.map_or(1, |op| op.attempts + 1),
        input_rejected: false,
    };
    let mut claimed = instance.clone();
    claimed.context[EXAMPLE_OPERATION] =
        serde_json::to_value(op).map_err(|_| PublicVerificationSessionError::InvalidState)?;
    claimed.updated_at = now.max(instance.updated_at + Duration::microseconds(1));
    Ok(Some((claimed, owner)))
}

pub(crate) fn require_example_owner(
    instance: &FlowInstanceRecord,
    owner: Uuid,
    now: DateTime<Utc>,
) -> Result<(), PublicVerificationSessionError> {
    if instance.status.is_terminal()
        || instance.expires_at.is_none_or(|expiry| expiry <= now)
        || !operation(instance)?
            .is_some_and(|op| op.owner == owner && !op.input_rejected && op.lease_expires_at > now)
    {
        return Err(PublicVerificationSessionError::SelectionConflict);
    }
    Ok(())
}

pub(crate) fn finish_example_attempt(
    instance: &FlowInstanceRecord,
    owner: Uuid,
    rejected: bool,
    now: DateTime<Utc>,
) -> Result<FlowInstanceRecord, PublicVerificationSessionError> {
    require_example_owner(instance, owner, now)?;
    let mut op = operation(instance)?.ok_or(PublicVerificationSessionError::InvalidState)?;
    op.input_rejected = rejected;
    op.lease_expires_at = now;
    let mut next = instance.clone();
    next.context[EXAMPLE_OPERATION] =
        serde_json::to_value(op).map_err(|_| PublicVerificationSessionError::InvalidState)?;
    next.updated_at = now.max(instance.updated_at + Duration::microseconds(1));
    Ok(next)
}

/// Use Core to preserve the emitted standard DCQL wire shape. No caller may
/// supply a request, audience, challenge, descriptor or raw presentation.
pub(crate) fn example_submission(
    instance: &FlowInstanceRecord,
    compact: String,
) -> Result<VerificationSubmissionInput, PublicVerificationSessionError> {
    let invalid = || PublicVerificationSessionError::InvalidState;
    let payload = &instance.context["mip_messages"]["presentation_request"]["payload"];
    if payload["client_id"] != instance.context["oid4vp_client_id"]
        || payload["nonce"] != instance.context["nonce"]
        || payload["presentation_definition"].is_object()
    {
        return Err(invalid());
    }
    let request: ParsedPresentationRequest = serde_json::from_value(json!({
        "client_id":payload["client_id"],"nonce":payload["nonce"],"response_uri":payload["response_uri"],
        "query_type":"dcql_query","dcql_query":payload["dcql_query"]
    })).map_err(|_| invalid())?;
    let queries = &request.dcql_query.as_ref().ok_or_else(invalid)?.credentials;
    let [query] = queries.as_slice() else {
        return Err(invalid());
    };
    if query.id.is_empty() || !matches!(query.format.as_str(), "dc+sd-jwt" | "vc+sd-jwt") {
        return Err(invalid());
    }
    let (vp_token, submission) = WalletEngine::new()
        .build_presentation_for_request(&request, HashMap::from([(query.id.clone(), compact)]))
        .map_err(|_| invalid())?;
    let presentation_submission = submission
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| invalid())?;
    Ok(VerificationSubmissionInput {
        vp_token,
        presentation_submission,
        state: Some(
            instance.context["oid4vp_expected_state"]
                .as_str()
                .unwrap_or(&instance.id)
                .into(),
        ),
        audience_override: None,
    })
}
