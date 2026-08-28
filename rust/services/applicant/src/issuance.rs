use crate::{Applicant, ApplicantError, Application, ClaimState, LifecycleStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

const ACTIVE_ATTEMPT: &str = "active_issuance_attempt";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuanceOffer {
    pub id: Option<String>,
    pub credential_offer_uri: Option<String>,
    #[serde(default)]
    pub credential_offer_uris: Map<String, Value>,
    #[serde(default)]
    pub credential_offer_labels: Map<String, Value>,
    pub expires_at: Option<String>,
    #[serde(default = "pending")]
    pub status: String,
    pub flow_instance_id: Option<String>,
    pub flow_definition_id: Option<String>,
    pub source: Option<String>,
}

impl IssuanceOffer {
    pub fn has_offer(&self) -> bool {
        self.credential_offer_uri
            .as_ref()
            .is_some_and(|value| !value.is_empty())
            || !self.credential_offer_uris.is_empty()
    }
}

fn pending() -> String {
    "pending".into()
}

pub fn reserve_attempt(
    application: &mut Application,
    claims: Map<String, Value>,
    now: DateTime<Utc>,
) -> Result<(Uuid, Map<String, Value>), IssuanceError> {
    if let Some(active) = application.system_data.get(ACTIVE_ATTEMPT) {
        let active = active
            .as_object()
            .ok_or(IssuanceError::InvalidAttemptState)?;
        let id = active
            .get("id")
            .and_then(Value::as_str)
            .ok_or(IssuanceError::InvalidAttemptState)?;
        let canonical = Uuid::parse_str(id).map_err(|_| IssuanceError::InvalidAttemptState)?;
        if canonical.to_string() != id {
            return Err(IssuanceError::InvalidAttemptState);
        }
        let claims = active
            .get("claims")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(IssuanceError::InvalidAttemptState)?;
        return Ok((canonical, claims));
    }
    let id = Uuid::new_v4();
    application.system_data.insert(
        ACTIVE_ATTEMPT.into(),
        json!({
            "id": id.to_string(), "claims": claims, "created_at": now.to_rfc3339()
        }),
    );
    application.updated_at = now;
    Ok((id, claims))
}

pub fn complete_attempt(application: &mut Application, id: Uuid) -> Result<(), IssuanceError> {
    let active_id = application
        .system_data
        .get(ACTIVE_ATTEMPT)
        .and_then(Value::as_object)
        .and_then(|active| active.get("id"))
        .and_then(Value::as_str);
    if active_id != Some(id.to_string().as_str()) {
        return Err(IssuanceError::AttemptChanged);
    }
    application.system_data.remove(ACTIVE_ATTEMPT);
    application.system_data.insert(
        "last_issuance_attempt_id".into(),
        Value::String(id.to_string()),
    );
    Ok(())
}

pub fn apply_offer(
    application: &mut Application,
    applicant: &mut Applicant,
    attempt_id: Uuid,
    offer: &IssuanceOffer,
    now: DateTime<Utc>,
) -> Result<(), IssuanceError> {
    if !offer.has_offer() {
        return Err(IssuanceError::MissingOffer);
    }
    if application.status == LifecycleStatus::Approved {
        application.status = application.status.transition(LifecycleStatus::Offered)?;
    } else if application.status != LifecycleStatus::Offered {
        return Err(IssuanceError::InvalidApplicationStatus(application.status));
    }
    complete_attempt(application, attempt_id)?;
    insert_optional(
        &mut application.system_data,
        "issuance_transaction_id",
        &offer.id,
    );
    insert_optional(
        &mut application.system_data,
        "credential_offer_uri",
        &offer.credential_offer_uri,
    );
    insert_optional(
        &mut application.system_data,
        "offer_expires_at",
        &offer.expires_at,
    );
    application.system_data.insert(
        "credential_offer_uris".into(),
        Value::Object(offer.credential_offer_uris.clone()),
    );
    application.system_data.insert(
        "credential_offer_labels".into(),
        Value::Object(offer.credential_offer_labels.clone()),
    );
    application
        .system_data
        .insert("offer_generated_at".into(), Value::String(now.to_rfc3339()));
    application.system_data.insert(
        "issuance_status".into(),
        Value::String(offer.status.clone()),
    );
    insert_optional(
        &mut application.system_data,
        "flow_instance_id",
        &offer.flow_instance_id,
    );
    insert_optional(
        &mut application.system_data,
        "flow_definition_id",
        &offer.flow_definition_id,
    );
    insert_optional(
        &mut application.system_data,
        "issuance_source",
        &offer.source,
    );
    application.claim_state = ClaimState::OfferReady;
    application.claim_blocker = None;
    application.issued_at = None;
    application.updated_at = now;
    advance_to_offered(applicant, now)?;
    Ok(())
}

pub fn mark_no_active_flow(application: &mut Application, now: DateTime<Utc>) {
    application.claim_state = ClaimState::Blocked;
    application.claim_blocker = Some(json!({
        "code":"NO_ACTIVE_ISSUANCE_FLOW", "owner":"ISSUER",
        "message":"The issuer is still preparing this credential."
    }));
    application.updated_at = now;
}

pub fn reconcile_transaction(
    application: &mut Application,
    applicant: &mut Applicant,
    status: &str,
    issued_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<bool, IssuanceError> {
    if matches!(
        application.status,
        LifecycleStatus::Rejected | LifecycleStatus::Withdrawn | LifecycleStatus::Suspended
    ) {
        return Ok(false);
    }
    let normalized = status.to_ascii_lowercase();
    let mut changed = false;
    match normalized.as_str() {
        "issued" => {
            let reconciled_issued_at = issued_at.or(application.issued_at).unwrap_or(now);
            if application.status != LifecycleStatus::Credentialed {
                application.status = LifecycleStatus::Credentialed;
                changed = true;
            }
            if application.issued_at != Some(reconciled_issued_at) {
                application.issued_at = Some(reconciled_issued_at);
                changed = true;
            }
            if application.claim_state != ClaimState::Claimed {
                application.claim_state = ClaimState::Claimed;
                changed = true;
            }
            if application.claim_blocker.take().is_some() {
                changed = true;
            }
            if applicant.status != LifecycleStatus::Credentialed {
                advance_to_credentialed(applicant, now)?;
                changed = true;
            }
        }
        "pending" if application.status == LifecycleStatus::Credentialed => {
            application.status = LifecycleStatus::Offered;
            application.issued_at = None;
            changed = true;
        }
        "authorized" | "signing" => {
            if application.status == LifecycleStatus::Credentialed {
                application.status = LifecycleStatus::Offered;
                application.issued_at = None;
                changed = true;
            }
            changed |= mark_offer_unclaimable(
                application,
                "OFFER_CONSUMED",
                "This credential offer has already been accepted. Request a new offer to use another wallet.",
            );
        }
        "failed" => {
            changed |= mark_offer_unclaimable(
                application,
                "ISSUANCE_FAILED",
                "Credential issuance did not complete. Request a new offer.",
            );
        }
        "expired" => {
            changed |= mark_offer_unclaimable(
                application,
                "OFFER_EXPIRED",
                "This credential offer has expired. Request a new offer.",
            );
        }
        "revoked" => {
            changed |= mark_offer_unclaimable(
                application,
                "ISSUANCE_REVOKED",
                "This credential offer is no longer valid. Request a new offer if permitted.",
            );
        }
        _ => {}
    }
    if application
        .system_data
        .get("issuance_status")
        .and_then(Value::as_str)
        != Some(normalized.as_str())
    {
        application
            .system_data
            .insert("issuance_status".into(), Value::String(normalized));
        changed = true;
    }
    if changed {
        application.updated_at = now;
    }
    Ok(changed)
}

fn mark_offer_unclaimable(application: &mut Application, code: &str, message: &str) -> bool {
    let blocker = json!({
        "code": code,
        "owner": "APPLICANT",
        "message": message,
    });
    let changed = application.claim_state != ClaimState::Expired
        || application.claim_blocker.as_ref() != Some(&blocker);
    application.claim_state = ClaimState::Expired;
    application.claim_blocker = Some(blocker);
    changed
}

fn advance_to_offered(applicant: &mut Applicant, now: DateTime<Utc>) -> Result<(), ApplicantError> {
    for target in [
        LifecycleStatus::Submitted,
        LifecycleStatus::UnderReview,
        LifecycleStatus::Approved,
        LifecycleStatus::Offered,
    ] {
        if applicant.status == LifecycleStatus::Credentialed
            || applicant.status == LifecycleStatus::Offered
        {
            break;
        }
        if applicant.status.transition(target).is_ok() {
            applicant.set_status(target, now)?;
        }
    }
    Ok(())
}
fn advance_to_credentialed(
    applicant: &mut Applicant,
    now: DateTime<Utc>,
) -> Result<(), ApplicantError> {
    advance_to_offered(applicant, now)?;
    if applicant.status == LifecycleStatus::Offered {
        applicant.set_status(LifecycleStatus::Credentialed, now)?;
    }
    Ok(())
}
fn insert_optional(values: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    values.insert(
        key.into(),
        value.clone().map(Value::String).unwrap_or(Value::Null),
    );
}

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("persisted issuance attempt state is invalid")]
    InvalidAttemptState,
    #[error("issuance attempt state changed before completion")]
    AttemptChanged,
    #[error("flow orchestration completed without a credential offer URI")]
    MissingOffer,
    #[error("cannot issue application in {0:?} status")]
    InvalidApplicationStatus(LifecycleStatus),
    #[error(transparent)]
    Applicant(#[from] ApplicantError),
}
