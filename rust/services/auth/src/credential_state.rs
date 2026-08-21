use std::sync::Arc;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac as _};
use mmf_data::CacheStore;
use mmf_push::{payload_digest, verify_event_signature, MINIMUM_EVENT_SECRET_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

pub const AUTH_CALLBACK_AUDIENCE: &str = "marty-auth-service";
pub const CREDENTIAL_CALLBACK_EVENT: &str = "flow.verification_completed";
const PENDING_PREFIX: &str = "marty:cred_login:pending:";
const COMPLETE_PREFIX: &str = "marty:cred_login:complete:";
const CLAIM_PREFIX: &str = "marty:cred_login:callback_claim:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCredentialLogin {
    pub nonce: String,
    pub flow_instance_id: String,
    pub presentation_policy_id: String,
    pub organization_id: String,
    #[serde(default = "pending_status")]
    pub status: String,
    #[serde(default)]
    pub revocation_checked: bool,
}

fn pending_status() -> String {
    "pending".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialVerifiedPayload {
    pub flow_instance_id: String,
    pub result: String,
    pub decision: String,
    #[serde(default)]
    pub decision_reason: String,
    #[serde(default)]
    pub verified_claims: Map<String, Value>,
    #[serde(default)]
    pub presentation_policy_id: String,
    #[serde(default)]
    pub completed_at: String,
    pub evidence_digest: String,
    pub decision_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialCallbackHeaders {
    pub event: String,
    pub audience: String,
    pub event_id: String,
    pub timestamp: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialCallbackPolicy {
    pub secret: String,
    pub expected_policy_id: String,
    pub expected_organization_id: String,
    pub maximum_timestamp_skew_seconds: i64,
    pub pending_ttl_seconds: u64,
    pub completion_ttl_seconds: u64,
    pub claim_lease_seconds: u64,
}

impl CredentialCallbackPolicy {
    pub fn validate(&self) -> Result<(), CredentialStateError> {
        if self.secret.len() < MINIMUM_EVENT_SECRET_BYTES {
            return Err(CredentialStateError::Unavailable(
                "verification callback secret must be at least 32 bytes".into(),
            ));
        }
        if self.expected_policy_id.is_empty() || self.expected_organization_id.is_empty() {
            return Err(CredentialStateError::Unavailable(
                "credential login policy and organization are required".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialStateError {
    #[error("AUTH.CREDENTIAL_CALLBACK_UNAVAILABLE: {0}")]
    Unavailable(String),
    #[error("AUTH.CREDENTIAL_CALLBACK_INVALID: {0}")]
    InvalidCallback(String),
    #[error("AUTH.CREDENTIAL_CALLBACK_EXPIRED")]
    Expired,
    #[error("AUTH.CREDENTIAL_CALLBACK_STATE_INVALID")]
    InvalidState,
    #[error("AUTH.CREDENTIAL_CALLBACK_MISMATCH")]
    Mismatch,
    #[error("AUTH.CREDENTIAL_CALLBACK_ALREADY_CLAIMED")]
    AlreadyClaimed,
    #[error("AUTH.CREDENTIAL_STATE_SERIALIZATION: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackClaim {
    Claimed(PendingCredentialLogin),
    AlreadyProcessed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialLoginCompletion {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default)]
    pub revocation_checked: bool,
    #[serde(default = "unknown_status")]
    pub revocation_status: String,
}

fn unknown_status() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CredentialLoginPoll {
    Pending,
    Expired,
    Completed {
        redirect_to: String,
        revocation_checked: bool,
        revocation_status: String,
    },
    Failed {
        reason_code: String,
        message: String,
        reason: Option<String>,
        detail: Option<String>,
    },
}

pub struct CredentialLoginStateStore {
    cache: Arc<dyn CacheStore>,
    policy: CredentialCallbackPolicy,
}

impl CredentialLoginStateStore {
    pub fn new(
        cache: Arc<dyn CacheStore>,
        policy: CredentialCallbackPolicy,
    ) -> Result<Self, CredentialStateError> {
        policy.validate()?;
        Ok(Self { cache, policy })
    }

    pub async fn save_pending(
        &self,
        pending: &PendingCredentialLogin,
        now_ms: u64,
    ) -> Result<(), CredentialStateError> {
        if pending.nonce.is_empty() {
            return Err(CredentialStateError::InvalidState);
        }
        self.cache
            .set(
                &key(PENDING_PREFIX, &pending.nonce),
                encode(pending)?,
                Some(self.policy.pending_ttl_seconds),
                now_ms,
            )
            .await
            .map(|_| ())
            .map_err(store_error)
    }

    pub fn verify_callback(
        &self,
        payload: &CredentialVerifiedPayload,
        headers: &CredentialCallbackHeaders,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialStateError> {
        verify_credential_callback(
            payload,
            headers,
            &self.policy.secret,
            now,
            self.policy.maximum_timestamp_skew_seconds,
        )
    }

    #[must_use]
    pub fn callback_session_id(&self, flow_instance_id: &str, nonce: &str) -> Uuid {
        credential_callback_session_id(&self.policy.secret, flow_instance_id, nonce)
    }

    pub async fn poll(
        &self,
        nonce: &str,
        now_ms: u64,
    ) -> Result<CredentialLoginPoll, CredentialStateError> {
        if let Some(raw) = self
            .cache
            .get(&key(COMPLETE_PREFIX, nonce), now_ms)
            .await
            .map_err(store_error)?
        {
            return completion_poll(decode(&raw)?, nonce);
        }
        let pending = self
            .cache
            .exists(&key(PENDING_PREFIX, nonce), now_ms)
            .await
            .map_err(store_error)?;
        Ok(if pending {
            CredentialLoginPoll::Pending
        } else {
            CredentialLoginPoll::Expired
        })
    }

    pub async fn claim_callback(
        &self,
        nonce: &str,
        payload: &CredentialVerifiedPayload,
        now_ms: u64,
    ) -> Result<CallbackClaim, CredentialStateError> {
        let pending_key = key(PENDING_PREFIX, nonce);
        let Some(raw) = self
            .cache
            .get(&pending_key, now_ms)
            .await
            .map_err(store_error)?
        else {
            let prior = self
                .cache
                .get(&key(CLAIM_PREFIX, nonce), now_ms)
                .await
                .map_err(store_error)?;
            return if prior.as_deref() == Some(payload.flow_instance_id.as_bytes()) {
                Ok(CallbackClaim::AlreadyProcessed)
            } else {
                Err(CredentialStateError::Expired)
            };
        };
        let pending: PendingCredentialLogin = decode(&raw)?;
        if pending.flow_instance_id != payload.flow_instance_id
            || pending.presentation_policy_id != payload.presentation_policy_id
            || pending.presentation_policy_id != self.policy.expected_policy_id
            || pending.organization_id != self.policy.expected_organization_id
        {
            return Err(CredentialStateError::Mismatch);
        }
        let claimed = self
            .cache
            .set_if_absent(
                &key(CLAIM_PREFIX, nonce),
                payload.flow_instance_id.as_bytes().to_vec(),
                Some(self.policy.claim_lease_seconds),
                now_ms,
            )
            .await
            .map_err(store_error)?;
        if !claimed {
            return Err(CredentialStateError::AlreadyClaimed);
        }
        Ok(CallbackClaim::Claimed(pending))
    }

    pub async fn complete(
        &self,
        nonce: &str,
        flow_instance_id: &str,
        session_id: &str,
        revocation_checked: bool,
        revocation_status: &str,
        now_ms: u64,
    ) -> Result<(), CredentialStateError> {
        let completion = CredentialLoginCompletion {
            status: "completed".into(),
            session_id: Some(session_id.into()),
            reason_code: None,
            message: None,
            reason: None,
            detail: None,
            revocation_checked,
            revocation_status: revocation_status.into(),
        };
        self.finish(nonce, flow_instance_id, &completion, now_ms)
            .await
    }

    pub async fn fail(
        &self,
        nonce: &str,
        flow_instance_id: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<CredentialLoginCompletion, CredentialStateError> {
        let completion = failure_payload(reason);
        self.finish(nonce, flow_instance_id, &completion, now_ms)
            .await?;
        Ok(completion)
    }

    pub async fn finalize(
        &self,
        nonce: &str,
        now_ms: u64,
    ) -> Result<Option<CredentialLoginCompletion>, CredentialStateError> {
        self.cache
            .take(&key(COMPLETE_PREFIX, nonce), now_ms)
            .await
            .map_err(store_error)?
            .map(|raw| decode(&raw))
            .transpose()
    }

    async fn finish(
        &self,
        nonce: &str,
        flow_instance_id: &str,
        completion: &CredentialLoginCompletion,
        now_ms: u64,
    ) -> Result<(), CredentialStateError> {
        self.cache
            .set(
                &key(COMPLETE_PREFIX, nonce),
                encode(completion)?,
                Some(self.policy.completion_ttl_seconds),
                now_ms,
            )
            .await
            .map_err(store_error)?;
        self.cache
            .set(
                &key(CLAIM_PREFIX, nonce),
                flow_instance_id.as_bytes().to_vec(),
                Some(self.policy.pending_ttl_seconds),
                now_ms,
            )
            .await
            .map_err(store_error)?;
        self.cache
            .delete(&key(PENDING_PREFIX, nonce))
            .await
            .map(|_| ())
            .map_err(store_error)
    }
}

pub fn verify_credential_callback(
    payload: &CredentialVerifiedPayload,
    headers: &CredentialCallbackHeaders,
    secret: &str,
    now: DateTime<Utc>,
    maximum_skew_seconds: i64,
) -> Result<(), CredentialStateError> {
    if secret.len() < MINIMUM_EVENT_SECRET_BYTES {
        return Err(CredentialStateError::Unavailable(
            "verification callback authentication is unavailable".into(),
        ));
    }
    if headers.event != CREDENTIAL_CALLBACK_EVENT
        || headers.audience != AUTH_CALLBACK_AUDIENCE
        || headers.event_id != payload.flow_instance_id
        || !is_lower_hex_64(&payload.evidence_digest)
        || !is_lower_hex_64(&payload.decision_digest)
    {
        return Err(invalid_callback());
    }
    let mut basis = serde_json::to_value(payload).map_err(serialization_error)?;
    basis
        .as_object_mut()
        .ok_or_else(invalid_callback)?
        .remove("decision_digest");
    let digest = payload_digest(&basis).map_err(|error| serialization_error(error.to_string()))?;
    if digest != payload.decision_digest {
        return Err(invalid_callback());
    }
    let timestamp = DateTime::parse_from_rfc3339(&headers.timestamp)
        .map_err(|_| invalid_callback())?
        .with_timezone(&Utc);
    if (now - timestamp).num_seconds().abs() > maximum_skew_seconds {
        return Err(CredentialStateError::InvalidCallback(
            "verification callback has expired".into(),
        ));
    }
    let payload = serde_json::to_value(payload).map_err(serialization_error)?;
    if !verify_event_signature(
        &headers.signature,
        secret,
        &headers.audience,
        &headers.event,
        &headers.event_id,
        &headers.timestamp,
        &payload,
    ) {
        return Err(invalid_callback());
    }
    Ok(())
}

#[must_use]
pub fn credential_callback_session_id(secret: &str, flow_instance_id: &str, nonce: &str) -> Uuid {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(b"credential-login-session\0");
    mac.update(flow_instance_id.as_bytes());
    mac.update(b"\0");
    mac.update(nonce.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[must_use]
pub fn failure_payload(reason: &str) -> CredentialLoginCompletion {
    let normalized = reason.trim();
    let reason_code = failure_reason_code(normalized);
    let detail = (!normalized.is_empty()
        && normalized != reason_code
        && !matches!(
            reason_code,
            "keycloak_user_not_found" | "keycloak_user_not_eligible" | "keycloak_admin_unavailable"
        ))
    .then(|| normalized.to_owned());
    CredentialLoginCompletion {
        status: "failed".into(),
        session_id: None,
        reason_code: Some(reason_code.into()),
        message: Some(failure_message(reason_code).into()),
        reason: (!normalized.is_empty()).then(|| normalized.into()),
        detail,
        revocation_checked: false,
        revocation_status: "unknown".into(),
    }
}

fn failure_reason_code(reason: &str) -> &'static str {
    let lower = reason.to_lowercase();
    if reason == "keycloak_user_not_found" {
        "keycloak_user_not_found"
    } else if reason == "keycloak_user_not_eligible" {
        "keycloak_user_not_eligible"
    } else if reason == "keycloak_admin_unavailable" {
        "keycloak_admin_unavailable"
    } else if contains_any(
        &lower,
        &[
            "does not match any trust source issuer identifier",
            "not in trust profile allowed_issuers",
            "explicitly denied by trust profile",
        ],
    ) {
        "issuer_not_trusted"
    } else if contains_any(
        &lower,
        &[
            "missing email claim",
            "missing email",
            "no email in verified_claims",
        ],
    ) {
        "missing_email_claim"
    } else if lower.contains("revocation status was not checked") {
        "revocation_not_checked"
    } else if lower.contains("credential is revoked") {
        "credential_revoked"
    } else if contains_any(
        &lower,
        &[
            "policy service unavailable",
            "temporarily unavailable",
            "trust profile validation failed",
            "could not be loaded",
        ],
    ) {
        "verification_service_unavailable"
    } else if contains_any(
        &lower,
        &[
            "did resolution failed",
            "unsupported credential format",
            "malformed",
            "invalid credential",
            "invalid presentation",
        ],
    ) {
        "credential_payload_invalid"
    } else {
        "verification_failed"
    }
}

fn failure_message(reason_code: &str) -> &'static str {
    match reason_code {
        "issuer_not_trusted" => {
            "This badge was issued by an issuer that ElevenID does not trust for sign-in on this site."
        }
        "missing_email_claim" => "This badge is missing the email claim required for sign-in.",
        "revocation_not_checked" => "We could not confirm this badge is still active.",
        "credential_revoked" => "This badge has been revoked and can no longer be used for sign-in.",
        "verification_service_unavailable" => {
            "Open Badge sign-in is temporarily unavailable. Please try again in a moment."
        }
        "credential_payload_invalid" => "We could not verify the badge that was presented.",
        "keycloak_user_not_found" => {
            "We verified the badge, but no ElevenID account matches the email in it."
        }
        "keycloak_user_not_eligible" => {
            "We verified the badge, but the matching ElevenID account is not eligible for Open Badge sign-in."
        }
        "keycloak_admin_unavailable" => {
            "We verified the badge, but account lookup is temporarily unavailable."
        }
        _ => "We could not verify this Open Badge for sign-in.",
    }
}

fn completion_poll(
    completion: CredentialLoginCompletion,
    nonce: &str,
) -> Result<CredentialLoginPoll, CredentialStateError> {
    match completion.status.as_str() {
        "completed" => Ok(CredentialLoginPoll::Completed {
            redirect_to: format!("/v1/auth/credential-login/finalize?nonce={nonce}"),
            revocation_checked: completion.revocation_checked,
            revocation_status: completion.revocation_status,
        }),
        "failed" => Ok(CredentialLoginPoll::Failed {
            reason_code: completion
                .reason_code
                .unwrap_or_else(|| "verification_failed".into()),
            message: completion
                .message
                .unwrap_or_else(|| failure_message("verification_failed").into()),
            reason: completion.reason,
            detail: completion.detail,
        }),
        _ => Err(CredentialStateError::InvalidState),
    }
}

fn key(prefix: &str, nonce: &str) -> String {
    format!("{prefix}{nonce}")
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CredentialStateError> {
    serde_json::to_vec(value).map_err(serialization_error)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, CredentialStateError> {
    serde_json::from_slice(bytes).map_err(serialization_error)
}

fn serialization_error(error: impl ToString) -> CredentialStateError {
    CredentialStateError::Serialization(error.to_string())
}

fn store_error(error: impl ToString) -> CredentialStateError {
    CredentialStateError::Unavailable(error.to_string())
}

fn invalid_callback() -> CredentialStateError {
    CredentialStateError::InvalidCallback("invalid verification callback".into())
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}
