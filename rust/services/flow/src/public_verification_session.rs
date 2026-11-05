//! Visitor capabilities are independent of wallet protocol nonces and IDs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_verification::flow::FlowInstanceStatus;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::{FlowInstanceRecord, PublicVerificationSelection};

pub(crate) const PUBLIC_SESSION: &str = "_marty_public_verification_session";
pub(crate) const RESULT_ACCESS_SECONDS: i64 = 600;

/// A browser generates 32 random bytes using Web Crypto and retains the
/// canonical base64url string across retries. Never put it in a URL or log it.
/// Deliberately implements neither Debug nor Serialize.
pub struct PublicVerificationSessionKey([u8; 32]);

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PublicVerificationSessionError {
    #[error("FLOW.PUBLIC_VERIFICATION_CAPABILITY_INVALID")]
    InvalidCapability,
    #[error("FLOW.PUBLIC_VERIFICATION_SESSION_UNAVAILABLE")]
    Unavailable,
    #[error("FLOW.PUBLIC_VERIFICATION_SESSION_STATE_INVALID")]
    InvalidState,
    #[error("FLOW.PUBLIC_VERIFICATION_SELECTION_CONFLICT")]
    SelectionConflict,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionSnapshot {
    key_hash: String,
    origin: String,
    catalog_revision: String,
    scenario_id: String,
    choice_id: String,
    #[serde(default)]
    example_id: Option<String>,
    #[serde(default)]
    request_digest: Option<String>,
    access_expires_at: DateTime<Utc>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicVerificationSessionStatus {
    AwaitingWallet,
    Verifying,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

/// Closed projection: no claims, policy IDs, holder identifiers, generic
/// context, provider error text, submission material or private histories.
#[derive(Debug, Serialize)]
pub struct PublicVerificationSessionView {
    pub session_id: String,
    pub scenario_id: String,
    pub choice_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_status: Option<crate::PublicVerificationExampleStatus>,
    pub catalog_revision: String,
    pub status: PublicVerificationSessionStatus,
    pub expires_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_uri: Option<String>,
}

impl PublicVerificationSessionKey {
    pub fn parse(value: &str) -> Result<Self, PublicVerificationSessionError> {
        if value.len() != 43 {
            return Err(PublicVerificationSessionError::InvalidCapability);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PublicVerificationSessionError::InvalidCapability)?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PublicVerificationSessionError::InvalidCapability)?;
        if URL_SAFE_NO_PAD.encode(secret) != value {
            return Err(PublicVerificationSessionError::InvalidCapability);
        }
        Ok(Self(secret))
    }

    fn digest(&self, organization_id: &str, origin: &str, purpose: &str) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in [
            "marty.public-verification/session/v1".as_bytes(),
            purpose.as_bytes(),
            organization_id.as_bytes(),
            origin.as_bytes(),
            self.0.as_slice(),
        ] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }

    #[must_use]
    pub fn instance_id(&self, organization_id: &str, origin: &str) -> Uuid {
        let digest = self.digest(organization_id, origin, "instance-id");
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest[..16]);
        // RFC 9562 UUIDv8: domain-separated SHA-256 payload, RFC variant.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }

    pub(crate) fn bind(
        &self,
        instance: &mut FlowInstanceRecord,
        origin: &str,
        selection: &PublicVerificationSelection,
    ) -> Result<(), PublicVerificationSessionError> {
        let expiry = instance
            .expires_at
            .ok_or(PublicVerificationSessionError::InvalidState)?;
        if instance.id
            != self
                .instance_id(&instance.organization_id, origin)
                .to_string()
            || instance.context.get(PUBLIC_SESSION).is_some()
            || !instance.context.is_object()
        {
            return Err(PublicVerificationSessionError::InvalidState);
        }
        let snapshot = SessionSnapshot {
            key_hash: hex::encode(self.digest(&instance.organization_id, origin, "capability")),
            origin: origin.into(),
            catalog_revision: selection.catalog_revision.clone(),
            scenario_id: selection.scenario_id.clone(),
            choice_id: selection.choice_id.clone(),
            example_id: selection.example_id.clone(),
            request_digest: selection.request_digest.clone(),
            access_expires_at: expiry
                .checked_add_signed(Duration::seconds(RESULT_ACCESS_SECONDS))
                .ok_or(PublicVerificationSessionError::InvalidState)?,
        };
        instance.context[PUBLIC_SESSION] = serde_json::to_value(snapshot)
            .map_err(|_| PublicVerificationSessionError::InvalidState)?;
        Ok(())
    }

    fn authorize(
        &self,
        instance: &FlowInstanceRecord,
        organization_id: &str,
        origin: &str,
        now: DateTime<Utc>,
    ) -> Result<SessionSnapshot, PublicVerificationSessionError> {
        let unavailable = || PublicVerificationSessionError::Unavailable;
        if instance.organization_id != organization_id
            || instance.id != self.instance_id(organization_id, origin).to_string()
        {
            return Err(unavailable());
        }
        let snapshot: SessionSnapshot = serde_json::from_value(
            instance
                .context
                .get(PUBLIC_SESSION)
                .ok_or_else(unavailable)?
                .clone(),
        )
        .map_err(|_| unavailable())?;
        let actual = hex::decode(&snapshot.key_hash).map_err(|_| unavailable())?;
        let expected = self.digest(organization_id, origin, "capability");
        let expiry = instance.expires_at.ok_or_else(unavailable)?;
        if actual.len() != expected.len()
            || !bool::from(actual.ct_eq(&expected))
            || snapshot.origin != origin
            || now >= snapshot.access_expires_at
            || Some(snapshot.access_expires_at)
                != expiry.checked_add_signed(Duration::seconds(RESULT_ACCESS_SECONDS))
        {
            return Err(unavailable());
        }
        Ok(snapshot)
    }

    /// A retry with a different choice never changes an existing request.
    pub fn require_same_selection(
        &self,
        instance: &FlowInstanceRecord,
        organization_id: &str,
        origin: &str,
        selection: &PublicVerificationSelection,
        now: DateTime<Utc>,
    ) -> Result<(), PublicVerificationSessionError> {
        let snapshot = self.authorize(instance, organization_id, origin, now)?;
        if !selection.consent
            || snapshot.catalog_revision != selection.catalog_revision
            || snapshot.scenario_id != selection.scenario_id
            || snapshot.choice_id != selection.choice_id
            || snapshot.example_id != selection.example_id
            || snapshot.request_digest != selection.request_digest
        {
            return Err(PublicVerificationSessionError::SelectionConflict);
        }
        Ok(())
    }

    pub fn view(
        &self,
        instance: &FlowInstanceRecord,
        organization_id: &str,
        origin: &str,
        now: DateTime<Utc>,
    ) -> Result<PublicVerificationSessionView, PublicVerificationSessionError> {
        let snapshot = self.authorize(instance, organization_id, origin, now)?;
        let expiry = instance
            .expires_at
            .ok_or(PublicVerificationSessionError::InvalidState)?;
        let status = if !instance.status.is_terminal() && now >= expiry {
            PublicVerificationSessionStatus::Expired
        } else {
            match instance.status {
                FlowInstanceStatus::AwaitingWallet => {
                    PublicVerificationSessionStatus::AwaitingWallet
                }
                FlowInstanceStatus::InProgress => PublicVerificationSessionStatus::Verifying,
                FlowInstanceStatus::Completed => PublicVerificationSessionStatus::Completed,
                FlowInstanceStatus::Failed => PublicVerificationSessionStatus::Failed,
                FlowInstanceStatus::Cancelled => PublicVerificationSessionStatus::Cancelled,
                FlowInstanceStatus::Expired => PublicVerificationSessionStatus::Expired,
                _ => return Err(PublicVerificationSessionError::InvalidState),
            }
        };
        let verified = match status {
            PublicVerificationSessionStatus::Completed
            | PublicVerificationSessionStatus::Failed => {
                let result = instance
                    .result
                    .as_ref()
                    .ok_or(PublicVerificationSessionError::InvalidState)?;
                match (
                    result["evaluation_result"].as_str(),
                    result["decision"].as_str(),
                    &status,
                ) {
                    (Some("passed"), Some("allow"), PublicVerificationSessionStatus::Completed) => {
                        Some(true)
                    }
                    (Some("failed"), Some("deny"), PublicVerificationSessionStatus::Failed) => {
                        Some(false)
                    }
                    (Some("passed"), Some("deny"), PublicVerificationSessionStatus::Failed)
                    | (Some("failed"), Some("allow"), PublicVerificationSessionStatus::Failed) => {
                        Some(false)
                    }
                    _ => return Err(PublicVerificationSessionError::InvalidState),
                }
            }
            _ => None,
        };
        let wallet_uri = if snapshot.example_id.is_none()
            && matches!(
                status,
                PublicVerificationSessionStatus::AwaitingWallet
                    | PublicVerificationSessionStatus::Verifying
            ) {
            Some(
                instance
                    .context
                    .get("auth_request")
                    .and_then(serde_json::Value::as_str)
                    .filter(|uri| uri.starts_with("openid4vp://authorize?"))
                    .ok_or(PublicVerificationSessionError::InvalidState)?
                    .to_owned(),
            )
        } else {
            None
        };
        Ok(PublicVerificationSessionView {
            session_id: instance.id.clone(),
            scenario_id: snapshot.scenario_id,
            choice_id: snapshot.choice_id,
            example_status: if snapshot.example_id.is_some()
                && matches!(
                    status,
                    PublicVerificationSessionStatus::AwaitingWallet
                        | PublicVerificationSessionStatus::Verifying
                ) {
                crate::public_verification_example::example_status(instance)?
            } else {
                None
            },
            example_id: snapshot.example_id,
            catalog_revision: snapshot.catalog_revision,
            status,
            expires_at: expiry,
            access_expires_at: snapshot.access_expires_at,
            verified,
            wallet_uri,
        })
    }
}

/// A sample-bound session must not accept a different credential from an
/// external wallet while its server-side specimen is being processed.
pub(crate) fn require_wallet_session(
    instance: &FlowInstanceRecord,
) -> Result<(), crate::FlowHttpError> {
    if instance
        .context
        .get(PUBLIC_SESSION)
        .and_then(|value| value.get("example_id"))
        .is_some_and(|value| !value.is_null())
    {
        return Err(crate::FlowHttpError::new(
            axum::http::StatusCode::NOT_FOUND,
            "verification_unavailable",
            "Verification request unavailable",
        ));
    }
    Ok(())
}
