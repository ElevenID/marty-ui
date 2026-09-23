use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_security::constant_time_secret_eq;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const MAX_REASON_CHARACTERS: usize = 2_000;
const MAX_COMMENTS_CHARACTERS: usize = 4_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedCredentialStatus {
    Active,
    Suspended,
    Revoked,
}

impl ManagedCredentialStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialLifecycleAction {
    Revoke,
    Suspend,
    Reinstate,
}

impl CredentialLifecycleAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoke => "revoke",
            Self::Suspend => "suspend",
            Self::Reinstate => "reinstate",
        }
    }

    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Revoke => "revoked",
            Self::Suspend => "suspended",
            Self::Reinstate => "reinstated",
        }
    }

    #[must_use]
    pub const fn target_status(self) -> ManagedCredentialStatus {
        match self {
            Self::Revoke => ManagedCredentialStatus::Revoked,
            Self::Suspend => ManagedCredentialStatus::Suspended,
            Self::Reinstate => ManagedCredentialStatus::Active,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedCredential {
    pub id: String,
    pub transaction_id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub issuer_did: Option<String>,
    pub status: ManagedCredentialStatus,
    pub status_updated_at: DateTime<Utc>,
    pub revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub revocation_profile_id: Option<String>,
    pub status_list_entries: Vec<Value>,
}

/// Trusted, non-public context retained with a lifecycle transition.
///
/// `comments` are operator-authored audit notes. Actor fields are populated
/// only from gateway-authenticated headers and are never returned in the
/// public issued-credential projection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialLifecycleAuditContext {
    pub comments: Option<String>,
    pub actor_id: Option<String>,
    pub actor_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLifecycleAuditRecord {
    pub action: CredentialLifecycleAction,
    pub previous_status: ManagedCredentialStatus,
    pub reason: Option<String>,
    pub comments: Option<String>,
    pub actor_id: Option<String>,
    pub actor_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialStatusView {
    pub id: String,
    pub issuer_did: Option<String>,
    pub status: String,
    pub status_updated_at: DateTime<Utc>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLifecycleEvent {
    pub event_type: String,
    pub credential_id: String,
    pub transaction_id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{0}")]
pub struct CredentialManagementPortError(pub String);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLifecycleSyncError {
    #[error(transparent)]
    Port(#[from] CredentialManagementPortError),
    #[error("Canvas delivery response cannot be encoded for persistence")]
    TextEncoding,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialManagementError {
    #[error("Credential not found")]
    NotFound,
    #[error("Resource not found")]
    ResourceNotFound,
    #[error("Credential already revoked")]
    AlreadyRevoked,
    #[error("Cannot suspend revoked credential")]
    CannotSuspendRevoked,
    #[error("Cannot reinstate revoked credential")]
    CannotReinstateRevoked,
    #[error("Only suspended credentials can be reinstated")]
    NotSuspended,
    #[error("Credential lifecycle reason exceeds 2000 characters")]
    ReasonTooLong,
    #[error("Credential lifecycle comments exceed 4000 characters")]
    CommentsTooLong,
    #[error("Credential repository unavailable: {0}")]
    RepositoryUnavailable(String),
    #[error("Revocation service unavailable: {0}")]
    PublicationUnavailable(String),
    #[error("Canvas lifecycle retry could not be recorded: {0}")]
    CanvasRetryUnavailable(String),
    #[error("Canvas delivery response cannot be encoded for persistence")]
    CanvasTextEncoding,
}

#[async_trait]
pub trait CredentialManagementRepository: Send + Sync {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError>;

    async fn persist(
        &self,
        credential: &ManagedCredential,
        expected_status: ManagedCredentialStatus,
        audit: &CredentialLifecycleAuditRecord,
    ) -> Result<ManagedCredential, CredentialManagementPortError>;

    /// Synchronize Canvas mirrors after local persistence. External failures
    /// are successful outcomes only after this port durably records retry
    /// metadata; an error means that durable retry recording itself failed.
    async fn synchronize_canvas(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError>;
}

#[async_trait]
pub trait CredentialStatusPublisher: Send + Sync {
    async fn publish(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError>;
}

#[async_trait]
pub trait CredentialLifecycleEventSink: Send + Sync {
    async fn emit(&self, event: CredentialLifecycleEvent);
}

#[derive(Clone)]
pub struct CredentialManagementService {
    repository: Arc<dyn CredentialManagementRepository>,
    publisher: Arc<dyn CredentialStatusPublisher>,
    events: Arc<dyn CredentialLifecycleEventSink>,
}

#[derive(Clone, Copy)]
enum ReasonPolicy {
    PublicLifecycleLimit,
    PreserveTransactionInput,
}

impl std::fmt::Debug for CredentialManagementService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialManagementService")
            .finish_non_exhaustive()
    }
}

impl CredentialManagementService {
    #[must_use]
    pub fn new(
        repository: Arc<dyn CredentialManagementRepository>,
        publisher: Arc<dyn CredentialStatusPublisher>,
        events: Arc<dyn CredentialLifecycleEventSink>,
    ) -> Self {
        Self {
            repository,
            publisher,
            events,
        }
    }

    pub async fn get_status(
        &self,
        credential_id: &str,
        trusted_organization_id: Option<&str>,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        let credential = self.load(credential_id).await?;
        enforce_organization(&credential, trusted_organization_id)?;
        Ok(status_view(
            &credential,
            credential.revocation_reason.clone(),
        ))
    }

    pub async fn transition(
        &self,
        credential_id: &str,
        trusted_organization_id: Option<&str>,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        self.transition_with_context(
            credential_id,
            trusted_organization_id,
            action,
            reason,
            &CredentialLifecycleAuditContext::default(),
        )
        .await
    }

    pub async fn transition_with_context(
        &self,
        credential_id: &str,
        trusted_organization_id: Option<&str>,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
        audit_context: &CredentialLifecycleAuditContext,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        let credential = self.load(credential_id).await?;
        self.apply_transition(
            credential,
            trusted_organization_id,
            action,
            reason,
            audit_context,
            ReasonPolicy::PublicLifecycleLimit,
        )
        .await
    }

    async fn apply_transition(
        &self,
        credential: ManagedCredential,
        trusted_organization_id: Option<&str>,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
        audit_context: &CredentialLifecycleAuditContext,
        reason_policy: ReasonPolicy,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        enforce_organization(&credential, trusted_organization_id)?;
        if matches!(reason_policy, ReasonPolicy::PublicLifecycleLimit) {
            validate_reason(reason)?;
        }
        let comments = meaningful_text(audit_context.comments.as_deref());
        validate_comments(comments)?;
        validate_transition(credential.status, action)?;

        self.publisher
            .publish(&credential, action, reason)
            .await
            .map_err(|error| CredentialManagementError::PublicationUnavailable(error.0))?;

        let previous_status = credential.status;
        let mut updated = credential;
        let now = Utc::now();
        updated.status = action.target_status();
        updated.status_updated_at = now;
        if action == CredentialLifecycleAction::Revoke {
            updated.revoked = true;
            updated.revoked_at = Some(now);
            updated.revocation_reason = reason.map(str::to_owned);
        }
        let updated = self
            .repository
            .persist(
                &updated,
                previous_status,
                &CredentialLifecycleAuditRecord {
                    action,
                    previous_status,
                    reason: reason.map(str::to_owned),
                    comments: comments.map(str::to_owned),
                    actor_id: meaningful_text(audit_context.actor_id.as_deref()).map(str::to_owned),
                    actor_type: meaningful_text(audit_context.actor_type.as_deref())
                        .map(str::to_owned),
                },
            )
            .await
            .map_err(|error| CredentialManagementError::RepositoryUnavailable(error.0))?;

        self.repository
            .synchronize_canvas(&updated, action, reason)
            .await
            .map_err(|error| match error {
                CanvasLifecycleSyncError::Port(error) => {
                    CredentialManagementError::CanvasRetryUnavailable(error.0)
                }
                CanvasLifecycleSyncError::TextEncoding => {
                    CredentialManagementError::CanvasTextEncoding
                }
            })?;

        self.events
            .emit(CredentialLifecycleEvent {
                event_type: action.event_type().to_owned(),
                credential_id: updated.id.clone(),
                transaction_id: updated.transaction_id.clone(),
                organization_id: updated.organization_id.clone(),
                credential_template_id: updated.credential_template_id.clone(),
                status: updated.status.as_str().to_owned(),
                timestamp: Utc::now(),
            })
            .await;

        Ok(status_view(&updated, reason.map(str::to_owned)))
    }

    /// Ensure canonical revocation publication for transaction-level retry
    /// reconciliation without weakening the public credential endpoint's
    /// `AlreadyRevoked` behavior.
    ///
    /// A transaction revocation can fail after the credential row is written
    /// but before the transaction row is committed. Retrying must therefore
    /// republish the idempotent canonical status bit and retry Canvas sync even
    /// when the local credential is already revoked.
    pub async fn reconcile_revocation(
        &self,
        credential_id: &str,
        trusted_organization_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        let credential = self.load(credential_id).await?;
        enforce_organization(&credential, trusted_organization_id)?;
        if credential.status != ManagedCredentialStatus::Revoked {
            let audit_context = CredentialLifecycleAuditContext::default();
            let transition = self
                .apply_transition(
                    credential,
                    trusted_organization_id,
                    CredentialLifecycleAction::Revoke,
                    reason,
                    &audit_context,
                    ReasonPolicy::PreserveTransactionInput,
                )
                .await;
            return match transition {
                Ok(status) => Ok(status),
                Err(error @ CredentialManagementError::RepositoryUnavailable(_)) => {
                    // A concurrent idempotent transaction revocation can win the
                    // credential status CAS after both requests loaded `active`.
                    // Re-read before surfacing the repository error: only an
                    // authoritative revoked row is safe to reconcile. Genuine
                    // persistence failures leave the row unchanged and retain
                    // their original fail-closed error.
                    let authoritative = self.load(credential_id).await?;
                    enforce_organization(&authoritative, trusted_organization_id)?;
                    if authoritative.status != ManagedCredentialStatus::Revoked {
                        return Err(error);
                    }
                    self.reconcile_persisted_revocation(&authoritative).await
                }
                Err(error) => Err(error),
            };
        }

        self.reconcile_persisted_revocation(&credential).await
    }

    async fn reconcile_persisted_revocation(
        &self,
        credential: &ManagedCredential,
    ) -> Result<CredentialStatusView, CredentialManagementError> {
        let persisted_reason = credential.revocation_reason.as_deref();
        self.publisher
            .publish(
                credential,
                CredentialLifecycleAction::Revoke,
                persisted_reason,
            )
            .await
            .map_err(|error| CredentialManagementError::PublicationUnavailable(error.0))?;
        self.repository
            .synchronize_canvas(
                credential,
                CredentialLifecycleAction::Revoke,
                persisted_reason,
            )
            .await
            .map_err(|error| match error {
                CanvasLifecycleSyncError::Port(error) => {
                    CredentialManagementError::CanvasRetryUnavailable(error.0)
                }
                CanvasLifecycleSyncError::TextEncoding => {
                    CredentialManagementError::CanvasTextEncoding
                }
            })?;
        Ok(status_view(
            credential,
            credential.revocation_reason.clone(),
        ))
    }

    async fn load(
        &self,
        credential_id: &str,
    ) -> Result<ManagedCredential, CredentialManagementError> {
        self.repository
            .get(credential_id)
            .await
            .map_err(|error| CredentialManagementError::RepositoryUnavailable(error.0))?
            .ok_or(CredentialManagementError::NotFound)
    }
}

fn validate_comments(comments: Option<&str>) -> Result<(), CredentialManagementError> {
    if comments.is_some_and(|value| value.chars().count() > MAX_COMMENTS_CHARACTERS) {
        Err(CredentialManagementError::CommentsTooLong)
    } else {
        Ok(())
    }
}

fn meaningful_text(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn validate_reason(reason: Option<&str>) -> Result<(), CredentialManagementError> {
    if reason.is_some_and(|value| value.chars().count() > MAX_REASON_CHARACTERS) {
        Err(CredentialManagementError::ReasonTooLong)
    } else {
        Ok(())
    }
}

fn enforce_organization(
    credential: &ManagedCredential,
    trusted_organization_id: Option<&str>,
) -> Result<(), CredentialManagementError> {
    if trusted_organization_id.is_some_and(|organization_id| {
        let organization_id = organization_id.trim();
        organization_id.is_empty()
            || !constant_time_secret_eq(
                organization_id.as_bytes(),
                credential.organization_id.as_bytes(),
            )
    }) {
        Err(CredentialManagementError::ResourceNotFound)
    } else {
        Ok(())
    }
}

fn validate_transition(
    status: ManagedCredentialStatus,
    action: CredentialLifecycleAction,
) -> Result<(), CredentialManagementError> {
    match (action, status) {
        (CredentialLifecycleAction::Revoke, ManagedCredentialStatus::Revoked) => {
            Err(CredentialManagementError::AlreadyRevoked)
        }
        (CredentialLifecycleAction::Suspend, ManagedCredentialStatus::Revoked) => {
            Err(CredentialManagementError::CannotSuspendRevoked)
        }
        (CredentialLifecycleAction::Reinstate, ManagedCredentialStatus::Revoked) => {
            Err(CredentialManagementError::CannotReinstateRevoked)
        }
        (CredentialLifecycleAction::Reinstate, ManagedCredentialStatus::Active) => {
            Err(CredentialManagementError::NotSuspended)
        }
        _ => Ok(()),
    }
}

fn status_view(credential: &ManagedCredential, reason: Option<String>) -> CredentialStatusView {
    CredentialStatusView {
        id: credential.id.clone(),
        issuer_did: credential.issuer_did.clone(),
        status: credential.status.as_str().to_owned(),
        status_updated_at: credential.status_updated_at,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct Harness {
        credential: Arc<Mutex<Option<ManagedCredential>>>,
        calls: Arc<Mutex<Vec<String>>>,
        publication_failure: Arc<Mutex<Option<String>>>,
        canvas_failure: Arc<Mutex<Option<String>>>,
        persist_failure: Arc<Mutex<Option<String>>>,
        persist_race_reason: Arc<Mutex<Option<String>>>,
        events: Arc<Mutex<Vec<CredentialLifecycleEvent>>>,
        audits: Arc<Mutex<Vec<CredentialLifecycleAuditRecord>>>,
    }

    impl Harness {
        fn new(status: ManagedCredentialStatus) -> Self {
            Self {
                credential: Arc::new(Mutex::new(Some(ManagedCredential {
                    id: "credential-a".to_owned(),
                    transaction_id: "transaction-a".to_owned(),
                    organization_id: "org-a".to_owned(),
                    credential_template_id: "template-a".to_owned(),
                    issuer_did: Some("did:web:issuer.example".to_owned()),
                    status,
                    status_updated_at: Utc
                        .with_ymd_and_hms(2026, 8, 30, 8, 0, 0)
                        .single()
                        .expect("timestamp"),
                    revoked: status == ManagedCredentialStatus::Revoked,
                    revoked_at: None,
                    revocation_reason: None,
                    revocation_profile_id: Some("profile-a".to_owned()),
                    status_list_entries: vec![json!({
                        "status_list_id": "profile-a",
                        "index": 19,
                        "type": "BitstringStatusListEntry",
                        "status_purpose": "revocation"
                    })],
                }))),
                calls: Arc::new(Mutex::new(Vec::new())),
                publication_failure: Arc::new(Mutex::new(None)),
                canvas_failure: Arc::new(Mutex::new(None)),
                persist_failure: Arc::new(Mutex::new(None)),
                persist_race_reason: Arc::new(Mutex::new(None)),
                events: Arc::new(Mutex::new(Vec::new())),
                audits: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn service(&self) -> CredentialManagementService {
            CredentialManagementService::new(
                Arc::new(self.clone()),
                Arc::new(self.clone()),
                Arc::new(self.clone()),
            )
        }
    }

    #[async_trait]
    impl CredentialManagementRepository for Harness {
        async fn get(
            &self,
            credential_id: &str,
        ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
            self.calls.lock().expect("calls").push("load".to_owned());
            Ok(self
                .credential
                .lock()
                .expect("credential")
                .clone()
                .filter(|credential| credential.id == credential_id))
        }

        async fn persist(
            &self,
            credential: &ManagedCredential,
            expected_status: ManagedCredentialStatus,
            audit: &CredentialLifecycleAuditRecord,
        ) -> Result<ManagedCredential, CredentialManagementPortError> {
            self.calls.lock().expect("calls").push("persist".to_owned());
            self.audits.lock().expect("audits").push(audit.clone());
            if let Some(error) = self
                .persist_failure
                .lock()
                .expect("persist failure")
                .clone()
            {
                return Err(CredentialManagementPortError(error));
            }
            let mut stored = self.credential.lock().expect("credential");
            if let Some(reason) = self
                .persist_race_reason
                .lock()
                .expect("persist race reason")
                .take()
            {
                let mut winner = stored
                    .as_ref()
                    .expect("race winner requires a stored credential")
                    .clone();
                winner.status = ManagedCredentialStatus::Revoked;
                winner.revoked = true;
                winner.revoked_at = Some(Utc::now());
                winner.revocation_reason = Some(reason);
                *stored = Some(winner);
                return Err(CredentialManagementPortError(
                    "Credential status changed concurrently".to_owned(),
                ));
            }
            let current = stored
                .as_ref()
                .ok_or_else(|| CredentialManagementPortError("missing".to_owned()))?;
            if current.status != expected_status {
                return Err(CredentialManagementPortError("stale status".to_owned()));
            }
            *stored = Some(credential.clone());
            Ok(credential.clone())
        }

        async fn synchronize_canvas(
            &self,
            _credential: &ManagedCredential,
            action: CredentialLifecycleAction,
            _reason: Option<&str>,
        ) -> Result<(), CanvasLifecycleSyncError> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("canvas:{}", action.as_str()));
            if let Some(error) = self.canvas_failure.lock().expect("canvas failure").clone() {
                Err(CredentialManagementPortError(error).into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn transaction_revocation_reconciles_an_authoritative_concurrent_winner() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        *harness
            .persist_race_reason
            .lock()
            .expect("persist race reason") = Some("winning request".to_owned());

        let status = harness
            .service()
            .reconcile_revocation("credential-a", Some("org-a"), Some("losing request"))
            .await
            .expect("concurrent revocation must converge");

        assert_eq!(status.status, "revoked");
        assert_eq!(status.reason.as_deref(), Some("winning request"));
        assert_eq!(
            *harness.calls.lock().expect("calls"),
            [
                "load",
                "publish:revoke",
                "persist",
                "load",
                "publish:revoke",
                "canvas:revoke",
            ]
        );
        assert!(harness.events.lock().expect("events").is_empty());
    }

    #[tokio::test]
    async fn transaction_revocation_keeps_genuine_persistence_failures_closed() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        *harness.persist_failure.lock().expect("persist failure") =
            Some("database unavailable".to_owned());

        let error = harness
            .service()
            .reconcile_revocation("credential-a", Some("org-a"), Some("request"))
            .await
            .expect_err("an unchanged authoritative row must not mask persistence failure");

        assert_eq!(
            error,
            CredentialManagementError::RepositoryUnavailable("database unavailable".to_owned())
        );
        assert_eq!(
            *harness.calls.lock().expect("calls"),
            ["load", "publish:revoke", "persist", "load"]
        );
        assert_eq!(
            harness
                .credential
                .lock()
                .expect("credential")
                .as_ref()
                .expect("credential")
                .status,
            ManagedCredentialStatus::Active
        );
    }

    #[async_trait]
    impl CredentialStatusPublisher for Harness {
        async fn publish(
            &self,
            _credential: &ManagedCredential,
            action: CredentialLifecycleAction,
            _reason: Option<&str>,
        ) -> Result<(), CredentialManagementPortError> {
            self.calls
                .lock()
                .expect("calls")
                .push(format!("publish:{}", action.as_str()));
            if let Some(error) = self
                .publication_failure
                .lock()
                .expect("publication failure")
                .clone()
            {
                Err(CredentialManagementPortError(error))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl CredentialLifecycleEventSink for Harness {
        async fn emit(&self, event: CredentialLifecycleEvent) {
            self.calls.lock().expect("calls").push("event".to_owned());
            self.events.lock().expect("events").push(event);
        }
    }

    #[tokio::test]
    async fn mutations_follow_the_frozen_publication_and_event_order() {
        let cases = [
            (
                ManagedCredentialStatus::Active,
                CredentialLifecycleAction::Revoke,
                "revoked",
            ),
            (
                ManagedCredentialStatus::Active,
                CredentialLifecycleAction::Suspend,
                "suspended",
            ),
            (
                ManagedCredentialStatus::Suspended,
                CredentialLifecycleAction::Reinstate,
                "active",
            ),
        ];
        for (initial, action, expected_status) in cases {
            let harness = Harness::new(initial);
            let response = harness
                .service()
                .transition(
                    "credential-a",
                    Some("org-a"),
                    action,
                    Some("contract reason"),
                )
                .await
                .expect("transition");

            assert_eq!(response.status, expected_status);
            assert_eq!(response.reason.as_deref(), Some("contract reason"));
            assert_eq!(
                *harness.calls.lock().expect("calls"),
                [
                    "load",
                    &format!("publish:{}", action.as_str()),
                    "persist",
                    &format!("canvas:{}", action.as_str()),
                    "event",
                ]
            );
            let events = harness.events.lock().expect("events");
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].event_type, action.event_type());
            assert_eq!(events[0].status, expected_status);
        }
    }

    #[tokio::test]
    async fn publication_failure_is_fail_closed() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        *harness
            .publication_failure
            .lock()
            .expect("publication failure") = Some("offline".to_owned());

        let error = harness
            .service()
            .transition(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Revoke,
                None,
            )
            .await
            .expect_err("publication must fail closed");

        assert_eq!(
            error,
            CredentialManagementError::PublicationUnavailable("offline".to_owned())
        );
        assert_eq!(
            harness
                .credential
                .lock()
                .expect("credential")
                .as_ref()
                .expect("credential")
                .status,
            ManagedCredentialStatus::Active
        );
        assert_eq!(
            *harness.calls.lock().expect("calls"),
            ["load", "publish:revoke"]
        );
        assert!(harness.events.lock().expect("events").is_empty());
    }

    #[tokio::test]
    async fn wrong_organization_is_hidden_before_publication() {
        let harness = Harness::new(ManagedCredentialStatus::Active);

        let error = harness
            .service()
            .transition(
                "credential-a",
                Some("org-b"),
                CredentialLifecycleAction::Suspend,
                None,
            )
            .await
            .expect_err("organization must be hidden");

        assert_eq!(error, CredentialManagementError::ResourceNotFound);
        assert_eq!(*harness.calls.lock().expect("calls"), ["load"]);
    }

    #[tokio::test]
    async fn transition_errors_match_the_language_neutral_contract() {
        let cases = [
            (
                ManagedCredentialStatus::Revoked,
                CredentialLifecycleAction::Revoke,
                CredentialManagementError::AlreadyRevoked,
            ),
            (
                ManagedCredentialStatus::Revoked,
                CredentialLifecycleAction::Suspend,
                CredentialManagementError::CannotSuspendRevoked,
            ),
            (
                ManagedCredentialStatus::Revoked,
                CredentialLifecycleAction::Reinstate,
                CredentialManagementError::CannotReinstateRevoked,
            ),
            (
                ManagedCredentialStatus::Active,
                CredentialLifecycleAction::Reinstate,
                CredentialManagementError::NotSuspended,
            ),
        ];
        for (status, action, expected) in cases {
            let harness = Harness::new(status);
            let error = harness
                .service()
                .transition("credential-a", None, action, None)
                .await
                .expect_err("invalid transition");
            assert_eq!(error, expected);
            assert_eq!(*harness.calls.lock().expect("calls"), ["load"]);
        }
    }

    #[tokio::test]
    async fn canvas_retry_recording_failure_never_emits_a_success_event() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        *harness.canvas_failure.lock().expect("canvas failure") =
            Some("retry storage unavailable".to_owned());

        let error = harness
            .service()
            .transition(
                "credential-a",
                None,
                CredentialLifecycleAction::Suspend,
                None,
            )
            .await
            .expect_err("retry recording failure");

        assert_eq!(
            error,
            CredentialManagementError::CanvasRetryUnavailable(
                "retry storage unavailable".to_owned()
            )
        );
        assert_eq!(
            *harness.calls.lock().expect("calls"),
            ["load", "publish:suspend", "persist", "canvas:suspend"]
        );
        assert!(harness.events.lock().expect("events").is_empty());
    }

    #[tokio::test]
    async fn status_reads_are_side_effect_free_and_reasons_are_bounded() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        let view = harness
            .service()
            .get_status("credential-a", Some("org-a"))
            .await
            .expect("status");
        assert_eq!(view.status, "active");
        assert_eq!(*harness.calls.lock().expect("calls"), ["load"]);

        let harness = Harness::new(ManagedCredentialStatus::Active);
        let accepted = "\u{1f642}".repeat(MAX_REASON_CHARACTERS);
        harness
            .service()
            .transition(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Suspend,
                Some(&accepted),
            )
            .await
            .expect("2000 astral Unicode scalars");

        let harness = Harness::new(ManagedCredentialStatus::Active);
        let reason = "\u{1f642}".repeat(MAX_REASON_CHARACTERS + 1);
        let error = harness
            .service()
            .transition(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Suspend,
                Some(&reason),
            )
            .await
            .expect_err("reason must be bounded");
        assert_eq!(error, CredentialManagementError::ReasonTooLong);
        assert_eq!(*harness.calls.lock().expect("calls"), ["load"]);
    }

    #[tokio::test]
    async fn trusted_comments_and_actor_are_persisted_with_the_transition() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        let context = CredentialLifecycleAuditContext {
            comments: Some("Verified offboarding ticket HR-42".to_owned()),
            actor_id: Some("operator-7".to_owned()),
            actor_type: Some("user".to_owned()),
        };

        harness
            .service()
            .transition_with_context(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Revoke,
                Some("affiliationChanged"),
                &context,
            )
            .await
            .expect("transition");

        assert_eq!(
            *harness.audits.lock().expect("audits"),
            [CredentialLifecycleAuditRecord {
                action: CredentialLifecycleAction::Revoke,
                previous_status: ManagedCredentialStatus::Active,
                reason: Some("affiliationChanged".to_owned()),
                comments: context.comments,
                actor_id: context.actor_id,
                actor_type: context.actor_type,
            }]
        );
    }

    #[tokio::test]
    async fn comments_use_unicode_scalar_limits_before_publication() {
        let harness = Harness::new(ManagedCredentialStatus::Active);
        let accepted = "\u{1f642}".repeat(MAX_COMMENTS_CHARACTERS);
        harness
            .service()
            .transition_with_context(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Suspend,
                None,
                &CredentialLifecycleAuditContext {
                    comments: Some(accepted),
                    ..CredentialLifecycleAuditContext::default()
                },
            )
            .await
            .expect("4000 astral Unicode scalars");

        let harness = Harness::new(ManagedCredentialStatus::Active);
        let rejected = "\u{1f642}".repeat(MAX_COMMENTS_CHARACTERS + 1);
        let error = harness
            .service()
            .transition_with_context(
                "credential-a",
                Some("org-a"),
                CredentialLifecycleAction::Suspend,
                None,
                &CredentialLifecycleAuditContext {
                    comments: Some(rejected),
                    ..CredentialLifecycleAuditContext::default()
                },
            )
            .await
            .expect_err("4001 astral Unicode scalars");
        assert_eq!(error, CredentialManagementError::CommentsTooLong);
        assert_eq!(*harness.calls.lock().expect("calls"), ["load"]);
    }
}
