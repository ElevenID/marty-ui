//! Retained P03 delegated-use commands behind explicit trusted runtime ports.
//!
//! The durable claim precedes preparation/signing. An unresolved claim never
//! automatically retries external work. Flow commits through the provided
//! transaction, so its authoritative nonce consumption and this owner's result
//! are one local commit. There is no public HTTP or allow-all composition here.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::use_postgres::{PgDelegationUseRepository, RetainedUseOutcome};
use crate::{
    commands::{canonical_command_json, canonical_uuid},
    domain::{valid_digest, valid_uri},
    BindingMethod, CommandGrantReference, DelegatedDecisionReceiptIssuer,
    DelegationAuthorityService, DelegationChallengeAdmission, DelegationChallengeIssuer,
    DelegationChallengeRequest, DelegationClock, DelegationCommandCaller, DelegationGrant,
    DelegationUseAuthorizer, DelegationUseEvaluation, DelegationUseRequest,
    IssuedDelegatedDecisionReceipt, Principal, SystemDelegationClock,
    VerifiedDelegationCommandAccess, DELEGATION_COMMAND_PROFILE, MAX_GRANT_REVISION,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationUseOperation {
    pub action: String,
    pub resource_id: String,
    pub audience: String,
    pub request_profile: String,
    pub request_digest: String,
}
impl DelegationUseOperation {
    fn validate(&self) -> bool {
        [
            &self.action,
            &self.resource_id,
            &self.audience,
            &self.request_profile,
        ]
        .into_iter()
        .all(|value| valid_uri(Some(value)))
            && valid_digest(Some(&self.request_digest))
    }
}

#[derive(Clone, Debug)]
pub enum DelegationUseIntent {
    Start {
        grant: CommandGrantReference,
        operation: DelegationUseOperation,
    },
    Finalize {
        challenge_id: Uuid,
        proof_submission_id: Uuid,
    },
}
impl DelegationUseIntent {
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Start { .. } => "START_USE",
            Self::Finalize { .. } => "FINALIZE_USE",
        }
    }
}

#[derive(Clone)]
pub struct DecodedDelegationUseMutation {
    pub(crate) command_id: Uuid,
    pub(crate) digest: String,
    pub(crate) document: Value,
    pub(crate) intent: DelegationUseIntent,
}
impl DecodedDelegationUseMutation {
    pub fn command_id(&self) -> Uuid {
        self.command_id
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn intent(&self) -> &DelegationUseIntent {
        &self.intent
    }
}

pub enum DecodedDelegationUseCommand {
    Mutation(DecodedDelegationUseMutation),
    Recover {
        original_command_id: Uuid,
        expected_command_digest: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationUseCommandError {
    #[error("delegated-use command is invalid")]
    InvalidCommand,
    #[error("delegated-use command access is denied")]
    AccessDenied,
    #[error("delegated-use command identity or retained state conflicts")]
    Conflict,
    #[error("original delegated-use preparation is unresolved; do not repeat external work")]
    PreparationPending,
    #[error("original delegated-use result not found; this does not prove no work is in progress")]
    ResultNotFound,
    #[error("delegated-use evidence or authorization is no longer live")]
    Expired,
    #[error("delegated-use command storage or preparation is unavailable")]
    Unavailable,
    #[error("delegated-use command profile is not supported")]
    Unsupported,
}

/// Separate decoder so the existing human command host does not accidentally
/// expose machine use when a library gains support. This shares the P03 digest
/// and command identity namespace with lifecycle commands.
pub fn decode_delegation_use_command(
    raw: &[u8],
) -> Result<DecodedDelegationUseCommand, DelegationUseCommandError> {
    let invalid = || DelegationUseCommandError::InvalidCommand;
    let document = crate::wire::read_document(raw).map_err(|_| invalid())?;
    let map = document.as_object().ok_or_else(invalid)?;
    if map.get("profile").and_then(Value::as_str) != Some(DELEGATION_COMMAND_PROFILE) {
        return Err(invalid());
    }
    let name = map
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let fields: &[&str] = match name {
        "START_USE" => &["profile", "command", "command_id", "grant", "operation"],
        "FINALIZE_USE" => &[
            "profile",
            "command",
            "command_id",
            "challenge_id",
            "proof_submission_id",
        ],
        "RECOVER_RESULT" => &[
            "profile",
            "command",
            "original_command_id",
            "expected_command_digest",
        ],
        _ => return Err(DelegationUseCommandError::Unsupported),
    };
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(invalid());
    }
    let uuid = |key: &str| canonical_uuid(&map[key]).map_err(|_| invalid());
    if name == "RECOVER_RESULT" {
        let digest = map["expected_command_digest"]
            .as_str()
            .ok_or_else(invalid)?;
        if !valid_digest(Some(digest)) {
            return Err(invalid());
        }
        return Ok(DecodedDelegationUseCommand::Recover {
            original_command_id: uuid("original_command_id")?,
            expected_command_digest: digest.into(),
        });
    }
    let command_id = uuid("command_id")?;
    let intent = if name == "START_USE" {
        let grant: CommandGrantReference =
            serde_json::from_value(map["grant"].clone()).map_err(|_| invalid())?;
        let operation: DelegationUseOperation =
            serde_json::from_value(map["operation"].clone()).map_err(|_| invalid())?;
        if grant.id.is_nil()
            || !(1..=MAX_GRANT_REVISION).contains(&grant.revision)
            || !valid_digest(Some(&grant.terms_digest))
            || !operation.validate()
            || serde_json::to_value(&grant).map_err(|_| invalid())? != map["grant"]
            || serde_json::to_value(&operation).map_err(|_| invalid())? != map["operation"]
        {
            return Err(invalid());
        }
        DelegationUseIntent::Start { grant, operation }
    } else {
        DelegationUseIntent::Finalize {
            challenge_id: uuid("challenge_id")?,
            proof_submission_id: uuid("proof_submission_id")?,
        }
    };
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(canonical_command_json(&document).map_err(|_| invalid())?)
    );
    Ok(DecodedDelegationUseCommand::Mutation(
        DecodedDelegationUseMutation {
            command_id,
            digest,
            document,
            intent,
        },
    ))
}

/// Flow-owned retained challenge correlation. This is an authenticated adapter
/// result, never a public DTO accepted from an operation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedUseChallengeSnapshot {
    pub organization_id: Uuid,
    pub challenge_id: Uuid,
    pub verifier_id: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedUseChallenge {
    pub organization_id: Uuid,
    pub challenge_id: Uuid,
    pub grant: DelegationGrant,
    pub operation: DelegationUseOperation,
    pub verifier_id: String,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The concrete Flow adapter holds its sealed prepared start. Its commit MUST
/// validate its independently pinned storage identity against this connection
/// and use only this transaction for the authoritative Flow write. No separate
/// commit, public mutable instance injection, or cross-database substitution.
#[async_trait]
pub trait PreparedUseChallenge: Send {
    fn snapshot(&self) -> &PreparedUseChallengeSnapshot;
    async fn revalidate(&mut self) -> Result<(), DelegationUseCommandError>;
    async fn commit(
        self: Box<Self>,
        transaction: &mut PgConnection,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationUseCommandError>;
}

/// The concrete Flow adapter locks and consumes the original Flow challenge and
/// stored proof submission through this connection. It checks exact retained
/// state, typed actor, nonce, proof digest and current definition before writing.
/// Returning success without consuming the authoritative Flow is not a qualified
/// implementation. The surrounding transaction also records the receipt/result.
#[async_trait]
pub trait PreparedUseFinalization: Send {
    async fn commit(
        self: Box<Self>,
        transaction: &mut PgConnection,
        evaluation: &DelegationUseEvaluation,
        receipt: &IssuedDelegatedDecisionReceipt,
        now: DateTime<Utc>,
    ) -> Result<(), DelegationUseCommandError>;
}

pub struct ResolvedUseProofSubmission {
    pub organization_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_submission_id: Uuid,
    pub actor: Principal,
    pub received_at: DateTime<Utc>,
    pub proof: Vec<u8>,
}

#[async_trait]
pub trait DelegationUseFlowOwner: Send + Sync {
    async fn prepare_start(
        &self,
        admission: DelegationChallengeAdmission,
    ) -> Result<Box<dyn PreparedUseChallenge>, DelegationUseCommandError>;
    async fn resolve_submission(
        &self,
        challenge: &RetainedUseChallenge,
        proof_submission_id: Uuid,
    ) -> Result<ResolvedUseProofSubmission, DelegationUseCommandError>;
    async fn prepare_finalization(
        &self,
        challenge: &RetainedUseChallenge,
        proof_submission_id: Uuid,
        proof_digest: &str,
    ) -> Result<Box<dyn PreparedUseFinalization>, DelegationUseCommandError>;
}

/// Separately qualified current authentication/permission source. No built-in
/// allow-all implementation. A historical read must use current access without
/// requiring the retained grant still be ACTIVE or its old proof still be live.
#[async_trait]
pub trait DelegationUseCommandAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationUseIntent,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError>;
    async fn authorize_recovery(
        &self,
        caller: &DelegationCommandCaller,
        original_grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum DelegationUseCommandResult {
    #[serde(rename = "CHALLENGE")]
    Challenge {
        challenge_id: Uuid,
        grant: CommandGrantReference,
        operation: DelegationUseOperation,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    #[serde(rename = "FINAL_USE")]
    FinalUse {
        challenge_id: Uuid,
        decision: String,
        receipt_ref: String,
        receipt_digest: String,
        recorded_at: DateTime<Utc>,
        authorization_expires_at: DateTime<Utc>,
        semantics: String,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationUseCommandResponse {
    pub profile: String,
    pub original_command_id: Uuid,
    pub command_digest: String,
    pub recovered: bool,
    pub result: DelegationUseCommandResult,
}

pub(crate) fn check_access(
    access: &VerifiedDelegationCommandAccess,
    started: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), DelegationUseCommandError> {
    if now < started
        || access.observed_at < started
        || access.observed_at > now
        || access.valid_until <= now
        || access
            .observed_at
            .checked_add_signed(Duration::seconds(30))
            .is_none_or(|end| access.valid_until > end)
    {
        return Err(DelegationUseCommandError::AccessDenied);
    }
    Ok(())
}

pub(crate) struct UseAccessGuard {
    pub caller: DelegationCommandCaller,
    pub command: DecodedDelegationUseMutation,
    pub grant: DelegationGrant,
    pub access: VerifiedDelegationCommandAccess,
    pub started: DateTime<Utc>,
    pub checked: DateTime<Utc>,
    pub clock: Arc<dyn DelegationClock>,
    pub authorizer: Arc<dyn DelegationUseCommandAuthorizer>,
}
impl UseAccessGuard {
    pub fn check(&self, now: DateTime<Utc>) -> Result<(), DelegationUseCommandError> {
        let current = self.clock.now();
        if now < self.checked
            || current < self.checked
            || now >= self.access.valid_until
            || current >= self.access.valid_until
        {
            return Err(DelegationUseCommandError::Expired);
        }
        Ok(())
    }
    pub async fn recheck(&mut self, now: DateTime<Utc>) -> Result<(), DelegationUseCommandError> {
        self.check(now)?;
        let start = self.clock.now();
        let fresh = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.authorizer
                .authorize(&self.caller, &self.command.intent, &self.grant, start),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        let checked = self.clock.now();
        check_access(&fresh, start, checked)?;
        self.access.valid_until = self.access.valid_until.min(fresh.valid_until);
        self.checked = checked;
        self.check(now.max(checked))
    }
}

/// Explicit internal composition. The authenticated actor source, Flow owner,
/// verifier/policy evaluator and managed signer all remain deployment-qualified
/// ports. The selected durable adapter supports KEY grants only.
pub struct DelegationUseCommandService {
    repository: PgDelegationUseRepository,
    lifecycle: Arc<DelegationAuthorityService>,
    challenges: Arc<DelegationChallengeIssuer>,
    evaluation: Arc<DelegationUseAuthorizer>,
    receipts: Arc<DelegatedDecisionReceiptIssuer>,
    flow: Arc<dyn DelegationUseFlowOwner>,
    access: Arc<dyn DelegationUseCommandAuthorizer>,
    clock: Arc<dyn DelegationClock>,
}

/// Authentication of a trusted service hop is an additional upper bound on
/// current source authorization. It never substitutes for that authorization.
struct AuthenticationBoundUseAuthorizer {
    inner: Arc<dyn DelegationUseCommandAuthorizer>,
    clock: Arc<dyn DelegationClock>,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
impl AuthenticationBoundUseAuthorizer {
    fn bound(
        &self,
        mut access: VerifiedDelegationCommandAccess,
        started: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        let now = self.clock.now();
        if now < started || now < self.observed_at || now >= self.expires_at {
            return Err(DelegationUseCommandError::Expired);
        }
        // Check the original source contract before shortening its deadline;
        // clamping must not make an overlong/unqualified source look valid.
        check_access(&access, started, now)?;
        access.valid_until = access.valid_until.min(self.expires_at);
        Ok(access)
    }
}
#[async_trait]
impl DelegationUseCommandAuthorizer for AuthenticationBoundUseAuthorizer {
    async fn authorize(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationUseIntent,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        let current = self.clock.now();
        if current < self.observed_at || current >= self.expires_at {
            return Err(DelegationUseCommandError::Expired);
        }
        self.bound(self.inner.authorize(caller, intent, grant, now).await?, now)
    }
    async fn authorize_recovery(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationUseCommandError> {
        let current = self.clock.now();
        if current < self.observed_at || current >= self.expires_at {
            return Err(DelegationUseCommandError::Expired);
        }
        self.bound(
            self.inner.authorize_recovery(caller, grant, now).await?,
            now,
        )
    }
}

impl DelegationUseCommandService {
    pub fn new(
        repository: PgDelegationUseRepository,
        lifecycle: Arc<DelegationAuthorityService>,
        challenges: Arc<DelegationChallengeIssuer>,
        evaluation: Arc<DelegationUseAuthorizer>,
        receipts: Arc<DelegatedDecisionReceiptIssuer>,
        flow: Arc<dyn DelegationUseFlowOwner>,
        access: Arc<dyn DelegationUseCommandAuthorizer>,
    ) -> Self {
        Self::with_clock(
            repository,
            lifecycle,
            challenges,
            evaluation,
            receipts,
            flow,
            access,
            Arc::new(SystemDelegationClock),
        )
    }
    pub fn with_clock(
        repository: PgDelegationUseRepository,
        lifecycle: Arc<DelegationAuthorityService>,
        challenges: Arc<DelegationChallengeIssuer>,
        evaluation: Arc<DelegationUseAuthorizer>,
        receipts: Arc<DelegatedDecisionReceiptIssuer>,
        flow: Arc<dyn DelegationUseFlowOwner>,
        access: Arc<dyn DelegationUseCommandAuthorizer>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            repository,
            lifecycle,
            challenges,
            evaluation,
            receipts,
            flow,
            access,
            clock,
        }
    }

    pub async fn execute(
        &self,
        caller: &DelegationCommandCaller,
        raw: &[u8],
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        self.execute_decoded(caller, decode_delegation_use_command(raw)?)
            .await
    }

    /// Selected only by the authenticated internal HTTP boundary. The original
    /// hop deadline reaches source rechecks, the ledger's commit deadline and
    /// its deferred database guard. No timeout cancels signing or COMMIT.
    pub(crate) async fn execute_before(
        &self,
        caller: &DelegationCommandCaller,
        raw: &[u8],
        observed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        let now = self.clock.now();
        if now < observed_at
            || now >= expires_at
            || observed_at
                .checked_add_signed(Duration::seconds(30))
                .is_none_or(|maximum| expires_at > maximum)
        {
            return Err(DelegationUseCommandError::Expired);
        }
        let scoped = Self {
            repository: self.repository.clone(),
            lifecycle: self.lifecycle.clone(),
            challenges: self.challenges.clone(),
            evaluation: self.evaluation.clone(),
            receipts: self.receipts.clone(),
            flow: self.flow.clone(),
            access: Arc::new(AuthenticationBoundUseAuthorizer {
                inner: self.access.clone(),
                clock: self.clock.clone(),
                observed_at,
                expires_at,
            }),
            clock: self.clock.clone(),
        };
        scoped.execute(caller, raw).await
    }
    pub async fn execute_decoded(
        &self,
        caller: &DelegationCommandCaller,
        command: DecodedDelegationUseCommand,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        match command {
            DecodedDelegationUseCommand::Recover {
                original_command_id,
                expected_command_digest,
            } => {
                let original = self
                    .repository
                    .original(caller, original_command_id)
                    .await?
                    .ok_or(DelegationUseCommandError::ResultNotFound)?;
                self.recover(caller, original, &expected_command_digest)
                    .await
            }
            DecodedDelegationUseCommand::Mutation(command) => {
                if let Some(original) = self.repository.original(caller, command.command_id).await?
                {
                    return self.recover(caller, original, &command.digest).await;
                }
                match command.intent.clone() {
                    DelegationUseIntent::Start { grant, operation } => {
                        self.start(caller, command, grant, operation).await
                    }
                    DelegationUseIntent::Finalize {
                        challenge_id,
                        proof_submission_id,
                    } => {
                        self.finalize(caller, command, challenge_id, proof_submission_id)
                            .await
                    }
                }
            }
        }
    }
    async fn recover(
        &self,
        caller: &DelegationCommandCaller,
        original: RetainedUseOutcome,
        expected: &str,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        // Current visibility is checked even for mismatched digests and pending
        // claims, avoiding an unauthenticated original-result existence oracle.
        let started = self.clock.now();
        let access = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.access
                .authorize_recovery(caller, &original.grant, started),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        check_access(&access, started, self.clock.now())?;
        if original.command.digest != expected {
            return Err(DelegationUseCommandError::Conflict);
        }
        let mut response = original
            .response
            .ok_or(DelegationUseCommandError::PreparationPending)?;
        response.recovered = true;
        Ok(response)
    }
    async fn guard(
        &self,
        caller: &DelegationCommandCaller,
        command: DecodedDelegationUseMutation,
        grant: DelegationGrant,
    ) -> Result<UseAccessGuard, DelegationUseCommandError> {
        if grant.organization_id != caller.organization_id()
            || &grant.terms.delegate != caller.actor()
        {
            return Err(DelegationUseCommandError::AccessDenied);
        }
        if grant.terms.binding.method != BindingMethod::Key {
            return Err(DelegationUseCommandError::Unsupported);
        }
        let started = self.clock.now();
        let access = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.access
                .authorize(caller, &command.intent, &grant, started),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        let checked = self.clock.now();
        check_access(&access, started, checked)?;
        Ok(UseAccessGuard {
            caller: caller.clone(),
            command,
            grant,
            access,
            started,
            checked,
            clock: self.clock.clone(),
            authorizer: self.access.clone(),
        })
    }
    async fn start(
        &self,
        caller: &DelegationCommandCaller,
        command: DecodedDelegationUseMutation,
        reference: CommandGrantReference,
        operation: DelegationUseOperation,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        let admission = self
            .challenges
            .admit(
                caller.organization_id(),
                caller.actor(),
                DelegationChallengeRequest {
                    grant_id: reference.id,
                    expected_revision: reference.revision,
                    action: operation.action.clone(),
                    audience: operation.audience.clone(),
                    resource: operation.resource_id.clone(),
                    operation_profile: operation.request_profile.clone(),
                    operation_digest: operation.request_digest.clone(),
                },
            )
            .await
            .map_err(|_| DelegationUseCommandError::AccessDenied)?;
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.lifecycle
                .resolve_verified(caller.organization_id(), reference.id),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)?
        .map_err(|_| DelegationUseCommandError::AccessDenied)?;
        if resolved.grant.id != reference.id
            || resolved.grant.revision != reference.revision
            || resolved.grant.terms_digest != reference.terms_digest
        {
            return Err(DelegationUseCommandError::Conflict);
        }
        let challenge_id = admission.binding().challenge_id;
        let deadline = admission.valid_until().min(resolved.consent_valid_until);
        let mut guard = self.guard(caller, command, resolved.grant).await?;
        let claim = match self.repository.claim(&mut guard, challenge_id).await? {
            crate::use_postgres::ClaimResult::New(claim) => claim,
            crate::use_postgres::ClaimResult::Existing(original) => {
                return self.recover(caller, original, &guard.command.digest).await
            }
        };
        guard.check(self.clock.now())?;
        // No timeout surrounds side-effecting preparation. If the connection is
        // cancelled or the provider errors, the durable claim remains unresolved.
        let prepared = self.flow.prepare_start(admission).await?;
        self.repository
            .commit_start(claim, guard, &self.lifecycle, prepared, deadline)
            .await
    }
    async fn finalize(
        &self,
        caller: &DelegationCommandCaller,
        command: DecodedDelegationUseMutation,
        challenge_id: Uuid,
        proof_submission_id: Uuid,
    ) -> Result<DelegationUseCommandResponse, DelegationUseCommandError> {
        let challenge = self.repository.challenge(caller, challenge_id).await?;
        if self.clock.now() >= challenge.expires_at {
            return Err(DelegationUseCommandError::Expired);
        }
        let mut guard = self.guard(caller, command, challenge.grant.clone()).await?;
        let claim = match self.repository.claim(&mut guard, challenge_id).await? {
            crate::use_postgres::ClaimResult::New(claim) => claim,
            crate::use_postgres::ClaimResult::Existing(original) => {
                return self.recover(caller, original, &guard.command.digest).await
            }
        };
        guard.check(self.clock.now())?;
        let submission = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.flow
                .resolve_submission(&challenge, proof_submission_id),
        )
        .await
        .map_err(|_| DelegationUseCommandError::Unavailable)??;
        guard.check(self.clock.now())?;
        let now = self.clock.now();
        if submission.organization_id != caller.organization_id()
            || submission.challenge_id != challenge_id
            || submission.proof_submission_id != proof_submission_id
            || &submission.actor != caller.actor()
            || submission.received_at < challenge.created_at
            || submission.received_at > now
            || submission.proof.is_empty()
            || submission.proof.len() > crate::MAX_DELEGATE_PROOF_BYTES
            || now >= challenge.expires_at
        {
            return Err(DelegationUseCommandError::InvalidCommand);
        }
        let proof_digest = format!("sha256:{:x}", Sha256::digest(&submission.proof));
        let request = DelegationUseRequest {
            organization_id: caller.organization_id(),
            grant_id: challenge.grant.id,
            expected_revision: challenge.grant.revision,
            challenge_id,
            actor: caller.actor().clone(),
            action: challenge.operation.action.clone(),
            audience: challenge.operation.audience.clone(),
            resource: challenge.operation.resource_id.clone(),
            operation_profile: challenge.operation.request_profile.clone(),
            operation_digest: challenge.operation.request_digest.clone(),
            proof: submission.proof,
        };
        let evaluation = self
            .evaluation
            .evaluate_decision(&request)
            .await
            .map_err(|_| DelegationUseCommandError::AccessDenied)?;
        guard.check(self.clock.now())?;
        let prepared = self
            .flow
            .prepare_finalization(&challenge, proof_submission_id, &proof_digest)
            .await?;
        guard.check(self.clock.now())?;
        // Exactly one invocation for this retained finalization identity. Failure
        // leaves Pending, never an automatic re-sign or a synthetic DENY receipt.
        let receipt = self
            .receipts
            .issue(&evaluation, self.clock.now())
            .await
            .map_err(|_| DelegationUseCommandError::Unavailable)?;
        self.repository
            .commit_final(
                claim,
                guard,
                &self.lifecycle,
                &challenge,
                evaluation,
                receipt,
                &proof_digest,
                prepared,
            )
            .await
    }
}

#[cfg(test)]
mod tests;
