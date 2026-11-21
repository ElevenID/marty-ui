//! P03 lifecycle command intent, atomic outcomes and historical recovery.
//!
//! This is an internal application boundary, not authentication or a public route.
//! Caller identity and authorization/confirmation providers must be established by
//! a separately qualified runtime. START_USE and FINALIZE_USE remain unsupported.
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    domain::{valid_digest, valid_uri},
    service::PreparedLifecycleMutation,
    ApprovalEvidence, DelegationAuthorityService, DelegationGrant, GrantStatus, GrantTerms,
    Principal, RepositoryError, MAX_GRANT_REVISION,
};

pub const DELEGATION_COMMAND_PROFILE: &str = "urn:marty:delegation-command:v1";
pub const DELEGATION_COMMAND_RESPONSE_PROFILE: &str = "urn:marty:delegation-command-response:v1";

/// The runtime authenticates both fields independently. This constructor performs
/// shape validation only; neither it nor a schema-shaped principal authenticates.
/// No Deserialize implementation may turn command-body fields into this context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationCommandCaller {
    organization_id: Uuid,
    actor: Principal,
}
impl DelegationCommandCaller {
    pub fn from_authenticated_context(
        organization_id: Uuid,
        actor: Principal,
    ) -> Result<Self, DelegationCommandError> {
        if organization_id.is_nil() || !valid_uri(Some(&actor.id)) {
            return Err(DelegationCommandError::AccessDenied);
        }
        Ok(Self {
            organization_id,
            actor,
        })
    }
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn actor(&self) -> &Principal {
        &self.actor
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandGrantReference {
    pub id: Uuid,
    pub revision: u64,
    pub terms_digest: String,
}
impl CommandGrantReference {
    fn matches(&self, grant: &DelegationGrant) -> bool {
        self.id == grant.id
            && self.revision == grant.revision
            && self.terms_digest == grant.terms_digest
    }
}

#[derive(Clone)]
pub enum DelegationMutation {
    Create {
        terms: GrantTerms,
    },
    Approve {
        grant: CommandGrantReference,
        confirmation_id: Uuid,
    },
    Suspend {
        grant: CommandGrantReference,
    },
    Reinstate {
        grant: CommandGrantReference,
    },
    Revoke {
        grant: CommandGrantReference,
    },
}
impl DelegationMutation {
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "CREATE_GRANT",
            Self::Approve { .. } => "APPROVE_GRANT",
            Self::Suspend { .. } => "SUSPEND_GRANT",
            Self::Reinstate { .. } => "REINSTATE_GRANT",
            Self::Revoke { .. } => "REVOKE_GRANT",
        }
    }
    pub fn grant_reference(&self) -> Option<&CommandGrantReference> {
        match self {
            Self::Create { .. } => None,
            Self::Approve { grant, .. }
            | Self::Suspend { grant }
            | Self::Reinstate { grant }
            | Self::Revoke { grant } => Some(grant),
        }
    }
}

/// A validated mutation retains its original JSON lexical values for equality.
/// It has no public constructor; successful decoding does not establish authority.
#[derive(Clone)]
pub struct DecodedDelegationMutation {
    pub(crate) command_id: Uuid,
    pub(crate) intent: DelegationMutation,
    pub(crate) document: Value,
    pub(crate) digest: String,
}
impl DecodedDelegationMutation {
    pub fn command_id(&self) -> Uuid {
        self.command_id
    }
    pub fn intent(&self) -> &DelegationMutation {
        &self.intent
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
pub enum DecodedDelegationCommand {
    Mutation(DecodedDelegationMutation),
    Recover {
        original_command_id: Uuid,
        expected_command_digest: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationCommandError {
    #[error("delegation command is invalid")]
    InvalidCommand,
    #[error("delegation command is not composed by this runtime")]
    UnsupportedCommand,
    #[error("delegation command access denied")]
    AccessDenied,
    #[error("delegation command identity or grant reference conflicts")]
    Conflict,
    #[error(
        "delegation original result was not found; this does not prove no work is in progress"
    )]
    ResultNotFound,
    #[error("delegation confirmation is not available from a trusted producer")]
    ConfirmationUnavailable,
    #[error("delegation lifecycle command was rejected")]
    LifecycleRejected,
    #[error("delegation command storage or authorization is unavailable")]
    Unavailable,
}

/// Reject duplicates, floats, explicit nulls, unknown fields and unsafe revisions
/// before calculating the P03 digest. UUID/time spellings use this Rust adapter's
/// canonical subset; unsupported spellings are rejected, never normalized first.
pub fn decode_delegation_command(
    raw: &[u8],
) -> Result<DecodedDelegationCommand, DelegationCommandError> {
    let invalid = || DelegationCommandError::InvalidCommand;
    let document = crate::wire::read_document(raw).map_err(|_| invalid())?;
    let map = document.as_object().ok_or_else(invalid)?;
    if map.get("profile").and_then(Value::as_str) != Some(DELEGATION_COMMAND_PROFILE) {
        return Err(invalid());
    }
    let command = map
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let fields: &[&str] = match command {
        "CREATE_GRANT" => &["profile", "command", "command_id", "terms"],
        "APPROVE_GRANT" => &[
            "profile",
            "command",
            "command_id",
            "grant",
            "confirmation_id",
        ],
        "SUSPEND_GRANT" | "REINSTATE_GRANT" | "REVOKE_GRANT" => {
            &["profile", "command", "command_id", "grant"]
        }
        "RECOVER_RESULT" => &[
            "profile",
            "command",
            "original_command_id",
            "expected_command_digest",
        ],
        "START_USE" | "FINALIZE_USE" => return Err(DelegationCommandError::UnsupportedCommand),
        _ => return Err(invalid()),
    };
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(invalid());
    }
    if command == "RECOVER_RESULT" {
        let original_command_id = canonical_uuid(&map["original_command_id"])?;
        let expected_command_digest = map["expected_command_digest"]
            .as_str()
            .ok_or_else(invalid)?;
        if !valid_digest(Some(expected_command_digest)) {
            return Err(invalid());
        }
        return Ok(DecodedDelegationCommand::Recover {
            original_command_id,
            expected_command_digest: expected_command_digest.into(),
        });
    }
    let command_id = canonical_uuid(&map["command_id"])?;
    let intent = if command == "CREATE_GRANT" {
        let terms: GrantTerms =
            serde_json::from_value(map["terms"].clone()).map_err(|_| invalid())?;
        terms.validate().map_err(|_| invalid())?;
        if serde_json::to_value(&terms).map_err(|_| invalid())? != map["terms"] {
            return Err(invalid());
        }
        DelegationMutation::Create { terms }
    } else {
        let value = &map["grant"];
        let grant: CommandGrantReference =
            serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if grant.id.is_nil()
            || !(1..=MAX_GRANT_REVISION).contains(&grant.revision)
            || !valid_digest(Some(&grant.terms_digest))
            || serde_json::to_value(&grant).map_err(|_| invalid())? != *value
        {
            return Err(invalid());
        }
        match command {
            "APPROVE_GRANT" => DelegationMutation::Approve {
                grant,
                confirmation_id: canonical_uuid(&map["confirmation_id"])?,
            },
            "SUSPEND_GRANT" => DelegationMutation::Suspend { grant },
            "REINSTATE_GRANT" => DelegationMutation::Reinstate { grant },
            "REVOKE_GRANT" => DelegationMutation::Revoke { grant },
            _ => return Err(invalid()),
        }
    };
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(canonical_command_json(&document)?)
    );
    Ok(DecodedDelegationCommand::Mutation(
        DecodedDelegationMutation {
            command_id,
            intent,
            document,
            digest,
        },
    ))
}

fn canonical_uuid(value: &Value) -> Result<Uuid, DelegationCommandError> {
    let text = value
        .as_str()
        .ok_or(DelegationCommandError::InvalidCommand)?;
    let id = Uuid::parse_str(text).map_err(|_| DelegationCommandError::InvalidCommand)?;
    if id.is_nil() || id.to_string() != text {
        return Err(DelegationCommandError::InvalidCommand);
    }
    Ok(id)
}

// RFC 8785 subset for this exact schema: the only numeric field is an unsigned,
// JSON-safe revision. This is not a canonicalizer for arbitrary JSON documents.
fn canonical_command_json(value: &Value) -> Result<Vec<u8>, DelegationCommandError> {
    let invalid = || DelegationCommandError::InvalidCommand;
    match value {
        Value::Number(n) => n
            .as_u64()
            .filter(|n| *n <= MAX_GRANT_REVISION)
            .map(|n| n.to_string().into_bytes())
            .ok_or_else(invalid),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let mut bytes = vec![b'{'];
            for (index, key) in keys.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                bytes.extend(serde_json::to_vec(key).map_err(|_| invalid())?);
                bytes.push(b':');
                bytes.extend(canonical_command_json(&map[*key])?);
            }
            bytes.push(b'}');
            Ok(bytes)
        }
        Value::Array(values) => {
            let mut bytes = vec![b'['];
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                bytes.extend(canonical_command_json(item)?);
            }
            bytes.push(b']');
            Ok(bytes)
        }
        Value::Null => Err(invalid()),
        _ => serde_json::to_vec(value).map_err(|_| invalid()),
    }
}

/// A fresh decision from the configured authorization owner, never a public
/// command field. The runtime must qualify the owner's revocation/freshness
/// guarantees; the local commit cannot lock an external authorization source.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedDelegationCommandAccess {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}
impl VerifiedDelegationCommandAccess {
    fn check(
        &self,
        started_at: DateTime<Utc>,
        current: DateTime<Utc>,
    ) -> Result<(), DelegationCommandError> {
        if current < started_at
            || self.observed_at < started_at
            || self.observed_at > current
            || self.valid_until <= current
            || self
                .observed_at
                .checked_add_signed(Duration::seconds(30))
                .is_none_or(|limit| self.valid_until > limit)
        {
            return Err(DelegationCommandError::AccessDenied);
        }
        Ok(())
    }
}

/// Required trusted port. Implementations authenticate their own policy sources.
/// No default allow-all authorizer is provided. Historical reads must check the
/// current tenant/typed actor/resource permissions, not the old grant's ACTIVE state.
#[async_trait]
pub trait DelegationCommandAuthorizer: Send + Sync {
    async fn authorize_mutation(
        &self,
        caller: &DelegationCommandCaller,
        intent: &DelegationMutation,
        current: Option<&DelegationGrant>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError>;
    async fn authorize_result_read(
        &self,
        caller: &DelegationCommandCaller,
        original_grant: &DelegationGrant,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegationCommandAccess, DelegationCommandAccessError>;
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("delegation command access was not authorized")]
pub struct DelegationCommandAccessError;

/// Resolve only an independently authenticated exact-terms confirmation. The
/// confirmation identifier must never be fetched as an arbitrary URI or retargeted.
/// This read-only provider is separate from current representation authority,
/// which the existing ConsentEvidenceVerifier still verifies during activation.
#[async_trait]
pub trait DelegationConfirmationSource: Send + Sync {
    async fn resolve_confirmation(
        &self,
        caller: &DelegationCommandCaller,
        grant: &DelegationGrant,
        confirmation_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ApprovalEvidence, DelegationConfirmationError>;
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("trusted delegation confirmation is unavailable")]
pub struct DelegationConfirmationError;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DelegationCommandIdentity {
    pub(crate) organization_id: Uuid,
    pub(crate) actor: Principal,
    pub(crate) command_id: Uuid,
}
impl DelegationCommandIdentity {
    fn new(caller: &DelegationCommandCaller, command_id: Uuid) -> Self {
        Self {
            organization_id: caller.organization_id,
            actor: caller.actor.clone(),
            command_id,
        }
    }
    pub(crate) fn lock_key(&self) -> Result<i64, RepositoryError> {
        let bytes = serde_json::to_vec(&(self.organization_id, &self.actor, self.command_id))
            .map_err(|_| RepositoryError::CorruptData)?;
        let digest = Sha256::digest(bytes);
        Ok(i64::from_be_bytes(
            digest[..8]
                .try_into()
                .map_err(|_| RepositoryError::CorruptData)?,
        ))
    }
}

/// Immutable historical outcome. Construction is restricted to the validated
/// lifecycle/command transaction and strict stored-record decoder.
#[derive(Clone)]
pub struct StoredDelegationCommandResult {
    pub(crate) identity: DelegationCommandIdentity,
    pub(crate) command: DecodedDelegationMutation,
    pub(crate) grant: DelegationGrant,
}
impl StoredDelegationCommandResult {
    pub(crate) fn validate(&self) -> Result<(), RepositoryError> {
        self.grant
            .validate()
            .map_err(|_| RepositoryError::CorruptData)?;
        if self.identity.organization_id != self.grant.organization_id
            || self.identity.command_id != self.command.command_id
        {
            return Err(RepositoryError::CorruptData);
        }
        let raw =
            serde_json::to_vec(&self.command.document).map_err(|_| RepositoryError::CorruptData)?;
        let DecodedDelegationCommand::Mutation(decoded) =
            decode_delegation_command(&raw).map_err(|_| RepositoryError::CorruptData)?
        else {
            return Err(RepositoryError::CorruptData);
        };
        if decoded.digest != self.command.digest {
            return Err(RepositoryError::CorruptData);
        }
        let expected_status = match &decoded.intent {
            DelegationMutation::Create { terms } => {
                if self.grant.revision != 1 || &self.grant.terms != terms {
                    return Err(RepositoryError::CorruptData);
                }
                GrantStatus::Pending
            }
            intent => {
                let reference = intent
                    .grant_reference()
                    .ok_or(RepositoryError::CorruptData)?;
                if reference.id != self.grant.id
                    || reference.terms_digest != self.grant.terms_digest
                    || reference.revision.checked_add(1) != Some(self.grant.revision)
                {
                    return Err(RepositoryError::CorruptData);
                }
                match intent {
                    DelegationMutation::Approve { .. } => {
                        if self
                            .grant
                            .approval
                            .as_ref()
                            .is_none_or(|a| a.approver != self.identity.actor)
                        {
                            return Err(RepositoryError::CorruptData);
                        }
                        GrantStatus::Active
                    }
                    DelegationMutation::Reinstate { .. } => GrantStatus::Active,
                    DelegationMutation::Suspend { .. } => GrantStatus::Suspended,
                    DelegationMutation::Revoke { .. } => GrantStatus::Revoked,
                    _ => return Err(RepositoryError::CorruptData),
                }
            }
        };
        if self.grant.status != expected_status {
            return Err(RepositoryError::CorruptData);
        }
        Ok(())
    }
    fn response(&self, recovered: bool) -> DelegationCommandResponse {
        DelegationCommandResponse {
            profile: DELEGATION_COMMAND_RESPONSE_PROFILE,
            original_command_id: self.identity.command_id,
            command_digest: self.command.digest.clone(),
            recovered,
            result: DelegationCommandResult::GrantSnapshot {
                grant: self.grant.clone(),
            },
        }
    }
}

/// Opaque preparation accepted by the repository's single atomic write boundary.
/// This cannot be constructed/deserialized by a network consumer.
pub struct PreparedDelegationCommand {
    pub(crate) result: StoredDelegationCommandResult,
    pub(crate) mutation: PreparedLifecycleMutation,
    access: VerifiedDelegationCommandAccess,
    access_checked_at: DateTime<Utc>,
    prepared_at: DateTime<Utc>,
    clock: Arc<dyn crate::DelegationClock>,
}
impl PreparedDelegationCommand {
    pub(crate) fn check_access(
        &self,
        database_now: Option<DateTime<Utc>>,
    ) -> Result<(), RepositoryError> {
        for now in std::iter::once(self.clock.now()).chain(database_now) {
            if now < self.prepared_at || now < self.mutation.grant.updated_at {
                return Err(RepositoryError::CommandAccessExpired);
            }
            self.access
                .check(self.access_checked_at, now)
                .map_err(|_| RepositoryError::CommandAccessExpired)?;
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct CommittedDelegationCommand {
    pub(crate) result: StoredDelegationCommandResult,
    pub(crate) recovered: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct DelegationCommandResponse {
    pub profile: &'static str,
    pub original_command_id: Uuid,
    pub command_digest: String,
    pub recovered: bool,
    pub result: DelegationCommandResult,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationCommandResult {
    GrantSnapshot { grant: DelegationGrant },
}

#[derive(Clone)]
pub struct DelegationCommandService {
    lifecycle: Arc<DelegationAuthorityService>,
    authorizer: Arc<dyn DelegationCommandAuthorizer>,
    confirmations: Option<Arc<dyn DelegationConfirmationSource>>,
}
impl DelegationCommandService {
    pub fn new(
        lifecycle: Arc<DelegationAuthorityService>,
        authorizer: Arc<dyn DelegationCommandAuthorizer>,
        confirmations: Option<Arc<dyn DelegationConfirmationSource>>,
    ) -> Self {
        Self {
            lifecycle,
            authorizer,
            confirmations,
        }
    }
    pub async fn execute(
        &self,
        caller: &DelegationCommandCaller,
        raw: &[u8],
    ) -> Result<DelegationCommandResponse, DelegationCommandError> {
        match decode_delegation_command(raw)? {
            DecodedDelegationCommand::Recover {
                original_command_id,
                expected_command_digest,
            } => self
                .recover(
                    caller,
                    &DelegationCommandIdentity::new(caller, original_command_id),
                    &expected_command_digest,
                )
                .await?
                .ok_or(DelegationCommandError::ResultNotFound),
            DecodedDelegationCommand::Mutation(command) => {
                let identity = DelegationCommandIdentity::new(caller, command.command_id);
                if let Some(original) = self.recover(caller, &identity, &command.digest).await? {
                    return Ok(original);
                }
                // Only read-only preparation is cancelled. Never cancel COMMIT
                // on an application timeout and infer that it rolled back.
                let work = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    self.prepare(caller, &command),
                )
                .await
                .unwrap_or(Err(DelegationCommandError::Unavailable));
                let prepared = match work {
                    Ok((mutation, access, access_checked_at, prepared_at)) => {
                        PreparedDelegationCommand {
                            result: StoredDelegationCommandResult {
                                identity: identity.clone(),
                                command: command.clone(),
                                grant: mutation.grant.clone(),
                            },
                            mutation,
                            access,
                            access_checked_at,
                            prepared_at,
                            clock: self.lifecycle.command_clock(),
                        }
                    }
                    Err(error) => {
                        // A competing identical command may have committed while this
                        // read-only preparation observed its newer grant revision.
                        return self
                            .recover(caller, &identity, &command.digest)
                            .await?
                            .ok_or(error);
                    }
                };
                match self.lifecycle.repository().commit_command(prepared).await {
                    Ok(committed) => {
                        self.check_read(caller, &committed.result).await?;
                        Ok(committed.result.response(committed.recovered))
                    }
                    Err(error) => {
                        if let Some(original) =
                            self.recover(caller, &identity, &command.digest).await?
                        {
                            return Ok(original);
                        }
                        Err(match error {
                            RepositoryError::RevisionConflict
                            | RepositoryError::CommandConflict => DelegationCommandError::Conflict,
                            _ => DelegationCommandError::Unavailable,
                        })
                    }
                }
            }
        }
    }
    async fn check_read(
        &self,
        caller: &DelegationCommandCaller,
        stored: &StoredDelegationCommandResult,
    ) -> Result<(), DelegationCommandError> {
        if stored.identity.organization_id != caller.organization_id
            || stored.identity.actor != caller.actor
        {
            return Err(DelegationCommandError::AccessDenied);
        }
        stored
            .validate()
            .map_err(|_| DelegationCommandError::Unavailable)?;
        let started_at = self.lifecycle.trusted_now();
        let access = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.authorizer
                .authorize_result_read(caller, &stored.grant, started_at),
        )
        .await
        .map_err(|_| DelegationCommandError::Unavailable)?
        .map_err(|_| DelegationCommandError::AccessDenied)?;
        access.check(started_at, self.lifecycle.trusted_now())
    }
    async fn recover(
        &self,
        caller: &DelegationCommandCaller,
        identity: &DelegationCommandIdentity,
        digest: &str,
    ) -> Result<Option<DelegationCommandResponse>, DelegationCommandError> {
        let Some(stored) = self
            .lifecycle
            .repository()
            .command_result(identity)
            .await
            .map_err(|_| DelegationCommandError::Unavailable)?
        else {
            return Ok(None);
        };
        self.check_read(caller, &stored).await?;
        if stored.command.digest != digest {
            return Err(DelegationCommandError::Conflict);
        }
        Ok(Some(stored.response(true)))
    }
    async fn prepare(
        &self,
        caller: &DelegationCommandCaller,
        command: &DecodedDelegationMutation,
    ) -> Result<
        (
            PreparedLifecycleMutation,
            VerifiedDelegationCommandAccess,
            DateTime<Utc>,
            DateTime<Utc>,
        ),
        DelegationCommandError,
    > {
        let started_at = self.lifecycle.trusted_now();
        let current = if let Some(reference) = command.intent.grant_reference() {
            let grant = self
                .lifecycle
                .command_grant(caller.organization_id, reference.id)
                .await
                .map_err(|_| DelegationCommandError::LifecycleRejected)?;
            Some(grant)
        } else {
            None
        };
        let authorization_started_at = self.lifecycle.trusted_now();
        if authorization_started_at < started_at {
            return Err(DelegationCommandError::LifecycleRejected);
        }
        let access = self
            .authorizer
            .authorize_mutation(
                caller,
                &command.intent,
                current.as_ref(),
                authorization_started_at,
            )
            .await
            .map_err(|_| DelegationCommandError::AccessDenied)?;
        access.check(authorization_started_at, self.lifecycle.trusted_now())?;
        // Access to this resource is checked before disclosing revision/digest
        // mismatch. Shape validation alone never authorizes conflict inspection.
        if command.intent.grant_reference().is_some_and(|reference| {
            current
                .as_ref()
                .is_none_or(|grant| !reference.matches(grant))
        }) {
            return Err(DelegationCommandError::Conflict);
        }
        let prepared = match &command.intent {
            DelegationMutation::Create { terms } => {
                self.lifecycle
                    .prepare_propose(caller.organization_id, terms.clone())
                    .await
            }
            DelegationMutation::Approve {
                grant,
                confirmation_id,
            } => {
                let current = current
                    .as_ref()
                    .ok_or(DelegationCommandError::LifecycleRejected)?;
                if caller.actor != current.terms.grantor {
                    return Err(DelegationCommandError::AccessDenied);
                }
                let source = self
                    .confirmations
                    .as_ref()
                    .ok_or(DelegationCommandError::ConfirmationUnavailable)?;
                let evidence = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    source.resolve_confirmation(
                        caller,
                        current,
                        *confirmation_id,
                        self.lifecycle.trusted_now(),
                    ),
                )
                .await
                .map_err(|_| DelegationCommandError::ConfirmationUnavailable)?
                .map_err(|_| DelegationCommandError::ConfirmationUnavailable)?;
                self.lifecycle
                    .prepare_approve(
                        caller.organization_id,
                        grant.id,
                        grant.revision,
                        &caller.actor,
                        evidence,
                    )
                    .await
            }
            DelegationMutation::Suspend { grant } => {
                self.lifecycle
                    .prepare_suspend(caller.organization_id, grant.id, grant.revision)
                    .await
            }
            DelegationMutation::Reinstate { grant } => {
                self.lifecycle
                    .prepare_reinstate(caller.organization_id, grant.id, grant.revision)
                    .await
            }
            DelegationMutation::Revoke { grant } => {
                self.lifecycle
                    .prepare_revoke(caller.organization_id, grant.id, grant.revision)
                    .await
            }
        }
        .map_err(|_| DelegationCommandError::LifecycleRejected)?;
        if command.intent.grant_reference().is_some_and(|reference| {
            prepared
                .previous
                .as_ref()
                .is_none_or(|previous| !reference.matches(previous))
        }) {
            return Err(DelegationCommandError::Conflict);
        }
        let current_time = self.lifecycle.trusted_now();
        if current_time < started_at
            || prepared.grant.updated_at < started_at
            || current_time < prepared.grant.updated_at
        {
            return Err(DelegationCommandError::LifecycleRejected);
        }
        access.check(authorization_started_at, current_time)?;
        Ok((prepared, access, authorization_started_at, current_time))
    }
}

#[cfg(test)]
mod tests;
