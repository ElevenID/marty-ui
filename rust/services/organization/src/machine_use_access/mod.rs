//! Explicit current access to Marty delegated-use entrypoints for full machines.
//! This owner does not authenticate a network caller or grant Rifare domain rights.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod owner;
mod source;
pub use owner::MachineUseAccessOwner;
pub use source::{
    validate_machine_use_access_schema, CurrentMachineUseAccess, PgMachineUseAccessSource,
};

pub const MACHINE_USE_ACCESS_MIGRATION: &str = "rust_organization_machine_use_access_0007";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MachineUseAccessError {
    #[error("machine use access request is invalid")]
    Invalid,
    #[error("machine use access is denied")]
    AccessDenied,
    #[error("machine use access revision or state conflicts")]
    Conflict,
    #[error("machine use access is unavailable")]
    Unavailable,
}
pub(super) use MachineUseAccessError as Error;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MachineUsePermission {
    StartUse,
    FinalizeUse,
    RecoverResult,
    RetrieveRequest,
    SubmitProof,
}
impl MachineUsePermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartUse => "START_USE",
            Self::FinalizeUse => "FINALIZE_USE",
            Self::RecoverResult => "RECOVER_RESULT",
            Self::RetrieveRequest => "RETRIEVE_REQUEST",
            Self::SubmitProof => "SUBMIT_PROOF",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MachineUseAccessInput {
    pub permissions: Vec<MachineUsePermission>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}
impl MachineUseAccessInput {
    fn validate(&self) -> Result<(), Error> {
        let unique: std::collections::BTreeSet<_> = self.permissions.iter().collect();
        if self.permissions.is_empty()
            || self.permissions.len() > 5
            || unique.len() != self.permissions.len()
            || self.valid_until <= self.valid_from
            || self.valid_from.timestamp_subsec_nanos() % 1000 != 0
            || self.valid_until.timestamp_subsec_nanos() % 1000 != 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Administrative history is inspectable but is never a current access permit.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineUseAccessRecord {
    pub organization_id: Uuid,
    pub machine_identity_id: Uuid,
    pub deployment_profile_id: Uuid,
    pub principal_id: String,
    pub revision: u64,
    pub status: String,
    pub permissions: Vec<MachineUsePermission>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl MachineUseAccessRecord {
    fn validate(&self) -> Result<(), Error> {
        if self.organization_id.is_nil()
            || self.machine_identity_id.is_nil()
            || self.deployment_profile_id.is_nil()
            || !valid_uri(&self.principal_id)
            || !valid_revision(self.revision)
            || !matches!(self.status.as_str(), "ACTIVE" | "REVOKED")
            || self.created_by.is_empty()
            || self.created_by.len() > 255
            || self.created_by.chars().any(char::is_control)
            || self.updated_at < self.created_at
        {
            return Err(Error::Invalid);
        }
        MachineUseAccessInput {
            permissions: self.permissions.clone(),
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
        .validate()
    }
}

/// Deployment selection is trusted configuration and cannot be supplied by a
/// command or proof body. A source is pinned to exactly one tenant/deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachineUseAccessSelection {
    organization_id: Uuid,
    deployment_profile_id: Uuid,
}
impl MachineUseAccessSelection {
    pub fn new(organization_id: Uuid, deployment_profile_id: Uuid) -> Result<Self, Error> {
        if organization_id.is_nil() || deployment_profile_id.is_nil() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            organization_id,
            deployment_profile_id,
        })
    }
    pub fn organization_id(self) -> Uuid {
        self.organization_id
    }
    pub fn deployment_profile_id(self) -> Uuid {
        self.deployment_profile_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineUseAccessRequest {
    Start {
        grant_id: Uuid,
        grant_revision: u64,
        terms_digest: String,
        key_thumbprint: String,
    },
    Finalize {
        grant_id: Uuid,
        grant_revision: u64,
        terms_digest: String,
        key_thumbprint: String,
        challenge_id: Uuid,
    },
    Recover {
        grant_id: Uuid,
        grant_revision: u64,
        terms_digest: String,
    },
    RequestRead {
        challenge_id: Uuid,
    },
    ProofSubmit {
        challenge_id: Uuid,
    },
}
impl MachineUseAccessRequest {
    pub fn permission(&self) -> MachineUsePermission {
        match self {
            Self::Start { .. } => MachineUsePermission::StartUse,
            Self::Finalize { .. } => MachineUsePermission::FinalizeUse,
            Self::Recover { .. } => MachineUsePermission::RecoverResult,
            Self::RequestRead { .. } => MachineUsePermission::RetrieveRequest,
            Self::ProofSubmit { .. } => MachineUsePermission::SubmitProof,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Start {
                grant_id,
                grant_revision,
                terms_digest,
                key_thumbprint,
            }
            | Self::Finalize {
                grant_id,
                grant_revision,
                terms_digest,
                key_thumbprint,
                ..
            } => {
                if grant_id.is_nil()
                    || !valid_revision(*grant_revision)
                    || !valid_digest(terms_digest)
                    || !valid_digest(key_thumbprint)
                {
                    return Err(Error::Invalid);
                }
            }
            Self::Recover {
                grant_id,
                grant_revision,
                terms_digest,
            } => {
                if grant_id.is_nil()
                    || !valid_revision(*grant_revision)
                    || !valid_digest(terms_digest)
                {
                    return Err(Error::Invalid);
                }
            }
            _ => {}
        }
        if match self {
            Self::Finalize { challenge_id, .. }
            | Self::RequestRead { challenge_id }
            | Self::ProofSubmit { challenge_id } => challenge_id.is_nil(),
            _ => false,
        } {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn expected_key(&self) -> Option<&str> {
        match self {
            Self::Start { key_thumbprint, .. } | Self::Finalize { key_thumbprint, .. } => {
                Some(key_thumbprint)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineUseAccessScope {
    pub organization_id: Uuid,
    pub principal_id: String,
    pub request: MachineUseAccessRequest,
}
impl MachineUseAccessScope {
    fn validate(&self, selection: MachineUseAccessSelection) -> Result<(), Error> {
        if self.organization_id != selection.organization_id || !valid_uri(&self.principal_id) {
            return Err(Error::Invalid);
        }
        self.request.validate()
    }
}

fn valid_uri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && url::Url::parse(value).is_ok()
}
fn valid_revision(value: u64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn unavailable<E>(_: E) -> Error {
    Error::Unavailable
}
fn database_error(e: sqlx::Error) -> Error {
    if e.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505") {
        Error::Conflict
    } else {
        Error::Unavailable
    }
}
