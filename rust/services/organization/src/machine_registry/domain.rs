use std::fmt;

use chrono::{DateTime, Utc};
use marty_principal_runtime_binding::{
    machine_policy::{qualify_machine_binding, valid_evidence_uri, MachineAuthenticationPolicy},
    parse_binding_record, parse_configuration, parse_machine_snapshot, ThumbprintEncoding,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MachineRegistryError {
    #[error("ORGANIZATION.MACHINE_REGISTRY_INVALID_REQUEST")]
    InvalidRequest,
    #[error("ORGANIZATION.MACHINE_REGISTRY_ACCESS_DENIED")]
    AccessDenied,
    #[error("ORGANIZATION.MACHINE_REGISTRY_NOT_FOUND")]
    NotFound,
    #[error("ORGANIZATION.MACHINE_REGISTRY_REVISION_CONFLICT")]
    Conflict,
    #[error("ORGANIZATION.MACHINE_REGISTRY_INVALID_TRANSITION")]
    InvalidTransition,
    #[error("ORGANIZATION.MACHINE_REGISTRY_UNAVAILABLE")]
    Unavailable,
    #[error("ORGANIZATION.MACHINE_REGISTRY_CORRUPT_DATA")]
    CorruptData,
}

/// Existing pinned documents supplied to the human administration application.
/// They are strictly parsed and qualified, and their selection is committed by
/// the owner. They are never accepted as replacements in a use request.
#[derive(Clone)]
pub struct MachineRegistryDocuments {
    pub binding_record: Vec<u8>,
    pub binding_configuration: Vec<u8>,
    pub machine_identity: Vec<u8>,
    pub machine_authentication_policy: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Projection {
    pub organization_id: Uuid,
    pub machine_identity_id: Uuid,
    pub deployment_profile_id: Uuid,
    pub principal_id: String,
    pub runtime_instance_ref: String,
    pub key_id: String,
    pub key_thumbprint: String,
    pub policy_id: Uuid,
    pub policy_digest: String,
}

pub(crate) struct ValidatedDocuments {
    pub projection: Projection,
    pub document: Value,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub key_valid_until: Option<DateTime<Utc>>,
}

impl MachineRegistryDocuments {
    pub(crate) fn validate(
        &self,
        organization: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ValidatedDocuments, MachineRegistryError> {
        let invalid = |_| MachineRegistryError::InvalidRequest;
        let record = parse_binding_record(&self.binding_record).map_err(invalid)?;
        let configuration = parse_configuration(&self.binding_configuration).map_err(invalid)?;
        let machine = parse_machine_snapshot(&self.machine_identity).map_err(invalid)?;
        let policy =
            MachineAuthenticationPolicy::from_trusted_document(&self.machine_authentication_policy)
                .map_err(|_| MachineRegistryError::InvalidRequest)?;
        let qualified = qualify_machine_binding(
            organization,
            &policy,
            &record,
            &configuration,
            &machine,
            now,
        )
        .map_err(|_| MachineRegistryError::InvalidRequest)?;
        let binding = qualified.binding();
        if binding.session_ref().is_some()
            || binding.issuer() != binding.principal_id()
            || binding.subject() != binding.principal_id()
        {
            return Err(MachineRegistryError::InvalidRequest);
        }
        let deployment_profile_id = Uuid::parse_str(binding.deployment_profile_id())
            .map_err(|_| MachineRegistryError::InvalidRequest)?;
        if deployment_profile_id.is_nil() {
            return Err(MachineRegistryError::InvalidRequest);
        }
        let projection = Projection {
            organization_id: organization,
            machine_identity_id: qualified.machine_identity_id(),
            deployment_profile_id,
            principal_id: binding.principal_id().into(),
            runtime_instance_ref: binding.runtime_instance_ref().into(),
            key_id: qualified.key_id().into(),
            key_thumbprint: binding
                .key_thumbprint()
                .reencode(ThumbprintEncoding::MipSha256Hex)
                .encoded_value(),
            policy_id: policy.id(),
            policy_digest: policy.digest().into(),
        };
        let document = self.document()?;
        let bytes =
            serde_json::to_vec(&document).map_err(|_| MachineRegistryError::InvalidRequest)?;
        Ok(ValidatedDocuments {
            projection,
            digest: digest(&bytes),
            bytes,
            document,
            key_valid_until: qualified.key_valid_until(),
        })
    }

    fn document(&self) -> Result<Value, MachineRegistryError> {
        fn value(raw: &[u8]) -> Result<Value, MachineRegistryError> {
            serde_json::from_slice(raw).map_err(|_| MachineRegistryError::InvalidRequest)
        }
        Ok(json!({
            "binding_record": value(&self.binding_record)?,
            "binding_configuration": value(&self.binding_configuration)?,
            "machine_identity": value(&self.machine_identity)?,
            "machine_authentication_policy": value(&self.machine_authentication_policy)?,
        }))
    }

    pub(crate) fn from_document(document: &Value) -> Result<Self, MachineRegistryError> {
        let object = document
            .as_object()
            .ok_or(MachineRegistryError::CorruptData)?;
        if object.len() != 4 {
            return Err(MachineRegistryError::CorruptData);
        }
        let bytes = |key| {
            object
                .get(key)
                .filter(|v| v.is_object())
                .ok_or(MachineRegistryError::CorruptData)
                .and_then(|v| serde_json::to_vec(v).map_err(|_| MachineRegistryError::CorruptData))
        };
        Ok(Self {
            binding_record: bytes("binding_record")?,
            binding_configuration: bytes("binding_configuration")?,
            machine_identity: bytes("machine_identity")?,
            machine_authentication_policy: bytes("machine_authentication_policy")?,
        })
    }
}

/// Private administrative state. Inspecting it provides no operational proof.
#[derive(Clone)]
pub struct MachineRegistryRecord {
    pub(crate) projection: Projection,
    pub(crate) status: String,
    pub(crate) revision: u64,
    pub(crate) documents: Value,
    pub(crate) document_bytes: Vec<u8>,
    pub(crate) document_digest: String,
    pub(crate) documents_recorded_at: DateTime<Utc>,
    pub(crate) created_by: String,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}
impl MachineRegistryRecord {
    pub fn machine_identity_id(&self) -> Uuid {
        self.projection.machine_identity_id
    }
    pub fn organization_id(&self) -> Uuid {
        self.projection.organization_id
    }
    pub fn deployment_profile_id(&self) -> Uuid {
        self.projection.deployment_profile_id
    }
    pub fn principal_id(&self) -> &str {
        &self.projection.principal_id
    }
    pub fn status(&self) -> &str {
        &self.status
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn documents(&self) -> &Value {
        &self.documents
    }
    pub fn document_bytes(&self) -> &[u8] {
        &self.document_bytes
    }
    pub fn document_digest(&self) -> &str {
        &self.document_digest
    }
    /// Last explicit publication; a later terminal transition does not rewrite
    /// historical protocol documents or pretend their key is still current.
    pub fn documents_recorded_at(&self) -> DateTime<Utc> {
        self.documents_recorded_at
    }
    pub fn created_by(&self) -> &str {
        &self.created_by
    }
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineRegistryLifecycle {
    Suspend,
    Revoke,
    Retire,
}
impl MachineRegistryLifecycle {
    pub(crate) fn status(self) -> &'static str {
        match self {
            Self::Suspend => "SUSPENDED",
            Self::Revoke => "REVOKED",
            Self::Retire => "RETIRED",
        }
    }
    pub(crate) fn action(self) -> &'static str {
        match self {
            Self::Suspend => "SUSPEND",
            Self::Revoke => "REVOKE",
            Self::Retire => "RETIRE",
        }
    }
    pub(crate) fn permission(self) -> &'static str {
        match self {
            Self::Suspend => "machine-identity:suspend",
            Self::Revoke => "machine-identity:revoke",
            Self::Retire => "machine-identity:retire",
        }
    }
    pub(crate) fn allowed(self, previous: &str) -> bool {
        match self {
            Self::Suspend => previous == "ACTIVE",
            Self::Revoke => matches!(previous, "ACTIVE" | "SUSPENDED"),
            Self::Retire => matches!(previous, "ACTIVE" | "SUSPENDED" | "REVOKED"),
        }
    }
}

/// Trusted deployment selection, configured when constructing the source.
#[derive(Clone, Copy)]
pub struct MachineRegistrySelection {
    organization_id: Uuid,
    deployment_profile_id: Uuid,
}
impl MachineRegistrySelection {
    pub fn new(
        organization_id: Uuid,
        deployment_profile_id: Uuid,
    ) -> Result<Self, MachineRegistryError> {
        if organization_id.is_nil() || deployment_profile_id.is_nil() {
            return Err(MachineRegistryError::InvalidRequest);
        }
        Ok(Self {
            organization_id,
            deployment_profile_id,
        })
    }
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn deployment_profile_id(&self) -> Uuid {
        self.deployment_profile_id
    }
}

/// Exact use request identity retained with the source observation. This is
/// purpose binding, not authentication of the supplied request or its holder.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineRegistryUseScope {
    pub organization_id: Uuid,
    pub principal_id: String,
    pub key_thumbprint: String,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub challenge_id: Uuid,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
}
impl MachineRegistryUseScope {
    pub(crate) fn validate(
        &self,
        selection: MachineRegistrySelection,
    ) -> Result<(), MachineRegistryError> {
        if self.organization_id != selection.organization_id
            || self.grant_id.is_nil()
            || self.challenge_id.is_nil()
            || !valid_revision(self.grant_revision)
            || !valid_digest(&self.key_thumbprint)
            || !valid_digest(&self.operation_digest)
            || [
                &self.principal_id,
                &self.action,
                &self.audience,
                &self.resource,
                &self.operation_profile,
            ]
            .iter()
            .any(|v| !valid_evidence_uri(v))
        {
            return Err(MachineRegistryError::InvalidRequest);
        }
        Ok(())
    }
}

pub(crate) fn valid_revision(value: u64) -> bool {
    (1..=9_007_199_254_740_991).contains(&value)
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
macro_rules! private_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { <private> }"))
            }
        }
    )+};
}
private_debug!(
    MachineRegistryDocuments,
    MachineRegistryRecord,
    MachineRegistrySelection,
    MachineRegistryUseScope
);
