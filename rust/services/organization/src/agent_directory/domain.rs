use chrono::{DateTime, Utc};
use marty_principal_runtime_binding::{jwk_sha256_thumbprint, parse_thumbprint, TypedThumbprint};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::AgentDirectoryError;

pub const MAX_AGENT_REVISION: u64 = 9_007_199_254_740_991;
pub const MAX_AGENT_REQUEST_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentKind {
    External,
    Managed,
}
impl AgentKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::External => "EXTERNAL",
            Self::Managed => "MANAGED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentIdentityStatus {
    Provisioned,
    Active,
    Suspended,
    Revoked,
    Retired,
}
impl AgentIdentityStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Provisioned => "PROVISIONED",
            Self::Active => "ACTIVE",
            Self::Suspended => "SUSPENDED",
            Self::Revoked => "REVOKED",
            Self::Retired => "RETIRED",
        }
    }
    pub(crate) fn terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentLifecycleAction {
    Suspend,
    Revoke,
    Retire,
}
impl AgentLifecycleAction {
    pub(crate) fn permission(self) -> &'static str {
        match self {
            Self::Suspend => "agent-identity:suspend",
            Self::Revoke => "agent-identity:revoke",
            Self::Retire => "agent-identity:retire",
        }
    }
    pub(crate) fn event(self) -> &'static str {
        match self {
            Self::Suspend => "SUSPEND",
            Self::Revoke => "REVOKE",
            Self::Retire => "RETIRE",
        }
    }
    pub(crate) fn apply(
        self,
        state: AgentIdentityStatus,
    ) -> Result<AgentIdentityStatus, AgentDirectoryError> {
        match (self, state) {
            (Self::Suspend, AgentIdentityStatus::Active | AgentIdentityStatus::Provisioned) => {
                Ok(AgentIdentityStatus::Suspended)
            }
            (
                Self::Revoke,
                AgentIdentityStatus::Active
                | AgentIdentityStatus::Provisioned
                | AgentIdentityStatus::Suspended,
            ) => Ok(AgentIdentityStatus::Revoked),
            (
                Self::Retire,
                AgentIdentityStatus::Active
                | AgentIdentityStatus::Provisioned
                | AgentIdentityStatus::Suspended
                | AgentIdentityStatus::Revoked,
            ) => Ok(AgentIdentityStatus::Retired),
            _ => Err(AgentDirectoryError::InvalidTransition),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgentRequest {
    pub kind: AgentKind,
    pub display_name: String,
    pub description: Option<String>,
    pub logical_application_ref: String,
    pub issuer: String,
    pub subject: String,
    pub runtime_instance_ref: String,
    pub public_key_jwk: Value,
}
// An unvalidated submitted JWK could contain a private member. Never include it
// in diagnostic formatting, even though the application rejects such a request.
impl std::fmt::Debug for RegisterAgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterAgentRequest")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAgentMetadataRequest {
    pub expected_revision: u64,
    pub display_name: String,
    pub description: Option<String>,
    pub logical_application_ref: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateAgentKeyRequest {
    pub expected_revision: u64,
    pub public_key_jwk: Value,
}
impl std::fmt::Debug for RotateAgentKeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateAgentKeyRequest")
            .field("expected_revision", &self.expected_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleRequest {
    pub expected_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMetadata {
    pub display_name: String,
    pub description: Option<String>,
    pub logical_application_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipal {
    #[serde(rename = "type")]
    pub principal_type: String,
    pub id: String,
}

/// Source provenance is an attributable operator declaration. It does not assert
/// that the declared external issuer or host has been authenticated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProvenance {
    pub kind: String,
    pub registered_by: String,
    pub registration_ref: String,
    pub managed_enrollment: String,
    pub external_authentication: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentKeyFingerprint {
    pub basis: String,
    pub encoding: String,
    pub value: String,
}
impl AgentKeyFingerprint {
    pub fn typed(&self) -> Result<TypedThumbprint, AgentDirectoryError> {
        parse_thumbprint(&serde_json::to_vec(self).map_err(|_| AgentDirectoryError::CorruptData)?)
            .map_err(|_| AgentDirectoryError::CorruptData)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentityKey {
    pub key_id: Uuid,
    pub algorithm: String,
    pub status: String,
    pub fingerprint: AgentKeyFingerprint,
    pub public_key_jwk: Value,
    pub created_at: DateTime<Utc>,
}

/// Serializable inventory projection, never an accepted registration body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub owner_user_id: String,
    pub created_by: String,
    pub kind: AgentKind,
    pub status: AgentIdentityStatus,
    pub revision: u64,
    pub metadata: AgentMetadata,
    pub principal: AgentPrincipal,
    pub issuer: String,
    pub subject: String,
    pub runtime_instance_ref: String,
    /// Current key only. The immutable revision history retains replaced keys.
    pub keys: Vec<AgentIdentityKey>,
    pub provenance: AgentProvenance,
    pub authority_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentIdentityPage {
    pub items: Vec<AgentIdentity>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct AgentHistoryEvent {
    pub revision: u64,
    pub action: String,
    pub actor_user_id: String,
    pub request_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub snapshot: AgentIdentity,
}
#[derive(Clone, Debug, Serialize)]
pub struct AgentHistoryPage {
    pub items: Vec<AgentHistoryEvent>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

/// A current inventory/key match. It has no Deserialize and is not authenticated
/// identity, proof of possession, a MAP result, a grant, or execution authority.
#[derive(Clone, Debug)]
pub struct CurrentAgentBinding {
    pub(crate) identity: AgentIdentity,
    pub(crate) observed_at: DateTime<Utc>,
}
impl CurrentAgentBinding {
    pub fn identity(&self) -> &AgentIdentity {
        &self.identity
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

pub(crate) fn valid_revision(value: u64) -> Result<(), AgentDirectoryError> {
    if !(1..MAX_AGENT_REVISION).contains(&value) {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    Ok(())
}
pub(crate) fn valid_metadata(
    name: &str,
    description: Option<&str>,
    application: &str,
) -> Result<(), AgentDirectoryError> {
    if name.trim().is_empty()
        || name.len() > 200
        || name.chars().any(char::is_control)
        || description.is_some_and(|text| text.len() > 2048 || text.contains('\0'))
        || !valid_uri(application)
    {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    Ok(())
}
pub(crate) fn valid_uri(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 1024
        || !value.is_ascii()
        || value
            .bytes()
            .any(|c| !c.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()+,;=%".contains(&c))
        || value.bytes().filter(|c| *c == b'#').count() > 1
    {
        return false;
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return false;
        }
    }
    url::Url::parse(value).is_ok()
}

pub(crate) fn public_key(
    value: &Value,
    now: DateTime<Utc>,
) -> Result<AgentIdentityKey, AgentDirectoryError> {
    let raw = serde_json::to_vec(value).map_err(|_| AgentDirectoryError::InvalidRequest)?;
    if raw.len() > 4096 {
        return Err(AgentDirectoryError::InvalidRequest);
    }
    let fingerprint =
        jwk_sha256_thumbprint(&raw).map_err(|_| AgentDirectoryError::InvalidRequest)?;
    let algorithm = match value.get("crv").and_then(Value::as_str) {
        Some("Ed25519") => "EdDSA",
        Some("P-256") => "ES256",
        _ => return Err(AgentDirectoryError::InvalidRequest),
    };
    Ok(AgentIdentityKey {
        key_id: Uuid::new_v4(),
        algorithm: algorithm.into(),
        status: "ACTIVE".into(),
        fingerprint: AgentKeyFingerprint {
            basis: "JWK_RFC7638_SHA256".into(),
            encoding: "BASE64URL_SHA256".into(),
            value: fingerprint.encoded_value(),
        },
        public_key_jwk: value.clone(),
        created_at: now,
    })
}

pub(crate) fn validate_snapshot(value: &AgentIdentity) -> Result<(), AgentDirectoryError> {
    let invalid = AgentDirectoryError::CorruptData;
    if value.id.is_nil()
        || value.organization_id.is_nil()
        || value.owner_user_id.is_empty()
        || value.created_by.is_empty()
        || value.revision == 0
        || value.revision > MAX_AGENT_REVISION
        || value.updated_at < value.created_at
        || value.authority_status != "NOT_ASSESSED"
        || !valid_uri(&value.issuer)
        || !valid_uri(&value.runtime_instance_ref)
        || value.subject.is_empty()
        || value.subject.len() > 512
        || value.subject.chars().any(char::is_control)
        || value.principal.id != format!("urn:marty:agent:{}", value.id)
        || value.principal.principal_type
            != match value.kind {
                AgentKind::External => "EXTERNAL",
                AgentKind::Managed => "SERVICE_ACCOUNT",
            }
        || value.kind == AgentKind::Managed
            && value.status == AgentIdentityStatus::Active
            && value.provenance.managed_enrollment != "KEY_CONTROL_VERIFIED"
        || value.provenance.kind != "OPERATOR_DECLARATION"
        || value.provenance.registered_by != value.created_by
        || value.provenance.registration_ref != format!("urn:marty:agent-registration:{}", value.id)
        || !matches!(
            value.provenance.managed_enrollment.as_str(),
            "NOT_ASSESSED" | "KEY_CONTROL_VERIFIED"
        )
        || value.kind == AgentKind::External
            && value.provenance.managed_enrollment != "NOT_ASSESSED"
        || value.status == AgentIdentityStatus::Provisioned
            && value.provenance.managed_enrollment != "NOT_ASSESSED"
        || value.provenance.external_authentication != "NOT_ASSESSED"
        || value.keys.len() != usize::from(!value.status.terminal())
    {
        return Err(invalid);
    }
    valid_metadata(
        &value.metadata.display_name,
        value.metadata.description.as_deref(),
        &value.metadata.logical_application_ref,
    )
    .map_err(|_| invalid)?;
    for key in &value.keys {
        let computed = public_key(&key.public_key_jwk, key.created_at).map_err(|_| invalid)?;
        if key.key_id.is_nil()
            || key.status != "ACTIVE"
            || key.algorithm != computed.algorithm
            || key.fingerprint != computed.fingerprint
            || key.created_at < value.created_at
            || key.created_at > value.updated_at
        {
            return Err(invalid);
        }
    }
    Ok(())
}
