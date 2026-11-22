use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{strict, ClientError, Result, COMMAND_PROFILE};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReference {
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    pub id: Uuid,
    pub revision: u64,
    pub terms_digest: String,
}
impl GrantReference {
    pub(crate) fn valid(&self) -> bool {
        !self.id.is_nil()
            && (1..=strict::MAX_REVISION).contains(&self.revision)
            && strict::valid_digest(&self.terms_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub action: String,
    pub resource_id: String,
    pub audience: String,
    pub request_profile: String,
    pub request_digest: String,
}
impl Operation {
    pub(crate) fn valid(&self) -> bool {
        [
            &self.action,
            &self.resource_id,
            &self.audience,
            &self.request_profile,
        ]
        .into_iter()
        .all(|value| strict::valid_uri(value))
            && strict::valid_digest(&self.request_digest)
    }
}

#[derive(Clone)]
struct Prepared {
    id: Uuid,
    digest: String,
    bytes: Vec<u8>,
}
impl Prepared {
    fn new(id: Uuid, document: serde_json::Value) -> Result<Self> {
        if id.is_nil() {
            return Err(ClientError::InvalidCommand);
        }
        let bytes = strict::canonical_command(&document)?;
        Ok(Self {
            id,
            digest: strict::digest(&bytes),
            bytes,
        })
    }
    fn recovery_bytes(&self) -> Vec<u8> {
        // Every field is a validated string in a closed, non-numeric schema.
        strict::canonical_command(&json!({
            "profile": COMMAND_PROFILE,
            "command": "RECOVER_RESULT",
            "original_command_id": self.id,
            "expected_command_digest": self.digest,
        }))
        .expect("closed recovery command is serializable")
    }
}

/// Retain this command before sending. Persisting its inputs (including the
/// exact command ID) and reconstructing it produces the same canonical bytes.
/// Deserializing a response is never a replacement for this original intent.
#[derive(Clone)]
pub struct PreparedStart {
    command: Prepared,
    pub(crate) grant: GrantReference,
    pub(crate) operation: Operation,
}
impl PreparedStart {
    pub fn new(command_id: Uuid, grant: GrantReference, operation: Operation) -> Result<Self> {
        if !grant.valid() || !operation.valid() {
            return Err(ClientError::InvalidCommand);
        }
        let command = Prepared::new(
            command_id,
            json!({
                "profile": COMMAND_PROFILE,
                "command": "START_USE",
                "command_id": command_id,
                "grant": grant,
                "operation": operation,
            }),
        )?;
        Ok(Self {
            command,
            grant,
            operation,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.command.bytes
    }
    pub fn command_id(&self) -> Uuid {
        self.command.id
    }
    pub fn command_digest(&self) -> &str {
        &self.command.digest
    }
    pub fn recovery_bytes(&self) -> Vec<u8> {
        self.command.recovery_bytes()
    }
}
impl fmt::Debug for PreparedStart {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("PreparedStart { <retained independent command> }")
    }
}

/// A FINALIZE_USE identity retained before I/O. A timeout or a missing recovered
/// result is not permission to generate another identity or repeat evaluation.
#[derive(Clone)]
pub struct PreparedFinalize {
    command: Prepared,
    pub(crate) challenge_id: Uuid,
}
impl PreparedFinalize {
    pub fn new(command_id: Uuid, challenge_id: Uuid, proof_submission_id: Uuid) -> Result<Self> {
        if challenge_id.is_nil() || proof_submission_id.is_nil() {
            return Err(ClientError::InvalidCommand);
        }
        let command = Prepared::new(
            command_id,
            json!({
                "profile": COMMAND_PROFILE,
                "command": "FINALIZE_USE",
                "command_id": command_id,
                "challenge_id": challenge_id,
                "proof_submission_id": proof_submission_id,
            }),
        )?;
        Ok(Self {
            command,
            challenge_id,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.command.bytes
    }
    pub fn command_id(&self) -> Uuid {
        self.command.id
    }
    pub fn command_digest(&self) -> &str {
        &self.command.digest
    }
    pub fn recovery_bytes(&self) -> Vec<u8> {
        self.command.recovery_bytes()
    }
}
impl fmt::Debug for PreparedFinalize {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("PreparedFinalize { <retained independent command> }")
    }
}

/// Wire data alone confers no authenticated provenance. Only the client's
/// sealed StartedUse/FinalizedUse wrappers establish transport correlation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResponse {
    pub profile: String,
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    pub original_command_id: Uuid,
    pub command_digest: String,
    pub recovered: bool,
    pub result: CommandResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CommandResult {
    #[serde(rename = "CHALLENGE")]
    Challenge {
        #[serde(deserialize_with = "strict::deserialize_uuid")]
        challenge_id: Uuid,
        grant: GrantReference,
        operation: Operation,
        #[serde(deserialize_with = "strict::deserialize_time")]
        created_at: DateTime<Utc>,
        #[serde(deserialize_with = "strict::deserialize_time")]
        expires_at: DateTime<Utc>,
    },
    #[serde(rename = "FINAL_USE")]
    FinalUse {
        #[serde(deserialize_with = "strict::deserialize_uuid")]
        challenge_id: Uuid,
        decision: String,
        receipt_ref: String,
        receipt_digest: String,
        #[serde(deserialize_with = "strict::deserialize_time")]
        recorded_at: DateTime<Utc>,
        #[serde(deserialize_with = "strict::deserialize_time")]
        authorization_expires_at: DateTime<Utc>,
        semantics: String,
    },
}

/// Transport-authenticated response and exactly bound Link, not a verified
/// authorization request or an authorization to perform a business operation.
pub struct StartedUse {
    pub(crate) response: CommandResponse,
    pub(crate) request_uri: String,
    pub(crate) organization: Uuid,
    pub(crate) challenge_id: Uuid,
}
impl StartedUse {
    pub fn response(&self) -> &CommandResponse {
        &self.response
    }
    pub fn request_uri(&self) -> &str {
        &self.request_uri
    }
    pub fn challenge_id(&self) -> Uuid {
        self.challenge_id
    }
}
impl fmt::Debug for StartedUse {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("StartedUse { <authenticated original challenge> }")
    }
}

pub struct FinalizedUse {
    pub(crate) response: CommandResponse,
}
impl FinalizedUse {
    pub fn response(&self) -> &CommandResponse {
        &self.response
    }
}
impl fmt::Debug for FinalizedUse {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("FinalizedUse { <authenticated retained result> }")
    }
}

/// Exact bytes returned by the authenticated host. This type deliberately says
/// nothing about issuer trust, JWS validity, nonce, audience, DCQL, or expiry.
pub struct UnverifiedRequestArtifact(pub(crate) String);
impl UnverifiedRequestArtifact {
    pub fn compact_jws(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for UnverifiedRequestArtifact {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("UnverifiedRequestArtifact { <unverified signed bytes> }")
    }
}

/// A caller assertion, not a cryptographic verification result from this crate.
/// Construct only after independently verifying the request signature, signing
/// identity, audience, nonce, lifetime, securing profile and exact DCQL query.
/// The client additionally constrains response_uri and state to its host and
/// original challenge before exposing any compact VP to the network.
pub struct CallerVerifiedRequest {
    pub response_uri: String,
    pub state: String,
    pub query_id: String,
}
impl fmt::Debug for CallerVerifiedRequest {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("CallerVerifiedRequest { <caller-verified request fields> }")
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSubmission {
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    pub submission_id: Uuid,
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    pub challenge_id: Uuid,
    pub proof_digest: String,
    #[serde(deserialize_with = "strict::deserialize_time")]
    pub received_at: DateTime<Utc>,
    pub recovered: bool,
}

/// Original retained evidence bytes, not a verified receipt. Its outer response
/// is bound to the independently retained FINALIZE_USE command by this client.
/// Pass exact compact_jws and independent context/trust to the receipt consumer.
pub struct ReceiptArtifact {
    pub(crate) wire: ReceiptWire,
}
impl ReceiptArtifact {
    pub fn original_response(&self) -> &CommandResponse {
        &self.wire.original_response
    }
    pub fn receipt_ref(&self) -> &str {
        &self.wire.receipt_ref
    }
    pub fn receipt_digest(&self) -> &str {
        &self.wire.receipt_digest
    }
    pub fn compact_jws(&self) -> &str {
        &self.wire.compact_jws
    }
    pub fn semantics(&self) -> &str {
        &self.wire.semantics
    }
}
impl fmt::Debug for ReceiptArtifact {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("ReceiptArtifact { <unverified original evidence bytes> }")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptWire {
    pub original_response: CommandResponse,
    pub receipt_ref: String,
    pub receipt_digest: String,
    pub compact_jws: String,
    pub semantics: String,
}
