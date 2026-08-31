use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_WALLET_SUBMISSION_BYTES: usize = 1_048_576;
pub const MAX_FROZEN_REQUEST_BYTES: usize = 262_144;
pub const MAX_EVIDENCE_PROJECTION_BYTES: usize = 1_048_576;
pub const MAX_IDENTIFIER_BYTES: usize = 255;
pub const MAX_CODE_BYTES: usize = 255;
pub const MAX_TOKEN_BYTES: usize = 262_144;
pub const MIN_TOKEN_BYTES: usize = 16;
pub const MAX_QUERY_DOCUMENT_BYTES: usize = 131_072;
pub const MAX_QUERY_REQUIREMENTS: usize = 64;
pub const MAX_TOKENS: usize = 64;
pub const MAX_CREDENTIALS: usize = 64;
pub const MAX_CLAIMS_PER_CREDENTIAL: usize = 128;
pub const MAX_CLAIM_VALUE_BYTES: usize = 16_384;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_DESCRIPTOR_DEPTH: usize = 8;
pub const MAX_REQUEST_LIFETIME_SECONDS: i64 = 7_200;
pub const MAX_STATUS_VALIDITY_SECONDS: i64 = 86_400;
pub const MAX_EVIDENCE_LIST_ITEMS: usize = 128;
pub const MIN_NONCE_BYTES: usize = 32;
/// Maximum percent-decoding work performed while scanning projected evidence
/// for encoded wallet material. Values that would require another pass are
/// rejected rather than accepted partially decoded.
pub const MAX_PRIVACY_PERCENT_DECODE_LAYERS: usize = 3;
pub const MAX_PRIVACY_BASE64_DECODE_LAYERS: usize = 2;
/// Maximum combined normalization steps across alternating percent and base64
/// encodings. Per-transform limits above remain independently enforced.
pub const MAX_PRIVACY_NORMALIZATION_STEPS: usize =
    MAX_PRIVACY_PERCENT_DECODE_LAYERS + MAX_PRIVACY_BASE64_DECODE_LAYERS;
/// Hard work bounds for the privacy normalization graph.
pub const MAX_PRIVACY_NORMALIZATION_STATES: usize = 64;
pub const MAX_PRIVACY_NORMALIZED_BYTES: usize = MAX_CLAIM_VALUE_BYTES;

pub const REQUIRED_OID4VP_CHECKS: [Oid4vpCheckId; 8] = [
    Oid4vpCheckId::PresentationStructure,
    Oid4vpCheckId::PresentationProof,
    Oid4vpCheckId::CredentialProof,
    Oid4vpCheckId::IssuerTrust,
    Oid4vpCheckId::CredentialStatus,
    Oid4vpCheckId::HolderBinding,
    Oid4vpCheckId::TransactionBinding,
    Oid4vpCheckId::ClaimConstraints,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum WalletSubmissionContractVersion {
    #[default]
    #[serde(rename = "marty.oid4vp-wallet-submission/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum FrozenRequestContractVersion {
    #[default]
    #[serde(rename = "marty.oid4vp-frozen-request/v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceProjectionContractVersion {
    #[default]
    #[serde(rename = "marty.oid4vp-evidence-projection/v1")]
    V1,
}

/// The complete public wallet input. It cannot represent policy or verified facts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletSubmissionV1 {
    pub contract: WalletSubmissionContractVersion,
    pub vp_token: VpToken,
    pub presentation_submission: Option<PresentationSubmission>,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VpToken {
    Single(String),
    ByQuery(BTreeMap<String, Vec<String>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<PresentationDescriptor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationDescriptor {
    pub id: String,
    pub format: String,
    pub path: String,
    pub path_nested: Option<Box<PresentationDescriptor>>,
}

/// Authority frozen by the server before accepting a wallet response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenOid4vpRequestV1 {
    pub contract: FrozenRequestContractVersion,
    pub session_id: String,
    pub organization_id: String,
    pub initiating_principal_id: String,
    pub policy: FrozenPolicyReference,
    pub query: FrozenQuery,
    pub verifier: FrozenVerifier,
    pub nonce: String,
    pub expected_state: String,
    pub issued_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPolicyReference {
    pub id: String,
    pub version: u32,
    pub content_digest: String,
    pub trust_profile: EvidenceProfileReference,
    pub max_trust_age_seconds: u32,
    pub presentation_proof_required: bool,
    pub alternative_requirement_groups: Vec<FrozenAlternativeRequirementGroup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenAlternativeRequirementGroup {
    pub id: String,
    pub requirement_ids: Vec<String>,
    pub min_satisfied: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenQuery {
    pub kind: QueryKind,
    /// Exact query emitted by the canonical protocol producer. It remains opaque
    /// here, but its bounded canonical digest is frozen with typed requirements.
    pub document: Value,
    pub document_digest: String,
    pub requirements: Vec<FrozenCredentialRequirement>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenCredentialRequirement {
    pub id: String,
    pub accepted_formats: Vec<String>,
    /// Exact canonical Presentation Exchange format option objects by format.
    /// DCQL requirements leave this map empty.
    pub format_options: BTreeMap<String, Value>,
    /// Canonical proof algorithms accepted for each format.
    pub accepted_algorithms: BTreeMap<String, Vec<String>>,
    /// Canonical alternative exact type/VCT sets. Both the outer alternatives
    /// and every inner set are sorted and unique.
    pub accepted_type_sets: Vec<Vec<String>>,
    pub required_claims: Vec<String>,
    pub allowed_claims: Vec<String>,
    pub retained_claims: Vec<String>,
    pub required: bool,
    pub min_credentials: u16,
    pub max_credentials: u16,
    pub status: FrozenStatusPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenStatusPolicy {
    pub mode: CredentialStatusMode,
    pub max_age_seconds: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatusMode {
    Required,
    AllowAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    Dcql,
    PresentationExchange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenVerifier {
    pub client_id: String,
    pub response_uri: String,
}

/// Strict, privacy-minimized projection emitted by a verifier candidate.
/// Deserializing this type does not authenticate it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vpEvidenceProjectionV1 {
    pub contract: EvidenceProjectionContractVersion,
    pub request_digest: String,
    pub response_digest: String,
    pub processing_status: EvidenceProcessingStatus,
    pub checks: Vec<Oid4vpCheckEvidence>,
    pub presentation: AuthenticatedPresentationEvidence,
    pub credentials: Vec<AuthenticatedCredentialEvidence>,
    pub binding: AuthenticatedBindingEvidence,
    pub policy_result: AuthenticatedPolicyResultV1,
    pub decision: AuthenticatedDecision,
}

/// Authenticated evidence is deliberately not deserializable or publicly
/// constructible. Arbitrary JSON can only become a validated projection.
///
/// ```compile_fail
/// let _: marty_oid4vp_contract::AuthenticatedOid4vpEvidenceV1 =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct AuthenticatedOid4vpEvidenceV1 {
    projection: Oid4vpEvidenceProjectionV1,
}

impl AuthenticatedOid4vpEvidenceV1 {
    #[must_use]
    pub fn projection(&self) -> &Oid4vpEvidenceProjectionV1 {
        &self.projection
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProcessingStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Oid4vpCheckId {
    #[serde(rename = "presentation.structure")]
    PresentationStructure,
    #[serde(rename = "presentation.proof")]
    PresentationProof,
    #[serde(rename = "credential.proof")]
    CredentialProof,
    #[serde(rename = "issuer.trust")]
    IssuerTrust,
    #[serde(rename = "credential.status")]
    CredentialStatus,
    #[serde(rename = "holder.binding")]
    HolderBinding,
    #[serde(rename = "transaction.binding")]
    TransactionBinding,
    #[serde(rename = "claim.constraints")]
    ClaimConstraints,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCheckOutcome {
    Passed,
    Failed,
    Indeterminate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Oid4vpCheckEvidence {
    pub check_id: Oid4vpCheckId,
    pub outcome: EvidenceCheckOutcome,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPresentationEvidence {
    pub structure: EvidenceFact,
    pub proof: EvidenceFact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFact {
    pub outcome: EvidenceCheckOutcome,
    pub code: String,
    pub evidence_digest: String,
    pub checked_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCredentialEvidence {
    pub credential_id: String,
    pub query_id: String,
    pub response_token_digest: String,
    pub format: String,
    pub authenticated_type_or_vct: Vec<String>,
    pub claims: BTreeMap<String, Value>,
    pub issuer_id: String,
    pub proof_algorithm: String,
    pub issued_at_epoch_seconds: i64,
    pub status_ids: Vec<String>,
    pub proof: EvidenceFact,
    pub trust: AuthenticatedTrustEvidence,
    pub status: AuthenticatedStatusEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedTrustEvidence {
    pub outcome: EvidenceCheckOutcome,
    pub profile: EvidenceProfileReference,
    pub trust_levels: Vec<String>,
    pub compliance_statuses: Vec<String>,
    pub accreditations: Vec<String>,
    pub checked_at_epoch_seconds: i64,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProfileReference {
    pub id: String,
    pub version: u32,
    pub content_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedStatusEvidence {
    pub outcome: EvidenceCheckOutcome,
    pub state: CredentialStatusState,
    pub checked_at_epoch_seconds: Option<i64>,
    pub valid_until_epoch_seconds: Option<i64>,
    pub evidence_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatusState {
    Active,
    Revoked,
    Unknown,
    Stale,
    NotPresent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedBindingEvidence {
    pub holder: HolderBindingEvidence,
    pub challenge: DigestBindingEvidence,
    pub audience: DigestBindingEvidence,
    pub replay: ReplayEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderBindingEvidence {
    pub outcome: EvidenceCheckOutcome,
    pub method: Option<String>,
    pub proof_profile: Option<String>,
    pub evidence_digest: Option<String>,
    pub checked_at_epoch_seconds: Option<i64>,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestBindingEvidence {
    pub expected_digest: String,
    pub observed_digest: Option<String>,
    pub outcome: EvidenceCheckOutcome,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEvidence {
    pub replay_key_digest: String,
    pub outcome: EvidenceCheckOutcome,
    pub code: String,
    pub consumed_at_epoch_seconds: Option<i64>,
    pub receipt_digest: Option<String>,
}

/// Versioned projection of the canonical policy result. It does not embed an
/// upstream service DTO, so the v1 wire shape cannot drift on dependency bumps.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPolicyResultV1 {
    pub policy: FrozenPolicyIdentity,
    pub result: AuthenticatedResult,
    pub decision: AuthenticatedDecisionAction,
    pub reason_code: String,
    pub evaluated_credential_ids: Vec<String>,
    pub total_requirements: u16,
    pub satisfied_requirements: u16,
    pub required_total: u16,
    pub required_satisfied: u16,
    pub verified_claims: BTreeMap<String, Value>,
    pub violation_codes: Vec<String>,
    pub evaluation_time_epoch_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPolicyIdentity {
    pub id: String,
    pub version: u32,
    pub content_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedDecision {
    pub result: AuthenticatedResult,
    pub decision: AuthenticatedDecisionAction,
    pub reason_code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedResult {
    Passed,
    Partial,
    Failed,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedDecisionAction {
    Allow,
    Deny,
    ManualReview,
}
