//! Actual issuer/holder cryptography for one explicitly selected machine
//! credential profile. This adapter accepts exactly one registered nested JWT
//! VC that covers every MAP-required type. It does not select a format from
//! caller data, promote directory inventory, or qualify a live source owner.
//!
//! The configured source owns current Trust Profile, issuer authorization/key,
//! credential status and durable evidence. It is an internal authenticated port,
//! never a public request DTO or a claim that an HTTP response was successful.

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_oid4vci::{
    jwt_vc_profile::{decode_unverified_jwt_vc, validate_unsigned_jwt_vc_profile_claims},
    presented_jwt_vc_with_profile,
    types::SigningAlgorithm,
    verify_jwt_vc_presentation_with_profile, JwtVcSecuringProfile, ResolvedSdJwtIssuerKey,
    TrustedSdJwtIssuerKeys, VerificationEngine,
};
use marty_principal_runtime_binding::{
    jwk_sha256_thumbprint,
    machine_policy::{valid_evidence_uri, valid_policy_revision},
    ThumbprintEncoding,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    domain::valid_digest,
    machine_auth::{
        MachineAuthenticationScope, MachineCredentialVerifier, MachineEvidenceError,
        MachineEvidenceRequest, VerifiedMachineCredential, VerifiedMachineCredentials,
    },
    DelegationClock, PrincipalType, SystemDelegationClock, MAX_DELEGATE_PROOF_BYTES,
};

pub const MACHINE_JWT_VC_SECURING_PROFILE: JwtVcSecuringProfile =
    JwtVcSecuringProfile::MartyNestedVc2JwtV1;
const SOURCE_MAX_AGE_SECONDS: i64 = 30;
const SOURCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_CREDENTIAL_TYPES: usize = 32;

/// Unauthenticated credential selectors bound to the already selected machine
/// operation. The source must use independently configured issuer/status owners
/// and authorize this exact Trust Profile; these hints are not trust evidence
/// and must never become caller-directed network locations.
#[derive(Clone, Eq, PartialEq)]
pub struct MachineJwtVcSelection {
    pub scope: MachineAuthenticationScope,
    pub trust_profile_id: Uuid,
    pub securing_profile: JwtVcSecuringProfile,
    pub credential_id: Uuid,
    /// SHA-256 of the exact original compact issuer credential, `sha256:<hex>`.
    pub credential_digest: String,
    pub issuer: String,
    pub verification_method_id: String,
    pub algorithm: SigningAlgorithm,
}

/// A source's independently observed current state, not a signature verdict.
/// Every state other than Active is rejected, including an unavailable status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineCredentialSourceStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
    Unknown,
}

/// Current source records for one exact credential and selected Trust Profile.
///
/// The source must authenticate the record owners, authorize the issuer for
/// every returned credential type under this profile, authenticate current
/// credential status, and bind the exact original token digest (not only a
/// reusable credential identifier). `valid_until` covers profile selection,
/// issuer authorization, issuer key and credential status together, and must
/// not exceed `observed_at + 30 seconds` or any underlying record's deadline.
/// The source must durably retain this record under `evidence_ref`; the
/// aggregate machine audit stores that reference, not these private documents.
/// No Deserialize implementation is supplied for a caller to manufacture it.
#[derive(Clone)]
pub struct ResolvedMachineJwtVcAuthority {
    pub selection: MachineJwtVcSelection,
    pub trust_profile_revision: u64,
    pub trust_profile_digest: String,
    pub trust_profile_status: MachineCredentialSourceStatus,
    pub issuer_status: MachineCredentialSourceStatus,
    pub issuer_key_status: MachineCredentialSourceStatus,
    pub credential_status: MachineCredentialSourceStatus,
    pub issuer_key: ResolvedSdJwtIssuerKey,
    pub authorized_credential_types: Vec<String>,
    pub evidence_ref: String,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait MachineJwtVcAuthoritySource: Send + Sync {
    async fn resolve_current(
        &self,
        selection: &MachineJwtVcSelection,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineJwtVcAuthority, MachineEvidenceError>;
}

/// Concrete Core-backed verification of the nested JWT VC selection only.
/// Required attestation, machine Cedar, current full-machine/MAP state and
/// final-use authorization remain their separately selected gates.
#[derive(Clone)]
pub struct MartyNestedJwtVcMachineCredentialVerifier {
    source: Arc<dyn MachineJwtVcAuthoritySource>,
    clock: Arc<dyn DelegationClock>,
}

impl MartyNestedJwtVcMachineCredentialVerifier {
    pub fn new(source: Arc<dyn MachineJwtVcAuthoritySource>) -> Self {
        Self::with_clock(source, Arc::new(SystemDelegationClock))
    }

    pub fn with_clock(
        source: Arc<dyn MachineJwtVcAuthoritySource>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self { source, clock }
    }
}

#[async_trait]
impl MachineCredentialVerifier for MartyNestedJwtVcMachineCredentialVerifier {
    async fn verify_required(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineCredentials, MachineEvidenceError> {
        validate_context(&request)?;
        let initial_now = self.clock.now();
        let original_deadline = request
            .now
            .checked_add_signed(Duration::seconds(SOURCE_MAX_AGE_SECONDS))
            .ok_or(MachineEvidenceError)?;
        if initial_now < request.now || initial_now >= original_deadline {
            return Err(MachineEvidenceError);
        }
        if request.operation.proof.is_empty()
            || request.operation.proof.len() > MAX_DELEGATE_PROOF_BYTES
        {
            return Err(MachineEvidenceError);
        }
        let presentation =
            std::str::from_utf8(&request.operation.proof).map_err(|_| MachineEvidenceError)?;
        if presentation.trim() != presentation {
            return Err(MachineEvidenceError);
        }
        // Authenticate the original VP before consulting a source on its inner
        // selection hints, and independently bind the actual signer to the
        // current registered machine key. The profiled Core call below also
        // authenticates issuer and self-certifying subject/holder binding.
        let audience = request.qualified_binding.binding().audience();
        let holder = VerificationEngine::new(audience, "")
            .verify_authenticated_vp_proof_at(
                presentation,
                &request.proof.challenge,
                initial_now.timestamp(),
            )
            .map_err(|_| MachineEvidenceError)?;
        let holder_key = jwk_sha256_thumbprint(
            &serde_json::to_vec(holder.signer_public_jwk()).map_err(|_| MachineEvidenceError)?,
        )
        .map_err(|_| MachineEvidenceError)?;
        if !holder_key.same_binding(request.qualified_binding.binding().key_thumbprint()) {
            return Err(MachineEvidenceError);
        }
        let holder_expires = timestamp_claim(holder.claims(), "exp")?;
        let holder_issued = timestamp_claim(holder.claims(), "iat")?;
        let maximum_age = request
            .policy
            .select_oid4vp_machine_key()
            .map_err(|_| MachineEvidenceError)?;
        let holder_age_deadline = holder_issued
            .checked_add_signed(Duration::seconds(i64::from(maximum_age)))
            .ok_or(MachineEvidenceError)?;
        if holder_expires > holder_age_deadline || holder_expires <= initial_now {
            return Err(MachineEvidenceError);
        }

        let credential =
            presented_jwt_vc_with_profile(presentation, MACHINE_JWT_VC_SECURING_PROFILE)
                .map_err(|_| MachineEvidenceError)?;
        let (header, claims) =
            decode_unverified_jwt_vc(&credential, MACHINE_JWT_VC_SECURING_PROFILE)
                .map_err(|_| MachineEvidenceError)?;
        let hints = validate_unsigned_jwt_vc_profile_claims(
            &claims,
            initial_now.timestamp(),
            MACHINE_JWT_VC_SECURING_PROFILE,
        )
        .map_err(|_| MachineEvidenceError)?;
        let credential_id = registered_credential_id(hints.credential_id)?;
        if !request
            .qualified_binding
            .credential_ids()
            .contains(&credential_id)
            || hints.subject_id != request.scope.principal.id
            || !bounded_text(hints.issuer, 2_048)
        {
            return Err(MachineEvidenceError);
        }
        let hinted_types = credential_types(hints.credential.get("type"))?;
        require_types(&hinted_types, request.policy.required_credential_types())?;
        let algorithm = match header.get("alg").and_then(Value::as_str) {
            Some("ES256") => SigningAlgorithm::ES256,
            Some("EdDSA") => SigningAlgorithm::EdDSA,
            _ => return Err(MachineEvidenceError),
        };
        let key_id = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|value| bounded_text(value, 2_048))
            .ok_or(MachineEvidenceError)?;
        let selection = MachineJwtVcSelection {
            scope: request.scope.clone(),
            trust_profile_id: request.policy.trust_profile_id(),
            securing_profile: MACHINE_JWT_VC_SECURING_PROFILE,
            credential_id,
            credential_digest: format!("sha256:{:x}", Sha256::digest(credential.as_bytes())),
            issuer: hints.issuer.into(),
            verification_method_id: key_id.into(),
            algorithm,
        };
        let authority = tokio::time::timeout(
            SOURCE_TIMEOUT,
            self.source.resolve_current(&selection, initial_now),
        )
        .await
        .map_err(|_| MachineEvidenceError)??;
        let observed_now = self.clock.now();
        validate_authority(&authority, &selection, observed_now)?;
        if observed_now < initial_now || observed_now >= original_deadline {
            return Err(MachineEvidenceError);
        }
        let issuer_types = validate_type_list(&authority.authorized_credential_types)?;
        if hinted_types
            .iter()
            .filter(|kind| kind.as_str() != "VerifiableCredential")
            .any(|kind| !issuer_types.contains(kind))
        {
            return Err(MachineEvidenceError);
        }
        let keys = TrustedSdJwtIssuerKeys::new(vec![authority.issuer_key.clone()])
            .map_err(|_| MachineEvidenceError)?;
        let verified = verify_jwt_vc_presentation_with_profile(
            presentation,
            &keys,
            &request.proof.challenge,
            audience,
            observed_now.timestamp(),
            MACHINE_JWT_VC_SECURING_PROFILE,
        )
        .map_err(|_| MachineEvidenceError)?;
        let authenticated = verified.credential();
        let types = credential_types(authenticated.credential().get("type"))?;
        require_types(&types, request.policy.required_credential_types())?;
        if registered_credential_id(authenticated.credential_id())? != credential_id
            || authenticated.subject_id() != request.scope.principal.id
            || authenticated.issuer() != selection.issuer
            || authenticated.verification_method_id() != Some(key_id)
            || authenticated.algorithm() != algorithm.as_str()
            || format!("sha256:{}", authenticated.credential_sha256())
                != selection.credential_digest
            || verified.credential_jwt() != credential
            || types != hinted_types
            || !authenticated.credential_dates_verified()
        {
            return Err(MachineEvidenceError);
        }
        let signature_expires = DateTime::from_timestamp(authenticated.signature_expires_at(), 0)
            .ok_or(MachineEvidenceError)?;
        let mut valid_until = authority
            .valid_until
            .min(original_deadline)
            .min(request.proof.valid_until)
            .min(holder_expires)
            .min(holder_age_deadline)
            .min(signature_expires);
        if let Some(until) = authenticated.credential_valid_until() {
            valid_until = valid_until.min(until);
        }
        if let Some(until) = request.qualified_binding.key_valid_until() {
            valid_until = valid_until.min(until);
        }
        let completed_at = self.clock.now();
        if completed_at < observed_now || completed_at >= valid_until {
            return Err(MachineEvidenceError);
        }
        Ok(VerifiedMachineCredentials {
            scope: selection.scope,
            trust_profile_id: selection.trust_profile_id,
            credentials: vec![VerifiedMachineCredential {
                credential_id,
                credential_types: types,
                evidence_ref: authority.evidence_ref,
            }],
            observed_at: authority.observed_at,
            valid_until,
        })
    }
}

fn validate_context(request: &MachineEvidenceRequest<'_>) -> Result<(), MachineEvidenceError> {
    let scope = request.scope;
    let operation = request.operation;
    let binding = request.qualified_binding.binding();
    let proof_digest = format!(
        "urn:marty:oid4vp-proof:{:x}",
        Sha256::digest(&operation.proof)
    );
    if scope.organization_id != request.policy.organization_id()
        || scope.organization_id.to_string() != binding.organization_id()
        || scope.organization_id != operation.organization_id
        || scope.machine_identity_id != request.qualified_binding.machine_identity_id()
        || scope.deployment_profile_id.to_string() != binding.deployment_profile_id()
        || scope.principal.principal_type != PrincipalType::MachineIdentity
        || scope.principal.id != binding.principal_id()
        || scope.principal.id != binding.issuer()
        || scope.principal.id != binding.subject()
        || scope.principal != operation.actor
        || scope.runtime_instance_ref != binding.runtime_instance_ref()
        || scope.key_id != request.qualified_binding.key_id()
        || scope.key_thumbprint
            != binding
                .key_thumbprint()
                .reencode(ThumbprintEncoding::MipSha256Hex)
                .encoded_value()
        || scope.policy_id != request.policy.id()
        || scope.policy_digest != request.policy.digest()
        || scope.grant_id != operation.grant_id
        || scope.grant_revision != operation.expected_revision
        || scope.challenge_id != operation.challenge_id
        || scope.challenge_digest
            != format!(
                "sha256:{:x}",
                Sha256::digest(request.proof.challenge.as_bytes())
            )
        || scope.proof_evidence_ref != request.proof.evidence_ref
        || scope.proof_evidence_ref != proof_digest
        || scope.action != operation.action
        || scope.audience != operation.audience
        || scope.resource != operation.resource
        || scope.operation_profile != operation.operation_profile
        || scope.operation_digest != operation.operation_digest
        || request.proof.verified_at > request.now
        || request.proof.valid_until <= request.now
        || request.proof.valid_until <= request.proof.verified_at
    {
        return Err(MachineEvidenceError);
    }
    Ok(())
}

fn validate_authority(
    authority: &ResolvedMachineJwtVcAuthority,
    selection: &MachineJwtVcSelection,
    now: DateTime<Utc>,
) -> Result<(), MachineEvidenceError> {
    let source_deadline = authority
        .observed_at
        .checked_add_signed(Duration::seconds(SOURCE_MAX_AGE_SECONDS))
        .ok_or(MachineEvidenceError)?;
    if authority.selection != *selection
        || !valid_policy_revision(authority.trust_profile_revision)
        || !valid_digest(Some(&authority.trust_profile_digest))
        || [
            authority.trust_profile_status,
            authority.issuer_status,
            authority.issuer_key_status,
            authority.credential_status,
        ]
        .iter()
        .any(|status| *status != MachineCredentialSourceStatus::Active)
        || authority.issuer_key.issuer() != selection.issuer
        || authority.issuer_key.key_id() != Some(selection.verification_method_id.as_str())
        || authority.issuer_key.algorithm() != selection.algorithm
        || !valid_evidence_uri(&authority.evidence_ref)
        || authority.observed_at > now
        || authority.valid_until <= now
        || authority.valid_until <= authority.observed_at
        || authority.valid_until > source_deadline
    {
        return Err(MachineEvidenceError);
    }
    Ok(())
}

fn registered_credential_id(value: &str) -> Result<Uuid, MachineEvidenceError> {
    let uuid = value
        .strip_prefix("urn:uuid:")
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .ok_or(MachineEvidenceError)?;
    if value != format!("urn:uuid:{uuid}") {
        return Err(MachineEvidenceError);
    }
    Ok(uuid)
}

fn timestamp_claim(claims: &Value, key: &str) -> Result<DateTime<Utc>, MachineEvidenceError> {
    claims
        .get(key)
        .and_then(Value::as_i64)
        .and_then(|value| DateTime::from_timestamp(value, 0))
        .ok_or(MachineEvidenceError)
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn credential_types(value: Option<&Value>) -> Result<Vec<String>, MachineEvidenceError> {
    let types = value
        .and_then(Value::as_array)
        .ok_or(MachineEvidenceError)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(MachineEvidenceError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_type_list(&types)?;
    if !types.iter().any(|kind| kind == "VerifiableCredential") {
        return Err(MachineEvidenceError);
    }
    Ok(types)
}

fn validate_type_list(types: &[String]) -> Result<BTreeSet<&String>, MachineEvidenceError> {
    let set: BTreeSet<_> = types.iter().collect();
    if types.is_empty()
        || types.len() > MAX_CREDENTIAL_TYPES
        || set.len() != types.len()
        || types.iter().any(|kind| !bounded_text(kind, 256))
    {
        return Err(MachineEvidenceError);
    }
    Ok(set)
}

fn require_types(actual: &[String], required: &[String]) -> Result<(), MachineEvidenceError> {
    if required.is_empty() || required.iter().any(|kind| !actual.contains(kind)) {
        return Err(MachineEvidenceError);
    }
    Ok(())
}

#[cfg(test)]
#[path = "machine_credentials_tests.rs"]
mod tests;
