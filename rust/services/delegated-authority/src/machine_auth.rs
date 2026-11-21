//! Explicit Machine Authentication Policy composition over the existing OID4VP
//! cryptographic proof adapter. No new proof wire or enrollment shortcut exists.
//!
//! The selected path requires a real current MachineIdentity, MACHINE_KEY,
//! OID4VP, all registered machine credentials required by the MAP, and every
//! selected attestation/MACHINE_AUTHORIZATION requirement. Providers are trusted
//! in-process verification ports, not request DTOs or caller success flags.
//! No production providers or public feature switch are installed by this module.
//! Atomic replay, current grant authority and domain authorization remain with
//! DelegationUseAuthorizer and the retained final-use owner.

use std::{collections::BTreeSet, fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_principal_runtime_binding::{
    machine_policy::{
        qualify_machine_binding, valid_evidence_uri, valid_policy_revision,
        MachineAuthenticationPolicy, QualifiedMachineBinding,
    },
    parse_binding_record, parse_configuration, parse_machine_snapshot, ThumbprintEncoding,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    domain::valid_digest, BindingMethod, DelegateProofError, DelegateProofVerifier,
    DelegationClock, DelegationGrant, DelegationOid4vpChallenge, DelegationOid4vpChallengeStore,
    DelegationOid4vpChallengeStoreError, DelegationUseRequest, MartyOid4vpDelegateProofVerifier,
    Principal, PrincipalType, SystemDelegationClock, VerifiedDelegateProof,
};

const SOURCE_MAX_AGE_SECONDS: i64 = 30;
const PROVIDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_EVIDENCE_BYTES: usize = 65_536;
pub const MACHINE_AUTHENTICATION_EVIDENCE_PROFILE: &str =
    "urn:marty:machine-authentication-evidence:v1";

/// All documents are loaded through an independently authenticated/configured
/// source, scoped by the grant tenant and typed delegate. The source must select
/// the current deployment's assigned MAP; request bodies cannot override it.
/// Its deadline bounds current machine/key, policy assignment, and status.
pub struct ResolvedMachineAuthenticationState {
    pub binding_record: Vec<u8>,
    pub binding_configuration: Vec<u8>,
    pub machine_identity: Vec<u8>,
    pub machine_authentication_policy: Vec<u8>,
    pub evidence_ref: String,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait MachineAuthenticationStateSource: Send + Sync {
    async fn resolve_current(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineAuthenticationState, MachineEvidenceError>;
}

/// Exact context derived after actual cryptographic verification. Providers
/// return this entire scope unchanged, including policy and proof identities.
/// Matching is byte-exact and does not infer trust from URI prefixes.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct MachineAuthenticationScope {
    pub organization_id: Uuid,
    pub machine_identity_id: Uuid,
    pub deployment_profile_id: Uuid,
    pub principal: Principal,
    pub runtime_instance_ref: String,
    pub key_id: String,
    pub key_thumbprint: String,
    pub policy_id: Uuid,
    pub policy_digest: String,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub challenge_id: Uuid,
    pub challenge_digest: String,
    pub proof_evidence_ref: String,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
}

/// A provider must cryptographically authenticate credentials, their issuer and
/// trust-profile selection, exact machine subject/key binding, validity and
/// current revocation/status before returning a positive record. Merely finding
/// a credential ID or matching a caller's credential type is insufficient.
pub struct VerifiedMachineCredential {
    pub credential_id: Uuid,
    pub credential_types: Vec<String>,
    pub evidence_ref: String,
}

pub struct VerifiedMachineCredentials {
    pub scope: MachineAuthenticationScope,
    pub trust_profile_id: Uuid,
    pub credentials: Vec<VerifiedMachineCredential>,
    /// These bounds cover all credential issuer/trust/status/validity checks.
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// Internal provider request. The raw VP has already passed the concrete Core
/// signature/holder/nonce verifier. Embedded credentials still require their
/// independent issuer, subject/key, status, and trust-profile verification.
pub struct MachineEvidenceRequest<'a> {
    pub scope: &'a MachineAuthenticationScope,
    pub policy: &'a MachineAuthenticationPolicy,
    pub qualified_binding: &'a QualifiedMachineBinding,
    pub operation: &'a DelegationUseRequest,
    pub proof: &'a VerifiedDelegateProof,
    pub now: DateTime<Utc>,
}

#[async_trait]
pub trait MachineCredentialVerifier: Send + Sync {
    async fn verify_required(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineCredentials, MachineEvidenceError>;
}

/// Positive appraisal from an authenticated configured attestation verifier.
/// The provider verifies the selected format/trust chain, original challenge,
/// exact machine identity key, and runtime association before returning it.
pub struct VerifiedMachineAttestation {
    pub scope: MachineAuthenticationScope,
    pub verifier_trust_profile_id: Uuid,
    pub format: String,
    pub result_digest: String,
    pub evidence_ref: String,
    pub produced_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait MachineAttestationVerifier: Send + Sync {
    async fn verify_required(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAttestation, MachineEvidenceError>;
}

/// Positive result of the configured, current MACHINE_AUTHORIZATION policy
/// evaluator. Deny, unknown/error, wrong policy type, absent policy and an
/// unqualified engine must return Err. This is separate from delegated/domain
/// Cedar authorization and cannot substitute for it.
pub struct VerifiedMachineAuthorization {
    pub scope: MachineAuthenticationScope,
    pub policy_set_id: Uuid,
    pub policy_type: String,
    pub revision: u64,
    pub policy_digest: String,
    pub evidence_ref: String,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

#[async_trait]
pub trait MachineAuthorizationVerifier: Send + Sync {
    async fn verify_permitted(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAuthorization, MachineEvidenceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("machine authentication evidence is unavailable or unqualified")]
pub struct MachineEvidenceError;

/// Completed selected provider gate. This cannot be deserialized or cloned.
/// It proves only the configured providers' bounded observations; a final-use
/// owner still rechecks current authority and atomically consumes its challenge.
///
/// ```compile_fail
/// use marty_delegated_authority::machine_auth::AuthenticatedMachineProof;
/// let forged: AuthenticatedMachineProof = serde_json::from_str("{}").unwrap();
/// ```
pub struct AuthenticatedMachineProof {
    proof: VerifiedDelegateProof,
    scope: MachineAuthenticationScope,
    source_evidence_ref: String,
    evidence_refs: Vec<String>,
    evidence_document: Value,
    evidence_bytes: Vec<u8>,
    completed_at: DateTime<Utc>,
}

impl AuthenticatedMachineProof {
    pub fn scope(&self) -> &MachineAuthenticationScope {
        &self.scope
    }
    pub fn source_evidence_ref(&self) -> &str {
        &self.source_evidence_ref
    }
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }
    /// Private audit data, not a public request or a bearer authorization. A
    /// qualified consuming host must durably retain it under the returned
    /// aggregate proof evidence reference; calculating its digest is not storage.
    pub fn evidence_document(&self) -> &Value {
        &self.evidence_document
    }
    /// Exact canonical bytes hashed by the aggregate proof evidence reference.
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }
    pub fn evidence_ref(&self) -> &str {
        &self.proof.evidence_ref
    }
    pub fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.proof.valid_until
    }
    pub fn ensure_current(&self, now: DateTime<Utc>) -> Result<(), MachineEvidenceError> {
        if now < self.completed_at || now >= self.proof.valid_until {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }
    /// Composition into DelegationUseAuthorizer; never an authorization by itself.
    pub fn into_delegate_proof(self) -> VerifiedDelegateProof {
        self.proof
    }
}

#[derive(Clone)]
pub struct MartyMachineOid4vpProofVerifier {
    challenges: Arc<dyn DelegationOid4vpChallengeStore>,
    state: Arc<dyn MachineAuthenticationStateSource>,
    credentials: Option<Arc<dyn MachineCredentialVerifier>>,
    attestation: Option<Arc<dyn MachineAttestationVerifier>>,
    authorization: Option<Arc<dyn MachineAuthorizationVerifier>>,
    clock: Arc<dyn DelegationClock>,
    timeout: std::time::Duration,
}

impl MartyMachineOid4vpProofVerifier {
    pub fn new(
        challenges: Arc<dyn DelegationOid4vpChallengeStore>,
        state: Arc<dyn MachineAuthenticationStateSource>,
        credentials: Option<Arc<dyn MachineCredentialVerifier>>,
        attestation: Option<Arc<dyn MachineAttestationVerifier>>,
        authorization: Option<Arc<dyn MachineAuthorizationVerifier>>,
    ) -> Self {
        Self::with_clock(
            challenges,
            state,
            credentials,
            attestation,
            authorization,
            Arc::new(SystemDelegationClock),
        )
    }

    pub fn with_clock(
        challenges: Arc<dyn DelegationOid4vpChallengeStore>,
        state: Arc<dyn MachineAuthenticationStateSource>,
        credentials: Option<Arc<dyn MachineCredentialVerifier>>,
        attestation: Option<Arc<dyn MachineAttestationVerifier>>,
        authorization: Option<Arc<dyn MachineAuthorizationVerifier>>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            challenges,
            state,
            credentials,
            attestation,
            authorization,
            clock,
            timeout: PROVIDER_TIMEOUT,
        }
    }

    pub async fn verify_machine(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedMachineProof, MachineEvidenceError> {
        tokio::time::timeout(self.timeout, self.verify_inner(grant, request, now))
            .await
            .map_err(|_| MachineEvidenceError)?
    }

    async fn verify_inner(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedMachineProof, MachineEvidenceError> {
        if request.actor.principal_type != PrincipalType::MachineIdentity
            || grant.terms.delegate != request.actor
            || grant.organization_id != request.organization_id
            || grant.id != request.grant_id
            || grant.revision != request.expected_revision
            || grant.terms.binding.method != BindingMethod::Key
        {
            return Err(MachineEvidenceError);
        }
        let mut window = ObservationWindow::new(now)?;
        window.refresh(self.clock.as_ref())?;
        let state = self
            .state
            .resolve_current(grant, request, window.now)
            .await?;
        window.refresh(self.clock.as_ref())?;
        window.constrain(state.observed_at, state.valid_until)?;
        if !valid_evidence_uri(&state.evidence_ref) {
            return Err(MachineEvidenceError);
        }
        let policy = MachineAuthenticationPolicy::from_trusted_document(
            &state.machine_authentication_policy,
        )
        .map_err(|_| MachineEvidenceError)?;
        let record =
            parse_binding_record(&state.binding_record).map_err(|_| MachineEvidenceError)?;
        let configuration =
            parse_configuration(&state.binding_configuration).map_err(|_| MachineEvidenceError)?;
        let machine =
            parse_machine_snapshot(&state.machine_identity).map_err(|_| MachineEvidenceError)?;
        // A source observation cannot attest to a policy/key state recorded
        // after that observation. Current expiry is bounded separately below.
        let qualified = qualify_machine_binding(
            request.organization_id,
            &policy,
            &record,
            &configuration,
            &machine,
            state.observed_at,
        )
        .map_err(|_| MachineEvidenceError)?;
        let binding = qualified.binding();
        let thumbprint = binding
            .key_thumbprint()
            .reencode(ThumbprintEncoding::MipSha256Hex)
            .encoded_value();
        if binding.principal_id() != request.actor.id
            || binding.issuer() != request.actor.id
            || binding.subject() != request.actor.id
            || grant.terms.binding.key_thumbprint.as_deref() != Some(thumbprint.as_str())
            || binding.session_ref().is_some()
        {
            return Err(MachineEvidenceError);
        }
        if let Some(expiry) = qualified.key_valid_until() {
            window.bound(expiry)?;
        }
        let credentials_provider = self.credentials.as_ref().ok_or(MachineEvidenceError)?;
        if (policy.required_attestation().is_some() && self.attestation.is_none())
            || (policy.authorization_policy_set_id().is_some() && self.authorization.is_none())
        {
            return Err(MachineEvidenceError);
        }
        // The concrete existing cryptographic verifier is mandatory. No injected
        // verified:true or arbitrary DelegateProofVerifier can replace it.
        let proof_verifier = MartyOid4vpDelegateProofVerifier::new(
            Arc::new(AudienceBoundChallengeStore {
                inner: self.challenges.clone(),
                expected_verifier: binding.audience().to_owned(),
            }),
            i64::from(
                policy
                    .select_oid4vp_machine_key()
                    .map_err(|_| MachineEvidenceError)?,
            ),
        )
        .map_err(|_| MachineEvidenceError)?;
        let mut proof = proof_verifier
            .verify(grant, request, window.now)
            .await
            .map_err(|_| MachineEvidenceError)?;
        window.refresh(self.clock.as_ref())?;
        if proof.verified_at > window.now || proof.verified_at < now {
            return Err(MachineEvidenceError);
        }
        window.bound(proof.valid_until)?;
        let scope = MachineAuthenticationScope {
            organization_id: request.organization_id,
            machine_identity_id: qualified.machine_identity_id(),
            deployment_profile_id: Uuid::parse_str(binding.deployment_profile_id())
                .map_err(|_| MachineEvidenceError)?,
            principal: request.actor.clone(),
            runtime_instance_ref: binding.runtime_instance_ref().into(),
            key_id: qualified.key_id().into(),
            key_thumbprint: thumbprint,
            policy_id: policy.id(),
            policy_digest: policy.digest().into(),
            grant_id: grant.id,
            grant_revision: grant.revision,
            challenge_id: request.challenge_id,
            challenge_digest: format!("sha256:{:x}", Sha256::digest(proof.challenge.as_bytes())),
            proof_evidence_ref: proof.evidence_ref.clone(),
            action: request.action.clone(),
            audience: request.audience.clone(),
            resource: request.resource.clone(),
            operation_profile: request.operation_profile.clone(),
            operation_digest: request.operation_digest.clone(),
        };
        if scope.deployment_profile_id.is_nil() {
            return Err(MachineEvidenceError);
        }
        let evidence = credentials_provider
            .verify_required(MachineEvidenceRequest {
                scope: &scope,
                policy: &policy,
                qualified_binding: &qualified,
                operation: request,
                proof: &proof,
                now: window.now,
            })
            .await?;
        window.refresh(self.clock.as_ref())?;
        window.constrain(evidence.observed_at, evidence.valid_until)?;
        let mut evidence_refs = validate_credentials(&policy, &qualified, &scope, &evidence)?;
        let mut attestation_document = None;
        if let Some(requirement) = policy.required_attestation() {
            let result = self
                .attestation
                .as_ref()
                .ok_or(MachineEvidenceError)?
                .verify_required(MachineEvidenceRequest {
                    scope: &scope,
                    policy: &policy,
                    qualified_binding: &qualified,
                    operation: request,
                    proof: &proof,
                    now: window.now,
                })
                .await?;
            window.refresh(self.clock.as_ref())?;
            window.constrain(result.observed_at, result.valid_until)?;
            let maximum_age = requirement.max_age_seconds().ok_or(MachineEvidenceError)?;
            let attestation_expiry = result
                .produced_at
                .checked_add_signed(Duration::seconds(i64::from(maximum_age)))
                .ok_or(MachineEvidenceError)?;
            if result.scope != scope
                || Some(result.verifier_trust_profile_id) != requirement.verifier_trust_profile_id()
                || !requirement.accepted_formats().contains(&result.format)
                || !valid_digest(Some(&result.result_digest))
                || !valid_evidence_uri(&result.evidence_ref)
                || result.produced_at > result.observed_at
                || result.produced_at > window.now
                || result.valid_until > attestation_expiry
            {
                return Err(MachineEvidenceError);
            }
            window.bound(attestation_expiry)?;
            attestation_document = Some(json!({
                "verifier_trust_profile_id": result.verifier_trust_profile_id,
                "format": result.format,
                "result_digest": result.result_digest,
                "evidence_ref": result.evidence_ref,
                "produced_at": result.produced_at,
                "observed_at": result.observed_at,
                "valid_until": result.valid_until,
            }));
            evidence_refs.push(result.evidence_ref);
        }
        let mut authorization_document = None;
        if let Some(policy_set_id) = policy.authorization_policy_set_id() {
            let result = self
                .authorization
                .as_ref()
                .ok_or(MachineEvidenceError)?
                .verify_permitted(MachineEvidenceRequest {
                    scope: &scope,
                    policy: &policy,
                    qualified_binding: &qualified,
                    operation: request,
                    proof: &proof,
                    now: window.now,
                })
                .await?;
            window.refresh(self.clock.as_ref())?;
            window.constrain(result.observed_at, result.valid_until)?;
            if result.scope != scope
                || result.policy_set_id != policy_set_id
                || result.policy_type != "MACHINE_AUTHORIZATION"
                || !valid_policy_revision(result.revision)
                || !valid_digest(Some(&result.policy_digest))
                || !valid_evidence_uri(&result.evidence_ref)
            {
                return Err(MachineEvidenceError);
            }
            authorization_document = Some(json!({
                "policy_set_id": result.policy_set_id,
                "policy_type": result.policy_type,
                "revision": result.revision,
                "policy_digest": result.policy_digest,
                "evidence_ref": result.evidence_ref,
                "observed_at": result.observed_at,
                "valid_until": result.valid_until,
            }));
            evidence_refs.push(result.evidence_ref);
        }
        window.refresh(self.clock.as_ref())?;
        let evidence_document = json!({
            "profile": MACHINE_AUTHENTICATION_EVIDENCE_PROFILE,
            "scope": scope,
            "policy_document": serde_json::from_slice::<Value>(&state.machine_authentication_policy)
                .map_err(|_| MachineEvidenceError)?,
            "state": {
                "evidence_ref": state.evidence_ref,
                "observed_at": state.observed_at,
                "valid_until": state.valid_until,
            },
            "proof": {
                "evidence_ref": proof.evidence_ref,
                "verified_at": proof.verified_at,
                "valid_until": proof.valid_until,
            },
            "credentials": {
                "trust_profile_id": evidence.trust_profile_id,
                "credentials": evidence.credentials.iter().map(|credential| json!({
                    "credential_id": credential.credential_id,
                    "credential_types": credential.credential_types,
                    "evidence_ref": credential.evidence_ref,
                })).collect::<Vec<_>>(),
                "observed_at": evidence.observed_at,
                "valid_until": evidence.valid_until,
            },
            "attestation": attestation_document,
            "machine_authorization": authorization_document,
            "completed_at": window.now,
            "valid_until": window.deadline,
        });
        let evidence_bytes = canonical_evidence_bytes(&evidence_document)?;
        proof.evidence_ref = format!(
            "urn:marty:machine-authentication:sha256:{:x}",
            Sha256::digest(&evidence_bytes)
        );
        proof.valid_until = window.deadline;
        Ok(AuthenticatedMachineProof {
            proof,
            scope,
            source_evidence_ref: state.evidence_ref,
            evidence_refs,
            evidence_document,
            evidence_bytes,
            completed_at: window.now,
        })
    }
}

fn canonical_evidence_bytes(value: &Value) -> Result<Vec<u8>, MachineEvidenceError> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys = object.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                let mut result = serde_json::Map::new();
                for key in keys {
                    result.insert(key.clone(), sorted(&object[key]));
                }
                Value::Object(result)
            }
            Value::Array(array) => Value::Array(array.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    // All member names are fixed ASCII; numbers are bounded integer revisions
    // or MAP ages. Source credentials/proofs and private signing keys are absent.
    let bytes = serde_json::to_vec(&sorted(value)).map_err(|_| MachineEvidenceError)?;
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(MachineEvidenceError);
    }
    Ok(bytes)
}

#[async_trait]
impl DelegateProofVerifier for MartyMachineOid4vpProofVerifier {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegateProof, DelegateProofError> {
        self.verify_machine(grant, request, now)
            .await
            .map(AuthenticatedMachineProof::into_delegate_proof)
            .map_err(|_| DelegateProofError)
    }
}

fn validate_credentials(
    policy: &MachineAuthenticationPolicy,
    qualified: &QualifiedMachineBinding,
    scope: &MachineAuthenticationScope,
    evidence: &VerifiedMachineCredentials,
) -> Result<Vec<String>, MachineEvidenceError> {
    if evidence.scope != *scope
        || evidence.trust_profile_id != policy.trust_profile_id()
        || evidence.credentials.is_empty()
        || evidence.credentials.len() > 32
    {
        return Err(MachineEvidenceError);
    }
    let mut ids = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut evidence_refs = Vec::new();
    for credential in &evidence.credentials {
        if !qualified
            .credential_ids()
            .contains(&credential.credential_id)
            || !ids.insert(credential.credential_id)
            || !valid_evidence_uri(&credential.evidence_ref)
            || credential.credential_types.is_empty()
            || credential.credential_types.len() > 32
            || credential
                .credential_types
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != credential.credential_types.len()
            || credential.credential_types.iter().any(|value| {
                value.is_empty()
                    || value.chars().count() > 256
                    || value.chars().any(char::is_control)
            })
        {
            return Err(MachineEvidenceError);
        }
        types.extend(credential.credential_types.iter());
        evidence_refs.push(credential.evidence_ref.clone());
    }
    if policy
        .required_credential_types()
        .iter()
        .any(|required| !types.contains(required))
    {
        return Err(MachineEvidenceError);
    }
    Ok(evidence_refs)
}

struct AudienceBoundChallengeStore {
    inner: Arc<dyn DelegationOid4vpChallengeStore>,
    expected_verifier: String,
}

#[async_trait]
impl DelegationOid4vpChallengeStore for AudienceBoundChallengeStore {
    async fn load_active(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
        let challenge = self
            .inner
            .load_active(organization_id, grant_id, challenge_id)
            .await?;
        if challenge.verifier_client_id != self.expected_verifier {
            return Err(DelegationOid4vpChallengeStoreError);
        }
        Ok(challenge)
    }
}

struct ObservationWindow {
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
}

impl ObservationWindow {
    fn new(now: DateTime<Utc>) -> Result<Self, MachineEvidenceError> {
        Ok(Self {
            now,
            deadline: now
                .checked_add_signed(Duration::seconds(SOURCE_MAX_AGE_SECONDS))
                .ok_or(MachineEvidenceError)?,
        })
    }
    fn refresh(&mut self, clock: &dyn DelegationClock) -> Result<(), MachineEvidenceError> {
        let current = clock.now();
        if current < self.now || current >= self.deadline {
            return Err(MachineEvidenceError);
        }
        self.now = current;
        Ok(())
    }
    fn constrain(
        &mut self,
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<(), MachineEvidenceError> {
        let limit = observed_at
            .checked_add_signed(Duration::seconds(SOURCE_MAX_AGE_SECONDS))
            .ok_or(MachineEvidenceError)?;
        if observed_at > self.now || valid_until <= observed_at || valid_until > limit {
            return Err(MachineEvidenceError);
        }
        self.bound(valid_until)
    }
    fn bound(&mut self, until: DateTime<Utc>) -> Result<(), MachineEvidenceError> {
        self.deadline = self.deadline.min(until);
        if self.now >= self.deadline {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }
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
    ResolvedMachineAuthenticationState,
    MachineAuthenticationScope,
    VerifiedMachineCredential,
    VerifiedMachineCredentials,
    VerifiedMachineAttestation,
    VerifiedMachineAuthorization,
    AuthenticatedMachineProof,
    MartyMachineOid4vpProofVerifier
);

#[cfg(test)]
#[path = "machine_auth_tests.rs"]
mod tests;
