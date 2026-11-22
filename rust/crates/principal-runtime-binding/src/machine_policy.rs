//! Bounded selection of the pinned Machine Authentication Policy contract.
//!
//! Parsing and consistency checks do not authenticate a policy, a machine, or a
//! credential. A configured host must independently load current source state,
//! verify the selected proof and every required credential/attestation/policy
//! requirement, then bound all evidence by current source freshness. This module
//! never converts enrollment key control into operational authentication.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    model, strict_json, validate_binding, validation, BindingRecord, HashBasis,
    MachineIdentitySnapshot, PrincipalType, ProfileConfiguration, RuntimeKind,
    TrustedBindingInputs, ValidatedPrincipalBinding,
};

pub const SELECTED_BINDING_METHOD: &str = "MACHINE_KEY";
pub const SELECTED_PROOF_PROFILE: &str = "OID4VP_VERIFIABLE_PRESENTATION";
pub const MAX_MACHINE_PROOF_AGE_SECONDS: u32 = 600;
const MAX_REQUIRED_CREDENTIALS: usize = 32;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Strictly parsed policy whose source and current selection are host obligations.
/// Its digest covers every supplied policy field; selecting a subset does not
/// discard required credentials, attestation, or MACHINE_AUTHORIZATION policy.
#[derive(Clone)]
pub struct MachineAuthenticationPolicy {
    document: PolicyDocument,
    digest: String,
}

impl MachineAuthenticationPolicy {
    pub fn from_trusted_document(raw: &[u8]) -> Result<Self, MachinePolicyError> {
        let value = strict_json::object(raw).map_err(|_| MachinePolicyError::InvalidPolicy)?;
        let document: PolicyDocument =
            serde_json::from_value(value.clone()).map_err(|_| MachinePolicyError::InvalidPolicy)?;
        document.validate()?;
        Ok(Self {
            document,
            digest: digest(&canonical_json(&value)),
        })
    }

    pub fn id(&self) -> Uuid {
        self.document.id
    }
    pub fn organization_id(&self) -> Uuid {
        self.document.organization_id
    }
    pub fn trust_profile_id(&self) -> Uuid {
        self.document.trust_profile_id
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn required_credential_types(&self) -> &[String] {
        &self.document.required_credential_types
    }
    pub fn required_attestation(&self) -> Option<&AttestationRequirement> {
        self.document
            .attestation_requirement
            .as_ref()
            .filter(|requirement| requirement.required)
    }
    pub fn authorization_policy_set_id(&self) -> Option<Uuid> {
        self.document.authorization_policy_set_id
    }

    /// Select the existing Core-backed OID4VP/MACHINE_KEY adapter. Other valid
    /// MAP selections fail closed here instead of weakening their requirements.
    pub fn select_oid4vp_machine_key(&self) -> Result<u32, MachinePolicyError> {
        let binding = &self.document.machine_binding;
        if self.document.status != "ACTIVE" {
            return Err(MachinePolicyError::InactivePolicy);
        }
        if !binding
            .binding_methods
            .iter()
            .any(|v| v == SELECTED_BINDING_METHOD)
            || !binding
                .proof_profiles
                .iter()
                .any(|v| v == SELECTED_PROOF_PROFILE)
        {
            return Err(MachinePolicyError::UnsupportedSelection);
        }
        binding
            .proof_freshness
            .max_proof_age_seconds
            .filter(|age| (30..=MAX_MACHINE_PROOF_AGE_SECONDS).contains(age))
            .ok_or(MachinePolicyError::UnsupportedSelection)
    }
}

/// Required attestation selection from the exact MAP. Evidence verification
/// remains with the configured attestation provider, not this parser.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequirement {
    required: bool,
    #[serde(default, deserialize_with = "model::present")]
    accepted_formats: Option<Vec<String>>,
    #[serde(default, deserialize_with = "model::present")]
    verifier_trust_profile_id: Option<Uuid>,
    #[serde(default, deserialize_with = "model::present")]
    max_age_seconds: Option<u32>,
    #[serde(default, deserialize_with = "model::present")]
    challenge_required: Option<bool>,
    #[serde(default, deserialize_with = "model::present")]
    identity_key_binding_required: Option<bool>,
}

impl AttestationRequirement {
    pub fn accepted_formats(&self) -> &[String] {
        self.accepted_formats.as_deref().unwrap_or_default()
    }
    pub fn verifier_trust_profile_id(&self) -> Option<Uuid> {
        self.verifier_trust_profile_id
    }
    pub fn max_age_seconds(&self) -> Option<u32> {
        self.max_age_seconds
    }
}

/// Opaque consistency output for the selected full MachineIdentity path.
/// It is not authenticated workload evidence and cannot be deserialized.
///
/// ```compile_fail
/// use marty_principal_runtime_binding::machine_policy::QualifiedMachineBinding;
/// let forged: QualifiedMachineBinding = serde_json::from_str("{}").unwrap();
/// ```
pub struct QualifiedMachineBinding {
    binding: ValidatedPrincipalBinding,
    machine_identity_id: Uuid,
    key_id: String,
    key_valid_until: Option<DateTime<Utc>>,
    credential_ids: Vec<Uuid>,
}

impl QualifiedMachineBinding {
    pub fn binding(&self) -> &ValidatedPrincipalBinding {
        &self.binding
    }
    pub fn machine_identity_id(&self) -> Uuid {
        self.machine_identity_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn key_valid_until(&self) -> Option<DateTime<Utc>> {
        self.key_valid_until
    }
    pub fn credential_ids(&self) -> &[Uuid] {
        &self.credential_ids
    }
}

/// Check the exact selected policy and current full machine/key snapshot before
/// a host verifies its cryptographic proof. SERVICE_ACCOUNT directory entries,
/// including enrolled ones, are deliberately not promoted into MachineIdentity.
pub fn qualify_machine_binding(
    authorized_organization_id: Uuid,
    policy: &MachineAuthenticationPolicy,
    record: &BindingRecord,
    configuration: &ProfileConfiguration,
    machine: &MachineIdentitySnapshot,
    now: DateTime<Utc>,
) -> Result<QualifiedMachineBinding, MachinePolicyError> {
    policy.select_oid4vp_machine_key()?;
    let p = &policy.document;
    if authorized_organization_id.is_nil() || p.organization_id != authorized_organization_id {
        return Err(MachinePolicyError::TenantMismatch);
    }
    if p.created_at > now || p.updated_at.is_some_and(|time| time > now) {
        return Err(MachinePolicyError::FutureSourceState);
    }
    let binding = validate_binding(
        record,
        TrustedBindingInputs::new(&authorized_organization_id.to_string(), configuration)
            .map_err(|_| MachinePolicyError::BindingMismatch)?
            .with_machine(machine),
    )
    .map_err(|_| MachinePolicyError::BindingMismatch)?;
    if binding.principal_type() != PrincipalType::MachineIdentity
        || binding.runtime_kind() != RuntimeKind::Managed
    {
        return Err(MachinePolicyError::FullMachineIdentityRequired);
    }
    let m = &machine.0;
    let assignments = m
        .assignments
        .as_ref()
        .ok_or(MachinePolicyError::BindingMismatch)?;
    if assignments.deployment_profile_id.as_deref() != Some(binding.deployment_profile_id())
        || assignments
            .operator_organization_id
            .as_deref()
            .is_some_and(|id| id != binding.organization_id())
        || binding.key_thumbprint().basis() != HashBasis::JwkRfc7638Sha256
    {
        return Err(MachinePolicyError::BindingMismatch);
    }
    let machine_identity_id =
        Uuid::parse_str(&m.id).map_err(|_| MachinePolicyError::BindingMismatch)?;
    if machine_identity_id.is_nil()
        || p.allowed_machine_types
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&m.machine_type))
    {
        return Err(MachinePolicyError::MachineTypeDenied);
    }
    let created_at = timestamp(&m.created_at)?;
    if created_at > now
        || m.updated_at
            .as_ref()
            .map(|v| timestamp(v))
            .transpose()?
            .is_some_and(|time| time > now || time < created_at)
        || m.suspended_at.is_some()
        || m.revoked_at.is_some()
        || m.retired_at.is_some()
    {
        return Err(MachinePolicyError::FutureSourceState);
    }
    let active = m
        .identity_keys
        .iter()
        .find(|key| key.status == "ACTIVE")
        .ok_or(MachinePolicyError::BindingMismatch)?;
    if active.public_key_jwk.is_none() {
        return Err(MachinePolicyError::BindingMismatch);
    }
    let valid_from = active
        .valid_from
        .as_ref()
        .map(|v| timestamp(v))
        .transpose()?;
    let valid_until = active
        .valid_until
        .as_ref()
        .map(|v| timestamp(v))
        .transpose()?;
    if valid_from.is_some_and(|time| time > now)
        || valid_until.is_some_and(|time| time <= now)
        || matches!((valid_from, valid_until), (Some(from), Some(until)) if from >= until)
    {
        return Err(MachinePolicyError::KeyNotCurrent);
    }
    let credential_ids: Vec<Uuid> = m
        .credential_ids
        .as_ref()
        .ok_or(MachinePolicyError::RegisteredCredentialsRequired)?
        .iter()
        .map(|id| {
            Uuid::parse_str(id).map_err(|_| MachinePolicyError::RegisteredCredentialsRequired)
        })
        .collect::<Result<_, _>>()?;
    if credential_ids.is_empty()
        || credential_ids.len() > MAX_REQUIRED_CREDENTIALS
        || credential_ids.iter().any(Uuid::is_nil)
        || credential_ids.iter().collect::<BTreeSet<_>>().len() != credential_ids.len()
    {
        return Err(MachinePolicyError::RegisteredCredentialsRequired);
    }
    Ok(QualifiedMachineBinding {
        binding,
        machine_identity_id,
        key_id: active.key_id.clone(),
        key_valid_until: valid_until,
        credential_ids,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachinePolicyError {
    InvalidPolicy,
    InactivePolicy,
    UnsupportedSelection,
    TenantMismatch,
    BindingMismatch,
    FullMachineIdentityRequired,
    MachineTypeDenied,
    FutureSourceState,
    KeyNotCurrent,
    RegisteredCredentialsRequired,
}

impl fmt::Display for MachinePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "INVALID_MACHINE_AUTHENTICATION_POLICY",
            Self::InactivePolicy => "INACTIVE_MACHINE_AUTHENTICATION_POLICY",
            Self::UnsupportedSelection => "UNSUPPORTED_MACHINE_AUTHENTICATION_SELECTION",
            Self::TenantMismatch => "MACHINE_AUTHENTICATION_TENANT_MISMATCH",
            Self::BindingMismatch => "MACHINE_AUTHENTICATION_BINDING_MISMATCH",
            Self::FullMachineIdentityRequired => "FULL_MACHINE_IDENTITY_REQUIRED",
            Self::MachineTypeDenied => "MACHINE_TYPE_DENIED",
            Self::FutureSourceState => "MACHINE_AUTHENTICATION_SOURCE_STATE_NOT_CURRENT",
            Self::KeyNotCurrent => "MACHINE_KEY_NOT_CURRENT",
            Self::RegisteredCredentialsRequired => "REGISTERED_MACHINE_CREDENTIALS_REQUIRED",
        })
    }
}
impl std::error::Error for MachinePolicyError {}

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
    MachineAuthenticationPolicy,
    AttestationRequirement,
    QualifiedMachineBinding
);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    id: Uuid,
    organization_id: Uuid,
    name: String,
    #[serde(default, deserialize_with = "model::present")]
    description: Option<String>,
    trust_profile_id: Uuid,
    required_credential_types: Vec<String>,
    #[serde(default, deserialize_with = "model::present")]
    allowed_machine_types: Option<Vec<String>>,
    machine_binding: MachineBinding,
    #[serde(default, deserialize_with = "model::present")]
    attestation_requirement: Option<AttestationRequirement>,
    #[serde(default)]
    authorization_policy_set_id: Option<Uuid>,
    status: String,
    created_at: DateTime<Utc>,
    #[serde(default, deserialize_with = "model::present")]
    updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineBinding {
    binding_methods: Vec<String>,
    proof_profiles: Vec<String>,
    proof_freshness: ProofFreshness,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofFreshness {
    challenge_required: bool,
    audience_binding_required: bool,
    replay_detection_required: bool,
    #[serde(default)]
    max_proof_age_seconds: Option<u32>,
}

impl PolicyDocument {
    fn validate(&self) -> Result<(), MachinePolicyError> {
        let b = &self.machine_binding;
        if [self.id, self.organization_id, self.trust_profile_id]
            .iter()
            .any(Uuid::is_nil)
            || self
                .authorization_policy_set_id
                .is_some_and(|id| id.is_nil())
            || !text(&self.name, 1, 128)
            || self
                .description
                .as_ref()
                .is_some_and(|value| !text(value, 0, 1024))
            || !unique_strings(&self.required_credential_types, MAX_REQUIRED_CREDENTIALS)
            || self
                .required_credential_types
                .iter()
                .any(|value| !text(value, 1, 256))
            || !members(
                &b.binding_methods,
                &["MACHINE_KEY", "CREDENTIAL_KEY", "SESSION_BINDING"],
            )
            || !members(
                &b.proof_profiles,
                &[
                    "X509_MACHINE_AUTHENTICATION",
                    "SIGNED_CHALLENGE",
                    "OID4VP_VERIFIABLE_PRESENTATION",
                    "CUSTOM",
                ],
            )
            || !b.proof_freshness.challenge_required
            || !b.proof_freshness.audience_binding_required
            || !b.proof_freshness.replay_detection_required
            || b.proof_freshness.max_proof_age_seconds == Some(0)
            || !matches!(self.status.as_str(), "DRAFT" | "ACTIVE" | "ARCHIVED")
            || self.updated_at.is_some_and(|time| time < self.created_at)
        {
            return Err(MachinePolicyError::InvalidPolicy);
        }
        if self.allowed_machine_types.as_ref().is_some_and(|values| {
            !members(
                values,
                &[
                    "SECURE_DOCUMENT_PRINTER",
                    "DOCUMENT_PERSONALIZATION_SYSTEM",
                    "VERIFICATION_APPLIANCE",
                    "WALLET_SECURE_ELEMENT",
                    "HSM_WORKLOAD",
                    "SECURE_PROCESSING_RUNTIME",
                    "OTHER",
                ],
            )
        }) {
            return Err(MachinePolicyError::InvalidPolicy);
        }
        if let Some(a) = &self.attestation_requirement {
            if a.accepted_formats.as_ref().is_some_and(|formats| {
                !members(
                    formats,
                    &["EAT", "TPM_QUOTE", "PLATFORM_ATTESTATION", "CUSTOM"],
                )
            }) || a.verifier_trust_profile_id.is_some_and(|id| id.is_nil())
                || a.max_age_seconds == Some(0)
                || a.challenge_required == Some(false)
                || a.identity_key_binding_required == Some(false)
                || (a.required
                    && (a.accepted_formats.is_none()
                        || a.verifier_trust_profile_id.is_none()
                        || a.max_age_seconds.is_none()
                        || a.challenge_required != Some(true)
                        || a.identity_key_binding_required != Some(true)))
            {
                return Err(MachinePolicyError::InvalidPolicy);
            }
        }
        Ok(())
    }
}

fn text(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.chars().count()) && !value.chars().any(char::is_control)
}
fn unique_strings(values: &[String], max: usize) -> bool {
    (1..=max).contains(&values.len())
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
fn members(values: &[String], allowed: &[&str]) -> bool {
    unique_strings(values, allowed.len())
        && values.iter().all(|value| allowed.contains(&value.as_str()))
}
fn timestamp(value: &str) -> Result<DateTime<Utc>, MachinePolicyError> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| MachinePolicyError::FutureSourceState)
}
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn canonical_json(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut names = object.keys().collect::<Vec<_>>();
                names.sort_unstable();
                let mut result = serde_json::Map::new();
                for name in names {
                    result.insert(name.clone(), sorted(&object[name]));
                }
                Value::Object(result)
            }
            Value::Array(array) => Value::Array(array.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    // Pinned MAP has fixed ASCII member names and bounded integer numbers only.
    serde_json::to_vec(&sorted(value)).expect("validated JSON document")
}

/// Validate one machine-provider result's URI without normalizing or fetching it.
pub fn valid_evidence_uri(value: &str) -> bool {
    validation::uri(value, 1024, true, "machine_evidence.uri").is_ok()
}

/// JSON-safe positive policy revisions are required at provider boundaries.
pub fn valid_policy_revision(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}
