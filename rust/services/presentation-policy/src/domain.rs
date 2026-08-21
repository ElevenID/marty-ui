use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    Draft,
    Active,
    Suspended,
    Archived,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintType {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    InSet,
    NotInSet,
    Presence,
    Regex,
    AgeOver,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPurpose {
    IdentityVerification,
    AgeVerification,
    EmploymentVerification,
    AddressVerification,
    QualificationVerification,
    Authorization,
    Compliance,
    Other,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimConstraint {
    pub id: Uuid,
    pub claim_name: String,
    pub constraint_type: ConstraintType,
    pub value: Option<Value>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedClaim {
    pub id: Uuid,
    pub claim_name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub required: bool,
    pub selective_disclosure: bool,
    pub accept_derived: bool,
    pub predicate_spec: Option<Value>,
    pub constraints: Vec<ClaimConstraint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequirement {
    pub id: Uuid,
    pub credential_template_id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub required: bool,
    pub credential_payload_format: String,
    pub requested_claims: Vec<RequestedClaim>,
    pub trust_profile_id: Option<Uuid>,
    pub max_age_seconds: Option<u64>,
    pub require_fresh_issuance: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlternativeRequirement {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub credential_requirements: Vec<CredentialRequirement>,
    pub min_satisfied: usize,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayMetadata {
    pub title: String,
    pub description: String,
    pub purpose: RequestPurpose,
    pub purpose_description: Option<String>,
    pub verifier_name: String,
    pub verifier_logo_url: Option<String>,
    pub privacy_policy_url: Option<String>,
    pub terms_of_service_url: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HolderBinding {
    pub required: bool,
    pub binding_methods: Vec<String>,
    pub proof_profiles: Vec<String>,
    pub proof_freshness: BTreeMap<String, bool>,
}

impl HolderBinding {
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.binding_methods = self
            .binding_methods
            .into_iter()
            .filter_map(|method| match method.as_str() {
                "NONCE" => Some("SESSION_BINDING".to_owned()),
                "BIOMETRIC" => None,
                _ => Some(method),
            })
            .collect();
        if self.required && self.binding_methods.is_empty() {
            self.binding_methods.push("DEVICE_KEY".into());
        }
        if self.required && self.proof_profiles.is_empty() {
            self.proof_profiles
                .push("OID4VP_VERIFIABLE_PRESENTATION".into());
        }
        if self.required && self.proof_freshness.is_empty() {
            self.proof_freshness = [
                ("challenge_required".into(), true),
                ("audience_binding_required".into(), true),
                ("replay_detection_required".into(), true),
            ]
            .into_iter()
            .collect();
        }
        self
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessPolicy {
    pub max_age_seconds: Option<u64>,
    pub require_not_revoked: bool,
    pub revocation_grace_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConstraints {
    pub min_trust_level: Option<u32>,
    pub required_compliance_statuses: Vec<String>,
    pub required_accreditations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationPolicy {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: PolicyStatus,
    pub display_metadata: DisplayMetadata,
    pub required_claims: Vec<RequestedClaim>,
    pub accepted_credential_types: Vec<String>,
    pub credential_requirements: Vec<CredentialRequirement>,
    pub alternative_requirements: Vec<AlternativeRequirement>,
    pub presentation_proof_required: bool,
    pub trust_profile_id: Option<Uuid>,
    pub holder_binding: HolderBinding,
    pub freshness: Option<FreshnessPolicy>,
    pub issuer_constraints: Option<IssuerConstraints>,
    pub credential_ranking_strategy: String,
    pub credential_ranking_weights: Option<BTreeMap<String, f64>>,
    pub purpose: Option<String>,
    pub compliance_profile_id: Option<Uuid>,
    pub prefer_predicates: bool,
    pub fallback_policy: Option<String>,
    pub supported_circuits: Vec<String>,
    pub version: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyDomainError {
    #[error("PRESENTATION_POLICY.INVALID: at least one credential, alternative, claim, or holder proof is required")]
    EmptyRequirements,
    #[error("PRESENTATION_POLICY.INVALID: credential requirement {id} has no requested claims")]
    EmptyRequestedClaims { id: Uuid },
    #[error("PRESENTATION_POLICY.INVALID: alternative {id} has an invalid satisfaction threshold")]
    InvalidAlternativeThreshold { id: Uuid },
    #[error("PRESENTATION_POLICY.INVALID: custom ranking requires weights")]
    MissingRankingWeights,
    #[error("PRESENTATION_POLICY.INVALID_TRANSITION: {from:?} cannot transition to {to:?}")]
    InvalidTransition {
        from: PolicyStatus,
        to: PolicyStatus,
    },
    #[error("PRESENTATION_POLICY.NATIVE: {0}")]
    Native(String),
}

impl PresentationPolicy {
    pub fn validate(&self) -> Result<(), PolicyDomainError> {
        if self.required_claims.is_empty()
            && self.credential_requirements.is_empty()
            && self.alternative_requirements.is_empty()
            && !self.presentation_proof_required
        {
            return Err(PolicyDomainError::EmptyRequirements);
        }
        for requirement in self.credential_requirements.iter().chain(
            self.alternative_requirements
                .iter()
                .flat_map(|alternative| alternative.credential_requirements.iter()),
        ) {
            if requirement.requested_claims.is_empty() {
                return Err(PolicyDomainError::EmptyRequestedClaims { id: requirement.id });
            }
        }
        for alternative in &self.alternative_requirements {
            if alternative.credential_requirements.is_empty()
                || alternative.min_satisfied == 0
                || alternative.min_satisfied > alternative.credential_requirements.len()
            {
                return Err(PolicyDomainError::InvalidAlternativeThreshold { id: alternative.id });
            }
        }
        if self.credential_ranking_strategy == "CUSTOM"
            && self
                .credential_ranking_weights
                .as_ref()
                .is_none_or(BTreeMap::is_empty)
        {
            return Err(PolicyDomainError::MissingRankingWeights);
        }
        Ok(())
    }

    pub fn activate(&mut self, now: DateTime<Utc>) -> Result<(), PolicyDomainError> {
        self.validate()?;
        self.transition(PolicyStatus::Active, now)
    }

    pub fn suspend(&mut self, now: DateTime<Utc>) -> Result<(), PolicyDomainError> {
        self.transition(PolicyStatus::Suspended, now)
    }

    fn transition(
        &mut self,
        next: PolicyStatus,
        now: DateTime<Utc>,
    ) -> Result<(), PolicyDomainError> {
        let allowed = matches!(
            (self.status, next),
            (
                PolicyStatus::Draft | PolicyStatus::Suspended,
                PolicyStatus::Active
            ) | (PolicyStatus::Active, PolicyStatus::Suspended)
                | (
                    PolicyStatus::Draft | PolicyStatus::Suspended,
                    PolicyStatus::Archived
                )
        );
        if !allowed {
            return Err(PolicyDomainError::InvalidTransition {
                from: self.status,
                to: next,
            });
        }
        self.status = next;
        self.updated_at = now;
        Ok(())
    }

    #[must_use]
    pub fn new_version(&self, id: Uuid, now: DateTime<Utc>) -> Self {
        let mut version = self.clone();
        version.id = id;
        version.status = PolicyStatus::Draft;
        version.version = self.version.saturating_add(1);
        version.created_at = now;
        version.updated_at = now;
        version
    }
}

#[must_use]
pub fn normalize_credential_format(value: &str) -> String {
    marty_verification::policy::canonical_credential_format(value)
}

pub fn evaluate_verified_facts_json(request_json: &str) -> Result<String, PolicyDomainError> {
    if request_json.len() > 1_000_000 {
        return Err(PolicyDomainError::Native(
            "request exceeds 1000000 bytes".into(),
        ));
    }
    let request = serde_json::from_str(request_json)
        .map_err(|error| PolicyDomainError::Native(error.to_string()))?;
    let result = marty_verification::policy::evaluate_service_policy(request)
        .map_err(|error| PolicyDomainError::Native(error.to_string()))?;
    serde_json::to_string(&result).map_err(|error| PolicyDomainError::Native(error.to_string()))
}
