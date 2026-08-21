use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use marty_verification::credential_format::{detect_credential_format, DetectedCredentialFormat};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    EvaluatePresentationRequest, PresentationPolicy, PresentationVerificationError,
    PresentationVerificationOrchestrator,
};

/// Verifier-owned trust profile supplied to native credential kernels.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedTrustProfile {
    pub id: Uuid,
    pub organization_id: Uuid,
    /// The internal trust-profile document contains only public verification
    /// material and governed relationship/lifecycle evidence.
    pub document: Value,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerTrustEvidence {
    pub verified: bool,
    pub failure_reason: Option<String>,
    pub trust_level: Option<u32>,
    pub compliance_statuses: Vec<String>,
    pub accreditations: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialStatusEvidence {
    pub checked_at_epoch_seconds: Option<u64>,
    pub not_revoked: Option<bool>,
    pub credential_status: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialVerificationContext {
    pub format: DetectedCredentialFormat,
    pub token: Value,
    pub nonce: Option<String>,
    pub audience: Option<String>,
    pub verifier_context: Map<String, Value>,
    pub trust_profile: Option<ResolvedTrustProfile>,
}

/// Authenticated material returned by one Rust credential-format kernel.
/// Unverified input is represented explicitly and never supplies claims.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialVerificationEvidence {
    pub verified: bool,
    pub failure_reason: Option<String>,
    pub credential_id: Option<String>,
    pub credential_status_ids: Vec<String>,
    pub claims: Map<String, Value>,
    pub issuer_id: Option<String>,
    pub issued_at_epoch_seconds: Option<u64>,
    pub warnings: Vec<String>,
    pub presentation_verified: bool,
    pub presentation_count: Option<usize>,
    pub holder_binding_verified: bool,
    pub holder_binding_method: Option<String>,
    pub proof_profile: Option<String>,
    pub challenge_verified: bool,
    pub audience_verified: bool,
    pub replay_check_verified: bool,
    pub proof_epoch_seconds: Option<u64>,
    pub status: CredentialStatusEvidence,
}

#[async_trait]
pub trait CredentialVerificationKernel: Send + Sync {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError>;
}

#[async_trait]
pub trait PresentationTrustResolver: Send + Sync {
    async fn load_profile(
        &self,
        profile_id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError>;

    async fn evaluate_issuer(
        &self,
        profile: &ResolvedTrustProfile,
        issuer_id: &str,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError>;
}

#[async_trait]
pub trait CredentialStatusResolver: Send + Sync {
    async fn resolve(
        &self,
        organization_id: Uuid,
        issuer_id: &str,
        credential_ids: &[String],
    ) -> Result<CredentialStatusEvidence, PresentationVerificationError>;
}

type EpochClock = dyn Fn() -> u64 + Send + Sync;

/// Converts native cryptographic, trust, and status evidence into the one
/// canonical request accepted by `marty-verification`'s policy kernel.
pub struct VerifiedFactsOrchestrator {
    kernel: Arc<dyn CredentialVerificationKernel>,
    trust: Arc<dyn PresentationTrustResolver>,
    status: Arc<dyn CredentialStatusResolver>,
    clock: Arc<EpochClock>,
}

impl VerifiedFactsOrchestrator {
    #[must_use]
    pub fn new(
        kernel: Arc<dyn CredentialVerificationKernel>,
        trust: Arc<dyn PresentationTrustResolver>,
        status: Arc<dyn CredentialStatusResolver>,
    ) -> Self {
        Self::with_clock(kernel, trust, status, Arc::new(system_epoch_seconds))
    }

    #[must_use]
    pub fn with_clock(
        kernel: Arc<dyn CredentialVerificationKernel>,
        trust: Arc<dyn PresentationTrustResolver>,
        status: Arc<dyn CredentialStatusResolver>,
        clock: Arc<EpochClock>,
    ) -> Self {
        Self {
            kernel,
            trust,
            status,
            clock,
        }
    }

    async fn verified_facts(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        let token = canonical_token(&request.vp_token)?;
        let format = detect_credential_format(&token);
        if format == DetectedCredentialFormat::Unknown {
            return Ok(rejected_facts(
                policy,
                "unknown",
                "Unsupported or malformed credential presentation",
                (self.clock)(),
                policy.trust_profile_id.is_none() && request.trust_profile_id.is_none(),
            ));
        }

        let profile_id = selected_trust_profile(policy, request)?;
        let trust_profile = match profile_id {
            Some(profile_id) => {
                let profile = self
                    .trust
                    .load_profile(profile_id, policy.organization_id)
                    .await?;
                if profile.id != profile_id || profile.organization_id != policy.organization_id {
                    return Err(PresentationVerificationError::Failed(
                        "Trust Profile identity or organization did not match the verifier request"
                            .into(),
                    ));
                }
                Some(profile)
            }
            None => None,
        };
        let requires_bound_presentation = policy.holder_binding.required
            || format == DetectedCredentialFormat::Mdoc
            || request.context.get("oid4vp_verifier_context") == Some(&Value::Bool(true));
        let challenge_required = freshness_flag(policy, "challenge_required");
        let audience_required = freshness_flag(policy, "audience_binding_required");

        let context = CredentialVerificationContext {
            format,
            token: request.vp_token.clone(),
            nonce: (requires_bound_presentation && challenge_required)
                .then(|| request.nonce.clone())
                .flatten(),
            audience: (requires_bound_presentation && audience_required)
                .then(|| request.audience.clone())
                .flatten(),
            verifier_context: request.context.clone(),
            trust_profile: trust_profile.clone(),
        };
        let mut evidence = self.kernel.verify(&context).await?;
        if !evidence.verified {
            evidence.claims.clear();
            evidence.issuer_id = None;
        }

        let issuer_id = evidence
            .issuer_id
            .as_deref()
            .filter(|issuer| !issuer.trim().is_empty())
            .unwrap_or("unknown")
            .to_string();
        let trust = match (&trust_profile, evidence.verified, issuer_id.as_str()) {
            (Some(profile), true, issuer) if issuer != "unknown" => {
                self.trust.evaluate_issuer(profile, issuer).await?
            }
            (Some(_), _, _) => IssuerTrustEvidence {
                verified: false,
                failure_reason: Some(if evidence.verified {
                    "Issuer identity was unavailable from the verified credential".into()
                } else {
                    "Issuer trust was not evaluated for an unverified credential".into()
                }),
                ..Default::default()
            },
            (None, _, _) => IssuerTrustEvidence {
                verified: true,
                ..Default::default()
            },
        };

        if evidence.verified
            && evidence.status.checked_at_epoch_seconds.is_none()
            && !evidence.credential_status_ids.is_empty()
            && issuer_id != "unknown"
        {
            evidence.status = self
                .status
                .resolve(
                    policy.organization_id,
                    &issuer_id,
                    &evidence.credential_status_ids,
                )
                .await?;
        }

        let evaluation_time = (self.clock)();
        let mut warnings = evidence.warnings;
        warnings.extend(evidence.status.warnings.clone());
        if !evidence.verified {
            warnings.push(format!(
                "Verifier denied credential: {}",
                evidence
                    .failure_reason
                    .as_deref()
                    .unwrap_or("Credential verification failed")
            ));
        }
        if let Some(reason) = trust.failure_reason.as_deref() {
            warnings.push(format!("Trust orchestration: {reason}"));
        }

        let claims = if evidence.verified {
            Value::Object(evidence.claims)
        } else {
            Value::Object(Map::new())
        };
        let credential_id = evidence
            .credential_id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "presented-credential".into());
        let templates = credential_template_ids(policy);
        let credential_status = normalized_status(evidence.status.credential_status.as_deref());

        Ok(json!({
            "credentials": [{
                "credential_id": credential_id,
                "credential_template_ids": templates,
                "credential_format": format.as_str(),
                "claims": claims,
                "issuer_id": issuer_id,
                "signature_verified": evidence.verified,
                "signature_failure_reason": if evidence.verified { None } else { evidence.failure_reason },
                "trust_profile_verified": trust.verified,
                "trust_failure_reason": trust.failure_reason,
                "trust_level": trust.trust_level,
                "compliance_statuses": normalized_upper(trust.compliance_statuses),
                "accreditations": normalized_lower(trust.accreditations),
                "issued_at_epoch_seconds": evidence.issued_at_epoch_seconds,
                "revocation_checked_at_epoch_seconds": evidence.status.checked_at_epoch_seconds,
                "not_revoked": evidence.status.not_revoked,
                "credential_status": credential_status,
                "warnings": warnings,
            }],
            "evaluation_time_epoch_seconds": evaluation_time,
            "presentation_verified": evidence.presentation_verified,
            "holder_binding_verified": evidence.holder_binding_verified,
            "holder_binding_method": evidence.holder_binding_method,
            "proof_profile": evidence.proof_profile,
            "challenge_verified": evidence.challenge_verified,
            "audience_verified": evidence.audience_verified,
            "replay_check_verified": evidence.replay_check_verified,
            "proof_epoch_seconds": evidence.proof_epoch_seconds,
            "external_authorization": Value::Null,
            "presentation_count": evidence.presentation_count.or(Some(1)),
        }))
    }
}

#[async_trait]
impl PresentationVerificationOrchestrator for VerifiedFactsOrchestrator {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        self.verified_facts(policy, request).await
    }
}

fn canonical_token(token: &Value) -> Result<String, PresentationVerificationError> {
    match token {
        Value::String(value) if !value.trim().is_empty() => Ok(value.clone()),
        Value::Object(_) => serde_json::to_string(token).map_err(|_| {
            PresentationVerificationError::Failed("Credential presentation is not JSON".into())
        }),
        _ => Err(PresentationVerificationError::Failed(
            "Credential presentation must be a non-empty string or object".into(),
        )),
    }
}

fn selected_trust_profile(
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Option<Uuid>, PresentationVerificationError> {
    if let Some(value) = request.trust_profile_id.as_deref() {
        return Uuid::parse_str(value).map(Some).map_err(|_| {
            PresentationVerificationError::Failed("trust_profile_id must be a UUID".into())
        });
    }
    Ok(policy.trust_profile_id.or_else(|| {
        policy
            .credential_requirements
            .iter()
            .find_map(|requirement| requirement.trust_profile_id)
    }))
}

fn freshness_flag(policy: &PresentationPolicy, name: &str) -> bool {
    policy
        .holder_binding
        .proof_freshness
        .get(name)
        .copied()
        .unwrap_or(true)
}

fn credential_template_ids(policy: &PresentationPolicy) -> Vec<String> {
    let mut values = BTreeSet::new();
    for requirement in &policy.credential_requirements {
        if !requirement.credential_template_id.is_empty() {
            values.insert(requirement.credential_template_id.clone());
        }
    }
    values.into_iter().collect()
}

fn normalized_upper(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_uppercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_lower(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalized_status(value: Option<&str>) -> Option<&'static str> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("active" | "good" | "valid") => Some("active"),
        Some("revoked") => Some("revoked"),
        Some("suspended") => Some("suspended"),
        Some("expired") => Some("expired"),
        Some(_) => Some("unknown"),
        None => None,
    }
}

fn rejected_facts(
    policy: &PresentationPolicy,
    format: &str,
    reason: &str,
    evaluation_time: u64,
    trust_profile_verified: bool,
) -> Value {
    json!({
        "credentials": [{
            "credential_id": "presented-credential",
            "credential_template_ids": credential_template_ids(policy),
            "credential_format": format,
            "claims": {},
            "issuer_id": "unknown",
            "signature_verified": false,
            "signature_failure_reason": reason,
            "trust_profile_verified": trust_profile_verified,
            "trust_failure_reason": Value::Null,
            "trust_level": Value::Null,
            "compliance_statuses": [],
            "accreditations": [],
            "issued_at_epoch_seconds": Value::Null,
            "revocation_checked_at_epoch_seconds": Value::Null,
            "not_revoked": Value::Null,
            "credential_status": Value::Null,
            "warnings": [format!("Verifier denied credential: {reason}")],
        }],
        "evaluation_time_epoch_seconds": evaluation_time,
        "presentation_verified": false,
        "holder_binding_verified": false,
        "holder_binding_method": Value::Null,
        "proof_profile": Value::Null,
        "challenge_verified": false,
        "audience_verified": false,
        "replay_check_verified": false,
        "proof_epoch_seconds": Value::Null,
        "external_authorization": Value::Null,
        "presentation_count": 1,
    })
}

fn system_epoch_seconds() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or_default()
}
