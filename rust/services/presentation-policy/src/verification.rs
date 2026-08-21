use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use marty_verification::credential_format::{detect_credential_format, DetectedCredentialFormat};
use mmf_security::{CredentialVerificationAuthorizationFacts, CredentialVerificationPolicyEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    control_plane::mdoc_direct_pin_lifecycle_verified, EvaluatePresentationRequest,
    PresentationPolicy, PresentationVerificationError, PresentationVerificationOrchestrator,
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
    pub algorithm: Option<String>,
    pub validity_checked: bool,
    pub is_expired: Option<bool>,
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
        format: DetectedCredentialFormat,
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
    credential_authorization: CredentialVerificationPolicyEngine,
    clock: Arc<EpochClock>,
}

impl VerifiedFactsOrchestrator {
    pub fn new(
        kernel: Arc<dyn CredentialVerificationKernel>,
        trust: Arc<dyn PresentationTrustResolver>,
        status: Arc<dyn CredentialStatusResolver>,
    ) -> Result<Self, PresentationVerificationError> {
        Self::with_clock(kernel, trust, status, Arc::new(system_epoch_seconds))
    }

    pub fn with_clock(
        kernel: Arc<dyn CredentialVerificationKernel>,
        trust: Arc<dyn PresentationTrustResolver>,
        status: Arc<dyn CredentialStatusResolver>,
        clock: Arc<EpochClock>,
    ) -> Result<Self, PresentationVerificationError> {
        Ok(Self {
            kernel,
            trust,
            status,
            credential_authorization: CredentialVerificationPolicyEngine::new().map_err(|_| {
                PresentationVerificationError::Failed(
                    "PRESENTATION_POLICY.NATIVE_AUTHORIZATION_UNAVAILABLE".into(),
                )
            })?,
            clock,
        })
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

        let presentation_only = is_presentation_only(policy);
        let profile_id = if presentation_only {
            None
        } else {
            selected_trust_profile(policy, request)?
        };
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
        apply_trusted_oid4vp_context(policy, request, &mut evidence);
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
                self.trust.evaluate_issuer(profile, issuer, format).await?
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

        let evaluation_time = (self.clock)();
        if !presentation_only
            && format == DetectedCredentialFormat::Mdoc
            && evidence.verified
            && evidence.status.checked_at_epoch_seconds.is_none()
            && trust_profile.as_ref().is_some_and(|profile| {
                mdoc_direct_pin_lifecycle_verified(
                    &profile.document,
                    &issuer_id,
                    chrono::DateTime::from_timestamp(
                        i64::try_from(evaluation_time).unwrap_or(i64::MAX),
                        0,
                    )
                    .unwrap_or_default(),
                )
            })
        {
            evidence.status = CredentialStatusEvidence {
                checked_at_epoch_seconds: Some(evaluation_time),
                not_revoked: Some(true),
                credential_status: Some("active".into()),
                warnings: Vec::new(),
            };
        }

        if !presentation_only
            && evidence.verified
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

        let external_authorization = if presentation_only {
            Value::Null
        } else {
            credential_external_authorization(
                &self.credential_authorization,
                policy,
                format,
                &evidence,
                &trust,
                &issuer_id,
                evaluation_time,
            )
        };
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
        let credentials = if presentation_only {
            json!([])
        } else {
            json!([{
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
            }])
        };

        Ok(json!({
            "credentials": credentials,
            "evaluation_time_epoch_seconds": evaluation_time,
            "presentation_verified": evidence.presentation_verified,
            "holder_binding_verified": evidence.holder_binding_verified,
            "holder_binding_method": evidence.holder_binding_method,
            "proof_profile": evidence.proof_profile,
            "challenge_verified": evidence.challenge_verified,
            "audience_verified": evidence.audience_verified,
            "replay_check_verified": evidence.replay_check_verified,
            "proof_epoch_seconds": evidence.proof_epoch_seconds,
            "external_authorization": external_authorization,
            "presentation_count": evidence.presentation_count.or(Some(1)),
        }))
    }
}

fn credential_external_authorization(
    authorizer: &CredentialVerificationPolicyEngine,
    policy: &PresentationPolicy,
    format: DetectedCredentialFormat,
    evidence: &CredentialVerificationEvidence,
    trust: &IssuerTrustEvidence,
    issuer_id: &str,
    evaluation_time: u64,
) -> Value {
    let revocation_required = policy
        .freshness
        .as_ref()
        .is_some_and(|freshness| freshness.require_not_revoked);
    let credential_age_seconds = evidence
        .issued_at_epoch_seconds
        .filter(|issued_at| *issued_at <= evaluation_time)
        .map(|issued_at| evaluation_time - issued_at);
    let mut missing = Vec::new();
    if trust.trust_level.is_none() {
        missing.push("numeric issuer trust");
    }
    if revocation_required
        && (evidence.status.checked_at_epoch_seconds.is_none()
            || evidence.status.not_revoked != Some(true))
    {
        missing.push("non-revocation");
    }
    if !evidence.validity_checked || evidence.is_expired.is_none() {
        missing.push("credential validity");
    }
    if credential_age_seconds.is_none() {
        missing.push("credential issuance time");
    }
    if evidence
        .algorithm
        .as_deref()
        .is_none_or(|algorithm| algorithm.trim().is_empty())
    {
        missing.push("signature algorithm");
    }
    if !missing.is_empty() {
        return json!({
            "evaluated": false,
            "allowed": false,
            "reasons": [],
            "errors": [format!("Cedar policy evidence is incomplete: {}", missing.join(", "))],
        });
    }

    let compliance_code = evidence
        .claims
        .get("_compliance_code")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("UNSPECIFIED");
    let facts = CredentialVerificationAuthorizationFacts {
        organization_id: policy.organization_id.to_string(),
        credential_format: cedar_credential_format(format).into(),
        compliance_code: compliance_code.into(),
        issuer_id: issuer_id.into(),
        issuer_trust_level: trust.trust_level.unwrap_or_default(),
        credential_age_seconds: credential_age_seconds.unwrap_or_default(),
        revocation_checked: evidence.status.checked_at_epoch_seconds.is_some(),
        revocation_required,
        is_revoked: evidence.status.not_revoked == Some(false),
        is_expired: evidence.is_expired.unwrap_or(true),
        holder_binding_present: evidence.holder_binding_verified,
        algorithm: evidence.algorithm.clone().unwrap_or_default(),
    };
    match authorizer.authorize(&facts) {
        Ok(decision) => json!({
            "evaluated": true,
            "allowed": decision.allowed,
            "reasons": decision.determining_policies,
            "errors": decision.errors,
        }),
        Err(_) => json!({
            "evaluated": true,
            "allowed": false,
            "reasons": [],
            "errors": ["Cedar policy evaluation failed: SecurityError"],
        }),
    }
}

fn cedar_credential_format(format: DetectedCredentialFormat) -> &'static str {
    match format {
        DetectedCredentialFormat::W3cVc => "VC_JWT",
        DetectedCredentialFormat::W3cVcdmDi => "W3C_VCDM_V2_DI",
        DetectedCredentialFormat::SdJwt => "SD_JWT_VC",
        DetectedCredentialFormat::Mdoc => "MDOC",
        DetectedCredentialFormat::OpenbadgeV2 => "OPEN_BADGES_V2",
        DetectedCredentialFormat::OpenbadgeV3 => "OPEN_BADGES_V3",
        DetectedCredentialFormat::Unknown => "UNKNOWN",
    }
}

fn is_presentation_only(policy: &PresentationPolicy) -> bool {
    policy.presentation_proof_required
        && policy.credential_requirements.is_empty()
        && policy.alternative_requirements.is_empty()
}

fn apply_trusted_oid4vp_context(
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
    evidence: &mut CredentialVerificationEvidence,
) {
    let trusted = request.trusted_internal_context
        && request.context.get("oid4vp_verifier_context") == Some(&Value::Bool(true));
    if !trusted {
        return;
    }
    if evidence.holder_binding_verified {
        if evidence
            .holder_binding_method
            .as_deref()
            .is_none_or(|method| {
                !policy.holder_binding.binding_methods.is_empty()
                    && !policy
                        .holder_binding
                        .binding_methods
                        .iter()
                        .any(|allowed| allowed == method)
                    && policy
                        .holder_binding
                        .binding_methods
                        .iter()
                        .any(|allowed| allowed == "DEVICE_KEY")
            })
        {
            evidence.holder_binding_method = Some("DEVICE_KEY".into());
        }
        if evidence.proof_profile.as_deref().is_none_or(|profile| {
            !policy.holder_binding.proof_profiles.is_empty()
                && !policy
                    .holder_binding
                    .proof_profiles
                    .iter()
                    .any(|allowed| allowed == profile)
                && policy
                    .holder_binding
                    .proof_profiles
                    .iter()
                    .any(|allowed| allowed == "OID4VP_VERIFIABLE_PRESENTATION")
        }) {
            evidence.proof_profile = Some("OID4VP_VERIFIABLE_PRESENTATION".into());
        }
    }
    evidence.replay_check_verified =
        request.context.get("replay_check_verified") == Some(&Value::Bool(true));
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
