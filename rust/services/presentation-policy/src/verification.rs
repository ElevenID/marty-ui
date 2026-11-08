use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::Utc;
use marty_verification::credential_format::{detect_credential_format, DetectedCredentialFormat};
use marty_verification::open_badges::is_retired_ob2;
use mmf_security::{
    CedarConfig, CedarPolicyEngine, CredentialVerificationAuthorizationFacts,
    CredentialVerificationPolicyEngine, CREDENTIAL_VERIFICATION_SCHEMA,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    EvaluatePresentationRequest, PresentationPolicy, PresentationVerificationError,
    PresentationVerificationOrchestrator, VerifiedPolicyMaterial,
};

pub(crate) const OB2_RETIRED: &str =
    "Open Badges 2.0 is retired; request a newly issued Open Badges 3.0 credential";

pub(crate) const MDOC_AUTHENTICATION_DIAGNOSTIC: &str = "mdoc_authentication_diagnostic";

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

/// Public type metadata read from the tenant's controlled template catalog.
/// A request's template ID is never itself evidence of credential membership.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCredentialTemplate {
    pub id: String,
    pub organization_id: Uuid,
    pub credential_type: String,
    pub vct: Option<String>,
    pub doctype: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedVerificationPolicy {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub revision: String,
    pub cedar_policies: String,
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
pub struct ResolvedIssuerKey {
    /// The authority which authorized this key, before signature verification.
    pub issuer_id: String,
    pub public_jwk: Value,
    pub provenance: IssuerKeyProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuerKeyMechanism {
    DidAssertionMethod,
    TrustProfileKey,
}

/// Verifier-owned origin of a selected public key. This alone is not evidence
/// that a credential was signed by the issuer; the kernel adds authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerKeyProvenance {
    pub mechanism: IssuerKeyMechanism,
    pub trust_profile_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub issuer_organization_id: Option<String>,
    pub source: String,
    pub retrieved_at: Option<String>,
    pub content_sha256: Option<String>,
}

/// Published only after the signature and exact issuer-to-key binding pass.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedIssuerEvidence {
    pub issuer_id: String,
    pub key_id: Option<String>,
    pub algorithm: String,
    pub provenance: IssuerKeyProvenance,
}

impl AuthenticatedIssuerEvidence {
    /// Bounds for the canonical protocol response, independent of trust
    /// acceptance or the algorithms supported by a credential verifier.
    pub(crate) fn satisfies_contract(&self) -> bool {
        let bounded = |value: &str, maximum: usize| {
            !value.is_empty() && value.chars().take(maximum + 1).count() <= maximum
        };
        bounded(&self.issuer_id, 2048)
            && self.key_id.as_deref().is_none_or(|v| bounded(v, 2048))
            && bounded(&self.algorithm, 64)
            && bounded(&self.provenance.source, 256)
            && self
                .provenance
                .issuer_organization_id
                .as_deref()
                .is_none_or(|v| bounded(v, 128))
            && self.provenance.retrieved_at.as_deref().is_none_or(|v| {
                // The producer uses a conservative calendar timestamp profile:
                // T/t separators, nonzero years and seconds below 60. Chrono
                // additionally accepts space separators, year zero and leap seconds.
                v.is_ascii()
                    && v.len() <= 64
                    && matches!(v.as_bytes().get(10), Some(&b'T' | &b't'))
                    && v.get(..4) != Some("0000")
                    && v.get(17..19) != Some("60")
                    && chrono::DateTime::parse_from_rfc3339(v).is_ok()
            })
            && self.provenance.content_sha256.as_deref().is_none_or(|v| {
                v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialVerificationContext {
    /// Prepared by the workload transport adapter; caller JSON cannot supply it.
    pub sd_jwt_dcql: Option<crate::SdJwtDcqlRequest>,
    /// Derived from the saved policy, never from caller-supplied context.
    /// A verified presentation need not carry a credential for this obligation.
    pub presentation_only: bool,
    /// Verifier-owned assertion key, separate from trust acceptance. Never copied from request context.
    pub resolved_issuer_key: Option<ResolvedIssuerKey>,
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
    /// Native query/subject/key evidence has no JSON promotion path.
    #[serde(skip)]
    pub authenticated_sd_jwt_query: Option<crate::AuthenticatedSdJwtQueryEvidence>,
    pub verified: bool,
    pub failure_reason: Option<String>,
    pub mdoc_authentication_diagnostic:
        Option<marty_oid4vp_contract::MdocAuthenticationDiagnosticV1>,
    pub credential_id: Option<String>,
    /// Comes only from the signed outer `jti` of a valid VC-JWT.
    pub authenticated_outer_jti: Option<String>,
    pub credential_status_ids: Vec<String>,
    /// Exact types authenticated by the format kernel: SD-JWT vct, mdoc
    /// docType, or W3C type entries. Never taken from the request or policy.
    pub credential_types: Vec<String>,
    /// Internal authenticated document for exact frozen-query evaluation. It
    /// is never included in the public policy or callback projection.
    pub authenticated_document: Option<Value>,
    pub claims: Map<String, Value>,
    pub issuer_id: Option<String>,
    pub authenticated_issuer: Option<AuthenticatedIssuerEvidence>,
    pub issued_at_epoch_seconds: Option<u64>,
    pub algorithm: Option<String>,
    pub holder_algorithm: Option<String>,
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

    async fn load_credential_template(
        &self,
        _template_id: &str,
        _organization_id: Uuid,
    ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
        Err(PresentationVerificationError::Failed(
            "Credential template resolution is unavailable".into(),
        ))
    }

    async fn load_verification_policy(
        &self,
        _policy_set_id: Uuid,
        _organization_id: Uuid,
    ) -> Result<ResolvedVerificationPolicy, PresentationVerificationError> {
        Err(PresentationVerificationError::Failed(
            "Linked credential verification PolicySet is unavailable".into(),
        ))
    }
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
            clock,
        })
    }

    async fn verified_material(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<VerifiedPolicyMaterial, PresentationVerificationError> {
        // Revalidate saved policies as well as new/activated ones. A signed
        // compliance code cannot stand in for unresolved governance metadata.
        crate::policy_contract::validate_policy(policy)
            .map_err(|error| failed(&error.to_string()))?;
        let profiles = effective_trust_profiles(policy, request)?;
        let associated = request
            .oid4vp_transport
            .as_ref()
            .map(|transport| {
                if !request.trusted_internal_context
                    || request.nonce.as_deref() != Some(transport.request_nonce.as_str())
                    || request
                        .audience
                        .as_deref()
                        .filter(|value| !value.is_empty())
                        .is_some_and(|value| value != transport.verifier_client_id)
                {
                    return Err(failed(
                        "OID4VP transport does not match the trusted verifier binding",
                    ));
                }
                transport.associate_response().map_err(|_| {
                    failed("OID4VP response does not completely match the frozen query")
                })
            })
            .transpose()?;
        if let (Some(response), Some(transport)) = (&associated, request.oid4vp_transport.as_ref())
        {
            // Check the original input before expanding it into per-item
            // requests, preserving the native producer's selection fence.
            let selected = if response.presentation_count == 1 {
                response.tokens[0].token.as_str()
            } else {
                transport.vp_token_raw.as_str()
            };
            if canonical_token(&request.vp_token)? != selected {
                return Err(failed(
                    "OID4VP selected presentation does not match the complete response",
                ));
            }
        }
        if associated.is_none()
            && request.trusted_internal_context
            && request.context.get("oid4vp_verifier_context") == Some(&Value::Bool(true))
        {
            return Err(failed(
                "OID4VP verification requires the complete frozen query and response",
            ));
        }
        let items: Vec<_> = match &associated {
            Some(response) => response
                .tokens
                .iter()
                .map(|item| (Value::String(item.token.clone()), Some(item)))
                .collect(),
            None => vec![(request.vp_token.clone(), None)],
        };
        if items.len().saturating_mul(profiles.len()) > marty_oid4vp_contract::MAX_CREDENTIALS {
            return Err(failed(
                "OID4VP credential and Trust Profile combination exceeds the verification bound",
            ));
        }
        let mut templates = BTreeMap::new();
        let mut groups = Vec::new();
        for (token, selection) in items {
            let mut item_request = request.clone();
            item_request.vp_token = token;
            let mut group = Vec::new();
            for profile_id in &profiles {
                group.push(
                    self.verified_item(
                        policy,
                        &item_request,
                        *profile_id,
                        selection,
                        &mut templates,
                    )
                    .await?,
                );
            }
            groups.push(group);
        }
        let presentation_count = associated
            .as_ref()
            .map(|response| response.presentation_count);
        Ok(combine_verified_material(groups, presentation_count))
    }

    async fn verified_item(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
        profile_id: Option<Uuid>,
        selection: Option<&marty_oid4vp_contract::AssociatedResponseToken>,
        templates: &mut BTreeMap<String, ResolvedCredentialTemplate>,
    ) -> Result<VerifiedPolicyMaterial, PresentationVerificationError> {
        let token = canonical_token(&request.vp_token)?;
        let format = detect_credential_format(&token);
        if format == DetectedCredentialFormat::Unknown {
            let reason = if is_retired_ob2(&request.vp_token)
                || request.vp_token.get("assertion").is_some()
            {
                OB2_RETIRED
            } else {
                "Unsupported or malformed credential presentation"
            };
            return Ok(VerifiedPolicyMaterial::facts_only(rejected_facts(
                policy,
                "unknown",
                reason,
                (self.clock)(),
                policy.trust_profile_id.is_none() && request.trust_profile_id.is_none(),
            )));
        }

        let sd_jwt_dcql =
            crate::SdJwtDcqlRequest::prepare(policy, request, format, (self.clock)())?;
        let presentation_only = is_presentation_only(policy);
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

        let transport = request.oid4vp_transport.as_ref();
        let context = CredentialVerificationContext {
            sd_jwt_dcql: sd_jwt_dcql.clone(),
            presentation_only,
            resolved_issuer_key: None,
            format,
            token: request.vp_token.clone(),
            nonce: sd_jwt_dcql
                .as_ref()
                .map(|query| query.nonce().to_owned())
                .or_else(|| transport.map(|value| value.request_nonce.clone()))
                .or_else(|| {
                    (requires_bound_presentation && challenge_required)
                        .then(|| request.nonce.clone())
                        .flatten()
                }),
            audience: sd_jwt_dcql
                .as_ref()
                .map(|query| query.audience().to_owned())
                .or_else(|| transport.map(|value| value.verifier_client_id.clone()))
                .or_else(|| {
                    (requires_bound_presentation && audience_required)
                        .then(|| request.audience.clone())
                        .flatten()
                }),
            verifier_context: request.context.clone(),
            trust_profile: trust_profile.clone(),
        };
        let mut evidence = self.kernel.verify(&context).await?;
        let query_evidence_matches = match (&sd_jwt_dcql, &evidence.authenticated_sd_jwt_query) {
            (Some(prepared), Some(authenticated)) => {
                prepared.matches_evidence(authenticated)
                    && authenticated.matches_claims(&evidence.claims)
                    && evidence.issuer_id.as_deref() == Some(authenticated.issuer_id())
                    && evidence
                        .authenticated_issuer
                        .as_ref()
                        .is_some_and(|issuer| {
                            issuer.issuer_id == authenticated.issuer_id()
                                && issuer.provenance.trust_profile_id
                                    == context.trust_profile.as_ref().map(|profile| profile.id)
                                && issuer.provenance.organization_id
                                    == context
                                        .trust_profile
                                        .as_ref()
                                        .map(|profile| profile.organization_id)
                        })
                    && evidence.verified
                    && evidence.holder_binding_verified
                    && evidence.challenge_verified
                    && evidence.audience_verified
            }
            (Some(_), None) => !evidence.verified,
            (None, None) => true,
            (None, Some(_)) => false,
        };
        if !query_evidence_matches {
            return Err(PresentationVerificationError::Failed(
                "PRESENTATION_POLICY.AUTHENTICATED_QUERY_EVIDENCE_MISMATCH".into(),
            ));
        }
        // The opaque SD-JWT/DCQL producer owns its stricter singleton profile;
        // other formats/queries use the shared authenticated-query adapter.
        if sd_jwt_dcql.is_none() {
            if let (Some(transport), Some(selection)) = (transport, selection) {
                if !crate::response_association::matches_query(
                    transport, selection, format, &evidence,
                ) {
                    evidence.verified = false;
                    evidence.failure_reason = Some(
                        "Authenticated credential does not satisfy its frozen OID4VP query".into(),
                    );
                    evidence.presentation_verified = false;
                    evidence.holder_binding_verified = false;
                    evidence.challenge_verified = false;
                    evidence.audience_verified = false;
                    evidence.replay_check_verified = false;
                }
            }
        }
        apply_trusted_oid4vp_context(policy, request, &mut evidence);
        let authenticated_outer_jti = if evidence.verified && !presentation_only {
            evidence.authenticated_outer_jti.clone()
        } else {
            None
        };
        if !evidence.verified {
            evidence.claims.clear();
            evidence.credential_types.clear();
            evidence.authenticated_document = None;
            evidence.issuer_id = None;
            evidence.authenticated_issuer = None;
            evidence.authenticated_sd_jwt_query = None;
        }

        let mut authenticated_sd_jwt_query = evidence.authenticated_sd_jwt_query.clone();

        let authenticated_issuer = if evidence.verified && !presentation_only {
            evidence.authenticated_issuer.clone()
        } else {
            None
        };

        let issuer_id = authenticated_issuer
            .as_ref()
            .map(|issuer| issuer.issuer_id.as_str())
            .or(evidence.issuer_id.as_deref())
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

        // A trusted mDL issuer certificate says nothing about the status of
        // this credential. Only credential-specific status evidence may set
        // not_revoked; policies requiring it fail closed when none is present.
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

        let matched_templates = if evidence.verified && !presentation_only {
            self.matching_template_ids(policy, format, &evidence.credential_types, templates)
                .await?
        } else {
            Vec::new()
        };
        let external_authorization = if presentation_only {
            Value::Null
        } else {
            self.configured_authorization(
                policy,
                trust_profile.as_ref(),
                format,
                &evidence,
                &trust,
                &issuer_id,
            )
            .await?
        };
        // Include every metadata/policy await in the native proof's validity
        // window; resolution must not extend the credential or holder proof.
        let evaluation_time = (self.clock)();
        if let Some(query) = authenticated_sd_jwt_query.as_mut() {
            query.revalidate_at(evaluation_time)?;
        }
        let mdoc_authentication_diagnostic =
            if !presentation_only && format == DetectedCredentialFormat::Mdoc {
                evidence.mdoc_authentication_diagnostic.clone()
            } else {
                None
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
        let credential_status = normalized_status(evidence.status.credential_status.as_deref());
        let credentials = if presentation_only {
            json!([])
        } else {
            json!([{
                "credential_id": credential_id,
                "credential_template_ids": matched_templates,
                "credential_types": evidence.credential_types,
                "credential_format": format.as_str(),
                "claims": claims,
                "issuer_id": issuer_id,
                "signature_verified": evidence.verified,
                "signature_failure_reason": if evidence.verified { None } else { evidence.failure_reason },
                "trust_profile_verified": trust.verified,
                "trust_profile_id": trust_profile.as_ref().map(|profile| profile.id.to_string()),
                "external_authorization": external_authorization,
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

        let mut facts = json!({
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
            "external_authorization": Value::Null,
            "presentation_count": evidence.presentation_count.or(Some(1)),
        });
        if let Some(diagnostic) = mdoc_authentication_diagnostic {
            facts[MDOC_AUTHENTICATION_DIAGNOSTIC] = json!(diagnostic);
        }
        Ok(VerifiedPolicyMaterial {
            policy_facts: facts,
            authenticated_outer_jti,
            authenticated_issuer,
            authenticated_sd_jwt_query,
        })
    }

    async fn matching_template_ids(
        &self,
        policy: &PresentationPolicy,
        format: DetectedCredentialFormat,
        credential_types: &[String],
        templates: &mut BTreeMap<String, ResolvedCredentialTemplate>,
    ) -> Result<Vec<String>, PresentationVerificationError> {
        let mut matching = BTreeSet::new();
        for requirement in requirements(policy) {
            if crate::policy_contract::is_inline_requirement(policy, requirement) {
                continue;
            }
            let id = &requirement.credential_template_id;
            if !templates.contains_key(id) {
                let template = self
                    .trust
                    .load_credential_template(id, policy.organization_id)
                    .await?;
                if &template.id != id
                    || template.organization_id != policy.organization_id
                    || !matches!(template.status.as_str(), "ACTIVE" | "DEPRECATED")
                {
                    return Err(failed(
                        "Credential template identity, organization, or lifecycle mismatch",
                    ));
                }
                templates.insert(id.clone(), template);
            }
            let template = &templates[id];
            let expected = match format {
                DetectedCredentialFormat::SdJwt => {
                    template.vct.as_deref().unwrap_or(&template.credential_type)
                }
                DetectedCredentialFormat::Mdoc => template
                    .doctype
                    .as_deref()
                    .unwrap_or(&template.credential_type),
                _ => template.credential_type.as_str(),
            };
            if !expected.is_empty() && credential_types.iter().any(|actual| actual == expected) {
                matching.insert(id.clone());
            }
        }
        Ok(matching.into_iter().collect())
    }

    #[allow(clippy::too_many_arguments)]
    async fn configured_authorization(
        &self,
        policy: &PresentationPolicy,
        profile: Option<&ResolvedTrustProfile>,
        format: DetectedCredentialFormat,
        evidence: &CredentialVerificationEvidence,
        trust: &IssuerTrustEvidence,
        issuer_id: &str,
    ) -> Result<Value, PresentationVerificationError> {
        let Some(link) = profile
            .and_then(|profile| profile.document.get("verification_policy_set_id"))
            .filter(|value| !value.is_null())
        else {
            return Ok(Value::Null);
        };
        let policy_set_id = link
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| failed("Linked verification PolicySet ID is invalid"))?;
        let resolved = self
            .trust
            .load_verification_policy(policy_set_id, policy.organization_id)
            .await?;
        if resolved.id != policy_set_id
            || resolved.organization_id != policy.organization_id
            || resolved.revision.is_empty()
            || resolved.cedar_policies.trim().is_empty()
        {
            return Err(failed(
                "Linked verification PolicySet identity or content is invalid",
            ));
        }
        let cedar = CedarPolicyEngine::from_human_schema(
            &resolved.cedar_policies,
            CREDENTIAL_VERIFICATION_SCHEMA,
            CedarConfig::default(),
        )
        .map_err(|_| failed("Linked verification PolicySet could not be compiled"))?;
        let authorizer = CredentialVerificationPolicyEngine::new(cedar);
        let mut decision = credential_external_authorization(
            &authorizer,
            policy,
            format,
            evidence,
            trust,
            issuer_id,
            (self.clock)(),
        );
        // Preserve the exact configured source identity with the decision,
        // while retaining Core's existing authorization-facts contract.
        let source = format!("policy-set:{}@{}", resolved.id, resolved.revision);
        if let Some(reasons) = decision["reasons"].as_array_mut() {
            reasons.insert(0, json!(source));
        }
        Ok(decision)
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
    if !trusted || !evidence.verified {
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
        Ok(self.verified_material(policy, request).await?.policy_facts)
    }

    async fn verify_material(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<VerifiedPolicyMaterial, PresentationVerificationError> {
        self.verified_material(policy, request).await
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

pub(crate) fn effective_trust_profiles(
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
) -> Result<Vec<Option<Uuid>>, PresentationVerificationError> {
    let mut profiles = requirements(policy)
        .map(|requirement| requirement.trust_profile_id.or(policy.trust_profile_id))
        .collect::<BTreeSet<_>>();
    if profiles.is_empty() {
        profiles.insert(if is_presentation_only(policy) {
            None
        } else {
            policy.trust_profile_id
        });
    }
    if let Some(value) = request.trust_profile_id.as_deref() {
        let requested =
            Uuid::parse_str(value).map_err(|_| failed("trust_profile_id must be a UUID"))?;
        if !profiles.contains(&Some(requested)) {
            return Err(failed(
                "Caller trust_profile_id cannot replace the saved policy's Trust Profile",
            ));
        }
    }
    Ok(profiles.into_iter().collect())
}

fn requirements(
    policy: &PresentationPolicy,
) -> impl Iterator<Item = &crate::CredentialRequirement> {
    policy.credential_requirements.iter().chain(
        policy
            .alternative_requirements
            .iter()
            .flat_map(|alternative| alternative.credential_requirements.iter()),
    )
}

fn combine_verified_material(
    groups: Vec<Vec<VerifiedPolicyMaterial>>,
    presentation_count: Option<usize>,
) -> VerifiedPolicyMaterial {
    if groups.len() == 1 && groups[0].len() == 1 {
        let mut material = groups
            .into_iter()
            .next()
            .expect("one group")
            .into_iter()
            .next()
            .expect("one material");
        if let Some(count) = presentation_count {
            material.policy_facts["presentation_count"] = json!(count);
        }
        return material;
    }
    let mut facts = groups[0][0].policy_facts.clone();
    let mut credentials = Vec::new();
    for credential in groups.iter().flatten().flat_map(|material| {
        material.policy_facts["credentials"]
            .as_array()
            .into_iter()
            .flatten()
    }) {
        if !credentials.contains(credential) {
            credentials.push(credential.clone());
        }
    }
    facts["credentials"] = Value::Array(credentials);
    for field in [
        "presentation_verified",
        "holder_binding_verified",
        "challenge_verified",
        "audience_verified",
        "replay_check_verified",
    ] {
        facts[field] = json!(groups.iter().all(|group| group
            .iter()
            .any(|material| material.policy_facts[field] == true)));
    }
    for field in ["holder_binding_method", "proof_profile"] {
        let values = groups
            .iter()
            .flatten()
            .filter(|material| material.policy_facts["holder_binding_verified"] == true)
            .filter_map(|material| material.policy_facts[field].as_str())
            .collect::<BTreeSet<_>>();
        facts[field] = if values.len() == 1 {
            json!(values.first())
        } else {
            Value::Null
        };
    }
    facts["proof_epoch_seconds"] = groups
        .iter()
        .flatten()
        .filter_map(|material| material.policy_facts["proof_epoch_seconds"].as_u64())
        .min()
        .map_or(Value::Null, |value| json!(value));
    facts["presentation_count"] = json!(presentation_count.unwrap_or(groups.len()));
    let all_authenticated = groups.iter().all(|group| {
        group.iter().any(|material| {
            material.policy_facts["credentials"]
                .as_array()
                .is_some_and(|credentials| {
                    credentials
                        .iter()
                        .any(|credential| credential["signature_verified"] == true)
                })
        })
    });
    if !all_authenticated {
        facts["external_authorization"] = json!({"evaluated": false, "allowed": false, "reasons": [], "errors": ["Every OID4VP response item must authenticate and match its query"]});
    }
    // The legacy single-credential provenance projection cannot represent a
    // multi-credential or multi-profile decision without choosing a candidate.
    VerifiedPolicyMaterial::facts_only(facts)
}

fn freshness_flag(policy: &PresentationPolicy, name: &str) -> bool {
    policy
        .holder_binding
        .proof_freshness
        .get(name)
        .copied()
        .unwrap_or(true)
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
    _policy: &PresentationPolicy,
    format: &str,
    reason: &str,
    evaluation_time: u64,
    trust_profile_verified: bool,
) -> Value {
    json!({
        "credentials": [{
            "credential_id": "presented-credential",
            "credential_template_ids": [],
            "credential_types": [],
            "credential_format": format,
            "claims": {},
            "issuer_id": "unknown",
            "signature_verified": false,
            "signature_failure_reason": reason,
            "trust_profile_verified": trust_profile_verified,
            "trust_profile_id": Value::Null,
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

fn failed(message: &str) -> PresentationVerificationError {
    PresentationVerificationError::Failed(message.into())
}
