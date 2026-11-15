//! Authority-owned snapshots and exact credential-type decisions.
//!
//! The canonical path deliberately uses persisted relationship keys and explicit
//! per-relationship grants. It does not resolve keys or broaden generic trust.

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use marty_oid4vp_contract::{
    digest_domain_json,
    trust_authority::{
        credential_authority_basis_digest, credential_authority_snapshot_digest,
        credential_authorizations, credential_trust_evaluation_digest, issuer_public_key_algorithm,
        issuer_public_key_thumbprint, CredentialAuthorityBasisV1, CredentialAuthorityIssuerV1,
        CredentialAuthorityPolicyControlsV1, CredentialAuthorityRevocationPolicyV1,
        CredentialAuthoritySnapshotV1, CredentialAuthorityTimePolicyV1,
        CredentialAuthorityValidationRulesV1, CredentialTrustEvaluationRequestV1,
        CredentialTrustEvaluationResponseV1, CredentialTypeAuthorizationV1,
        CREDENTIAL_AUTHORITY_MAX_AGE_SECONDS, CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT,
        CREDENTIAL_TRUST_EVALUATION_CONTRACT, MAX_CREDENTIAL_AUTHORITY_ISSUERS,
    },
    EvidenceCheckOutcome, EvidenceProfileReference,
};
use serde::Serialize;
use serde_json::Value;

use crate::{IssuerEntity, TrustProfile, TrustProfileIssuer, TrustProfileRepositoryError};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialAuthorityError {
    #[error("TRUST_PROFILE.INVALID_CREDENTIAL_AUTHORITY_REQUEST")]
    InvalidRequest,
    #[error("TRUST_PROFILE.CREDENTIAL_AUTHORITY_REVISION_MISMATCH")]
    RevisionMismatch,
    #[error("TRUST_PROFILE.CREDENTIAL_AUTHORITY_UNAVAILABLE")]
    Unavailable,
    #[error("TRUST_PROFILE.CREDENTIAL_AUTHORITY_UNSUPPORTED_CONFIGURATION")]
    UnsupportedConfiguration,
}

pub(crate) fn authority_basis(
    profile: &TrustProfile,
    relationships: Vec<(TrustProfileIssuer, IssuerEntity)>,
) -> Result<CredentialAuthorityBasisV1, TrustProfileRepositoryError> {
    if relationships.len() > MAX_CREDENTIAL_AUTHORITY_ISSUERS {
        return Err(invalid("credential_authority.issuer_count"));
    }
    let mut issuers = Vec::with_capacity(relationships.len());
    for (relationship, issuer) in relationships {
        if relationship.trust_profile_id != profile.id || relationship.issuer_id != issuer.id {
            return Err(invalid("credential_authority.relationship"));
        }
        crate::reject_private_custody_metadata(&issuer.metadata)
            .map_err(|_| invalid("credential_authority.private_metadata"))?;
        crate::reject_private_custody_metadata(&relationship.metadata)
            .map_err(|_| invalid("credential_authority.private_metadata"))?;
        let mut keys = match issuer.metadata.get("verification_keys") {
            None => Vec::new(),
            Some(Value::Array(keys)) if keys.len() <= 32 => keys.clone(),
            Some(_) => return Err(invalid("credential_authority.verification_keys")),
        };
        let mut keyed = keys
            .drain(..)
            .map(|key| {
                issuer_public_key_thumbprint(&key)
                    .map(|fingerprint| (fingerprint, key))
                    .map_err(|_| invalid("credential_authority.verification_keys"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        issuers.push(CredentialAuthorityIssuerV1 {
            relationship_id: relationship.id.to_string(),
            issuer_entity_id: issuer.id.to_string(),
            issuer_id: issuer.issuer_id,
            issuer_organization_id: issuer.organization_id,
            is_system_issuer: issuer.is_system_issuer,
            relationship_status: name(&relationship.relationship_status)?,
            trust_level: u32::from(relationship.trust_level),
            compliance_status: name(&issuer.compliance_status)?,
            accreditations: sorted(issuer.accreditations),
            valid_from: timestamp(issuer.valid_from),
            valid_until: issuer.valid_until.map(timestamp),
            revoked_at: issuer.revoked_at.map(timestamp),
            verification_keys: keyed.into_iter().map(|(_, key)| key).collect(),
            credential_authorizations: credential_authorizations(&relationship.metadata)
                .map_err(|_| invalid("credential_authority.authorizations"))?,
            issuer_created_at: timestamp(issuer.created_at),
            issuer_updated_at: timestamp(issuer.updated_at),
            relationship_created_at: timestamp(relationship.created_at),
            relationship_updated_at: timestamp(relationship.updated_at),
        });
    }
    issuers.sort_by(|left, right| left.relationship_id.cmp(&right.relationship_id));
    let basis = CredentialAuthorityBasisV1 {
        id: profile.id.to_string(),
        organization_id: profile.organization_id.clone(),
        status: name(&profile.status)?,
        compliance_status: name(&profile.compliance_status)?,
        trust_purposes: sorted(
            profile
                .trust_purposes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(name)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        supported_formats: sorted(profile.supported_formats.clone()),
        allowed_algorithms: sorted(profile.validation_rules.allowed_algorithms.clone()),
        allowed_issuers: profile.allowed_issuers.clone().map(sorted),
        denied_issuers: sorted(profile.denied_issuers.clone().unwrap_or_default()),
        policy_controls: policy_controls(profile)?,
        created_at: timestamp(profile.created_at),
        updated_at: timestamp(profile.updated_at),
        issuer_relationships: issuers,
    };
    basis
        .validate()
        .map_err(|_| invalid("credential_authority.basis"))?;
    Ok(basis)
}

fn policy_controls(
    profile: &TrustProfile,
) -> Result<CredentialAuthorityPolicyControlsV1, TrustProfileRepositoryError> {
    // Unsupported owner settings are still part of every revision, without
    // projecting registry credentials, unbounded metadata, or ignored key
    // overrides into the decision document. A named unsupported setting always
    // blocks this profile; its digest is not an authorization assertion.
    let mut unsupported = BTreeMap::<&str, Value>::new();
    if !profile.system_issuer_overrides.is_empty() {
        unsupported.insert(
            "system_issuer_overrides",
            serialize(&profile.system_issuer_overrides)?,
        );
    }
    if !profile.trust_sources.is_empty() {
        unsupported.insert("trust_sources", serialize(&profile.trust_sources)?);
    }
    if !profile.validation_rules.extensions.is_empty() {
        unsupported.insert(
            "validation_rules.extensions",
            serialize(&profile.validation_rules.extensions)?,
        );
    }
    if let Some(reference) = &profile.verification_policy_set_id {
        unsupported.insert("verification_policy_set_id", serialize(reference)?);
    }
    if let Some(reference) = &profile.revocation_profile_id {
        unsupported.insert("revocation_profile_id", serialize(reference)?);
    }
    if !profile.compatible_compliance_codes.is_empty() {
        unsupported.insert(
            "compatible_compliance_codes",
            serialize(&profile.compatible_compliance_codes)?,
        );
    }
    if profile.profile_type != crate::TrustProfileType::Custom {
        unsupported.insert("profile_type", serialize(&profile.profile_type)?);
    }
    if serde_json::to_vec(&unsupported)
        .map_err(|_| invalid("credential_authority.configuration"))?
        .len()
        > 2_097_152
    {
        return Err(invalid("credential_authority.configuration_size"));
    }
    let rules = &profile.validation_rules;
    let time = &profile.time_policy;
    let revocation = &profile.revocation_policy;
    Ok(CredentialAuthorityPolicyControlsV1 {
        validation_rules: CredentialAuthorityValidationRulesV1 {
            min_key_size_rsa: rules.min_key_size_rsa,
            min_key_size_ec: rules.min_key_size_ec,
            require_key_usage: rules.require_key_usage,
            max_chain_depth: rules.max_chain_depth,
            allow_self_signed: rules.allow_self_signed,
        },
        time_policy: CredentialAuthorityTimePolicyV1 {
            max_clock_skew_seconds: time.max_clock_skew_seconds,
            credential_freshness_hours: time.credential_freshness_hours,
            require_not_before: time.require_not_before,
            require_expiration: time.require_expiration,
        },
        revocation_policy: CredentialAuthorityRevocationPolicyV1 {
            check_mode: name(&revocation.check_mode)?,
            check_ocsp: revocation.check_ocsp,
            check_crl: revocation.check_crl,
            check_status_list: revocation.check_status_list,
            offline_grace_period_hours: revocation.offline_grace_period_hours,
            cache_duration_hours: revocation.cache_duration_hours,
        },
        trusted_assertion_formats: profile
            .trusted_assertion_formats
            .as_ref()
            .map(|formats| {
                formats
                    .iter()
                    .map(name)
                    .collect::<Result<Vec<_>, _>>()
                    .map(sorted)
            })
            .transpose()?,
        unsupported_configuration_fields: unsupported
            .keys()
            .map(|field| (*field).to_owned())
            .collect(),
        unsupported_configuration_digest: digest_domain_json(
            "marty.trust-profile/unsupported-credential-authority-configuration/v1",
            &unsupported,
        )
        .map_err(|_| invalid("credential_authority.configuration_digest"))?,
    })
}

/// Guard the bounded managed SD-JWT profile. The repository publishes the real
/// configuration revision before this guard runs, including rejected settings.
pub fn validate_supported_configuration(
    basis: &CredentialAuthorityBasisV1,
) -> Result<(), CredentialAuthorityError> {
    let controls = &basis.policy_controls;
    if !controls.unsupported_configuration_fields.is_empty()
        || controls.validation_rules.min_key_size_ec > 256
        || controls.time_policy.credential_freshness_hours.is_some()
        || controls.revocation_policy.check_ocsp
        || controls.revocation_policy.check_crl
        || controls.revocation_policy.check_status_list
        || controls
            .trusted_assertion_formats
            .as_ref()
            .is_some_and(|formats| !formats.iter().any(|format| format == "JWT"))
    {
        return Err(CredentialAuthorityError::UnsupportedConfiguration);
    }
    // RSA/certificate-chain constraints do not apply to the supported Ed25519
    // and P-256 public JWKs. Native credential time checks use zero skew and
    // require expiration; configured nbf is enforced by the native producer.
    // Managed status is always checked live and fails closed. It cannot satisfy
    // configured external OCSP, CRL or status-list requirements, rejected above.
    Ok(())
}

pub(crate) fn authority_snapshot(
    basis: CredentialAuthorityBasisV1,
    version: u32,
) -> Result<CredentialAuthoritySnapshotV1, TrustProfileRepositoryError> {
    let digest = credential_authority_basis_digest(&basis)
        .map_err(|_| invalid("credential_authority.digest"))?;
    let mut snapshot = CredentialAuthoritySnapshotV1 {
        contract: CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT.into(),
        organization_id: basis.organization_id.clone(),
        profile: EvidenceProfileReference {
            id: basis.id.clone(),
            version,
            content_digest: digest,
        },
        basis,
        response_digest: String::new(),
    };
    snapshot.response_digest = credential_authority_snapshot_digest(&snapshot)
        .map_err(|_| invalid("credential_authority.digest"))?;
    snapshot
        .validate()
        .map_err(|_| invalid("credential_authority.snapshot"))?;
    Ok(snapshot)
}

/// Assess the exact authenticated selection against the current owner snapshot.
/// The caller still has to authenticate the credential; this result grants only
/// the trust authority's narrowly scoped permission for that selection.
pub fn evaluate_credential_authority(
    snapshot: &CredentialAuthoritySnapshotV1,
    request: &CredentialTrustEvaluationRequestV1,
    now: DateTime<Utc>,
) -> Result<CredentialTrustEvaluationResponseV1, CredentialAuthorityError> {
    request
        .validate()
        .map_err(|_| CredentialAuthorityError::InvalidRequest)?;
    snapshot
        .validate()
        .map_err(|_| CredentialAuthorityError::Unavailable)?;
    if request.organization_id != snapshot.organization_id
        || request.expected_profile.id != snapshot.profile.id
    {
        return Err(CredentialAuthorityError::InvalidRequest);
    }
    if request.expected_profile != snapshot.profile {
        return Err(CredentialAuthorityError::RevisionMismatch);
    }
    validate_supported_configuration(&snapshot.basis)?;
    let checked_at = now.timestamp();
    let default_deadline = checked_at
        .checked_add(CREDENTIAL_AUTHORITY_MAX_AGE_SECONDS)
        .filter(|_| checked_at > 0)
        .ok_or(CredentialAuthorityError::Unavailable)?;
    let (reason, selected) = decision(&snapshot.basis, request, now)?;
    let passed = reason == "TRUST_PROFILE.CREDENTIAL_AUTHORIZED";
    let valid_until = if passed {
        selected
            .and_then(|issuer| issuer.valid_until.as_deref())
            .map(parse_timestamp)
            .transpose()?
            .map_or(default_deadline, |until| {
                until.timestamp().min(default_deadline)
            })
    } else {
        default_deadline
    };
    // There must be at least one full observation second left for a receipt.
    let passed = passed && valid_until > checked_at;
    let mut response = CredentialTrustEvaluationResponseV1 {
        contract: CREDENTIAL_TRUST_EVALUATION_CONTRACT.into(),
        organization_id: request.organization_id.clone(),
        profile: snapshot.profile.clone(),
        issuer_id: request.issuer_id.clone(),
        format: request.format.clone(),
        vct: request.vct.clone(),
        issuer_algorithm: request.issuer_algorithm.clone(),
        issuer_key_thumbprint: request.issuer_key_thumbprint.clone(),
        request_binding_digest: request.request_binding_digest.clone(),
        outcome: if passed {
            EvidenceCheckOutcome::Passed
        } else {
            EvidenceCheckOutcome::Failed
        },
        reason_code: if !passed && reason == "TRUST_PROFILE.CREDENTIAL_AUTHORIZED" {
            "TRUST_PROFILE.AUTHORITY_WINDOW_EXHAUSTED".into()
        } else {
            reason.into()
        },
        trust_level: selected.filter(|_| passed).map(|issuer| issuer.trust_level),
        compliance_statuses: selected
            .filter(|_| passed)
            .map(|issuer| vec![issuer.compliance_status.clone()])
            .unwrap_or_default(),
        accreditations: selected
            .filter(|_| passed)
            .map(|issuer| issuer.accreditations.clone())
            .unwrap_or_default(),
        checked_at_epoch_seconds: checked_at,
        valid_until_epoch_seconds: if passed {
            valid_until
        } else {
            default_deadline
        },
        evidence_digest: String::new(),
    };
    response.evidence_digest = credential_trust_evaluation_digest(&response)
        .map_err(|_| CredentialAuthorityError::Unavailable)?;
    response
        .validate_for_request(request, checked_at)
        .map_err(|_| CredentialAuthorityError::Unavailable)?;
    Ok(response)
}

fn decision<'a>(
    basis: &'a CredentialAuthorityBasisV1,
    request: &CredentialTrustEvaluationRequestV1,
    now: DateTime<Utc>,
) -> Result<(&'static str, Option<&'a CredentialAuthorityIssuerV1>), CredentialAuthorityError> {
    let deny = |reason| Ok((reason, None));
    if basis.status != "active"
        || basis.compliance_status != "COMPLIANT"
        || !basis
            .trust_purposes
            .iter()
            .any(|purpose| purpose == "CREDENTIAL_ISSUER")
    {
        return deny("TRUST_PROFILE.PROFILE_NOT_ACTIVE_FOR_CREDENTIALS");
    }
    if !basis.supported_formats.contains(&request.format)
        || !basis.allowed_algorithms.contains(&request.issuer_algorithm)
    {
        return deny("TRUST_PROFILE.FORMAT_OR_ALGORITHM_NOT_AUTHORIZED");
    }
    if basis.denied_issuers.contains(&request.issuer_id)
        || basis
            .allowed_issuers
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&request.issuer_id))
    {
        return deny("TRUST_PROFILE.ISSUER_NOT_AUTHORIZED");
    }
    let Some(issuer) = basis
        .issuer_relationships
        .iter()
        .find(|issuer| issuer.issuer_id == request.issuer_id)
    else {
        return deny("TRUST_PROFILE.ISSUER_NOT_AUTHORIZED");
    };
    if issuer.relationship_status != "TRUSTED" || issuer.trust_level == 0 {
        return deny("TRUST_PROFILE.RELATIONSHIP_NOT_TRUSTED");
    }
    if !matches!(
        issuer.compliance_status.as_str(),
        "ACCREDITED" | "COMPLIANT"
    ) || issuer.revoked_at.is_some()
        || parse_timestamp(&issuer.valid_from)? > now
        || issuer
            .valid_until
            .as_deref()
            .map(parse_timestamp)
            .transpose()?
            .is_some_and(|until| until <= now)
    {
        return deny("TRUST_PROFILE.ISSUER_NOT_CURRENT");
    }
    if !issuer
        .credential_authorizations
        .contains(&CredentialTypeAuthorizationV1 {
            format: request.format.clone(),
            vct: request.vct.clone(),
        })
    {
        return deny("TRUST_PROFILE.CREDENTIAL_TYPE_NOT_AUTHORIZED");
    }
    let key_matches = issuer.verification_keys.iter().any(|key| {
        issuer_public_key_thumbprint(key)
            .is_ok_and(|fingerprint| fingerprint == request.issuer_key_thumbprint)
            && issuer_public_key_algorithm(key)
                .is_ok_and(|algorithm| algorithm == request.issuer_algorithm)
            && (!basis.policy_controls.validation_rules.require_key_usage
                || key.get("use").and_then(Value::as_str) == Some("sig")
                || key
                    .get("key_ops")
                    .is_some_and(|operations| operations == &serde_json::json!(["verify"])))
    });
    if !key_matches {
        return deny("TRUST_PROFILE.ISSUER_KEY_NOT_AUTHORIZED");
    }
    Ok(("TRUST_PROFILE.CREDENTIAL_AUTHORIZED", Some(issuer)))
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, CredentialAuthorityError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CredentialAuthorityError::Unavailable)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn name(value: &impl Serialize) -> Result<String, TrustProfileRepositoryError> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid("credential_authority.enum"))
}

fn serialize(value: &impl Serialize) -> Result<Value, TrustProfileRepositoryError> {
    serde_json::to_value(value).map_err(|_| invalid("credential_authority.configuration"))
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn invalid(field: &'static str) -> TrustProfileRepositoryError {
    TrustProfileRepositoryError::InvalidData(field)
}
