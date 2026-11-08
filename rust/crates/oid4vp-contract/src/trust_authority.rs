//! Bounded wire contracts for the Trust Profile credential authority.
//!
//! Parsing and digest validation establish correspondence only. These DTOs do
//! not authenticate themselves and cannot construct canonical OID4VP evidence.
//! Consumers must obtain them from the configured deployment-trusted owner.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    digest_domain_json, EvidenceCheckOutcome, EvidenceProfileReference, Oid4vpContractError,
};

pub const CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT: &str = "marty.credential-authority-snapshot/v1";
pub const CREDENTIAL_TRUST_EVALUATION_CONTRACT: &str = "marty.credential-trust-evaluation/v1";
pub const CREDENTIAL_AUTHORITY_METADATA_KEY: &str = "marty_credential_authorizations_v1";
pub const CREDENTIAL_AUTHORITY_MAX_AGE_SECONDS: i64 = 60;
pub const MAX_CREDENTIAL_AUTHORITY_BYTES: usize = crate::MAX_FROZEN_REQUEST_BYTES;
pub const MAX_CREDENTIAL_AUTHORITY_ISSUERS: usize = 128;
pub const MAX_CREDENTIAL_AUTHORIZATIONS: usize = 128;
const MAX_KEYS_PER_ISSUER: usize = 32;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTypeAuthorizationV1 {
    pub format: String,
    pub vct: String,
}

impl CredentialTypeAuthorizationV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        if self.format != "SD_JWT_VC"
            || !bounded_text(&self.vct, 2_048)
            || url::Url::parse(&self.vct).is_err()
        {
            return Err(invalid("credential_authorization"));
        }
        Ok(())
    }
}

/// A strictly validated grant list under the existing relationship metadata
/// permission. Absence is an empty list, never an implicit authorization.
pub fn credential_authorizations(
    metadata: &Value,
) -> Result<Vec<CredentialTypeAuthorizationV1>, Oid4vpContractError> {
    let Some(object) = metadata.as_object() else {
        // Legacy metadata shapes have no explicit grant; preserve their generic
        // write behavior while the canonical path grants nothing implicitly.
        return Ok(Vec::new());
    };
    let Some(value) = object.get(CREDENTIAL_AUTHORITY_METADATA_KEY) else {
        return Ok(Vec::new());
    };
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        > 300_000
    {
        return Err(invalid("credential_authorizations"));
    }
    let mut rules: Vec<CredentialTypeAuthorizationV1> =
        serde_json::from_value(value.clone()).map_err(|_| invalid("credential_authorizations"))?;
    if rules.len() > MAX_CREDENTIAL_AUTHORIZATIONS {
        return Err(invalid("credential_authorizations"));
    }
    for rule in &rules {
        rule.validate()?;
    }
    rules.sort();
    if rules.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("credential_authorizations"));
    }
    Ok(rules)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthoritySnapshotRequestV1 {
    pub organization_id: String,
}

impl CredentialAuthoritySnapshotRequestV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_text(&self.organization_id, 255, "organization_id")
    }
}

/// Exact persisted decision inputs, sorted before the authority computes its
/// revision. Date strings retain the database's full stored precision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityBasisV1 {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    pub compliance_status: String,
    pub trust_purposes: Vec<String>,
    pub supported_formats: Vec<String>,
    pub allowed_algorithms: Vec<String>,
    pub allowed_issuers: Option<Vec<String>>,
    pub denied_issuers: Vec<String>,
    pub policy_controls: CredentialAuthorityPolicyControlsV1,
    pub created_at: String,
    pub updated_at: String,
    pub issuer_relationships: Vec<CredentialAuthorityIssuerV1>,
}

/// Controls owned by the Trust Profile service. Unimplemented configuration is
/// committed by an owner digest and named explicitly; it can never authorize a
/// credential in this bounded profile. No service secrets are projected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityPolicyControlsV1 {
    pub validation_rules: CredentialAuthorityValidationRulesV1,
    pub time_policy: CredentialAuthorityTimePolicyV1,
    pub revocation_policy: CredentialAuthorityRevocationPolicyV1,
    pub trusted_assertion_formats: Option<Vec<String>>,
    pub unsupported_configuration_fields: Vec<String>,
    pub unsupported_configuration_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityValidationRulesV1 {
    pub min_key_size_rsa: u16,
    pub min_key_size_ec: u16,
    pub require_key_usage: bool,
    pub max_chain_depth: u8,
    pub allow_self_signed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityTimePolicyV1 {
    pub max_clock_skew_seconds: u32,
    pub credential_freshness_hours: Option<u32>,
    pub require_not_before: bool,
    pub require_expiration: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityRevocationPolicyV1 {
    pub check_mode: String,
    pub check_ocsp: bool,
    pub check_crl: bool,
    pub check_status_list: bool,
    pub offline_grace_period_hours: u16,
    pub cache_duration_hours: u16,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorityIssuerV1 {
    pub relationship_id: String,
    pub issuer_entity_id: String,
    /// Exact issuer identifier authenticated by the native credential verifier.
    pub issuer_id: String,
    pub issuer_organization_id: Option<String>,
    pub is_system_issuer: bool,
    pub relationship_status: String,
    pub trust_level: u32,
    pub compliance_status: String,
    pub accreditations: Vec<String>,
    pub valid_from: String,
    pub valid_until: Option<String>,
    pub revoked_at: Option<String>,
    pub verification_keys: Vec<Value>,
    pub credential_authorizations: Vec<CredentialTypeAuthorizationV1>,
    pub issuer_created_at: String,
    pub issuer_updated_at: String,
    pub relationship_created_at: String,
    pub relationship_updated_at: String,
}

impl CredentialAuthorityBasisV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_size(self, MAX_CREDENTIAL_AUTHORITY_BYTES)?;
        require_text(&self.id, 255, "profile.id")?;
        require_text(&self.organization_id, 255, "organization_id")?;
        if !matches!(
            self.status.as_str(),
            "draft" | "active" | "suspended" | "archived"
        ) || !matches!(
            self.compliance_status.as_str(),
            "COMPLIANT" | "NEEDS_ATTENTION" | "SETUP_REQUIRED"
        ) {
            return Err(invalid("profile.lifecycle"));
        }
        sorted_strings(&self.trust_purposes, 16, 64)?;
        sorted_strings(&self.supported_formats, 32, 64)?;
        sorted_strings(&self.allowed_algorithms, 32, 64)?;
        sorted_strings(
            &self.policy_controls.unsupported_configuration_fields,
            32,
            128,
        )?;
        if !valid_digest(&self.policy_controls.unsupported_configuration_digest) {
            return Err(invalid("profile.unsupported_configuration_digest"));
        }
        if let Some(formats) = &self.policy_controls.trusted_assertion_formats {
            sorted_strings(formats, 16, 64)?;
        }
        if !matches!(
            self.policy_controls.revocation_policy.check_mode.as_str(),
            "HARD_FAIL" | "SOFT_FAIL" | "SKIP"
        ) {
            return Err(invalid("profile.revocation_policy"));
        }
        if let Some(issuers) = &self.allowed_issuers {
            sorted_strings(issuers, MAX_CREDENTIAL_AUTHORITY_ISSUERS, 2_048)?;
        }
        sorted_strings(
            &self.denied_issuers,
            MAX_CREDENTIAL_AUTHORITY_ISSUERS,
            2_048,
        )?;
        require_text(&self.created_at, 64, "profile.created_at")?;
        require_text(&self.updated_at, 64, "profile.updated_at")?;
        if self.issuer_relationships.len() > MAX_CREDENTIAL_AUTHORITY_ISSUERS
            || self
                .issuer_relationships
                .windows(2)
                .any(|pair| pair[0].relationship_id >= pair[1].relationship_id)
        {
            return Err(invalid("issuer_relationships"));
        }
        let mut identities = BTreeSet::new();
        let mut entities = BTreeSet::new();
        for issuer in &self.issuer_relationships {
            require_text(&issuer.relationship_id, 255, "relationship.id")?;
            require_text(&issuer.issuer_entity_id, 255, "issuer.entity_id")?;
            require_text(&issuer.issuer_id, 2_048, "issuer.id")?;
            if !identities.insert(&issuer.issuer_id)
                || !entities.insert(&issuer.issuer_entity_id)
                || issuer.trust_level > 100
                || !matches!(
                    issuer.relationship_status.as_str(),
                    "TRUSTED" | "DENIED" | "UNDER_REVIEW"
                )
                || !matches!(
                    issuer.compliance_status.as_str(),
                    "ACCREDITED" | "COMPLIANT" | "SUSPENDED" | "REVOKED"
                )
                || !(issuer.issuer_organization_id.as_deref()
                    == Some(self.organization_id.as_str())
                    || (issuer.issuer_organization_id.is_none() && issuer.is_system_issuer))
            {
                return Err(invalid("issuer.authority"));
            }
            sorted_strings(&issuer.accreditations, 128, 128)?;
            for value in [
                Some(issuer.valid_from.as_str()),
                issuer.valid_until.as_deref(),
                issuer.revoked_at.as_deref(),
                Some(issuer.issuer_created_at.as_str()),
                Some(issuer.issuer_updated_at.as_str()),
                Some(issuer.relationship_created_at.as_str()),
                Some(issuer.relationship_updated_at.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                require_text(value, 64, "issuer.lifecycle")?;
            }
            if issuer.verification_keys.len() > MAX_KEYS_PER_ISSUER {
                return Err(invalid("issuer.verification_keys"));
            }
            let mut previous_key = None;
            let mut material = BTreeSet::new();
            for key in &issuer.verification_keys {
                require_size(key, 16_384)?;
                let thumbprint = issuer_public_key_thumbprint(key)?;
                if !material.insert(thumbprint.clone()) {
                    return Err(invalid("issuer.verification_keys"));
                }
                if previous_key
                    .as_ref()
                    .is_some_and(|previous| previous >= &thumbprint)
                {
                    return Err(invalid("issuer.verification_keys"));
                }
                previous_key = Some(thumbprint);
            }
            if issuer.credential_authorizations.len() > MAX_CREDENTIAL_AUTHORIZATIONS
                || issuer
                    .credential_authorizations
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid("credential_authorizations"));
            }
            for rule in &issuer.credential_authorizations {
                rule.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthoritySnapshotV1 {
    pub contract: String,
    pub organization_id: String,
    pub profile: EvidenceProfileReference,
    pub basis: CredentialAuthorityBasisV1,
    pub response_digest: String,
}

impl CredentialAuthoritySnapshotV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_size(self, MAX_CREDENTIAL_AUTHORITY_BYTES)?;
        self.basis.validate()?;
        validate_profile_reference(&self.profile)?;
        if self.contract != CREDENTIAL_AUTHORITY_SNAPSHOT_CONTRACT
            || self.organization_id != self.basis.organization_id
            || self.profile.id != self.basis.id
            || self.profile.content_digest != credential_authority_basis_digest(&self.basis)?
            || self.response_digest != credential_authority_snapshot_digest(self)?
        {
            return Err(invalid("credential_authority_snapshot"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTrustEvaluationRequestV1 {
    pub organization_id: String,
    pub expected_profile: EvidenceProfileReference,
    pub issuer_id: String,
    pub format: String,
    pub vct: String,
    pub issuer_algorithm: String,
    pub issuer_key_thumbprint: String,
    pub request_binding_digest: String,
}

impl CredentialTrustEvaluationRequestV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_size(self, 16_384)?;
        require_text(&self.organization_id, 255, "organization_id")?;
        validate_profile_reference(&self.expected_profile)?;
        require_text(&self.issuer_id, 2_048, "issuer_id")?;
        CredentialTypeAuthorizationV1 {
            format: self.format.clone(),
            vct: self.vct.clone(),
        }
        .validate()?;
        if !matches!(self.issuer_algorithm.as_str(), "EdDSA" | "ES256")
            || !valid_thumbprint(&self.issuer_key_thumbprint)
            || !valid_digest(&self.request_binding_digest)
        {
            return Err(invalid("credential_trust_request"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTrustEvaluationResponseV1 {
    pub contract: String,
    pub organization_id: String,
    pub profile: EvidenceProfileReference,
    pub issuer_id: String,
    pub format: String,
    pub vct: String,
    pub issuer_algorithm: String,
    pub issuer_key_thumbprint: String,
    pub request_binding_digest: String,
    pub outcome: EvidenceCheckOutcome,
    pub reason_code: String,
    pub trust_level: Option<u32>,
    pub compliance_statuses: Vec<String>,
    pub accreditations: Vec<String>,
    pub checked_at_epoch_seconds: i64,
    /// A freshness deadline, not a promise that authority cannot be revoked.
    pub valid_until_epoch_seconds: i64,
    pub evidence_digest: String,
}

impl CredentialTrustEvaluationResponseV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        require_size(self, 32_768)?;
        let request = self.request();
        request.validate()?;
        require_text(&self.reason_code, 128, "reason_code")?;
        sorted_strings(&self.compliance_statuses, 16, 64)?;
        sorted_strings(&self.accreditations, 128, 128)?;
        let lifetime = self
            .valid_until_epoch_seconds
            .checked_sub(self.checked_at_epoch_seconds)
            .ok_or_else(|| invalid("credential_trust_lifetime"))?;
        if self.contract != CREDENTIAL_TRUST_EVALUATION_CONTRACT
            || self.checked_at_epoch_seconds <= 0
            || !(1..=CREDENTIAL_AUTHORITY_MAX_AGE_SECONDS).contains(&lifetime)
            || self.trust_level.is_some_and(|level| level > 100)
            || (self.outcome == EvidenceCheckOutcome::Passed
                && (self.reason_code != "TRUST_PROFILE.CREDENTIAL_AUTHORIZED"
                    || self.trust_level.is_none_or(|level| level == 0)
                    || self.compliance_statuses.is_empty()))
            || (self.outcome != EvidenceCheckOutcome::Passed
                && (self.trust_level.is_some()
                    || !self.compliance_statuses.is_empty()
                    || !self.accreditations.is_empty()))
            || self.evidence_digest != credential_trust_evaluation_digest(self)?
        {
            return Err(invalid("credential_trust_response"));
        }
        Ok(())
    }

    pub fn validate_for_request(
        &self,
        request: &CredentialTrustEvaluationRequestV1,
        now: i64,
    ) -> Result<(), Oid4vpContractError> {
        request.validate()?;
        self.validate()?;
        if self.request() != *request
            || now < self.checked_at_epoch_seconds
            || now >= self.valid_until_epoch_seconds
        {
            return Err(invalid("credential_trust_correspondence"));
        }
        Ok(())
    }

    fn request(&self) -> CredentialTrustEvaluationRequestV1 {
        CredentialTrustEvaluationRequestV1 {
            organization_id: self.organization_id.clone(),
            expected_profile: self.profile.clone(),
            issuer_id: self.issuer_id.clone(),
            format: self.format.clone(),
            vct: self.vct.clone(),
            issuer_algorithm: self.issuer_algorithm.clone(),
            issuer_key_thumbprint: self.issuer_key_thumbprint.clone(),
            request_binding_digest: self.request_binding_digest.clone(),
        }
    }
}

pub fn credential_authority_basis_digest(
    basis: &CredentialAuthorityBasisV1,
) -> Result<String, Oid4vpContractError> {
    digest_domain_json("marty.trust-profile/credential-authority-basis/v1", basis)
}

pub fn credential_authority_snapshot_digest(
    snapshot: &CredentialAuthoritySnapshotV1,
) -> Result<String, Oid4vpContractError> {
    digest_domain_json(
        "marty.trust-profile/credential-authority-snapshot/v1",
        &json!({
            "contract": snapshot.contract,
            "organization_id": snapshot.organization_id,
            "profile": snapshot.profile,
            "basis": snapshot.basis,
        }),
    )
}

pub fn credential_trust_evaluation_digest(
    response: &CredentialTrustEvaluationResponseV1,
) -> Result<String, Oid4vpContractError> {
    let mut value =
        serde_json::to_value(response).map_err(|_| Oid4vpContractError::Serialization)?;
    value
        .as_object_mut()
        .ok_or(Oid4vpContractError::Serialization)?
        .remove("evidence_digest");
    digest_domain_json("marty.trust-profile/credential-trust-evaluation/v1", &value)
}

/// RFC 7638 public-key fingerprint used by both the native caller and owner.
/// Key metadata remains a constraint; it cannot replace the governed key.
pub fn issuer_public_key_thumbprint(jwk: &Value) -> Result<String, Oid4vpContractError> {
    let object = jwk
        .as_object()
        .ok_or_else(|| invalid("issuer.public_jwk"))?;
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err(invalid("issuer.public_jwk"));
    }
    let (algorithm, members): (&str, &[&str]) = match (
        object.get("kty").and_then(Value::as_str),
        object.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => ("ES256", &["crv", "kty", "x", "y"]),
        (Some("OKP"), Some("Ed25519")) => ("EdDSA", &["crv", "kty", "x"]),
        _ => return Err(invalid("issuer.public_jwk")),
    };
    if object
        .get("alg")
        .is_some_and(|value| value.as_str() != Some(algorithm))
        || object
            .get("use")
            .is_some_and(|value| value.as_str() != Some("sig"))
        || object
            .get("key_ops")
            .is_some_and(|value| value != &json!(["verify"]))
        || (object.contains_key("use") && object.contains_key("key_ops"))
        || object
            .get("kid")
            .is_some_and(|value| value.as_str().is_none_or(|kid| !bounded_text(kid, 2_048)))
    {
        return Err(invalid("issuer.public_jwk"));
    }
    let mut public = BTreeMap::new();
    let mut coordinates = Vec::new();
    for member in members {
        let value = object
            .get(*member)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("issuer.public_jwk"))?;
        if matches!(*member, "x" | "y") {
            let bytes = URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| invalid("issuer.public_jwk"))?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
                return Err(invalid("issuer.public_jwk"));
            }
            coordinates.extend(bytes);
        }
        public.insert(*member, value);
    }
    if algorithm == "ES256" {
        let mut point = vec![4];
        point.extend(coordinates);
        p256::PublicKey::from_sec1_bytes(&point).map_err(|_| invalid("issuer.public_jwk"))?;
    }
    let bytes = serde_json::to_vec(&public).map_err(|_| Oid4vpContractError::Serialization)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

pub fn issuer_public_key_algorithm(jwk: &Value) -> Result<&'static str, Oid4vpContractError> {
    issuer_public_key_thumbprint(jwk)?;
    match jwk["kty"].as_str() {
        Some("EC") => Ok("ES256"),
        Some("OKP") => Ok("EdDSA"),
        _ => Err(invalid("issuer.public_jwk")),
    }
}

fn validate_profile_reference(
    profile: &EvidenceProfileReference,
) -> Result<(), Oid4vpContractError> {
    require_text(&profile.id, 255, "profile.id")?;
    if profile.version == 0 || !valid_digest(&profile.content_digest) {
        return Err(invalid("profile.revision"));
    }
    Ok(())
}

fn sorted_strings(
    values: &[String],
    maximum: usize,
    text_maximum: usize,
) -> Result<(), Oid4vpContractError> {
    if values.len() > maximum
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values
            .iter()
            .any(|value| !bounded_text(value, text_maximum))
    {
        return Err(invalid("authority.string_list"));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_thumbprint(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == value)
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn require_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), Oid4vpContractError> {
    if bounded_text(value, maximum) {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

fn require_size(value: &impl Serialize, maximum: usize) -> Result<(), Oid4vpContractError> {
    if serde_json::to_vec(value)
        .map_err(|_| Oid4vpContractError::Serialization)?
        .len()
        <= maximum
    {
        Ok(())
    } else {
        Err(invalid("credential_authority.size"))
    }
}

fn invalid(field: &'static str) -> Oid4vpContractError {
    Oid4vpContractError::InvalidField(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key() -> Value {
        json!({"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "use":"sig",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})
    }

    #[test]
    fn governed_fingerprint_is_rfc7638_and_rejects_invalid_or_private_key_roles() {
        let key = public_key();
        assert_eq!(
            issuer_public_key_thumbprint(&key).unwrap(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        let mut alternate = key.clone();
        alternate.as_object_mut().unwrap().remove("use");
        alternate["key_ops"] = json!(["verify"]);
        alternate["kid"] = json!("key-version-2");
        assert_eq!(
            issuer_public_key_thumbprint(&alternate),
            issuer_public_key_thumbprint(&key)
        );
        for (field, value) in [
            ("d", json!("private")),
            ("k", json!("symmetric")),
            ("crv", json!("X25519")),
            ("alg", json!("ES256")),
            ("use", json!("enc")),
            ("key_ops", json!(["verify"])),
            ("x", json!("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=")),
            ("x", json!("short")),
        ] {
            let mut invalid = key.clone();
            invalid[field] = value;
            assert!(issuer_public_key_thumbprint(&invalid).is_err(), "{field}");
        }
        for operations in [json!(["sign"]), json!(["verify", "sign"]), json!([])] {
            alternate["key_ops"] = operations;
            assert!(issuer_public_key_thumbprint(&alternate).is_err());
        }
        let zero_point = json!({"kty":"EC","crv":"P-256","alg":"ES256", "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
        assert!(issuer_public_key_thumbprint(&zero_point).is_err());
    }

    #[test]
    fn exact_grants_are_bounded_and_missing_metadata_never_grants_a_type() {
        for absent in [json!({}), Value::Null, json!("legacy-note")] {
            assert!(credential_authorizations(&absent).unwrap().is_empty());
        }
        let rule = json!({"format":"SD_JWT_VC","vct":"https://types.example.test/Employee"});
        assert_eq!(
            credential_authorizations(&json!({CREDENTIAL_AUTHORITY_METADATA_KEY:[rule.clone()]}))
                .unwrap()
                .len(),
            1
        );
        for rules in [
            json!([rule.clone(), rule.clone()]),
            json!([{"format":"dc+sd-jwt","vct":"https://types.example.test/Employee"}]),
            json!([{"format":"SD_JWT_VC","vct":"Employee"}]),
            json!([{"format":"SD_JWT_VC","vct":"https://types.example.test/Employee","trusted":true}]),
            json!(vec![rule; MAX_CREDENTIAL_AUTHORIZATIONS + 1]),
        ] {
            assert!(
                credential_authorizations(&json!({CREDENTIAL_AUTHORITY_METADATA_KEY: rules}))
                    .is_err()
            );
        }
    }

    #[test]
    fn receipt_validation_binds_every_request_field_and_exact_freshness_boundary() {
        let request = CredentialTrustEvaluationRequestV1 {
            organization_id: "org-a".into(),
            expected_profile: EvidenceProfileReference {
                id: "profile-a".into(),
                version: 1,
                content_digest: format!("sha256:{}", "a".repeat(64)),
            },
            issuer_id: "https://issuer.example.test".into(),
            format: "SD_JWT_VC".into(),
            vct: "https://types.example.test/Employee".into(),
            issuer_algorithm: "EdDSA".into(),
            issuer_key_thumbprint: issuer_public_key_thumbprint(&public_key()).unwrap(),
            request_binding_digest: format!("sha256:{}", "b".repeat(64)),
        };
        let mut response = CredentialTrustEvaluationResponseV1 {
            contract: CREDENTIAL_TRUST_EVALUATION_CONTRACT.into(),
            organization_id: request.organization_id.clone(),
            profile: request.expected_profile.clone(),
            issuer_id: request.issuer_id.clone(),
            format: request.format.clone(),
            vct: request.vct.clone(),
            issuer_algorithm: request.issuer_algorithm.clone(),
            issuer_key_thumbprint: request.issuer_key_thumbprint.clone(),
            request_binding_digest: request.request_binding_digest.clone(),
            outcome: EvidenceCheckOutcome::Passed,
            reason_code: "TRUST_PROFILE.CREDENTIAL_AUTHORIZED".into(),
            trust_level: Some(70),
            compliance_statuses: vec!["COMPLIANT".into()],
            accreditations: vec![],
            checked_at_epoch_seconds: 1_800_000_000,
            valid_until_epoch_seconds: 1_800_000_060,
            evidence_digest: String::new(),
        };
        response.evidence_digest = credential_trust_evaluation_digest(&response).unwrap();
        response
            .validate_for_request(&request, 1_800_000_000)
            .unwrap();
        response
            .validate_for_request(&request, 1_800_000_059)
            .unwrap();
        assert!(response
            .validate_for_request(&request, 1_799_999_999)
            .is_err());
        assert!(response
            .validate_for_request(&request, 1_800_000_060)
            .is_err());
        for field in [
            "organization_id",
            "profile_id",
            "profile_version",
            "profile_digest",
            "issuer_id",
            "vct",
            "issuer_algorithm",
            "issuer_key_thumbprint",
            "request_binding_digest",
        ] {
            let mut changed = response.clone();
            match field {
                "organization_id" => changed.organization_id = "org-b".into(),
                "profile_id" => changed.profile.id = "profile-b".into(),
                "profile_version" => changed.profile.version += 1,
                "profile_digest" => {
                    changed.profile.content_digest = format!("sha256:{}", "c".repeat(64))
                }
                "issuer_id" => changed.issuer_id = "https://other.example.test".into(),
                "vct" => changed.vct = "https://types.example.test/Other".into(),
                "issuer_algorithm" => changed.issuer_algorithm = "ES256".into(),
                "issuer_key_thumbprint" => {
                    changed.issuer_key_thumbprint =
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
                }
                _ => changed.request_binding_digest = format!("sha256:{}", "d".repeat(64)),
            }
            // A self-consistent digest does not authenticate or repair a crossed
            // request. Full tuple correspondence is independently required.
            changed.evidence_digest = credential_trust_evaluation_digest(&changed).unwrap();
            changed.validate().unwrap();
            assert!(
                changed
                    .validate_for_request(&request, 1_800_000_000)
                    .is_err(),
                "{field}"
            );
        }
        response.valid_until_epoch_seconds += 1;
        response.evidence_digest = credential_trust_evaluation_digest(&response).unwrap();
        assert!(response.validate().is_err());
    }
}
