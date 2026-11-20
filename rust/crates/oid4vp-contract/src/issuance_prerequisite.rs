//! Correspondence contracts for a configured verification-before-issuance flow.
//!
//! These wire values carry no authority. Flow authenticates its Issuance owner
//! channel and establishes the intent before publishing a wallet request;
//! Issuance authenticates Flow's owner channel before admitting an observation.
//! Neither a JSON value nor a correctly recomputed public digest can substitute
//! for either acquisition, a durable Flow receipt, or the atomic signing claim.

use serde::{Deserialize, Serialize};

use crate::{
    digest_domain_json, FrozenPolicyIdentity, ManagedOid4vpEvidenceProjectionV2,
    Oid4vpContractError, MAX_IDENTIFIER_BYTES,
};

pub const ISSUANCE_INTENT_CONTRACT_V1: &str = "marty.issuance-intent/v1";
pub const ISSUANCE_PREREQUISITE_START_REQUEST_V1: &str =
    "marty.issuance-prerequisite-start-request/v1";
pub const ISSUANCE_PREREQUISITE_START_RESPONSE_V1: &str =
    "marty.issuance-prerequisite-start-response/v1";
pub const ISSUANCE_PREREQUISITE_EVIDENCE_REQUEST_V1: &str =
    "marty.issuance-prerequisite-evidence-request/v1";
pub const ISSUANCE_PREREQUISITE_EVIDENCE_RESPONSE_V1: &str =
    "marty.issuance-prerequisite-evidence-response/v1";
pub const ISSUANCE_INTENT_DIGEST_DOMAIN_V1: &str = "marty.issuance/intent/v1";
pub const ISSUANCE_DATASET_DIGEST_DOMAIN_V1: &str = "marty.issuance/dataset/v1";
pub const ISSUANCE_PREREQUISITE_CONTEXT_V1: &str = "_marty_issuance_prerequisite_v1";
pub const MAX_ISSUANCE_INTENT_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuancePrerequisiteProfileV1 {
    ManagedSdJwtDcqlSameHolderV1,
}

/// Saved, versioned template selection. Flow resolves the exact configured
/// definition and policy revision; callers cannot supply a replacement graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePrerequisitePolicyV1 {
    pub profile: IssuancePrerequisiteProfileV1,
    pub flow_definition_id: String,
    pub flow_definition_version: u32,
    pub policy: FrozenPolicyIdentity,
    pub verifier_issuer_did: String,
    pub ttl_seconds: u32,
}

impl IssuancePrerequisitePolicyV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        identifier(&self.flow_definition_id)?;
        identifier(&self.verifier_issuer_did)?;
        self.policy.validate()?;
        if self.flow_definition_version == 0
            || !(60..=900).contains(&self.ttl_seconds)
            || !self.verifier_issuer_did.starts_with("did:")
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Omission preserves an existing selection; explicit null is never a request
/// to remove a security prerequisite from an existing template.
pub fn optional_policy<'de, D>(
    deserializer: D,
) -> Result<Option<IssuancePrerequisitePolicyV1>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let policy = IssuancePrerequisitePolicyV1::deserialize(deserializer)?;
    policy.validate().map_err(serde::de::Error::custom)?;
    Ok(Some(policy))
}

pub fn parse_optional_policy_json(
    value: &str,
) -> Result<Option<IssuancePrerequisitePolicyV1>, Oid4vpContractError> {
    if value.is_empty() {
        return Ok(None);
    }
    let policy: IssuancePrerequisitePolicyV1 = crate::managed_evidence::parse_strict(value)?;
    policy.validate()?;
    Ok(Some(policy))
}

/// Immutable selection reserved by Issuance before the prerequisite starts.
/// The applicant fields bind the requested target; only the authenticated
/// initiating principal and later native holder proof establish authority.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceIntentBindingV1 {
    pub contract: String,
    pub organization_id: String,
    pub transaction_id: String,
    pub initiating_principal_id: String,
    pub applicant_id: Option<String>,
    pub application_id: Option<String>,
    pub subject_did: Option<String>,
    pub credential_template_id: String,
    pub credential_template_version: u32,
    pub credential_configuration_id: String,
    pub credential_payload_format: String,
    pub issuer_did: String,
    pub dataset_digest: String,
    pub prerequisite: IssuancePrerequisitePolicyV1,
    pub flow_instance_id: String,
    pub created_at_epoch_micros: i64,
    pub expires_at_epoch_micros: i64,
    pub intent_digest: String,
}

impl std::fmt::Debug for IssuanceIntentBindingV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuanceIntentBindingV1")
            .field("contract", &self.contract)
            .field("intent_digest", &self.intent_digest)
            .finish_non_exhaustive()
    }
}

impl IssuanceIntentBindingV1 {
    pub fn from_json(input: &str) -> Result<Self, Oid4vpContractError> {
        if input.len() > MAX_ISSUANCE_INTENT_BYTES {
            return Err(Oid4vpContractError::SizeLimit("issuance_intent"));
        }
        let value: Self = crate::managed_evidence::parse_strict(input)?;
        value.validate()?;
        Ok(value)
    }

    /// Seal correspondence data only. This does not authenticate its creator.
    pub fn seal(mut self) -> Result<Self, Oid4vpContractError> {
        self.intent_digest = self.recompute_digest()?;
        self.validate()?;
        Ok(self)
    }

    pub fn recompute_digest(&self) -> Result<String, Oid4vpContractError> {
        self.validate_body()?;
        let mut value =
            serde_json::to_value(self).map_err(|_| Oid4vpContractError::Serialization)?;
        value
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("intent_digest");
        digest_domain_json(ISSUANCE_INTENT_DIGEST_DOMAIN_V1, &value)
    }

    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        digest(&self.intent_digest)?;
        if self.recompute_digest()? != self.intent_digest {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now_epoch_micros: i64) -> Result<(), Oid4vpContractError> {
        self.validate()?;
        if now_epoch_micros < self.created_at_epoch_micros
            || now_epoch_micros >= self.expires_at_epoch_micros
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_body(&self) -> Result<(), Oid4vpContractError> {
        if self.contract != ISSUANCE_INTENT_CONTRACT_V1
            || self.credential_template_version == 0
            || self.credential_payload_format != "SD_JWT_VC"
            || !self.issuer_did.starts_with("did:")
        {
            return Err(invalid());
        }
        for value in [
            &self.organization_id,
            &self.transaction_id,
            &self.initiating_principal_id,
            &self.credential_template_id,
            &self.credential_configuration_id,
            &self.issuer_did,
            &self.flow_instance_id,
        ] {
            identifier(value)?;
        }
        for value in [&self.applicant_id, &self.application_id, &self.subject_did]
            .into_iter()
            .flatten()
        {
            identifier(value)?;
        }
        // The first accepted route has no application approval continuation.
        if self.application_id.is_some() {
            return Err(invalid());
        }
        self.prerequisite.validate()?;
        digest(&self.dataset_digest)?;
        let maximum = self
            .created_at_epoch_micros
            .checked_add(i64::from(self.prerequisite.ttl_seconds) * 1_000_000)
            .ok_or(Oid4vpContractError::InvalidLifetime)?;
        if self.created_at_epoch_micros <= 0
            || self.expires_at_epoch_micros <= self.created_at_epoch_micros
            || self.expires_at_epoch_micros > maximum
        {
            return Err(Oid4vpContractError::InvalidLifetime);
        }
        if serde_json::to_vec(self)
            .map_err(|_| Oid4vpContractError::Serialization)?
            .len()
            > MAX_ISSUANCE_INTENT_BYTES
        {
            return Err(Oid4vpContractError::SizeLimit("issuance_intent"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePrerequisiteStartRequestV1 {
    pub contract: String,
    pub intent: IssuanceIntentBindingV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePrerequisiteEvidenceRequestV1 {
    pub contract: String,
    pub intent: IssuanceIntentBindingV1,
}

macro_rules! owner_request {
    ($kind:ty, $contract:ident) => {
        impl $kind {
            pub fn from_json(input: &str) -> Result<Self, Oid4vpContractError> {
                let value: Self = crate::managed_evidence::parse_strict(input)?;
                value.validate()?;
                Ok(value)
            }

            pub fn validate(&self) -> Result<(), Oid4vpContractError> {
                if self.contract != $contract {
                    return Err(invalid());
                }
                self.intent.validate()
            }
        }
    };
}
owner_request!(
    IssuancePrerequisiteStartRequestV1,
    ISSUANCE_PREREQUISITE_START_REQUEST_V1
);
owner_request!(
    IssuancePrerequisiteEvidenceRequestV1,
    ISSUANCE_PREREQUISITE_EVIDENCE_REQUEST_V1
);

/// Public initiation projection. It contains no credential or Policy evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePrerequisiteStartResponseV1 {
    pub contract: String,
    pub intent_digest: String,
    pub flow_instance_id: String,
    pub request_uri: String,
    pub qr_data: String,
    pub expires_at_epoch_micros: i64,
}

impl IssuancePrerequisiteStartResponseV1 {
    pub fn from_json(input: &str) -> Result<Self, Oid4vpContractError> {
        crate::managed_evidence::parse_strict(input)
    }

    pub fn validate_for_intent(
        &self,
        intent: &IssuanceIntentBindingV1,
        now_epoch_micros: i64,
    ) -> Result<(), Oid4vpContractError> {
        intent.validate_at(now_epoch_micros)?;
        if self.contract != ISSUANCE_PREREQUISITE_START_RESPONSE_V1
            || self.intent_digest != intent.intent_digest
            || self.flow_instance_id != intent.flow_instance_id
            || self.expires_at_epoch_micros > intent.expires_at_epoch_micros
            || self.expires_at_epoch_micros <= now_epoch_micros
            || self.qr_data.is_empty()
            || self.qr_data.len() > 16_384
            || self.request_uri.len() > 4_096
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        let uri = url::Url::parse(&self.request_uri).map_err(|_| invalid())?;
        if uri.scheme() != "https"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
        {
            return Err(invalid());
        }
        // The wallet launch must select the same signed request as readback.
        // Refuse duplicate or alternative request transports before a UI can
        // present an otherwise valid but unrelated QR payload to the holder.
        let launch = url::Url::parse(&self.qr_data).map_err(|_| invalid())?;
        if launch.scheme() != "openid4vp"
            || launch.host_str() != Some("authorize")
            || !launch.path().is_empty()
            || !launch.username().is_empty()
            || launch.password().is_some()
            || launch.port().is_some()
            || launch.fragment().is_some()
        {
            return Err(invalid());
        }
        let mut parameters = std::collections::BTreeMap::new();
        for (key, value) in launch.query_pairs() {
            if !matches!(
                key.as_ref(),
                "client_id" | "request_uri" | "request_uri_method"
            ) || parameters
                .insert(key.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(invalid());
            }
        }
        if parameters.get("request_uri").map(String::as_str) != Some(self.request_uri.as_str())
            || parameters.get("client_id").is_none_or(|client| {
                client.is_empty() || client.len() > 4_096 || client.chars().any(char::is_control)
            })
            || parameters
                .get("request_uri_method")
                .is_some_and(|method| method != "post")
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        Ok(())
    }
}

/// Private Flow-owner response. Deserializing this type grants no capability;
/// only Issuance's fixed authenticated owner client may admit its contents.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuancePrerequisiteEvidenceResponseV1 {
    pub contract: String,
    pub intent: IssuanceIntentBindingV1,
    pub evidence: ManagedOid4vpEvidenceProjectionV2,
    pub observed_at_epoch_micros: i64,
}

impl std::fmt::Debug for IssuancePrerequisiteEvidenceResponseV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuancePrerequisiteEvidenceResponseV1")
            .field("contract", &self.contract)
            .field("intent_digest", &self.intent.intent_digest)
            .finish_non_exhaustive()
    }
}

impl IssuancePrerequisiteEvidenceResponseV1 {
    pub fn from_json(input: &str) -> Result<Self, Oid4vpContractError> {
        crate::managed_evidence::parse_strict(input)
    }

    /// Checks correspondence and an exclusive live deadline. The caller must
    /// separately establish owner authentication, native holder proof, and
    /// atomic single consumption under the issuance transaction lock.
    pub fn validate_for_intent(
        &self,
        intent: &IssuanceIntentBindingV1,
        now_epoch_micros: i64,
    ) -> Result<(), Oid4vpContractError> {
        intent.validate_at(now_epoch_micros)?;
        self.evidence.validate_historical()?;
        let request = &self.evidence.request;
        let receipt = &self.evidence.receipt;
        let validity = &self.evidence.policy_evidence.validity;
        if self.contract != ISSUANCE_PREREQUISITE_EVIDENCE_RESPONSE_V1
            || self.intent != *intent
            || request.organization_id != intent.organization_id
            || request.flow_instance_id != intent.flow_instance_id
            || request.initiating_principal_id != intent.initiating_principal_id
            || request.policy != intent.prerequisite.policy
            || validity.evaluated_at_epoch_micros < intent.created_at_epoch_micros
            || receipt.nonce_consumed_at_epoch_micros < intent.created_at_epoch_micros
            || self.observed_at_epoch_micros < receipt.nonce_consumed_at_epoch_micros
            || self.observed_at_epoch_micros >= intent.expires_at_epoch_micros
            || self.observed_at_epoch_micros
                > now_epoch_micros.checked_add(5_000_000).ok_or(invalid())?
        {
            return Err(Oid4vpContractError::BindingMismatch);
        }
        validity.validate_at(self.observed_at_epoch_micros)?;
        validity.validate_at(now_epoch_micros)?;
        Ok(())
    }

    pub fn valid_until_epoch_micros(&self) -> i64 {
        self.intent.expires_at_epoch_micros.min(
            self.evidence
                .policy_evidence
                .validity
                .valid_until_epoch_micros,
        )
    }
}

fn identifier(value: &str) -> Result<(), Oid4vpContractError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(())
}

fn digest(value: &str) -> Result<(), Oid4vpContractError> {
    if !value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(Oid4vpContractError::InvalidDigest("issuance_prerequisite"));
    }
    Ok(())
}

fn invalid() -> Oid4vpContractError {
    Oid4vpContractError::InvalidField("issuance_prerequisite")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> IssuanceIntentBindingV1 {
        IssuanceIntentBindingV1 {
            contract: ISSUANCE_INTENT_CONTRACT_V1.into(),
            organization_id: "org-1".into(),
            transaction_id: "transaction-1".into(),
            initiating_principal_id: "user:principal-1".into(),
            applicant_id: Some("applicant-1".into()),
            application_id: None,
            subject_did: None,
            credential_template_id: "template-1".into(),
            credential_template_version: 1,
            credential_configuration_id: "Membership_sd_jwt_vc".into(),
            credential_payload_format: "SD_JWT_VC".into(),
            issuer_did: "did:web:issuer.example".into(),
            dataset_digest: format!("sha256:{}", "a".repeat(64)),
            prerequisite: IssuancePrerequisitePolicyV1 {
                profile: IssuancePrerequisiteProfileV1::ManagedSdJwtDcqlSameHolderV1,
                flow_definition_id: "flow-1".into(),
                flow_definition_version: 1,
                policy: FrozenPolicyIdentity {
                    id: "policy-1".into(),
                    version: 1,
                    content_digest: format!("sha256:{}", "b".repeat(64)),
                },
                verifier_issuer_did: "did:web:verifier.example".into(),
                ttl_seconds: 300,
            },
            flow_instance_id: "instance-1".into(),
            created_at_epoch_micros: 1_800_000_000_000_000,
            expires_at_epoch_micros: 1_800_000_300_000_000,
            intent_digest: String::new(),
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn entire_issuance_selection_is_bound() {
        let original = intent();
        let changes: &[fn(&mut IssuanceIntentBindingV1)] = &[
            |v| v.organization_id.push('x'),
            |v| v.transaction_id.push('x'),
            |v| v.initiating_principal_id.push('x'),
            |v| v.applicant_id = None,
            |v| v.subject_did = Some("did:example:substitute".into()),
            |v| v.credential_template_id.push('x'),
            |v| v.credential_template_version += 1,
            |v| v.credential_configuration_id.push('x'),
            |v| v.issuer_did.push('x'),
            |v| v.dataset_digest = format!("sha256:{}", "c".repeat(64)),
            |v| v.prerequisite.policy.version += 1,
            |v| v.prerequisite.flow_definition_version += 1,
            |v| v.flow_instance_id.push('x'),
            |v| v.expires_at_epoch_micros -= 1,
        ];
        for change in changes {
            let mut changed = original.clone();
            change(&mut changed);
            assert!(changed.validate().is_err());
        }
    }

    #[test]
    fn lifetime_is_bounded_and_exclusive() {
        let value = intent();
        assert!(value.validate_at(value.created_at_epoch_micros).is_ok());
        assert!(value.validate_at(value.expires_at_epoch_micros - 1).is_ok());
        assert!(value.validate_at(value.expires_at_epoch_micros).is_err());
        assert!(value
            .validate_at(value.created_at_epoch_micros - 1)
            .is_err());
        let mut extended = value;
        extended.expires_at_epoch_micros += 1;
        assert!(extended.seal().is_err());
    }

    #[test]
    fn strict_json_rejects_duplicate_nested_policy_and_unknown_fields() {
        let value = serde_json::to_string(&intent()).unwrap();
        assert!(IssuanceIntentBindingV1::from_json(&value).is_ok());
        let duplicate = value.replace(
            "\"ttl_seconds\":300",
            "\"ttl_seconds\":300,\"ttl_seconds\":300",
        );
        assert!(IssuanceIntentBindingV1::from_json(&duplicate).is_err());
        let unknown = value.replacen('{', "{\"evidence\":{},", 1);
        assert!(IssuanceIntentBindingV1::from_json(&unknown).is_err());
    }

    #[test]
    fn unsupported_routes_and_unbounded_configuration_are_rejected() {
        let mut value = intent();
        value.application_id = Some("approval-1".into());
        assert!(value.seal().is_err());
        for ttl in [0, 59, 901, u32::MAX] {
            let mut policy = intent().prerequisite;
            policy.ttl_seconds = ttl;
            assert!(policy.validate().is_err());
        }
        let mut value = intent();
        value.credential_payload_format = "MDOC".into();
        assert!(value.seal().is_err());
    }

    #[test]
    fn debug_does_not_disclose_applicant_or_dataset() {
        let value = intent();
        let debug = format!("{value:?}");
        assert!(!debug.contains("applicant-1"));
        assert!(!debug.contains(&value.dataset_digest));
    }

    #[test]
    fn wallet_launch_selects_exactly_the_bound_request_uri() {
        let intent = intent();
        let request_uri = "https://flow.example/v1/flows/instances/instance-1/request";
        let mut launch = url::Url::parse("openid4vp://authorize").unwrap();
        launch
            .query_pairs_mut()
            .append_pair("client_id", "x509_san_dns:flow.example")
            .append_pair("request_uri", request_uri);
        let response = IssuancePrerequisiteStartResponseV1 {
            contract: ISSUANCE_PREREQUISITE_START_RESPONSE_V1.into(),
            intent_digest: intent.intent_digest.clone(),
            flow_instance_id: intent.flow_instance_id.clone(),
            request_uri: request_uri.into(),
            qr_data: launch.to_string(),
            expires_at_epoch_micros: intent.expires_at_epoch_micros,
        };
        assert!(response
            .validate_for_intent(&intent, intent.created_at_epoch_micros)
            .is_ok());
        for bad in [
            response.qr_data.replace("instance-1", "another-instance"),
            format!("{}&request_uri={request_uri}", response.qr_data),
            format!("{}&request=unrelated-token", response.qr_data),
            format!("{}#unrelated", response.qr_data),
            response.qr_data.replace("openid4vp:", "https:"),
        ] {
            let changed = IssuancePrerequisiteStartResponseV1 {
                qr_data: bad,
                ..response.clone()
            };
            assert!(changed
                .validate_for_intent(&intent, intent.created_at_epoch_micros)
                .is_err());
        }
    }
}
