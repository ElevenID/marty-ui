//! Read-only observations of an Issuance-owned SD-JWT lifecycle record.
//!
//! These are wire values, not authenticated presentation evidence. Consumers
//! must authenticate their configured authority channel and match the complete
//! request to a natively verified credential before accepting an observation.
//! This mode does not verify an external status list or promise that a record
//! cannot change before the observation's freshness deadline.

use serde::{Deserialize, Serialize};

use crate::{digest_domain_json, Oid4vpContractError, MAX_TOKEN_BYTES};

pub const MANAGED_STATUS_OBSERVATION_PATH: &str = "/internal/issuance/sd-jwt-status/observe";
pub const MANAGED_STATUS_CONTRACT: &str = "marty.issuance-managed-status/v1";
pub const MANAGED_STATUS_AUTHORITY: &str = "issuance_internal_status_record";
pub const MAX_MANAGED_STATUS_AGE_SECONDS: u32 = 60;
pub const MANAGED_STATUS_ISSUER_JWS_DOMAIN: &str = "marty.issuance/managed-sd-jwt-issuer-jws/v1";
pub const MANAGED_STATUS_OBSERVATION_DOMAIN: &str = "marty.issuance/managed-status-observation/v1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialStatusRequestV1 {
    pub organization_id: String,
    pub issuer_id: String,
    pub credential_id: String,
    pub credential_template_id: String,
    pub issuer_jwt_digest: String,
    pub request_binding_digest: String,
    pub max_age_seconds: u32,
}

impl std::fmt::Debug for ManagedCredentialStatusRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedCredentialStatusRequestV1")
            .field("request_binding_digest", &self.request_binding_digest)
            .field("issuer_jwt_digest", &self.issuer_jwt_digest)
            .finish_non_exhaustive()
    }
}

impl ManagedCredentialStatusRequestV1 {
    pub fn validate(&self) -> Result<(), Oid4vpContractError> {
        if !bounded_text(&self.organization_id, 255)
            || !bounded_text(&self.issuer_id, 2048)
            || !bounded_text(&self.credential_id, 2048)
            || !bounded_text(&self.credential_template_id, 255)
            || !digest(&self.issuer_jwt_digest)
            || !digest(&self.request_binding_digest)
            || !(1..=MAX_MANAGED_STATUS_AGE_SECONDS).contains(&self.max_age_seconds)
        {
            return Err(invalid("managed_status.request"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCredentialStatusState {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialStatusObservationV1 {
    pub contract: String,
    pub authority: String,
    pub request: ManagedCredentialStatusRequestV1,
    pub state: ManagedCredentialStatusState,
    pub status_updated_at_epoch_seconds: i64,
    pub checked_at_epoch_seconds: i64,
    pub valid_until_epoch_seconds: i64,
    pub credential_expires_at_epoch_seconds: i64,
    pub evidence_digest: String,
}

impl ManagedCredentialStatusObservationV1 {
    /// Validate wire integrity, exact scope, and a live observation window.
    /// The digest is not a signature or a substitute for the authority channel.
    pub fn validate_for_request(
        &self,
        request: &ManagedCredentialStatusRequestV1,
        now: i64,
    ) -> Result<(), Oid4vpContractError> {
        request.validate()?;
        let maximum_deadline = self
            .checked_at_epoch_seconds
            .checked_add(i64::from(request.max_age_seconds))
            .ok_or_else(|| invalid("managed_status.valid_until"))?;
        if self.contract != MANAGED_STATUS_CONTRACT
            || self.authority != MANAGED_STATUS_AUTHORITY
            || &self.request != request
            || self.status_updated_at_epoch_seconds < 0
            || self.checked_at_epoch_seconds <= 0
            || self.status_updated_at_epoch_seconds > self.checked_at_epoch_seconds
            || self.checked_at_epoch_seconds > now
            || self.valid_until_epoch_seconds <= now
            || self.valid_until_epoch_seconds > maximum_deadline
            || self.valid_until_epoch_seconds > self.credential_expires_at_epoch_seconds
            || !digest(&self.evidence_digest)
            || self.evidence_digest != digest_managed_status_observation(self)?
        {
            return Err(invalid("managed_status.observation"));
        }
        Ok(())
    }
}

/// Digest the exact issuer compact JWS, independently of selectively disclosed
/// claims and the wallet's KB-JWT. Accept either that JWS alone or an SD-JWT
/// serialization beginning with it. This helper does not verify a signature.
pub fn digest_sd_jwt_issuer_jws(value: &str) -> Result<String, Oid4vpContractError> {
    if value.len() > MAX_TOKEN_BYTES {
        return Err(invalid("managed_status.issuer_jws"));
    }
    let issuer = value.split('~').next().unwrap_or_default();
    let parts = issuer.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(invalid("managed_status.issuer_jws"));
    }
    digest_domain_json(MANAGED_STATUS_ISSUER_JWS_DOMAIN, issuer)
}

pub fn digest_managed_status_observation(
    observation: &ManagedCredentialStatusObservationV1,
) -> Result<String, Oid4vpContractError> {
    #[derive(Serialize)]
    struct DigestValue<'a> {
        contract: &'a str,
        authority: &'a str,
        request: &'a ManagedCredentialStatusRequestV1,
        state: ManagedCredentialStatusState,
        status_updated_at_epoch_seconds: i64,
        checked_at_epoch_seconds: i64,
        valid_until_epoch_seconds: i64,
        credential_expires_at_epoch_seconds: i64,
    }
    digest_domain_json(
        MANAGED_STATUS_OBSERVATION_DOMAIN,
        &DigestValue {
            contract: &observation.contract,
            authority: &observation.authority,
            request: &observation.request,
            state: observation.state,
            status_updated_at_epoch_seconds: observation.status_updated_at_epoch_seconds,
            checked_at_epoch_seconds: observation.checked_at_epoch_seconds,
            valid_until_epoch_seconds: observation.valid_until_epoch_seconds,
            credential_expires_at_epoch_seconds: observation.credential_expires_at_epoch_seconds,
        },
    )
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn invalid(field: &'static str) -> Oid4vpContractError {
    Oid4vpContractError::InvalidField(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ManagedCredentialStatusRequestV1 {
        ManagedCredentialStatusRequestV1 {
            organization_id: "org-a".into(),
            issuer_id: "did:web:issuer.example".into(),
            credential_id: "urn:uuid:owned-credential".into(),
            credential_template_id: "template-a".into(),
            issuer_jwt_digest: digest_sd_jwt_issuer_jws("header.payload.signature~").unwrap(),
            request_binding_digest: format!("sha256:{}", "a".repeat(64)),
            max_age_seconds: 30,
        }
    }

    fn observation() -> ManagedCredentialStatusObservationV1 {
        let mut observation = ManagedCredentialStatusObservationV1 {
            contract: MANAGED_STATUS_CONTRACT.into(),
            authority: MANAGED_STATUS_AUTHORITY.into(),
            request: request(),
            state: ManagedCredentialStatusState::Active,
            status_updated_at_epoch_seconds: 900,
            checked_at_epoch_seconds: 1000,
            valid_until_epoch_seconds: 1030,
            credential_expires_at_epoch_seconds: 2000,
            evidence_digest: String::new(),
        };
        observation.evidence_digest = digest_managed_status_observation(&observation).unwrap();
        observation
    }

    #[test]
    fn issuer_artifact_digest_is_independent_of_disclosures_and_holder_proof() {
        let issuer = "header.payload.signature";
        let expected = digest_sd_jwt_issuer_jws(issuer).unwrap();
        for token in [
            format!("{issuer}~"),
            format!("{issuer}~disclosure-one~holder.proof.signature"),
            format!("{issuer}~different-disclosure~another.holder.proof"),
        ] {
            assert_eq!(digest_sd_jwt_issuer_jws(&token).unwrap(), expected);
        }
        assert_ne!(
            digest_sd_jwt_issuer_jws("header.other-payload.signature~").unwrap(),
            expected,
        );
        for malformed in ["", "a.b", "a..c", "a.b.c.d", "a.b.c=", "a.b.c\n"] {
            assert!(digest_sd_jwt_issuer_jws(malformed).is_err());
        }
    }

    #[test]
    fn exact_request_digest_and_freshness_are_all_required() {
        let observation = observation();
        observation.validate_for_request(&request(), 1005).unwrap();
        let mut foreign = request();
        foreign.organization_id = "other-tenant".into();
        assert!(observation.validate_for_request(&foreign, 1005).is_err());
        assert!(observation.validate_for_request(&request(), 999).is_err());
        assert!(observation.validate_for_request(&request(), 1030).is_err());
        let mut tampered = observation.clone();
        tampered.state = ManagedCredentialStatusState::Revoked;
        assert!(tampered.validate_for_request(&request(), 1005).is_err());
        tampered.evidence_digest = digest_managed_status_observation(&tampered).unwrap();
        tampered.validate_for_request(&request(), 1005).unwrap();
        tampered.valid_until_epoch_seconds = 2001;
        tampered.evidence_digest = digest_managed_status_observation(&tampered).unwrap();
        assert!(tampered.validate_for_request(&request(), 1005).is_err());
    }

    #[test]
    fn status_wire_shapes_reject_unknown_fields_and_unbounded_age() {
        let mut value = serde_json::to_value(request()).unwrap();
        value["unchecked"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ManagedCredentialStatusRequestV1>(value).is_err());
        let mut value = serde_json::to_value(observation()).unwrap();
        value["unchecked"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ManagedCredentialStatusObservationV1>(value).is_err());
        for age in [0, MAX_MANAGED_STATUS_AGE_SECONDS + 1, u32::MAX] {
            let mut request = request();
            request.max_age_seconds = age;
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn observation_cannot_cross_any_native_request_binding() {
        let observation = observation();
        for field in [
            "organization_id",
            "issuer_id",
            "credential_id",
            "credential_template_id",
            "issuer_jwt_digest",
            "request_binding_digest",
            "max_age_seconds",
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value[field] = if field == "max_age_seconds" {
                serde_json::json!(31)
            } else if field.ends_with("digest") {
                serde_json::json!(format!("sha256:{}", "b".repeat(64)))
            } else {
                serde_json::json!("another-scope")
            };
            let crossed: ManagedCredentialStatusRequestV1 = serde_json::from_value(value).unwrap();
            crossed.validate().unwrap();
            assert!(
                observation.validate_for_request(&crossed, 1005).is_err(),
                "{field}"
            );

            let mut substituted = observation.clone();
            substituted.request = crossed;
            substituted.evidence_digest = digest_managed_status_observation(&substituted).unwrap();
            assert!(
                substituted.validate_for_request(&request(), 1005).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn even_digest_consistent_observations_require_a_valid_clock_window() {
        for (updated, checked, deadline, expires) in [
            (-1, 1000, 1030, 2000),
            (1001, 1000, 1030, 2000),
            (900, 1006, 1030, 2000),
            (900, 1000, 1005, 2000),
            (900, 1000, 1031, 2000),
            (900, 1000, 1030, 1029),
            (900, i64::MAX, i64::MAX, i64::MAX),
        ] {
            let mut observation = observation();
            observation.status_updated_at_epoch_seconds = updated;
            observation.checked_at_epoch_seconds = checked;
            observation.valid_until_epoch_seconds = deadline;
            observation.credential_expires_at_epoch_seconds = expires;
            observation.evidence_digest = digest_managed_status_observation(&observation).unwrap();
            assert!(observation.validate_for_request(&request(), 1005).is_err());
        }
    }
}
