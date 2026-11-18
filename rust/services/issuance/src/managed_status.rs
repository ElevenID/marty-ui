//! Fresh observations of this service's own persisted SD-JWT lifecycle state.
//!
//! The caller separately authenticates the presentation. This owner matches the
//! exact issuer-signed artifact stored by issuance; it does not verify a remote
//! status list or promise that a lifecycle record cannot change after the read.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use marty_oid4vp_contract::{
    managed_status::{
        digest_managed_status_observation, digest_sd_jwt_issuer_jws,
        ManagedCredentialStatusObservationV1, ManagedCredentialStatusRequestV1,
        ManagedCredentialStatusState, MANAGED_STATUS_AUTHORITY, MANAGED_STATUS_CONTRACT,
    },
    MAX_TOKEN_BYTES,
};
use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::credential_management::ManagedCredentialStatus;

/// One tenant-scoped database snapshot. Credential bytes never leave this owner.
#[derive(Clone, PartialEq)]
pub struct ManagedSdJwtStatusRecord {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub issuer_did: Option<String>,
    pub credential_jwt: String,
    pub status: ManagedCredentialStatus,
    pub revoked: bool,
    pub status_updated_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
}

impl std::fmt::Debug for ManagedSdJwtStatusRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedSdJwtStatusRecord")
            .field("status", &self.status)
            .field("contents", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ManagedStatusError {
    #[error("Invalid managed credential status request")]
    InvalidRequest,
    #[error("Managed credential was not found")]
    NotFound,
    #[error("Stored credential does not support this status observation")]
    UnsupportedRecord,
    #[error("Managed credential status is temporarily unavailable")]
    Unavailable,
}

/// Construct only after the repository returns its one authoritative snapshot.
pub(crate) fn observe_record(
    request: &ManagedCredentialStatusRequestV1,
    record: &ManagedSdJwtStatusRecord,
    now: DateTime<Utc>,
) -> Result<ManagedCredentialStatusObservationV1, ManagedStatusError> {
    request
        .validate()
        .map_err(|_| ManagedStatusError::InvalidRequest)?;
    if record.organization_id != request.organization_id || record.id != request.credential_id {
        return Err(ManagedStatusError::NotFound);
    }
    let unsupported = || ManagedStatusError::UnsupportedRecord;
    if record.issuer_did.as_deref() != Some(request.issuer_id.as_str())
        || record.credential_template_id != request.credential_template_id
        || record.revoked != (record.status == ManagedCredentialStatus::Revoked)
        || record.observed_at > now
        || record.status_updated_at > record.observed_at
        || record.issued_at > record.observed_at
        || record.credential_jwt.len() > MAX_TOKEN_BYTES
        || !record.credential_jwt.ends_with('~')
        || digest_sd_jwt_issuer_jws(&record.credential_jwt).map_err(|_| unsupported())?
            != request.issuer_jwt_digest
    {
        return Err(unsupported());
    }
    let mut segments = record.credential_jwt.split('~');
    let issuer_jwt = segments.next().ok_or_else(unsupported)?;
    // Issuance stores an issuer credential, not a presentation with a KB-JWT.
    // A disclosure is a base64url JSON array; empty interior segments are invalid.
    let mut suffix = segments.peekable();
    while let Some(disclosure) = suffix.next() {
        if suffix.peek().is_none() && disclosure.is_empty() {
            break;
        }
        let bytes = canonical_segment(disclosure)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| unsupported())?;
        let values = value.as_array().ok_or_else(unsupported)?;
        if !(2..=3).contains(&values.len())
            || values[0].as_str().is_none_or(str::is_empty)
            || (values.len() == 3 && values[1].as_str().is_none_or(str::is_empty))
        {
            return Err(unsupported());
        }
    }
    let mut parts = issuer_jwt.split('.');
    let header = unique_object(parts.next().ok_or_else(unsupported)?)?;
    let payload = unique_object(parts.next().ok_or_else(unsupported)?)?;
    let signature = canonical_segment(parts.next().ok_or_else(unsupported)?)?;
    if parts.next().is_some()
        || header.get("typ").and_then(Value::as_str) != Some("dc+sd-jwt")
        || !matches!(
            header.get("alg").and_then(Value::as_str),
            Some("ES256" | "EdDSA")
        )
        || signature.len() != 64
        || payload.get("iss").and_then(Value::as_str) != Some(request.issuer_id.as_str())
        || payload.get("jti").and_then(Value::as_str) != Some(request.credential_id.as_str())
        || payload
            .get("vct")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(unsupported());
    }
    let signed_issued_at = payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(unsupported)?;
    let signed_expires_at = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(unsupported)?;
    let checked_at = record.observed_at.timestamp();
    let record_expires_at = record.expires_at.ok_or_else(unsupported)?.timestamp();
    let expires_at = signed_expires_at.min(record_expires_at);
    if signed_issued_at < 0
        || signed_issued_at > checked_at
        || signed_expires_at <= signed_issued_at
        || expires_at <= now.timestamp()
        || payload.get("nbf").is_some_and(|value| {
            value
                .as_i64()
                .is_none_or(|not_before| not_before < 0 || not_before > checked_at)
        })
    {
        return Err(unsupported());
    }
    let deadline = checked_at
        .checked_add(i64::from(request.max_age_seconds))
        .ok_or_else(unsupported)?
        .min(expires_at);
    let mut observation = ManagedCredentialStatusObservationV1 {
        contract: MANAGED_STATUS_CONTRACT.into(),
        authority: MANAGED_STATUS_AUTHORITY.into(),
        request: request.clone(),
        state: match record.status {
            ManagedCredentialStatus::Active => ManagedCredentialStatusState::Active,
            ManagedCredentialStatus::Suspended => ManagedCredentialStatusState::Suspended,
            ManagedCredentialStatus::Revoked => ManagedCredentialStatusState::Revoked,
        },
        status_updated_at_epoch_seconds: record.status_updated_at.timestamp(),
        checked_at_epoch_seconds: checked_at,
        valid_until_epoch_seconds: deadline,
        credential_expires_at_epoch_seconds: expires_at,
        evidence_digest: String::new(),
    };
    observation.evidence_digest =
        digest_managed_status_observation(&observation).map_err(|_| unsupported())?;
    observation
        .validate_for_request(request, now.timestamp())
        .map_err(|_| unsupported())?;
    Ok(observation)
}

fn canonical_segment(segment: &str) -> Result<Vec<u8>, ManagedStatusError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| ManagedStatusError::UnsupportedRecord)?;
    if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != segment {
        return Err(ManagedStatusError::UnsupportedRecord);
    }
    Ok(bytes)
}

fn unique_object(segment: &str) -> Result<Map<String, Value>, ManagedStatusError> {
    struct UniqueObject(Map<String, Value>);
    impl<'de> Deserialize<'de> for UniqueObject {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> de::Visitor<'de> for Visitor {
                type Value = UniqueObject;
                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("a JSON object with unique member names")
                }
                fn visit_map<A: de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut values = Map::new();
                    while let Some((key, value)) = map.next_entry::<String, Value>()? {
                        if values.insert(key, value).is_some() {
                            return Err(de::Error::custom("duplicate issuer member"));
                        }
                    }
                    Ok(UniqueObject(values))
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    let bytes = canonical_segment(segment)?;
    serde_json::from_slice::<UniqueObject>(&bytes)
        .map(|value| value.0)
        .map_err(|_| ManagedStatusError::UnsupportedRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn time(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    // This owner never authenticates presentations: these bytes model the trusted
    // persisted artifact, while the consumer's native verifier supplies its digest.
    fn artifact(header: &Value, payload: &Value) -> String {
        format!(
            "{}.{}.{}~",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap()),
            URL_SAFE_NO_PAD.encode([0_u8; 64]),
        )
    }

    fn claims() -> Value {
        json!({
            "iss": "did:web:issuer.example",
            "jti": "urn:uuid:owned-credential",
            "vct": "EmployeeCredential",
            "iat": NOW - 10,
            "exp": NOW + 600,
        })
    }

    fn fixture() -> (ManagedCredentialStatusRequestV1, ManagedSdJwtStatusRecord) {
        let credential = artifact(&json!({"typ": "dc+sd-jwt", "alg": "EdDSA"}), &claims());
        let request = ManagedCredentialStatusRequestV1 {
            organization_id: "org-a".into(),
            issuer_id: "did:web:issuer.example".into(),
            credential_id: "urn:uuid:owned-credential".into(),
            credential_template_id: "template-a".into(),
            issuer_jwt_digest: digest_sd_jwt_issuer_jws(&credential).unwrap(),
            request_binding_digest: format!("sha256:{}", "a".repeat(64)),
            max_age_seconds: 30,
        };
        let record = ManagedSdJwtStatusRecord {
            id: request.credential_id.clone(),
            organization_id: request.organization_id.clone(),
            credential_template_id: request.credential_template_id.clone(),
            issuer_did: Some(request.issuer_id.clone()),
            credential_jwt: credential,
            status: ManagedCredentialStatus::Active,
            revoked: false,
            status_updated_at: time(NOW - 5),
            issued_at: time(NOW - 10),
            expires_at: Some(time(NOW + 600)),
            observed_at: time(NOW),
        };
        (request, record)
    }

    #[test]
    fn owner_observation_binds_exact_request_and_preserves_negative_lifecycle_states() {
        let (request, mut record) = fixture();
        for (stored, observed) in [
            (
                ManagedCredentialStatus::Active,
                ManagedCredentialStatusState::Active,
            ),
            (
                ManagedCredentialStatus::Suspended,
                ManagedCredentialStatusState::Suspended,
            ),
            (
                ManagedCredentialStatus::Revoked,
                ManagedCredentialStatusState::Revoked,
            ),
        ] {
            record.status = stored;
            record.revoked = stored == ManagedCredentialStatus::Revoked;
            let observation = observe_record(&request, &record, time(NOW + 5)).unwrap();
            assert_eq!(observation.request, request);
            assert_eq!(observation.state, observed);
            assert_eq!(observation.checked_at_epoch_seconds, NOW);
            assert_eq!(observation.valid_until_epoch_seconds, NOW + 30);
            observation.validate_for_request(&request, NOW + 5).unwrap();
            let response = serde_json::to_string(&observation).unwrap();
            assert!(!response.contains(&record.credential_jwt));
            assert!(!response.contains("credential_jwt"));
        }
        assert!(!format!("{record:?}").contains(&record.credential_jwt));
        assert!(!format!("{record:?}").contains(&record.id));
    }

    #[test]
    fn owner_observation_rejects_cross_tenant_artifact_and_record_bindings() {
        let (request, record) = fixture();
        for field in [
            "organization",
            "credential",
            "issuer",
            "template",
            "artifact",
            "revoked",
        ] {
            let mut changed = record.clone();
            match field {
                "organization" => changed.organization_id = "foreign-org".into(),
                "credential" => changed.id = "foreign-credential".into(),
                "issuer" => changed.issuer_did = Some("did:web:other.example".into()),
                "template" => changed.credential_template_id = "foreign-template".into(),
                "artifact" => {
                    changed.credential_jwt =
                        artifact(&json!({"typ": "dc+sd-jwt", "alg": "ES256"}), &claims())
                }
                "revoked" => changed.revoked = true,
                _ => unreachable!(),
            }
            let expected = if matches!(field, "organization" | "credential") {
                ManagedStatusError::NotFound
            } else {
                ManagedStatusError::UnsupportedRecord
            };
            assert_eq!(
                observe_record(&request, &changed, time(NOW)),
                Err(expected),
                "{field}"
            );
        }
        let mut invalid = request;
        invalid.max_age_seconds = 61;
        assert_eq!(
            observe_record(&invalid, &record, time(NOW)),
            Err(ManagedStatusError::InvalidRequest)
        );
    }

    #[test]
    fn observation_deadline_is_capped_by_signed_and_stored_expiry() {
        let (mut request, mut record) = fixture();
        record.expires_at = Some(time(NOW + 7));
        let observation = observe_record(&request, &record, time(NOW + 5)).unwrap();
        assert_eq!(observation.valid_until_epoch_seconds, NOW + 7);
        assert_eq!(observation.credential_expires_at_epoch_seconds, NOW + 7);
        assert_eq!(
            observe_record(&request, &record, time(NOW + 7)),
            Err(ManagedStatusError::UnsupportedRecord)
        );

        let mut payload = claims();
        payload["exp"] = json!(NOW + 9);
        record.credential_jwt = artifact(&json!({"typ":"dc+sd-jwt", "alg":"ES256"}), &payload);
        request.issuer_jwt_digest = digest_sd_jwt_issuer_jws(&record.credential_jwt).unwrap();
        record.expires_at = Some(time(NOW + 600));
        let observation = observe_record(&request, &record, time(NOW + 5)).unwrap();
        assert_eq!(observation.valid_until_epoch_seconds, NOW + 9);
        assert_eq!(observation.credential_expires_at_epoch_seconds, NOW + 9);
        assert!(observe_record(&request, &record, time(NOW + 9)).is_err());
        record.expires_at = None;
        assert!(observe_record(&request, &record, time(NOW)).is_err());
    }

    #[test]
    fn owner_clock_rejects_future_reads_inconsistent_updates_and_stale_observations() {
        let (request, record) = fixture();
        assert!(observe_record(&request, &record, time(NOW - 1)).is_err());
        assert!(observe_record(&request, &record, time(NOW + 29)).is_ok());
        assert!(observe_record(&request, &record, time(NOW + 30)).is_err());
        for field in ["updated", "issued"] {
            let mut changed = record.clone();
            match field {
                "updated" => {
                    changed.status_updated_at = record.observed_at + Duration::nanoseconds(1)
                }
                "issued" => changed.issued_at = record.observed_at + Duration::nanoseconds(1),
                _ => unreachable!(),
            }
            assert!(
                observe_record(&request, &changed, time(NOW + 1)).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn persisted_artifact_metadata_must_match_even_when_request_digest_matches() {
        let (request, record) = fixture();
        let header = json!({"typ": "dc+sd-jwt", "alg": "EdDSA"});
        for (field, value) in [
            ("iss", json!("did:web:foreign.example")),
            ("jti", json!("foreign-credential")),
            ("vct", json!("")),
            ("iat", json!(NOW + 1)),
            ("iat", Value::Null),
            ("exp", json!(NOW)),
            ("exp", Value::Null),
            ("nbf", json!(NOW + 1)),
        ] {
            let mut payload = claims();
            payload[field] = value;
            let mut changed = record.clone();
            changed.credential_jwt = artifact(&header, &payload);
            let mut matching = request.clone();
            matching.issuer_jwt_digest = digest_sd_jwt_issuer_jws(&changed.credential_jwt).unwrap();
            assert!(
                observe_record(&matching, &changed, time(NOW)).is_err(),
                "{field}"
            );
        }
        for header in [
            json!({"alg": "EdDSA"}),
            json!({"typ": "JWT", "alg": "EdDSA"}),
            json!({"typ": "dc+sd-jwt", "alg": "none"}),
        ] {
            let mut changed = record.clone();
            changed.credential_jwt = artifact(&header, &claims());
            let mut matching = request.clone();
            matching.issuer_jwt_digest = digest_sd_jwt_issuer_jws(&changed.credential_jwt).unwrap();
            assert!(observe_record(&matching, &changed, time(NOW)).is_err());
        }
    }

    #[test]
    fn only_structural_issuer_sd_jwt_records_are_observable() {
        let (request, record) = fixture();
        let disclosure = URL_SAFE_NO_PAD.encode(br#"["salt","email","ada@example.test"]"#);
        let mut with_disclosure = record.clone();
        with_disclosure
            .credential_jwt
            .push_str(&format!("{disclosure}~"));
        assert!(observe_record(&request, &with_disclosure, time(NOW)).is_ok());
        for suffix in [
            "",
            "~~",
            "~holder.proof.signature",
            "~bm90LWpzb24~",
            "~W10~",
        ] {
            let mut changed = record.clone();
            changed.credential_jwt =
                format!("{}{}", record.credential_jwt.trim_end_matches('~'), suffix);
            assert!(
                observe_record(&request, &changed, time(NOW)).is_err(),
                "{suffix}"
            );
        }
        let mut duplicate = record;
        duplicate.credential_jwt = format!(
            "{}.{}.{}~",
            URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","typ":"dc+sd-jwt","alg":"EdDSA"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims()).unwrap()),
            URL_SAFE_NO_PAD.encode([0_u8; 64]),
        );
        let mut matching = request;
        matching.issuer_jwt_digest = digest_sd_jwt_issuer_jws(&duplicate.credential_jwt).unwrap();
        assert!(observe_record(&matching, &duplicate, time(NOW)).is_err());
    }
}
