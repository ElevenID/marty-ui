//! Ingestion of client-reported offline verification events, not a second verifier.
//!
//! The native wire model is pinned in the contract fixture. This module owns the
//! allowlist once, before both hashing and persistence. It deliberately accepts
//! no caller-supplied tenant/device authority, credential, claim, or biometric score.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const CONTRACT: &str = "offline-verification-ingest.v1";
pub const RECEIPT_KIND: &str = "offline-verification-receipt.v1";
pub const EVENT_TYPE: &str = "offline_verification.reported";
pub const PERMISSION: &str = "audit:ingest";
pub const SCOPE: &str = "audit:write";
pub const MAX_BATCH: usize = 100;
pub const MAX_BODY_BYTES: usize = 131_072;

#[derive(Debug, thiserror::Error)]
pub enum OfflineAuditError {
    #[error("OFFLINE_AUDIT.AUTHENTICATION_REQUIRED")]
    Unauthorized,
    #[error("OFFLINE_AUDIT.SCOPE_REQUIRED")]
    Forbidden,
    #[error("OFFLINE_AUDIT.INVALID_EVENT")]
    InvalidEvent,
    #[error("OFFLINE_AUDIT.EVENT_ID_CONFLICT")]
    Conflict,
    #[error("OFFLINE_AUDIT.RECEIPT_NOT_FOUND")]
    NotFound,
    #[error("OFFLINE_AUDIT.PERSISTENCE_UNAVAILABLE")]
    Persistence,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuditBatch {
    pub events: Vec<OfflineVerificationEvent>,
}

/// The privacy-minimized `marty-reporting` verification variant. Unknown fields
/// are rejected instead of silently removing personal data after accepting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineVerificationEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub payload: OfflineVerificationPayload,
    pub device_id: Option<String>,
    pub hardware_tier: Option<String>,
    pub org_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineVerificationPayload {
    #[serde(rename = "type")]
    pub payload_type: String,
    pub verification_id: Uuid,
    pub credential_type: String,
    pub result: String,
    pub jurisdiction: Option<String>,
    pub trust_chain_type: Option<String>,
    pub offline_verified: bool,
    pub processing_time_ms: Option<u64>,
    pub biometric_verified: Option<bool>,
    // A unit value permits the native null field while rejecting every score.
    pub biometric_score: Option<()>,
}

#[derive(Debug, Clone)]
pub struct ValidatedOfflineEvent {
    pub(crate) event: OfflineVerificationEvent,
    pub(crate) payload_sha256: String,
}

impl OfflineAuditBatch {
    pub fn validate(
        self,
        now: DateTime<Utc>,
    ) -> Result<Vec<ValidatedOfflineEvent>, OfflineAuditError> {
        if self.events.is_empty() || self.events.len() > MAX_BATCH {
            return Err(OfflineAuditError::InvalidEvent);
        }
        let mut event_ids = BTreeSet::new();
        let mut verification_ids = BTreeSet::new();
        self.events
            .into_iter()
            .map(|event| {
                if !event_ids.insert(event.event_id)
                    || !verification_ids.insert(event.payload.verification_id)
                {
                    return Err(OfflineAuditError::Conflict);
                }
                event.validate(now)
            })
            .collect()
    }
}

impl OfflineVerificationEvent {
    pub fn validate(self, now: DateTime<Utc>) -> Result<ValidatedOfflineEvent, OfflineAuditError> {
        let payload = &self.payload;
        if self.event_id.get_version_num() != 4
            || payload.verification_id.get_version_num() != 4
            || self.event_id.get_variant() != uuid::Variant::RFC4122
            || payload.verification_id.get_variant() != uuid::Variant::RFC4122
            || self.event_type != "verification"
            || payload.payload_type != "verification"
            || !payload.offline_verified
            || !matches!(
                payload.credential_type.as_str(),
                "mdl" | "emrtd" | "oid4vp" | "sd-jwt" | "dtc" | "open-badge"
            )
            || !matches!(
                payload.result.as_str(),
                "valid" | "invalid" | "failed" | "expired" | "revoked" | "pending"
            )
            || self.timestamp > now + Duration::minutes(5)
            || self.device_id.is_some()
            || self.org_id.is_some()
            || self.hardware_tier.is_some()
            || payload.biometric_score.is_some()
            || payload
                .processing_time_ms
                .is_some_and(|value| value > 86_400_000)
            || payload.jurisdiction.as_deref().is_some_and(|value| {
                !(2..=3).contains(&value.len()) || !value.bytes().all(|c| c.is_ascii_uppercase())
            })
            || payload
                .trust_chain_type
                .as_deref()
                .is_some_and(|value| !matches!(value, "x509" | "did" | "iaca" | "csca" | "unknown"))
        {
            return Err(OfflineAuditError::InvalidEvent);
        }
        let encoded = serde_json::to_vec(&self).map_err(|_| OfflineAuditError::InvalidEvent)?;
        Ok(ValidatedOfflineEvent {
            event: self,
            payload_sha256: format!("{:x}", Sha256::digest(encoded)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAuditReceipt {
    pub kind: String,
    pub audit_event_id: Uuid,
    pub organization_id: Uuid,
    /// The authenticated API-key ID; this is not physical-device attestation.
    pub producer_id: Uuid,
    pub event_id: Uuid,
    pub verification_id: Uuid,
    pub payload_sha256: String,
    pub received_at: DateTime<Utc>,
    pub event: OfflineVerificationEvent,
}

impl OfflineAuditReceipt {
    pub(crate) fn matches(&self, event: &ValidatedOfflineEvent) -> bool {
        self.event_id == event.event.event_id
            && self.verification_id == event.event.payload.verification_id
            && self.payload_sha256 == event.payload_sha256
            && self.event == event.event
    }
}

#[derive(Debug, Serialize)]
pub struct OfflineAuditAcknowledgement {
    pub kind: &'static str,
    pub accepted: usize,
    pub duplicates: usize,
    pub receipts: Vec<OfflineAuditReceipt>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contracts/offline-verification-ingest.json"
        )))
        .unwrap()
    }

    fn now() -> DateTime<Utc> {
        "2026-10-20T12:00:01Z".parse().unwrap()
    }

    fn parse_validate(value: Value) -> Result<Vec<ValidatedOfflineEvent>, OfflineAuditError> {
        serde_json::from_value::<OfflineAuditBatch>(value)
            .map_err(|_| OfflineAuditError::InvalidEvent)?
            .validate(now())
    }

    #[test]
    fn offline_audit_accepts_the_pinned_native_null_authority_payload() {
        let validated = parse_validate(fixture()["native_request"].clone()).unwrap();
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].event.payload.credential_type, "dtc");
        assert_eq!(validated[0].payload_sha256.len(), 64);
        assert_eq!(
            validated[0].payload_sha256,
            "9ba68c00fdda57e68e46098d4732c9c112bbaa20b4cbbd3ad1a0b3fc01d3a4a8"
        );
        let roundtrip = serde_json::to_value(&validated[0].event).unwrap();
        assert_eq!(roundtrip, fixture()["native_request"]["events"][0]);
    }

    #[test]
    fn offline_audit_rejects_personal_data_and_client_authority_at_every_level() {
        let original = fixture()["native_request"].clone();
        for field in [
            "name",
            "credential",
            "portrait",
            "organization_id",
            "producer_id",
        ] {
            for level in 0..=2 {
                let mut value = original.clone();
                let target = match level {
                    0 => &mut value,
                    1 => &mut value["events"][0],
                    _ => &mut value["events"][0]["payload"],
                };
                target[field] = json!("must never persist");
                assert!(parse_validate(value).is_err(), "{field} level {level}");
            }
        }
        for field in ["device_id", "org_id", "hardware_tier"] {
            let mut value = original.clone();
            value["events"][0][field] = json!(Uuid::new_v4());
            assert!(parse_validate(value).is_err(), "{field}");
        }
        let mut value = original;
        value["events"][0]["payload"]["biometric_score"] = json!(0.99);
        assert!(parse_validate(value).is_err());
    }

    #[test]
    fn offline_audit_bounds_batches_and_rejects_ambiguous_ids() {
        let event = fixture()["native_request"]["events"][0].clone();
        assert!(parse_validate(json!({"events":[]})).is_err());
        assert!(parse_validate(json!({"events":vec![event.clone(); MAX_BATCH + 1]})).is_err());
        assert!(matches!(
            parse_validate(json!({"events":[event.clone(),event.clone()]})),
            Err(OfflineAuditError::Conflict)
        ));
        let mut changed_id = event.clone();
        changed_id["event_id"] = json!(Uuid::new_v4());
        assert!(matches!(
            parse_validate(json!({"events":[event,changed_id]})),
            Err(OfflineAuditError::Conflict)
        ));
    }

    #[test]
    fn offline_audit_rejects_online_claims_unknown_results_and_future_events() {
        let original = fixture()["native_request"].clone();
        for (field, invalid) in [
            ("offline_verified", json!(false)),
            ("result", json!("a free-form subject name")),
            ("trust_chain_type", json!("a subject identifier")),
            ("jurisdiction", json!("Alice")),
            ("processing_time_ms", json!(86_400_001)),
        ] {
            let mut value = original.clone();
            value["events"][0]["payload"][field] = invalid;
            assert!(parse_validate(value).is_err(), "{field}");
        }
        let mut value = original.clone();
        value["events"][0]["timestamp"] = json!("2026-10-21T00:00:00Z");
        assert!(parse_validate(value).is_err());
        let mut value = original;
        value["events"][0]["event_id"] = json!(Uuid::nil());
        assert!(parse_validate(value).is_err());
    }

    #[test]
    fn offline_audit_hash_is_stable_for_field_order_and_changes_with_payload() {
        let first = parse_validate(fixture()["native_request"].clone())
            .unwrap()
            .remove(0);
        let mut changed = fixture()["native_request"].clone();
        changed["events"][0]["payload"]["result"] = json!("invalid");
        let changed = parse_validate(changed).unwrap().remove(0);
        assert_ne!(first.payload_sha256, changed.payload_sha256);
        let reordered = serde_json::to_value(&first.event).unwrap();
        let repeated = parse_validate(json!({"events":[reordered]}))
            .unwrap()
            .remove(0);
        assert_eq!(first.payload_sha256, repeated.payload_sha256);
    }
}
