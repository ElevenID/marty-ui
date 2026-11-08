//! Identity of the exact policy snapshot used to build and evaluate a request.
//!
//! The snapshot includes every saved policy field, including organization,
//! status and lifecycle timestamps at their stored precision. The authoritative
//! JSONB `policy_document` preserves the serialized timestamps; legacy records
//! use the timestamps reconstructed by the existing persistence adapter. A newer
//! saved `updated_at` on suspension/reactivation invalidates the earlier active
//! reference. This digest is not a monotonic generation counter for writes that
//! restore the exact same saved document.
//! This is an evaluation-time snapshot check, not a lock on remote policy state
//! for the lifetime of a presentation or a future issuance transaction.

use marty_oid4vp_contract::{digest_policy_snapshot, FrozenPolicyIdentity, Oid4vpContractError};
use serde_json::{json, Value};

use crate::PresentationPolicy;

pub fn policy_revision(
    policy: &PresentationPolicy,
) -> Result<FrozenPolicyIdentity, Oid4vpContractError> {
    let revision = FrozenPolicyIdentity {
        id: policy.id.to_string(),
        version: policy.version,
        content_digest: digest_policy_snapshot(policy)?,
    };
    revision.validate()?;
    Ok(revision)
}

pub(crate) fn policy_revision_value(
    policy: &PresentationPolicy,
) -> Result<Value, Oid4vpContractError> {
    let revision = policy_revision(policy)?;
    Ok(json!({
        "organization_id": policy.organization_id,
        "id": revision.id,
        "version": revision.version,
        "content_digest": revision.content_digest,
    }))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::*;
    use crate::{built_in_presentation_policies, PolicyRecord, PolicyStatus};

    #[test]
    fn revision_binds_tenant_semantics_and_lifecycle() {
        let original = built_in_presentation_policies().remove(0);
        let expected = policy_revision(&original).unwrap();
        for changed in [
            {
                let mut policy = original.clone();
                policy.organization_id = uuid::Uuid::new_v4();
                policy
            },
            {
                let mut policy = original.clone();
                policy.holder_binding.required = !policy.holder_binding.required;
                policy
            },
            {
                let mut policy = original.clone();
                policy.status = PolicyStatus::Suspended;
                policy
            },
            {
                let mut policy = original.clone();
                // Reactivating restores Active, but not the prior lifecycle revision.
                policy.updated_at += Duration::microseconds(1);
                policy
            },
        ] {
            assert_ne!(expected, policy_revision(&changed).unwrap());
        }
    }

    #[test]
    fn revision_preserves_stored_precision_and_survives_policy_record_round_trip() {
        let mut policy = built_in_presentation_policies().remove(0);
        policy.created_at = Utc.timestamp_opt(1_700_000_000, 123_456_789).unwrap();
        policy.updated_at = Utc.timestamp_opt(1_700_000_001, 987_654_321).unwrap();
        let expected = policy_revision(&policy).unwrap();
        let recovered = PolicyRecord::from_policy(&policy)
            .unwrap()
            .into_policy()
            .unwrap();
        assert_eq!(expected, policy_revision(&recovered).unwrap());
        policy.updated_at += Duration::nanoseconds(1);
        assert_ne!(expected, policy_revision(&policy).unwrap());
    }
}
