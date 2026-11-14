//! Derive finalization bounds only from authenticated native managed material.

use marty_oid4vp_contract::{PolicyEvaluationValidityRequest, PolicyEvaluationValidityV1};
use serde_json::Value;

use crate::{
    AuthenticatedSdJwtQueryEvidence, EvaluatePresentationRequest, PresentationPolicy,
    PresentationVerificationError, VerifiedManagedCredentialAuthority,
};

pub(crate) fn managed_validity(
    policy: &PresentationPolicy,
    request: &EvaluatePresentationRequest,
    query: &AuthenticatedSdJwtQueryEvidence,
    authority: &VerifiedManagedCredentialAuthority,
    result: &Value,
) -> Result<PolicyEvaluationValidityV1, PresentationVerificationError> {
    if !request.trusted_internal_context
        || !query.matches_request(policy, request)
        || !authority.matches_query(query)
    {
        return Err(invalid());
    }
    let evaluated_at = seconds_to_micros(query.checked_at_epoch_seconds())?;
    let projected_time = result["evaluation_timestamp"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .filter(|value| value.timestamp_subsec_nanos() % 1_000 == 0)
        .map(|value| value.timestamp_micros());
    if projected_time != Some(evaluated_at) {
        return Err(invalid());
    }
    let deadline = query
        .finalization_deadline_micros(policy)?
        .min(authority.finalization_deadline_micros(policy)?);
    let policy_identity = crate::policy_revision(policy).map_err(|_| invalid())?;
    let organization_id = policy.organization_id.to_string();
    let context = Value::Object(request.context.clone());
    let binding = PolicyEvaluationValidityRequest {
        organization_id: &organization_id,
        policy: &policy_identity,
        nonce: request.nonce.as_deref().ok_or_else(invalid)?,
        audience: request.audience.as_deref().ok_or_else(invalid)?,
        vp_token: request.vp_token.as_str().ok_or_else(invalid)?,
        trust_profile_id: request.trust_profile_id.as_deref(),
        context: &context,
        oid4vp_transport: request.oid4vp_transport.as_ref().ok_or_else(invalid)?,
    };
    PolicyEvaluationValidityV1::bind(&binding, result, evaluated_at, deadline)
        .map_err(|_| invalid())
}

pub(crate) fn seconds_to_micros(value: u64) -> Result<i64, PresentationVerificationError> {
    i64::try_from(value)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000))
        .filter(|micros| *micros > 0)
        .ok_or_else(invalid)
}

pub(crate) fn signed_seconds_to_micros(value: i64) -> Result<i64, PresentationVerificationError> {
    u64::try_from(value)
        .map_err(|_| invalid())
        .and_then(seconds_to_micros)
}

/// Floor the exact represented NumericDate, without a floating-point multiply
/// rounding a deadline upward. The resulting exclusive bound is conservative
/// for both expiration and the native holder proof's inclusive age boundary.
pub(crate) fn numeric_date_floor_micros(value: f64) -> Result<i64, PresentationVerificationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(invalid());
    }
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    let (significand, shift) = if exponent == 0 {
        (u128::from(fraction), -1074)
    } else {
        (u128::from(fraction | (1_u64 << 52)), exponent - 1023 - 52)
    };
    let numerator = significand.checked_mul(1_000_000).ok_or_else(invalid)?;
    let micros = if shift >= 0 {
        let multiplier = 1_u128.checked_shl(shift as u32).ok_or_else(invalid)?;
        numerator.checked_mul(multiplier).ok_or_else(invalid)?
    } else {
        numerator.checked_shr((-shift) as u32).unwrap_or(0)
    };
    i64::try_from(micros)
        .ok()
        .filter(|micros| *micros > 0)
        .ok_or_else(invalid)
}

pub(crate) fn invalid() -> PresentationVerificationError {
    PresentationVerificationError::Failed(
        "PRESENTATION_POLICY.INVALID_FINALIZATION_VALIDITY".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_date_deadlines_never_round_up_and_reject_unbounded_clocks() {
        assert_eq!(
            numeric_date_floor_micros(1_800_000_000.25).unwrap(),
            1_800_000_000_250_000
        );
        assert_eq!(
            numeric_date_floor_micros(1_800_000_000.5).unwrap(),
            1_800_000_000_500_000
        );
        // The immediate predecessor of a whole microsecond is still below it.
        let before = f64::from_bits(1.0_f64.to_bits() - 1);
        assert_eq!(numeric_date_floor_micros(before).unwrap(), 999_999);
        assert_eq!(numeric_date_floor_micros(1.0).unwrap(), 1_000_000);
        for value in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
            0.0,
            f64::MAX,
        ] {
            assert!(numeric_date_floor_micros(value).is_err());
        }
        assert!(seconds_to_micros(u64::MAX).is_err());
        assert!(signed_seconds_to_micros(-1).is_err());
    }
}
