//! Bind the currently supported single-credential SD-JWT DCQL lane to the
//! emitted request. This is an input binding check, not an eligibility engine.
use crate::{CredentialVerificationEvidence, EvaluatePresentationRequest};
use marty_oid4vp_contract::QueryKind;
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::Value;

fn sd_jwt(format: &str) -> bool {
    matches!(format, "dc+sd-jwt" | "vc+sd-jwt")
}

pub(crate) fn bind_sd_jwt_query(
    format: DetectedCredentialFormat,
    request: &EvaluatePresentationRequest,
    evidence: &mut CredentialVerificationEvidence,
) {
    let Some(transport) = &request.oid4vp_transport else {
        return;
    };
    if transport.query_kind != QueryKind::Dcql || !evidence.verified {
        return;
    }
    let queries = transport.query_document["credentials"].as_array();
    let requests_sd_jwt = queries.is_some_and(|queries| {
        queries
            .iter()
            .any(|query| query["format"].as_str().is_some_and(sd_jwt))
    });
    if format != DetectedCredentialFormat::SdJwt && !requests_sd_jwt {
        return;
    }
    let matches = (|| {
        if !request.trusted_internal_context
            || transport.validate_transport().is_err()
            || request.nonce.as_deref() != Some(transport.request_nonce.as_str())
            || request.audience.as_deref() != Some(transport.verifier_client_id.as_str())
            || transport.presentation_submission.is_some()
            || format != DetectedCredentialFormat::SdJwt
            || !evidence.presentation_verified
            || !evidence.holder_binding_verified
            || !evidence.challenge_verified
            || !evidence.audience_verified
        {
            return None;
        }
        // The current kernel authenticates exactly one credential, so it must
        // never assert coverage of several query IDs or response tokens.
        let [query] = queries?.as_slice() else {
            return None;
        };
        let id = query["id"].as_str().filter(|id| !id.is_empty())?;
        let requested_format = query["format"].as_str().filter(|format| sd_jwt(format))?;
        if evidence.authenticated_sd_jwt_type.as_deref() != Some(requested_format) {
            return None;
        }
        let vct = evidence
            .authenticated_sd_jwt_vct
            .as_deref()
            .filter(|vct| !vct.is_empty())?;
        let accepted = query["meta"]["vct_values"].as_array()?;
        if accepted.is_empty()
            || accepted
                .iter()
                .any(|value| value.as_str().is_none_or(str::is_empty))
            || !accepted.iter().any(|value| value.as_str() == Some(vct))
        {
            return None;
        }
        let raw: Value = serde_json::from_str(&transport.vp_token_raw).ok()?;
        let response = raw.as_object()?;
        if response.len() != 1 {
            return None;
        }
        let [token] = response.get(id)?.as_array()?.as_slice() else {
            return None;
        };
        if token.as_str()? != request.vp_token.as_str()? {
            return None;
        }
        Some(())
    })()
    .is_some();
    if !matches {
        // A genuine issuer signature alone cannot authenticate a response to
        // this request. Keep it nonterminal; another wallet input may retry.
        evidence.verified = false;
        evidence.failure_reason =
            Some("OID4VP SD-JWT response did not match the emitted DCQL request".into());
        evidence.claims.clear();
        evidence.authenticated_sd_jwt_vct = None;
        evidence.authenticated_sd_jwt_type = None;
        evidence.presentation_verified = false;
        evidence.holder_binding_verified = false;
        evidence.challenge_verified = false;
        evidence.audience_verified = false;
        evidence.replay_check_verified = false;
    }
}
