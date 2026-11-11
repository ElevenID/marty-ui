//! Native association of exact trust-owner and Issuance-owner observations.
//! This is deliberately not canonical OID4VP evidence or issuance authority:
//! Flow still has to commit durable replay state after policy evaluation.

use marty_oid4vp_contract::{
    managed_status::ManagedCredentialStatusObservationV1,
    trust_authority::CredentialTrustEvaluationResponseV1,
};
use serde::Serialize;

use crate::{
    owner_channel::Owner, AuthenticatedOwnerResponse, AuthenticatedSdJwtQueryEvidence,
    PresentationVerificationError,
};

/// Only the native orchestrator can associate these owner responses with a
/// holder-bound credential. Serialized observations cannot construct this type.
/// The full status request, including the credential identifier, stays private.
///
/// ```compile_fail
/// let _: marty_presentation_policy::VerifiedManagedCredentialAuthority =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Serialize)]
pub struct VerifiedManagedCredentialAuthority {
    contract: &'static str,
    trust: CredentialTrustEvaluationResponseV1,
    status: ManagedStatusProjection,
    #[serde(skip)]
    status_observation: AuthenticatedOwnerResponse<ManagedCredentialStatusObservationV1>,
    #[serde(skip)]
    trust_observation: AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ManagedStatusProjection {
    authority: String,
    state: marty_oid4vp_contract::managed_status::ManagedCredentialStatusState,
    request_binding_digest: String,
    issuer_jwt_digest: String,
    checked_at_epoch_seconds: i64,
    valid_until_epoch_seconds: i64,
    evidence_digest: String,
}

impl VerifiedManagedCredentialAuthority {
    pub(crate) fn from_owner_observations(
        query: &AuthenticatedSdJwtQueryEvidence,
        trust: AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1>,
        status: AuthenticatedOwnerResponse<ManagedCredentialStatusObservationV1>,
    ) -> Result<Self, PresentationVerificationError> {
        let result = Self {
            contract: "marty.managed-sd-jwt-authority/v1",
            trust: trust.response().clone(),
            status: ManagedStatusProjection {
                authority: status.response().authority.clone(),
                state: status.response().state,
                request_binding_digest: status.response().request.request_binding_digest.clone(),
                issuer_jwt_digest: status.response().request.issuer_jwt_digest.clone(),
                checked_at_epoch_seconds: status.response().checked_at_epoch_seconds,
                valid_until_epoch_seconds: status.response().valid_until_epoch_seconds,
                evidence_digest: status.response().evidence_digest.clone(),
            },
            status_observation: status,
            trust_observation: trust,
        };
        if !result.matches_query(query) {
            return Err(PresentationVerificationError::Failed(
                "PRESENTATION_POLICY.MANAGED_AUTHORITY_BINDING_INVALID".into(),
            ));
        }
        Ok(result)
    }

    pub(crate) fn matches_query(&self, query: &AuthenticatedSdJwtQueryEvidence) -> bool {
        let Ok((trust_request, status_request)) = query.authority_requests() else {
            return false;
        };
        let Ok(now) = i64::try_from(query.checked_at_epoch_seconds()) else {
            return false;
        };
        self.trust_observation.is_owner(Owner::TrustProfile)
            && self.status_observation.is_owner(Owner::Issuance)
            && self.trust.validate_for_request(&trust_request, now).is_ok()
            && self
                .status_observation
                .response()
                .validate_for_request(&status_request, now)
                .is_ok()
    }
}

impl std::fmt::Debug for VerifiedManagedCredentialAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedManagedCredentialAuthority")
            .field("contract", &self.contract)
            .finish_non_exhaustive()
    }
}
