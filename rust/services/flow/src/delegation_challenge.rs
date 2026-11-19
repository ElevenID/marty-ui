//! Flow-owned adapter for resolving delegation OID4VP challenges.
//!
//! Reads the existing persisted Flow instance, frozen OID4VP request and
//! replay/session state. It adds no second nonce store or protocol endpoint.
//! Flow's existing submission finalizer remains the authoritative nonce
//! consumer after the delegated operation evaluation has been committed.

use async_trait::async_trait;
use marty_delegated_authority::{
    DelegationFlowContextV1, DelegationOid4vpChallenge, DelegationOid4vpChallengeStore,
    DelegationOid4vpChallengeStoreError, DELEGATION_FLOW_CONTEXT_KEY,
};
use marty_verification::flow::FlowInstanceStatus;
use uuid::Uuid;

use crate::{
    presentation_request::load_frozen_flow_presentation_request, FlowType,
    PostgresFlowRepository,
};

#[derive(Clone)]
pub struct FlowDelegationOid4vpChallengeStore {
    repository: PostgresFlowRepository,
}

impl FlowDelegationOid4vpChallengeStore {
    pub fn new(repository: PostgresFlowRepository) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl DelegationOid4vpChallengeStore for FlowDelegationOid4vpChallengeStore {
    async fn load_active(
        &self,
        organization_id: Uuid,
        grant_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
        let unavailable = || DelegationOid4vpChallengeStoreError;
        let instance_id = challenge_id.to_string();
        let instance = self
            .repository
            .instance(&instance_id)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if instance.id != instance_id
            || instance.organization_id != organization_id.to_string()
            || !matches!(
                instance.status,
                FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
            )
        {
            return Err(unavailable());
        }

        let definition = self
            .repository
            .definition(&instance.flow_definition_id)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if definition.organization_id != instance.organization_id
            || definition.flow_type != FlowType::Oid4vpPresentation
        {
            return Err(unavailable());
        }

        // Use the same frozen-request validator as normal Flow submission.
        // This binds the nonce and query to the original saved OID4VP request.
        let frozen = load_frozen_flow_presentation_request(&instance)
            .map_err(|_| unavailable())?;
        let audience = instance
            .context
            .get("oid4vp_client_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(unavailable)?;
        let binding: DelegationFlowContextV1 = serde_json::from_value(
            instance
                .context
                .get(DELEGATION_FLOW_CONTEXT_KEY)
                .cloned()
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        binding.validate().map_err(|_| unavailable())?;
        if binding.grant_id != grant_id || instance.expires_at.is_none() {
            return Err(unavailable());
        }

        Ok(DelegationOid4vpChallenge {
            id: challenge_id,
            organization_id,
            grant_id,
            grant_revision: binding.grant_revision,
            nonce: frozen.nonce,
            audience: audience.to_owned(),
            expires_at: instance.expires_at.ok_or_else(unavailable)?,
            session_ref: binding.session_ref,
            establishment_evidence_ref: binding.establishment_evidence_ref,
            session_key_thumbprint: binding.session_key_thumbprint,
        })
    }
}
