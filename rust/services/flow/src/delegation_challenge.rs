//! Flow-owned adapter for resolving delegation OID4VP challenges.
//!
//! Reads the existing persisted Flow instance, frozen OID4VP request and
//! private operation binding. It adds no nonce store or protocol endpoint.
//! The authenticated Flow start path still needs to produce the private binding
//! snapshot. The consuming final-use integration must coordinate Flow nonce
//! consumption with grant revision and operation replay protection; reading a
//! challenge here does not implement that transaction or authorize execution.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_delegated_authority::{
    DelegationFlowContextV1, DelegationOid4vpChallenge, DelegationOid4vpChallengeStore,
    DelegationOid4vpChallengeStoreError, DELEGATION_FLOW_CONTEXT_KEY,
};
use marty_verification::flow::FlowInstanceStatus;
use uuid::Uuid;

use crate::{
    presentation_request::load_frozen_flow_presentation_request, DefinitionStatus,
    FlowDefinitionRecord, FlowInstanceRecord, FlowType, PostgresFlowRepository,
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
        // Do not load a foreign tenant's definition or expose a different error.
        if instance.id != instance_id || instance.organization_id != organization_id.to_string() {
            return Err(unavailable());
        }

        let definition = self
            .repository
            .definition(&instance.flow_definition_id)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        challenge_from_records(
            organization_id,
            grant_id,
            challenge_id,
            &instance,
            &definition,
            Utc::now(),
        )
    }
}

fn challenge_from_records(
    organization_id: Uuid,
    grant_id: Uuid,
    challenge_id: Uuid,
    instance: &FlowInstanceRecord,
    definition: &FlowDefinitionRecord,
    now: DateTime<Utc>,
) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
    let unavailable = || DelegationOid4vpChallengeStoreError;
    if instance.id != challenge_id.to_string()
        || instance.organization_id != organization_id.to_string()
        || definition.id != instance.flow_definition_id
        || definition.organization_id != instance.organization_id
        || definition.status != DefinitionStatus::Active
        || definition.flow_type != FlowType::Oid4vpPresentation
        || !matches!(
            instance.status,
            FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
        )
        || instance.completed_at.is_some()
        || instance.result.is_some()
        || instance.error.is_some()
    {
        return Err(unavailable());
    }
    let expires_at = instance
        .expires_at
        .filter(|expiry| *expiry > now)
        .ok_or_else(unavailable)?;

    // Use the same frozen-request validator as normal Flow submission. This
    // binds the nonce and query to the original saved OID4VP request.
    let frozen = load_frozen_flow_presentation_request(instance).map_err(|_| unavailable())?;
    let binding: DelegationFlowContextV1 = serde_json::from_value(
        instance
            .context
            .get(DELEGATION_FLOW_CONTEXT_KEY)
            .cloned()
            .ok_or_else(unavailable)?,
    )
    .map_err(|_| unavailable())?;
    binding.validate()?;
    if binding.challenge_id != challenge_id
        || binding.organization_id != organization_id
        || binding.grant_id != grant_id
        || instance
            .context
            .get("oid4vp_client_id")
            .and_then(serde_json::Value::as_str)
            != Some(binding.audience.as_str())
    {
        return Err(unavailable());
    }

    Ok(DelegationOid4vpChallenge {
        binding,
        nonce: frozen.nonce,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use marty_delegated_authority::{Principal, PrincipalType};
    use marty_oid4vci::presentation_request::PresentationRequestArtifacts;
    use marty_oid4vp_contract::FrozenPolicyIdentity;
    use serde_json::json;

    use crate::presentation_request::{
        freeze_flow_presentation_request, FROZEN_PRESENTATION_REQUEST_KEY,
    };

    struct Fixture {
        organization_id: Uuid,
        grant_id: Uuid,
        challenge_id: Uuid,
        instance: FlowInstanceRecord,
        definition: FlowDefinitionRecord,
        now: DateTime<Utc>,
    }

    impl Fixture {
        fn resolve(
            &self,
        ) -> Result<DelegationOid4vpChallenge, DelegationOid4vpChallengeStoreError> {
            challenge_from_records(
                self.organization_id,
                self.grant_id,
                self.challenge_id,
                &self.instance,
                &self.definition,
                self.now,
            )
        }
    }

    fn fixture() -> Fixture {
        let organization_id = Uuid::new_v4();
        let grant_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let now = DateTime::from_timestamp(1_794_934_801, 0).unwrap();
        let binding = DelegationFlowContextV1 {
            challenge_id,
            organization_id,
            grant_id,
            grant_revision: 2,
            actor: Principal {
                principal_type: PrincipalType::MachineIdentity,
                id: "urn:example:delegate".into(),
            },
            action: "urn:example:action:read".into(),
            audience: "https://verifier.example".into(),
            resource: "urn:example:resource:123".into(),
            operation_profile: "urn:example:operation:v1".into(),
            operation_digest: format!("sha256:{}", "b".repeat(64)),
            session_ref: None,
            establishment_evidence_ref: None,
            session_key_thumbprint: None,
        };
        let definition = serde_json::from_value(json!({
            "id": "flow-1", "organization_id": organization_id,
            "name": "Delegated presentation", "status": "ACTIVE",
            "flow_type": "oid4vp_presentation", "steps": [], "transitions": [],
            "approval_strategy": "AUTO", "default_timeout_seconds": 120,
            "max_retries": 0, "retry_cooldown_minutes": 0, "enable_resume": false,
            "version": 1, "created_at": now, "updated_at": now,
        }))
        .unwrap();
        let mut instance: FlowInstanceRecord = serde_json::from_value(json!({
            "id": challenge_id, "flow_definition_id": "flow-1",
            "organization_id": organization_id, "status": "awaiting_wallet",
            "context": {
                "nonce": "A-single-use-OID4VP-nonce-123456",
                "presentation_policy_id": "policy-1",
                "oid4vp_client_id": "https://verifier.example",
            },
            "subject_type": "machine_identity", "created_at": now, "updated_at": now,
            "expires_at": now + Duration::seconds(120),
        }))
        .unwrap();
        instance.context[DELEGATION_FLOW_CONTEXT_KEY] = serde_json::to_value(binding).unwrap();
        freeze_flow_presentation_request(
            &mut instance,
            FrozenPolicyIdentity {
                id: "policy-1".into(),
                version: 1,
                content_digest: format!("sha256:{}", "a".repeat(64)),
            },
            None,
            &PresentationRequestArtifacts {
                presentation_definition: json!({"id":"query-1","input_descriptors":[{"id":"member"}]}),
                dcql_query: json!({"credentials":[{"id":"member"}]}),
            },
        ).unwrap();
        Fixture {
            organization_id,
            grant_id,
            challenge_id,
            instance,
            definition,
            now,
        }
    }

    #[test]
    fn challenge_reuses_frozen_flow_nonce_and_exact_private_operation_snapshot() {
        let mut fixture = fixture();
        for status in [
            FlowInstanceStatus::AwaitingWallet,
            FlowInstanceStatus::InProgress,
        ] {
            fixture.instance.status = status;
            let challenge = fixture.resolve().unwrap();
            assert_eq!(
                challenge.nonce,
                fixture.instance.context["nonce"].as_str().unwrap()
            );
            assert_eq!(challenge.expires_at, fixture.instance.expires_at.unwrap());
            assert_eq!(challenge.binding.challenge_id, fixture.challenge_id);
            assert_eq!(challenge.binding.grant_id, fixture.grant_id);
            assert_eq!(challenge.binding.organization_id, fixture.organization_id);
            assert_eq!(
                serde_json::to_value(&challenge.binding).unwrap(),
                fixture.instance.context[DELEGATION_FLOW_CONTEXT_KEY]
            );
        }
    }

    #[test]
    fn challenge_rejects_foreign_records_stale_state_and_changed_verifier_authority() {
        let mutations: &[fn(&mut Fixture)] = &[
            |f| f.organization_id = Uuid::new_v4(),
            |f| f.grant_id = Uuid::new_v4(),
            |f| f.challenge_id = Uuid::new_v4(),
            |f| f.definition.id = "other-flow".into(),
            |f| f.definition.organization_id = Uuid::new_v4().to_string(),
            |f| f.definition.status = DefinitionStatus::Paused,
            |f| f.definition.flow_type = FlowType::Siopv2,
            |f| f.instance.expires_at = None,
            |f| f.instance.expires_at = Some(f.now),
            |f| f.instance.completed_at = Some(f.now),
            |f| f.instance.result = Some(json!({"consumed": true})),
            |f| f.instance.error = Some("failed".into()),
            |f| f.instance.context["nonce"] = json!("changed-frozen-nonce-123456"),
            |f| f.instance.context["oid4vp_client_id"] = json!("https://attacker.example"),
            |f| f.instance.context[FROZEN_PRESENTATION_REQUEST_KEY] = json!(null),
            |f| {
                f.instance.context[FROZEN_PRESENTATION_REQUEST_KEY]["dcql_query"] =
                    json!({"changed": true})
            },
            |f| f.instance.context[DELEGATION_FLOW_CONTEXT_KEY] = json!(null),
            |f| {
                f.instance.context[DELEGATION_FLOW_CONTEXT_KEY]["unchecked_authority"] = json!(true)
            },
            |f| {
                f.instance.context[DELEGATION_FLOW_CONTEXT_KEY]["session_ref"] =
                    json!("urn:session:unbound")
            },
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut fixture = fixture();
            mutate(&mut fixture);
            assert!(fixture.resolve().is_err(), "accepted mutation {index}");
        }
        for status in [
            FlowInstanceStatus::Created,
            FlowInstanceStatus::Pending,
            FlowInstanceStatus::AwaitingApproval,
            FlowInstanceStatus::AwaitingEvidence,
            FlowInstanceStatus::Completed,
            FlowInstanceStatus::Failed,
            FlowInstanceStatus::Cancelled,
            FlowInstanceStatus::Expired,
        ] {
            let mut fixture = fixture();
            fixture.instance.status = status;
            assert!(fixture.resolve().is_err(), "accepted {status}");
        }
    }

    #[test]
    fn private_snapshot_cannot_be_copied_to_another_flow_instance_or_tenant() {
        let mut changed_instance = fixture();
        changed_instance.challenge_id = Uuid::new_v4();
        changed_instance.instance.id = changed_instance.challenge_id.to_string();
        changed_instance.instance.context[FROZEN_PRESENTATION_REQUEST_KEY]["instance_id"] =
            json!(changed_instance.challenge_id);
        assert!(changed_instance.resolve().is_err());

        let mut changed_tenant = fixture();
        changed_tenant.organization_id = Uuid::new_v4();
        changed_tenant.instance.organization_id = changed_tenant.organization_id.to_string();
        changed_tenant.definition.organization_id = changed_tenant.organization_id.to_string();
        changed_tenant.instance.context[FROZEN_PRESENTATION_REQUEST_KEY]["organization_id"] =
            json!(changed_tenant.organization_id);
        assert!(changed_tenant.resolve().is_err());
    }
}
