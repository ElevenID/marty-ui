use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use marty_verification::flow::FlowInstanceStatus;
use mmf_messaging::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{FlowDefinition, FlowInstance};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FlowArtifact {
    pub id: String,
    pub flow_instance_id: String,
    pub issuance_transaction_id: Option<String>,
    pub payload: Value,
    pub expires_at_ms: Option<u64>,
    pub attempt_number: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApplicationEventReceipt {
    pub event_id_sha256: String,
    pub payload_sha256: String,
    pub organization_id: String,
    pub application_id: String,
    pub flow_plan: Vec<BTreeMap<String, String>>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PlannedApplicationFlow {
    pub instance: FlowInstance,
    pub plan_entry: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    #[error("FLOW.REPOSITORY_FAILURE: {0}")]
    Storage(String),
    #[error("FLOW.APPLICATION_OFFER_CONFLICT: {0}")]
    ApplicationOfferConflict(String),
    #[error("FLOW.INVALID_REPLAY_DIGEST")]
    InvalidReplayDigest,
    #[error("FLOW.ARTIFACT_CONFLICT: {0}")]
    ArtifactConflict(String),
}

#[derive(Default)]
struct RepositoryState {
    definitions: BTreeMap<String, FlowDefinition>,
    instances: BTreeMap<String, FlowInstance>,
    artifacts: BTreeMap<String, FlowArtifact>,
    issuance_artifacts: BTreeMap<String, String>,
    consumed_nonce_digests: BTreeMap<String, u64>,
    finalized_instance_ids: BTreeSet<String>,
    callback_outbox: BTreeMap<String, Message>,
    application_flow_instances: BTreeMap<(String, String), String>,
    application_event_receipts: BTreeMap<String, ApplicationEventReceipt>,
}

#[derive(Default)]
pub struct InMemoryFlowRepository {
    state: Mutex<RepositoryState>,
}

impl InMemoryFlowRepository {
    pub fn save_definition(&self, definition: FlowDefinition) -> Result<(), RepositoryError> {
        self.lock()?
            .definitions
            .insert(definition.id.clone(), definition);
        Ok(())
    }

    pub fn definition(&self, id: &str) -> Result<Option<FlowDefinition>, RepositoryError> {
        Ok(self.lock()?.definitions.get(id).cloned())
    }

    pub fn definitions_for_tenant(
        &self,
        organization_id: &str,
    ) -> Result<Vec<FlowDefinition>, RepositoryError> {
        Ok(self
            .lock()?
            .definitions
            .values()
            .filter(|definition| definition.organization_id == organization_id)
            .cloned()
            .collect())
    }

    pub fn delete_definition(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(self.lock()?.definitions.remove(id).is_some())
    }

    pub fn save_instance(&self, instance: FlowInstance) -> Result<(), RepositoryError> {
        let mut state = self.lock()?;
        if state
            .instances
            .get(&instance.id)
            .is_some_and(|stored| stored.status.is_terminal())
        {
            return Ok(());
        }
        let id = instance.id.clone();
        if instance.status.is_terminal() {
            state.finalized_instance_ids.insert(id.clone());
        }
        state.instances.insert(id, instance);
        Ok(())
    }

    pub fn instance(&self, id: &str) -> Result<Option<FlowInstance>, RepositoryError> {
        Ok(self.lock()?.instances.get(id).cloned())
    }

    pub fn instances_for_tenant(
        &self,
        organization_id: &str,
    ) -> Result<Vec<FlowInstance>, RepositoryError> {
        Ok(self
            .lock()?
            .instances
            .values()
            .filter(|instance| instance.organization_id == organization_id)
            .cloned()
            .collect())
    }

    /// Commit replay consumption, the terminal result, and its callback as one
    /// fenced operation. A false result means another request already won or
    /// the expected live state no longer exists.
    pub fn finalize_verification(
        &self,
        instance: FlowInstance,
        nonce_digest: &str,
        replay_expires_at_ms: u64,
        expected_status: FlowInstanceStatus,
        callback: Option<Message>,
        now_ms: u64,
    ) -> Result<bool, RepositoryError> {
        if !valid_sha256(nonce_digest) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        if !matches!(
            expected_status,
            FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
        ) {
            return Ok(false);
        }
        let mut state = self.lock()?;
        state
            .consumed_nonce_digests
            .retain(|_, expiry| *expiry > now_ms);
        let accepted = !state.consumed_nonce_digests.contains_key(nonce_digest)
            && !state.finalized_instance_ids.contains(&instance.id)
            && state.instances.get(&instance.id).is_some_and(|stored| {
                stored.status == expected_status
                    && stored.expires_at_ms.is_none_or(|expiry| now_ms <= expiry)
            });
        if !accepted {
            return Ok(false);
        }
        if callback.as_ref().is_some_and(|message| {
            message.metadata.message_id != instance.id
                || message.metadata.tenant_id.as_deref() != Some(instance.organization_id.as_str())
        }) {
            return Err(RepositoryError::Storage(
                "callback identity does not match terminal flow".into(),
            ));
        }

        state
            .consumed_nonce_digests
            .insert(nonce_digest.to_owned(), replay_expires_at_ms);
        state.finalized_instance_ids.insert(instance.id.clone());
        if let Some(callback) = callback {
            state
                .callback_outbox
                .insert(callback.metadata.message_id.clone(), callback);
        }
        state.instances.insert(instance.id.clone(), instance);
        Ok(true)
    }

    pub fn callback(&self, event_id: &str) -> Result<Option<Message>, RepositoryError> {
        Ok(self.lock()?.callback_outbox.get(event_id).cloned())
    }

    pub fn save_artifact(&self, artifact: FlowArtifact) -> Result<FlowArtifact, RepositoryError> {
        let mut state = self.lock()?;
        let existing_id = artifact
            .issuance_transaction_id
            .as_ref()
            .and_then(|transaction_id| state.issuance_artifacts.get(transaction_id))
            .cloned()
            .or_else(|| {
                state
                    .artifacts
                    .contains_key(&artifact.id)
                    .then(|| artifact.id.clone())
            });
        if let Some(existing_id) = existing_id {
            let existing = state
                .artifacts
                .get_mut(&existing_id)
                .ok_or_else(|| RepositoryError::Storage("artifact index is inconsistent".into()))?;
            if existing.flow_instance_id != artifact.flow_instance_id {
                return Err(RepositoryError::ArtifactConflict(
                    "issuance transaction belongs to another flow".into(),
                ));
            }
            let id = existing.id.clone();
            *existing = artifact;
            existing.id = id;
            return Ok(existing.clone());
        }
        if let Some(transaction_id) = &artifact.issuance_transaction_id {
            state
                .issuance_artifacts
                .insert(transaction_id.clone(), artifact.id.clone());
        }
        state
            .artifacts
            .insert(artifact.id.clone(), artifact.clone());
        Ok(artifact)
    }

    pub fn reserve_application_event_plan(
        &self,
        mut receipt: ApplicationEventReceipt,
        planned: Vec<PlannedApplicationFlow>,
    ) -> Result<(ApplicationEventReceipt, bool), RepositoryError> {
        if !valid_sha256(&receipt.event_id_sha256) || !valid_sha256(&receipt.payload_sha256) {
            return Err(RepositoryError::InvalidReplayDigest);
        }
        let mut state = self.lock()?;
        if let Some(existing) = state
            .application_event_receipts
            .get(&receipt.event_id_sha256)
        {
            if existing.payload_sha256 != receipt.payload_sha256
                || existing.organization_id != receipt.organization_id
                || existing.application_id != receipt.application_id
            {
                return Err(RepositoryError::ApplicationOfferConflict(
                    "event identity is bound to another payload".into(),
                ));
            }
            return Ok((existing.clone(), false));
        }

        let mut staged = Vec::new();
        let mut final_plan = Vec::with_capacity(planned.len());
        for candidate in planned {
            let application_key = candidate
                .instance
                .context
                .get("_marty_application_offer_semantics_hash_v1")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    RepositoryError::ApplicationOfferConflict(
                        "planned flow has no issuance semantics hash".into(),
                    )
                })?
                .to_owned();
            let logical_key = (
                candidate.instance.organization_id.clone(),
                candidate
                    .instance
                    .application_flow_key_hash
                    .as_deref()
                    .unwrap_or_default()
                    .to_owned(),
            );
            let selected = state
                .application_flow_instances
                .get(&logical_key)
                .and_then(|id| state.instances.get(id))
                .cloned()
                .unwrap_or_else(|| candidate.instance.clone());
            if selected
                .context
                .get("_marty_application_offer_semantics_hash_v1")
                .and_then(Value::as_str)
                != Some(application_key.as_str())
            {
                return Err(RepositoryError::ApplicationOfferConflict(
                    "application and flow are bound to different issuance claims".into(),
                ));
            }
            if !state.instances.contains_key(&selected.id) {
                staged.push((logical_key, selected.clone()));
            }
            let mut entry = candidate.plan_entry;
            entry.insert("instance_id".into(), selected.id);
            final_plan.push(entry);
        }

        for (logical_key, instance) in staged {
            state
                .application_flow_instances
                .insert(logical_key, instance.id.clone());
            state.instances.insert(instance.id.clone(), instance);
        }
        receipt.flow_plan = final_plan;
        state
            .application_event_receipts
            .insert(receipt.event_id_sha256.clone(), receipt.clone());
        Ok((receipt, true))
    }

    fn lock(&self) -> Result<MutexGuard<'_, RepositoryState>, RepositoryError> {
        self.state
            .lock()
            .map_err(|_| RepositoryError::Storage("repository lock poisoned".into()))
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
