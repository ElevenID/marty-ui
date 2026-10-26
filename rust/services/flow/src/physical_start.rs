//! Durable, body-free reservation before physical passport initialization.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    prepare_instance_start_with_key, start_instance_record, FlowDefinitionRecord,
    FlowInstanceExecutionError, FlowInstanceRecord, FlowInstanceSideEffectError,
    FlowProviderRegistry, PhysicalStartReservation, PostgresFlowRepository, RepositoryError,
    StartFlowRequest,
};

#[derive(Debug, Error)]
pub enum PhysicalStartError {
    #[error("Physical Flow Idempotency-Key is invalid")]
    InvalidKey,
    #[error("Physical Flow start is in progress; retry with the same key")]
    InProgress,
    #[error("Physical Flow start identity changed")]
    Conflict,
    #[error("Stored physical Flow start is incomplete")]
    StoredIncomplete,
    #[error(transparent)]
    Execution(#[from] FlowInstanceExecutionError),
    #[error(transparent)]
    SideEffect(#[from] FlowInstanceSideEffectError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub struct PhysicalStartResult {
    pub instance: FlowInstanceRecord,
    pub created: bool,
}

fn canonical(value: &Value) -> String {
    match value {
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(name, value)| format!(
                    "{}:{}",
                    serde_json::to_string(name).expect("JSON key"),
                    canonical(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        _ => value.to_string(),
    }
}

fn hash(prefix: &str, value: &str) -> String {
    hex::encode(Sha256::digest(format!("{prefix}{value}").as_bytes()))
}

pub fn validated_client_key(value: Option<&str>) -> Result<Option<&str>, PhysicalStartError> {
    let Some(value) = value else { return Ok(None) };
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(PhysicalStartError::InvalidKey);
    }
    Ok(Some(value))
}

pub async fn start_physical_instance(
    repository: &PostgresFlowRepository,
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
    request: StartFlowRequest,
    actor: &str,
    public_base_url: &str,
    now: DateTime<Utc>,
    client_key: Option<&str>,
) -> Result<PhysicalStartResult, PhysicalStartError> {
    let key = validated_client_key(client_key)?;
    let semantic = serde_json::to_value(&request).map_err(|_| PhysicalStartError::Conflict)?;
    let request_hash = hash(
        "marty:physical-flow-start-request:v1:",
        &canonical(&semantic),
    );
    let mut instance = start_instance_record(definition, request, actor, now)?;
    let operation_key = key.unwrap_or(&instance.id);
    let key_hash = hash("marty:physical-flow-start-key:v1:", operation_key);
    let reservation = repository
        .reserve_physical_start(
            &instance.organization_id,
            &instance.flow_definition_id,
            operation_key,
            &key_hash,
            &request_hash,
            key.is_none(),
            &instance.id,
            now,
        )
        .await
        .map_err(|error| match error {
            RepositoryError::PhysicalStartKeyConflict => PhysicalStartError::Conflict,
            other => PhysicalStartError::Repository(other),
        })?;
    let (instance_id, claim_token) = match reservation {
        PhysicalStartReservation::InProgress { .. } => return Err(PhysicalStartError::InProgress),
        PhysicalStartReservation::Completed { instance_id } => {
            let existing = repository
                .instance(&instance_id)
                .await?
                .ok_or(PhysicalStartError::StoredIncomplete)?;
            if existing.organization_id != instance.organization_id
                || existing.flow_definition_id != instance.flow_definition_id
            {
                return Err(PhysicalStartError::StoredIncomplete);
            }
            return Ok(PhysicalStartResult {
                instance: existing,
                created: false,
            });
        }
        PhysicalStartReservation::Acquired {
            instance_id,
            claim_token,
        } => (instance_id, claim_token),
    };
    instance.id = instance_id.clone();
    let prepared = prepare_instance_start_with_key(
        providers,
        definition,
        instance,
        public_base_url,
        now,
        Some(&instance_id),
    )
    .await?;
    if !repository
        .save_started_physical_instance(&prepared.instance, &key_hash, claim_token)
        .await?
    {
        return Err(PhysicalStartError::Conflict);
    }
    Ok(PhysicalStartResult {
        instance: prepared.instance,
        created: true,
    })
}

#[cfg(test)]
mod tests {
    use super::{canonical, hash, validated_client_key};
    use serde_json::json;

    #[test]
    fn start_key_rejects_ambiguous_or_unbounded_values() {
        for key in ["", " padded", "a b", "x/y", "x\n", &"a".repeat(129)] {
            assert!(validated_client_key(Some(key)).is_err());
        }
        assert_eq!(
            validated_client_key(Some("owned-flow:42")).unwrap(),
            Some("owned-flow:42")
        );
    }

    #[test]
    fn physical_start_digest_is_order_independent_and_domain_separated() {
        let a = json!({"organization_id":"org-a", "initial_context": {
            "physical_document": {"mrz": {"line_2": "private", "line_1": "private"}, "country_code":"USA"}}});
        let b = json!({"initial_context": {"physical_document": {
            "country_code":"USA", "mrz": {"line_1": "private", "line_2": "private"}}},
            "organization_id":"org-a"});
        let digest = hash("marty:physical-flow-start-request:v1:", &canonical(&a));
        assert_eq!(
            digest,
            hash("marty:physical-flow-start-request:v1:", &canonical(&b))
        );
        assert_ne!(
            digest,
            hash("marty:physical-flow-start-key:v1:", &canonical(&a))
        );
        assert!(!digest.contains("private"));
    }
}
