//! Durable, body-free reservation before physical passport initialization.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    prepare_instance_start_with_key, start_instance_record, FlowDefinitionRecord,
    FlowInstanceExecutionError, FlowInstanceRecord, FlowInstanceSideEffectError, FlowProviderError,
    FlowProviderRegistry, FlowType, PhysicalStartReservation, PhysicalStartReservationInput,
    PostgresFlowRepository, RepositoryError, StartFlowRequest,
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
    #[error("Original physical Flow deadline expired; native outcome requires reconciliation")]
    Expired,
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

pub struct PhysicalStartInvocation<'a> {
    pub request: StartFlowRequest,
    pub actor: &'a str,
    pub public_base_url: &'a str,
    pub now: DateTime<Utc>,
    pub client_key: Option<&'a str>,
}

/// Tenant configuration captured before native dispatch; it contains no holder request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalStartSnapshot {
    pub definition: FlowDefinitionRecord,
    pub issuer_did: String,
}

impl PhysicalStartSnapshot {
    pub fn matches(&self, organization_id: &str, definition_id: &str) -> bool {
        self.definition.organization_id == organization_id
            && self.definition.id == definition_id
            && crate::effective_flow_type(&self.definition) == FlowType::PhysicalDocumentIssuance
            && self.issuer_did.starts_with("did:")
            && self.issuer_did.trim() == self.issuer_did
    }
}

fn decode_snapshot(
    value: Value,
    organization_id: &str,
) -> Result<PhysicalStartSnapshot, PhysicalStartError> {
    let snapshot: PhysicalStartSnapshot =
        serde_json::from_value(value).map_err(|_| PhysicalStartError::StoredIncomplete)?;
    if !snapshot.matches(organization_id, &snapshot.definition.id) {
        return Err(PhysicalStartError::StoredIncomplete);
    }
    Ok(snapshot)
}

pub async fn physical_start_snapshot_for_key(
    repository: &PostgresFlowRepository,
    organization_id: &str,
    key: &str,
) -> Result<Option<PhysicalStartSnapshot>, PhysicalStartError> {
    validated_client_key(Some(key))?;
    let key_hash = hash("marty:physical-flow-start-key:v1:", key);
    repository
        .physical_start_snapshot(organization_id, &key_hash)
        .await?
        .map(|value| decode_snapshot(value, organization_id))
        .transpose()
}

pub async fn physical_start_snapshot_for_instance(
    repository: &PostgresFlowRepository,
    organization_id: &str,
    instance_id: &str,
) -> Result<Option<PhysicalStartSnapshot>, PhysicalStartError> {
    repository
        .physical_start_snapshot_by_instance(organization_id, instance_id)
        .await?
        .map(|value| decode_snapshot(value, organization_id))
        .transpose()
}

pub async fn bound_definition_for_instance(
    repository: &PostgresFlowRepository,
    instance: &FlowInstanceRecord,
) -> Result<Option<FlowDefinitionRecord>, PhysicalStartError> {
    if let Some(snapshot) =
        physical_start_snapshot_for_instance(repository, &instance.organization_id, &instance.id)
            .await?
    {
        if snapshot.definition.id != instance.flow_definition_id
            || snapshot.definition.organization_id != instance.organization_id
        {
            return Err(PhysicalStartError::StoredIncomplete);
        }
        return Ok(Some(snapshot.definition));
    }
    Ok(repository
        .definition(&instance.flow_definition_id)
        .await?
        .filter(|definition| definition.organization_id == instance.organization_id))
}

pub async fn physical_start_snapshot_for_definition_key(
    repository: &PostgresFlowRepository,
    definition_id: &str,
    key: &str,
) -> Result<Option<PhysicalStartSnapshot>, PhysicalStartError> {
    validated_client_key(Some(key))?;
    let key_hash = hash("marty:physical-flow-start-key:v1:", key);
    repository
        .physical_start_snapshot_by_definition_key(definition_id, &key_hash)
        .await?
        .map(|(organization_id, value)| {
            let snapshot = decode_snapshot(value, &organization_id)?;
            if snapshot.definition.id != definition_id
                || snapshot.definition.organization_id != organization_id
            {
                return Err(PhysicalStartError::StoredIncomplete);
            }
            Ok(snapshot)
        })
        .transpose()
}

async fn capture_snapshot(
    providers: &FlowProviderRegistry,
    definition: &FlowDefinitionRecord,
) -> Result<PhysicalStartSnapshot, PhysicalStartError> {
    fn reference(value: &Option<String>) -> Result<&str, FlowInstanceSideEffectError> {
        value
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or(FlowInstanceSideEffectError::InvalidContext(
                "physical document definition references are required",
            ))
    }
    let template_id = reference(&definition.credential_template_id)?;
    reference(&definition.application_template_id)?;
    reference(&definition.delivery_destination_profile_id)?;
    let provider =
        providers
            .credential_template
            .as_ref()
            .ok_or(FlowInstanceSideEffectError::Provider(
                FlowProviderError::Unavailable {
                    provider: "credential_template",
                },
            ))?;
    let template = provider
        .get_template(template_id)
        .await
        .map_err(FlowInstanceSideEffectError::from)?;
    crate::instance_side_effects::validate_template(
        &template,
        template_id,
        &definition.organization_id,
    )?;
    crate::validate_physical_document_template(&template)
        .map_err(FlowInstanceSideEffectError::from)?;
    Ok(PhysicalStartSnapshot {
        definition: definition.clone(),
        issuer_did: template.issuer_did,
    })
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
    invocation: PhysicalStartInvocation<'_>,
) -> Result<PhysicalStartResult, PhysicalStartError> {
    let PhysicalStartInvocation {
        request,
        actor,
        public_base_url,
        now,
        client_key,
    } = invocation;
    let key = validated_client_key(client_key)?;
    let semantic = serde_json::to_value(&request).map_err(|_| PhysicalStartError::Conflict)?;
    let request_hash = hash(
        "marty:physical-flow-start-request:v1:",
        &canonical(&semantic),
    );
    let prior = if let Some(key) = key {
        physical_start_snapshot_for_key(repository, &request.organization_id, key).await?
    } else {
        None
    };
    let candidate = if let Some(snapshot) = prior {
        snapshot
    } else {
        capture_snapshot(providers, definition).await?
    };
    if !candidate.matches(&request.organization_id, &request.flow_definition_id) {
        return Err(PhysicalStartError::Conflict);
    }
    let mut instance = start_instance_record(&candidate.definition, request.clone(), actor, now)?;
    let proposed_deadline = instance
        .expires_at
        .ok_or(PhysicalStartError::StoredIncomplete)?;
    let operation_key = key.unwrap_or(&instance.id);
    let key_hash = hash("marty:physical-flow-start-key:v1:", operation_key);
    let reservation = repository
        .reserve_physical_start(PhysicalStartReservationInput {
            organization_id: &instance.organization_id,
            definition_id: &instance.flow_definition_id,
            operation_key,
            key_hash: &key_hash,
            request_hash: &request_hash,
            definition_snapshot: &candidate,
            initial_actor: actor,
            original_deadline_at: proposed_deadline,
            generated_key: key.is_none(),
            proposed_instance_id: &instance.id,
            now,
        })
        .await
        .map_err(|error| match error {
            RepositoryError::PhysicalStartKeyConflict => PhysicalStartError::Conflict,
            other => PhysicalStartError::Repository(other),
        })?;
    let (instance_id, claim_token) = match reservation {
        PhysicalStartReservation::InProgress { .. } => return Err(PhysicalStartError::InProgress),
        PhysicalStartReservation::Expired { .. } => return Err(PhysicalStartError::Expired),
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
    let origin = repository
        .physical_start_origin(&instance.organization_id, &key_hash)
        .await?
        .ok_or(PhysicalStartError::StoredIncomplete)?;
    let persisted = decode_snapshot(origin.definition_snapshot, &instance.organization_id)?;
    if !persisted.matches(&instance.organization_id, &instance.flow_definition_id) {
        return Err(PhysicalStartError::StoredIncomplete);
    }
    if now >= origin.original_deadline_at {
        return Err(PhysicalStartError::Expired);
    }
    instance = start_instance_record(
        &persisted.definition,
        request,
        &origin.initial_actor,
        origin.created_at,
    )?;
    instance.id = instance_id.clone();
    let prepared = prepare_instance_start_with_key(
        providers,
        &persisted.definition,
        instance,
        public_base_url,
        origin.created_at,
        Some(&instance_id),
        Some(&persisted.issuer_did),
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
