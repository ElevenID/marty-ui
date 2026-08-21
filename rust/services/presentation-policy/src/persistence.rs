use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{HolderBinding, PresentationPolicy};

pub const PRESENTATION_POLICY_MIGRATION: &str =
    include_str!("../migrations/0001_presentation_policy.sql");

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRecord {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub display_metadata: Value,
    pub credential_requirements: Value,
    pub alternative_requirements: Value,
    pub compliance_profile_id: Option<String>,
    pub version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub policy_document: Value,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PolicyRecordError {
    #[error("PRESENTATION_POLICY.STORAGE: policy document is malformed")]
    MalformedDocument,
    #[error("PRESENTATION_POLICY.STORAGE: legacy {field} is malformed")]
    MalformedLegacy { field: &'static str },
}

impl PolicyRecord {
    pub fn from_policy(policy: &PresentationPolicy) -> Result<Self, PolicyRecordError> {
        let policy_document =
            serde_json::to_value(policy).map_err(|_| PolicyRecordError::MalformedDocument)?;
        let mut display_metadata = serde_json::to_value(&policy.display_metadata)
            .map_err(|_| PolicyRecordError::MalformedDocument)?;
        let display = display_metadata
            .as_object_mut()
            .ok_or(PolicyRecordError::MalformedDocument)?;
        display.insert(
            "protocol".into(),
            json!({
                "purpose": policy.purpose,
                "trust_profile_id": policy.trust_profile_id,
                "accepted_credential_types": policy.accepted_credential_types,
                "presentation_proof_required": policy.presentation_proof_required,
                "holder_binding": policy.holder_binding,
                "freshness": policy.freshness,
                "issuer_constraints": policy.issuer_constraints,
                "credential_ranking_strategy": policy.credential_ranking_strategy,
                "credential_ranking_weights": policy.credential_ranking_weights,
                "prefer_predicates": policy.prefer_predicates,
                "fallback_policy": policy.fallback_policy,
                "supported_circuits": policy.supported_circuits,
                "required_claims": policy.required_claims
            }),
        );
        Ok(Self {
            id: policy.id.to_string(),
            organization_id: policy.organization_id.to_string(),
            name: policy.name.clone(),
            description: policy.description.clone(),
            status: serde_json::to_value(policy.status)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(PolicyRecordError::MalformedDocument)?,
            display_metadata,
            credential_requirements: serde_json::to_value(&policy.credential_requirements)
                .map_err(|_| PolicyRecordError::MalformedDocument)?,
            alternative_requirements: serde_json::to_value(&policy.alternative_requirements)
                .map_err(|_| PolicyRecordError::MalformedDocument)?,
            compliance_profile_id: policy.compliance_profile_id.map(|id| id.to_string()),
            version: i32::try_from(policy.version)
                .map_err(|_| PolicyRecordError::MalformedDocument)?,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
            policy_document,
        })
    }

    pub fn into_policy(self) -> Result<PresentationPolicy, PolicyRecordError> {
        if self
            .policy_document
            .as_object()
            .is_some_and(|document| !document.is_empty())
        {
            return serde_json::from_value(self.policy_document)
                .map_err(|_| PolicyRecordError::MalformedDocument);
        }
        self.legacy_policy()
    }

    fn legacy_policy(self) -> Result<PresentationPolicy, PolicyRecordError> {
        let mut display = self.display_metadata.as_object().cloned().ok_or(
            PolicyRecordError::MalformedLegacy {
                field: "display_metadata",
            },
        )?;
        let protocol = display.remove("protocol").unwrap_or_else(|| json!({}));
        let protocol = protocol
            .as_object()
            .ok_or(PolicyRecordError::MalformedLegacy { field: "protocol" })?;
        let requirements = array(self.credential_requirements, "credential_requirements")?;
        let alternatives = array(self.alternative_requirements, "alternative_requirements")?;
        let accepted = protocol
            .get("accepted_credential_types")
            .cloned()
            .unwrap_or_else(|| {
                Value::Array(
                    requirements
                        .iter()
                        .filter_map(|requirement| {
                            requirement
                                .get("credential_template_id")
                                .and_then(Value::as_str)
                                .filter(|value| !value.is_empty())
                                .map(|value| Value::String(value.to_owned()))
                        })
                        .collect(),
                )
            });
        let holder = protocol
            .get("holder_binding")
            .cloned()
            .map(serde_json::from_value::<HolderBinding>)
            .transpose()
            .map_err(|_| PolicyRecordError::MalformedLegacy {
                field: "holder_binding",
            })?
            .unwrap_or_default()
            .normalize();
        let document = json!({
            "id": parse_uuid(&self.id, "id")?,
            "organization_id": parse_uuid(&self.organization_id, "organization_id")?,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "display_metadata": Value::Object(display),
            "required_claims": protocol.get("required_claims").cloned().unwrap_or_else(|| json!([])),
            "accepted_credential_types": accepted,
            "credential_requirements": requirements,
            "alternative_requirements": alternatives,
            "presentation_proof_required": protocol.get("presentation_proof_required").and_then(Value::as_bool).unwrap_or(false),
            "trust_profile_id": protocol.get("trust_profile_id").cloned().unwrap_or(Value::Null),
            "holder_binding": holder,
            "freshness": protocol.get("freshness").cloned().unwrap_or(Value::Null),
            "issuer_constraints": protocol.get("issuer_constraints").cloned().unwrap_or(Value::Null),
            "credential_ranking_strategy": protocol.get("credential_ranking_strategy").cloned().unwrap_or_else(|| Value::String("FRESHEST_FIRST".into())),
            "credential_ranking_weights": protocol.get("credential_ranking_weights").cloned().unwrap_or(Value::Null),
            "purpose": protocol.get("purpose").cloned().unwrap_or(Value::Null),
            "compliance_profile_id": self.compliance_profile_id,
            "prefer_predicates": protocol.get("prefer_predicates").and_then(Value::as_bool).unwrap_or(false),
            "fallback_policy": protocol.get("fallback_policy").cloned().unwrap_or(Value::Null),
            "supported_circuits": protocol.get("supported_circuits").cloned().unwrap_or_else(|| json!([])),
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        });
        serde_json::from_value(document).map_err(|_| PolicyRecordError::MalformedDocument)
    }
}

fn array(value: Value, field: &'static str) -> Result<Vec<Value>, PolicyRecordError> {
    value
        .as_array()
        .cloned()
        .ok_or(PolicyRecordError::MalformedLegacy { field })
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, PolicyRecordError> {
    value
        .parse()
        .map_err(|_| PolicyRecordError::MalformedLegacy { field })
}
