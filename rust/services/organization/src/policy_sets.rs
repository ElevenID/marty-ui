use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use mmf_security::CedarPolicyValidator;
use regex::Regex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::application::{OrganizationApplication, OrganizationApplicationError};
use crate::domain::{PolicySet, PolicySetSpec, PolicySetStatus, PolicySetType};
use crate::postgres::RepositoryError;

pub const ORGANIZATION_CEDAR_SCHEMA: &str = r#"
namespace MIP {
  type ApprovalContext = { all_required_evidence_satisfied: Bool };
  entity User;
  entity Application;
  action "applications:approve" appliesTo {
    principal: [User],
    resource: [Application],
    context: ApprovalContext
  };
}
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CedarPolicyDocument {
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub cedar_text: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePolicySetCommand {
    pub organization_id: Uuid,
    pub name: String,
    pub policies: Vec<CedarPolicyDocument>,
    pub policy_type: PolicySetType,
    pub description: Option<String>,
    pub created_by: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpdatePolicySetPatch {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub policies: Option<Vec<CedarPolicyDocument>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePolicySetCommand {
    pub organization_id: Uuid,
    pub policy_set_id: Uuid,
    pub patch: UpdatePolicySetPatch,
    pub now: DateTime<Utc>,
}

impl OrganizationApplication {
    pub fn policy_validation_errors(
        &self,
        policies: &[CedarPolicyDocument],
    ) -> Result<Vec<String>, OrganizationApplicationError> {
        let validator = self
            .policy_validator
            .as_deref()
            .ok_or(OrganizationApplicationError::PolicyValidatorUnavailable)?;
        Ok(validate_policy_documents(policies, validator))
    }

    pub async fn create_policy_set(
        &self,
        command: CreatePolicySetCommand,
    ) -> Result<PolicySet, OrganizationApplicationError> {
        require_text(&command.name, "policy-set name is required")?;
        self.validate_policy_documents(&command.policies)?;
        let cedar_policies = serialize_policy_documents(&command.policies)?;
        let policy_set = PolicySet::create(PolicySetSpec {
            organization_id: command.organization_id,
            name: command.name,
            cedar_policies,
            policy_type: command.policy_type,
            description: command.description,
            created_by: command.created_by,
            cedar_schema_version: Some("MIP/1.0".into()),
            now: command.now,
        });
        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .organization_by_id_for_update_in_transaction(&mut transaction, command.organization_id)
            .await?
            .ok_or(OrganizationApplicationError::NotFound(
                command.organization_id,
            ))?;
        self.store
            .save_policy_set_in_transaction(&mut transaction, &policy_set)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(policy_set)
    }

    pub async fn update_policy_set(
        &self,
        command: UpdatePolicySetCommand,
    ) -> Result<PolicySet, OrganizationApplicationError> {
        if let Some(name) = command.patch.name.as_deref() {
            require_text(name, "policy-set name must not be empty")?;
        }
        let serialized_policies = command
            .patch
            .policies
            .as_ref()
            .map(|policies| {
                self.validate_policy_documents(policies)?;
                serialize_policy_documents(policies)
            })
            .transpose()?;
        let mut transaction = self.store.begin_transaction().await?;
        let mut policy_set = self
            .store
            .policy_set_by_id_for_update_in_transaction(
                &mut transaction,
                command.organization_id,
                command.policy_set_id,
            )
            .await?
            .ok_or(OrganizationApplicationError::PolicySetNotFound(
                command.policy_set_id,
            ))?;
        if let Some(name) = command.patch.name {
            policy_set.name = name;
        }
        if let Some(description) = command.patch.description {
            policy_set.description = description;
        }
        if let Some(policies) = serialized_policies {
            policy_set.cedar_policies = policies;
        }
        policy_set.updated_at = command.now;
        self.store
            .save_policy_set_in_transaction(&mut transaction, &policy_set)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(policy_set)
    }

    pub async fn archive_policy_set(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PolicySet, OrganizationApplicationError> {
        let mut transaction = self.store.begin_transaction().await?;
        let mut policy_set = self
            .store
            .policy_set_by_id_for_update_in_transaction(
                &mut transaction,
                organization_id,
                policy_set_id,
            )
            .await?
            .ok_or(OrganizationApplicationError::PolicySetNotFound(
                policy_set_id,
            ))?;
        policy_set.archive(now);
        self.store
            .save_policy_set_in_transaction(&mut transaction, &policy_set)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(policy_set)
    }

    pub async fn activate_policy_set(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PolicySet, OrganizationApplicationError> {
        let mut transaction = self.store.begin_transaction().await?;
        let mut policy_set = self
            .store
            .policy_set_by_id_for_update_in_transaction(
                &mut transaction,
                organization_id,
                policy_set_id,
            )
            .await?
            .ok_or(OrganizationApplicationError::PolicySetNotFound(
                policy_set_id,
            ))?;
        let documents = deserialize_policy_documents(&policy_set.cedar_policies);
        self.validate_policy_documents(&documents)?;
        let all_policy_sets = self
            .store
            .policy_sets_by_organization_for_update_in_transaction(
                &mut transaction,
                organization_id,
            )
            .await?;
        let archive_ids = policy_set_ids_to_archive(&policy_set, &all_policy_sets)
            .into_iter()
            .collect::<BTreeSet<_>>();
        for mut active in all_policy_sets
            .into_iter()
            .filter(|candidate| archive_ids.contains(&candidate.id))
        {
            active.archive(now);
            self.store
                .save_policy_set_in_transaction(&mut transaction, &active)
                .await?;
        }
        policy_set.activate(now);
        self.store
            .save_policy_set_in_transaction(&mut transaction, &policy_set)
            .await?;
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(policy_set)
    }

    pub async fn delete_policy_set(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<(), OrganizationApplicationError> {
        let mut transaction = self.store.begin_transaction().await?;
        self.store
            .policy_set_by_id_for_update_in_transaction(
                &mut transaction,
                organization_id,
                policy_set_id,
            )
            .await?
            .ok_or(OrganizationApplicationError::PolicySetNotFound(
                policy_set_id,
            ))?;
        if !self
            .store
            .delete_policy_set_in_transaction(&mut transaction, organization_id, policy_set_id)
            .await?
        {
            return Err(OrganizationApplicationError::PolicySetNotFound(
                policy_set_id,
            ));
        }
        transaction.commit().await.map_err(RepositoryError::from)?;
        Ok(())
    }

    pub async fn get_policy_set(
        &self,
        organization_id: Uuid,
        policy_set_id: Uuid,
    ) -> Result<Option<PolicySet>, OrganizationApplicationError> {
        Ok(self
            .store
            .policy_set_by_id(organization_id, policy_set_id)
            .await?)
    }

    pub async fn list_policy_sets(
        &self,
        organization_id: Uuid,
        status: Option<PolicySetStatus>,
    ) -> Result<Vec<PolicySet>, OrganizationApplicationError> {
        Ok(self
            .store
            .policy_sets_by_organization(organization_id, status)
            .await?)
    }

    fn validate_policy_documents(
        &self,
        policies: &[CedarPolicyDocument],
    ) -> Result<(), OrganizationApplicationError> {
        let errors = self.policy_validation_errors(policies)?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(OrganizationApplicationError::InvalidPolicy(
                errors.join("; "),
            ))
        }
    }
}

#[must_use]
pub fn policy_set_ids_to_archive(target: &PolicySet, policy_sets: &[PolicySet]) -> Vec<Uuid> {
    policy_sets
        .iter()
        .filter(|candidate| {
            candidate.id != target.id
                && candidate.policy_type == target.policy_type
                && candidate.status == PolicySetStatus::Active
        })
        .map(|candidate| candidate.id)
        .collect()
}

#[must_use]
pub fn deserialize_policy_documents(value: &str) -> Vec<CedarPolicyDocument> {
    if let Ok(documents) = serde_json::from_str::<Vec<CedarPolicyDocument>>(value) {
        return documents;
    }
    let effect = Regex::new(r"\b(permit|forbid)\s*\(")
        .expect("static legacy Cedar expression must compile")
        .captures(value)
        .and_then(|captures| captures.get(1))
        .map_or("permit", |effect| effect.as_str());
    vec![CedarPolicyDocument {
        policy_id: "legacy_policy".into(),
        effect: effect.into(),
        cedar_text: value.into(),
        description: None,
        enabled: true,
    }]
}

#[must_use]
pub fn validate_policy_documents(
    policies: &[CedarPolicyDocument],
    validator: &CedarPolicyValidator,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut policy_ids = BTreeSet::new();
    let mut enabled_text = Vec::new();
    for policy in policies {
        if !policy_ids.insert(policy.policy_id.clone()) {
            errors.push(format!("Duplicate policy_id: {}", policy.policy_id));
        }
        let effect_pattern = Regex::new(&format!(r"\b{}\s*\(", regex::escape(&policy.effect)))
            .expect("escaped effect must compile");
        if !effect_pattern.is_match(&policy.cedar_text) {
            errors.push(format!(
                "Policy {} effect does not match its Cedar statement",
                policy.policy_id
            ));
        }
        if policy.enabled {
            enabled_text.push(policy.cedar_text.as_str());
        }
    }
    if !errors.is_empty() {
        return errors;
    }
    if enabled_text.is_empty() {
        return vec!["At least one policy must be enabled".into()];
    }
    match validator.validate_policy_source(&enabled_text.join("\n\n")) {
        Ok(()) => Vec::new(),
        Err(error) => vec![error.to_string()],
    }
}

fn serialize_policy_documents(
    policies: &[CedarPolicyDocument],
) -> Result<String, OrganizationApplicationError> {
    serde_json::to_string(policies)
        .map_err(|error| OrganizationApplicationError::InvalidPolicy(error.to_string()))
}

fn require_text(value: &str, error: &'static str) -> Result<(), OrganizationApplicationError> {
    if value.trim().is_empty() {
        Err(OrganizationApplicationError::InvalidCommand(error))
    } else {
        Ok(())
    }
}

const fn enabled_by_default() -> bool {
    true
}
