use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationSecretMetadata {
    pub id: String,
    pub organization_id: String,
    pub provider: String,
    pub purpose: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedIntegrationSecret {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub provider: String,
    pub purpose: String,
    pub secret_hint: Option<String>,
    pub metadata: Map<String, Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ManagedIntegrationSecret {
    #[must_use]
    pub fn secret_ref(&self) -> String {
        integration_secret_ref(&self.organization_id, &self.id)
    }
}

#[derive(Clone, PartialEq)]
pub struct NewIntegrationSecret {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub provider: String,
    pub purpose: String,
    pub value: String,
    pub metadata: Value,
}

impl fmt::Debug for NewIntegrationSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewIntegrationSecret")
            .field("id", &self.id)
            .field("organization_id", &self.organization_id)
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("purpose", &self.purpose)
            .field("value", &"[REDACTED]")
            .field("metadata", &"[REDACTED]")
            .finish()
    }
}

impl NewIntegrationSecret {
    #[must_use]
    pub fn secret_ref(&self) -> String {
        integration_secret_ref(&self.organization_id, &self.id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IntegrationSecretError {
    #[error("integration secret persistence is unavailable")]
    RepositoryUnavailable,
}

#[must_use]
pub fn integration_secret_ref(organization_id: &str, secret_id: &str) -> String {
    format!("org_secret://{organization_id}/{secret_id}")
}

#[must_use]
pub fn integration_secret_hint(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| {
        format!(
            "...{}",
            value
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>()
        )
    })
}

#[must_use]
pub fn integration_secret_id_from_ref<'value>(
    organization_id: &str,
    secret_ref: &'value str,
) -> Option<&'value str> {
    secret_ref
        .strip_prefix(&format!("org_secret://{organization_id}/"))
        .filter(|value| !value.is_empty() && !value.contains('/'))
}

#[cfg(test)]
mod reference_tests {
    use super::{integration_secret_id_from_ref, integration_secret_ref, NewIntegrationSecret};

    #[test]
    fn references_are_tenant_bound_and_values_are_redacted() {
        assert_eq!(
            integration_secret_ref("org-1", "secret-1"),
            "org_secret://org-1/secret-1"
        );
        assert_eq!(
            integration_secret_id_from_ref("org-1", "org_secret://org-1/secret-1"),
            Some("secret-1")
        );
        assert_eq!(
            integration_secret_id_from_ref("org-2", "org_secret://org-1/secret-1"),
            None
        );
        assert_eq!(
            integration_secret_id_from_ref("org-1", "org_secret://org-1/path/secret"),
            None
        );
        let secret = NewIntegrationSecret {
            id: "secret-1".to_owned(),
            organization_id: "org-1".to_owned(),
            name: "Secret".to_owned(),
            provider: "canvas".to_owned(),
            purpose: "oauth_access_token".to_owned(),
            value: "plaintext-sensitive".to_owned(),
            metadata: serde_json::json!({"token": "metadata-sensitive"}),
        };
        let debug = format!("{secret:?}");
        assert!(!debug.contains("plaintext-sensitive"));
        assert!(!debug.contains("metadata-sensitive"));
    }
}
