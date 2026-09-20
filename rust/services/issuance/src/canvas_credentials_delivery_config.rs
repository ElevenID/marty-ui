//! Delivery policy only. Management validation retains its distinct token policy.
use crate::{
    canvas_credentials_protocol::{https_origin, provider_alias, DEFAULT_API_BASE_URL},
    canvas_credentials_validation::{
        CanvasCredentialsSecretResolver, CanvasCredentialsValidationConfig,
    },
    canvas_operator_secret::{resolve_canvas_operator_token, CanvasOperatorSecretReader},
    canvas_response_text::CanvasResponseTextError,
    python_text::PythonText,
    python_value::{python_string, python_truthy, strip},
};
use serde_json::{Map, Value};
use std::{collections::BTreeSet, sync::Arc};
use url::Url;

#[derive(Clone, Default, Eq, PartialEq)]
pub struct CanvasCredentialsDeliveryConfig {
    /// Direct token and fixed file selector from the operator owner. No tenant
    /// metadata can select an environment variable or a filesystem path.
    pub provider: CanvasCredentialsValidationConfig,
    /// Legacy operator fallback selects a URL but does not grant origin trust.
    pub legacy_api_base_url: Option<String>,
    pub status_sync_url: Option<String>,
    pub revoke_url_template: Option<String>,
    pub portable_enabled: bool,
    pub pilot_organizations: BTreeSet<String>,
}

impl std::fmt::Debug for CanvasCredentialsDeliveryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanvasCredentialsDeliveryConfig")
            .field("provider", &self.provider)
            .field(
                "legacy_api_base_url_configured",
                &self.legacy_api_base_url.is_some(),
            )
            .field(
                "status_sync_url_configured",
                &self.status_sync_url.is_some(),
            )
            .field(
                "revoke_url_template_configured",
                &self.revoke_url_template.is_some(),
            )
            .field("portable_enabled", &self.portable_enabled)
            .field("pilot_organization_count", &self.pilot_organizations.len())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CanvasCredentialsProviderError {
    /// Repository/model invariant failure, not a provider RuntimeError projection.
    #[error("Canvas publication stored data is invalid")]
    InvalidStoredData,
    #[error("{0}")]
    Runtime(String),
    #[error("Canvas provider error contains non-scalar response text")]
    NonScalarRuntime(PythonText),
    #[error(transparent)]
    ResponseText(#[from] CanvasResponseTextError),
}

impl CanvasCredentialsProviderError {
    pub fn message(&self) -> PythonText {
        match self {
            Self::InvalidStoredData => "Canvas publication stored data is invalid"
                .to_owned()
                .into(),
            Self::Runtime(message) => message.clone().into(),
            Self::NonScalarRuntime(message) => message.clone(),
            Self::ResponseText(error) => error.to_string().into(),
        }
    }
}

pub(crate) struct DeliveryConfiguration<'a> {
    pub config: &'a CanvasCredentialsDeliveryConfig,
    pub secrets: &'a Arc<dyn CanvasCredentialsSecretResolver>,
    pub operator_secrets: &'a Arc<dyn CanvasOperatorSecretReader>,
}
impl DeliveryConfiguration<'_> {
    pub(crate) async fn token(
        &self,
        organization: &str,
        sources: &[&Map<String, Value>],
    ) -> Result<Option<String>, CanvasCredentialsProviderError> {
        for source in sources {
            let reference = [
                "api_token_secret_id",
                "api_token_secret_ref",
                "api_token_ref",
                "canvas_credentials_api_token_secret_id",
                "canvas_credentials_api_token_secret_ref",
            ]
            .iter()
            .filter_map(|key| source.get(*key))
            .find(|value| python_truthy(value))
            .and_then(python_string)
            .unwrap_or_default();
            let reference = strip(&reference);
            if reference.is_empty() {
                continue;
            }
            let identifier = if reference.starts_with("org_secret://") {
                reference
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
            } else {
                reference
            };
            // Lookup is always scoped by the verified delivery organization,
            // never by an organization component embedded in the reference.
            let token = self
                .secrets
                .secret_value(organization, identifier)
                .await
                .map_err(|()| error("Canvas Credentials secret lookup failed"))?;
            if let Some(token) = token.filter(|value| !value.is_empty()) {
                return Ok(Some(token));
            }
        }
        resolve_canvas_operator_token(
            self.config.provider.operator_api_token.as_deref(),
            self.config.provider.operator_api_token_file.as_deref(),
            self.operator_secrets.as_ref(),
        )
        .await
        .map_err(|failure| error(failure.to_string()))
    }

    pub(crate) fn provider(&self, sources: &[&Map<String, Value>]) -> String {
        let raw = config_value(
            sources,
            &["provider", "canvas_credentials_provider"],
            self.config.provider.provider.as_deref(),
        )
        .to_lowercase();
        if raw.is_empty() {
            if self
                .config
                .provider
                .publish_url
                .as_deref()
                .is_some_and(|value| !strip(value).is_empty())
            {
                return "bridge".into();
            }
            if !config_value(
                sources,
                &["badgeclass_id", "canvas_credentials_badgeclass_id"],
                self.config.provider.badgeclass_id.as_deref(),
            )
            .is_empty()
            {
                return "badgr_api".into();
            }
            return "bridge".into();
        }
        provider_alias(raw)
    }

    pub(crate) fn base_url(
        &self,
        sources: &[&Map<String, Value>],
    ) -> Result<String, CanvasCredentialsProviderError> {
        let configured = config_value(
            sources,
            &[
                "api_base_url",
                "base_url",
                "canvas_credentials_api_base_url",
                "canvas_credentials_base_url",
            ],
            self.config
                .provider
                .api_base_url
                .as_deref()
                .filter(|value| !strip(value).is_empty())
                .or(self.config.legacy_api_base_url.as_deref()),
        );
        let value = if configured.is_empty() {
            DEFAULT_API_BASE_URL
        } else {
            &configured
        }
        .trim_end_matches('/');
        let invalid = || error("Canvas Credentials API base URL must be a trusted HTTPS URL");
        let parsed = Url::parse(value).map_err(|_| invalid())?;
        let origin = https_origin(value).ok_or_else(invalid)?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(invalid());
        }
        let allowed = std::iter::once(DEFAULT_API_BASE_URL)
            .chain(self.config.provider.api_base_url.as_deref())
            .chain(
                self.config
                    .provider
                    .allowed_api_origins
                    .iter()
                    .map(String::as_str),
            )
            .filter_map(https_origin)
            .any(|candidate| candidate == origin);
        if !allowed {
            return Err(error(
                "Canvas Credentials API origin is not in CANVAS_CREDENTIALS_API_ORIGIN_ALLOWLIST",
            ));
        }
        Ok(value.into())
    }
}

pub(crate) fn metadata_sources(metadata: &Value) -> Vec<&Map<String, Value>> {
    let Some(metadata) = metadata.as_object() else {
        return Vec::new();
    };
    [
        "canvas_credentials",
        "canvas_credentials_config",
        "provider_config",
    ]
    .iter()
    .filter_map(|key| metadata.get(*key).and_then(Value::as_object))
    .chain(std::iter::once(metadata))
    .collect()
}

pub(crate) fn config_value(
    sources: &[&Map<String, Value>],
    keys: &[&str],
    operator: Option<&str>,
) -> String {
    sources
        .iter()
        .flat_map(|source| keys.iter().filter_map(|key| source.get(*key)))
        .filter(|value| !value.is_null())
        .filter_map(python_string)
        .map(|value| strip(&value).to_owned())
        .find(|value| !value.is_empty())
        .or_else(|| {
            operator
                .map(strip)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

pub(crate) fn error(detail: impl Into<String>) -> CanvasCredentialsProviderError {
    CanvasCredentialsProviderError::Runtime(detail.into())
}
