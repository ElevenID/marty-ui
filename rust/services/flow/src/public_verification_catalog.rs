//! Server-owned, finite request choices for the website demonstration.
//!
//! This is the admission contract, not a public route or authorization grant.
//! The HTTP adapter must still enforce visitor capabilities, consent, origin,
//! traffic limits, actor authorization and active reference validation before
//! preparing and persisting a canonical verification session.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    defined_verification::valid_policy_digest, FlowDefinitionRecord, VerificationDefinitionBinding,
};

const MAXIMUM_CONFIG_BYTES: usize = 65_536;
const MAXIMUM_SCENARIOS: usize = 8;
const MAXIMUM_CHOICES: usize = 8;

/// Operator configuration. Never serialize this as the public catalog response.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationCatalogConfig {
    pub organization_id: String,
    pub application_origin: String,
    pub notice: String,
    pub scenarios: Vec<PublicVerificationScenarioConfig>,
    #[serde(default)]
    pub examples: Vec<crate::PublicVerificationExampleConfig>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationScenarioConfig {
    pub id: String,
    pub label: String,
    pub choices: Vec<PublicVerificationChoiceConfig>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationChoiceConfig {
    pub id: String,
    pub label: String,
    pub definition: VerificationDefinitionBinding,
    pub presentation_policy_id: String,
    pub policy_configuration_digest: String,
}

/// Server-owned execution settings and request-local visitor admission. The
/// HTTP adapter must construct this from trusted configuration, not principal
/// headers supplied by the visitor.
pub struct PublicVerificationStartInvocation<'a> {
    pub selection: &'a PublicVerificationSelection,
    pub browser_origin: &'a str,
    pub issuer_did: &'a str,
    pub context: crate::VerificationStartContext<'a>,
    pub session_key: &'a crate::PublicVerificationSessionKey,
}

#[derive(Debug, Error)]
pub enum PublicVerificationStartError {
    #[error(transparent)]
    Catalog(#[from] PublicVerificationCatalogError),
    #[error(transparent)]
    Definition(#[from] crate::DefinedVerificationError),
    #[error(transparent)]
    Provider(#[from] crate::FlowProviderError),
    #[error(transparent)]
    Session(#[from] crate::PublicVerificationSessionError),
    #[error("FLOW.PUBLIC_VERIFICATION_OPERATOR_INVALID")]
    InvalidOperator,
}

/// Validated configuration is immutable; edits require a new catalog revision.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicVerificationCatalog {
    config: PublicVerificationCatalogConfig,
    revision: String,
}

#[derive(Debug, Eq, Error, PartialEq)]
pub enum PublicVerificationCatalogError {
    #[error("FLOW.PUBLIC_VERIFICATION_CATALOG_INVALID")]
    InvalidConfiguration,
    #[error("FLOW.PUBLIC_VERIFICATION_ORIGIN_REJECTED")]
    OriginRejected,
    #[error("FLOW.PUBLIC_VERIFICATION_CONSENT_REQUIRED")]
    ConsentRequired,
    #[error("FLOW.PUBLIC_VERIFICATION_CATALOG_CHANGED")]
    CatalogChanged,
    #[error("FLOW.PUBLIC_VERIFICATION_CHOICE_UNAVAILABLE")]
    ChoiceUnavailable,
    #[error("FLOW.PUBLIC_VERIFICATION_CONFIGURATION_CHANGED")]
    ConfigurationChanged,
}

/// The only visitor-supplied selection fields. No arbitrary policy, rule,
/// organization, callback, principal or flow identifiers are accepted.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicVerificationSelection {
    pub catalog_revision: String,
    pub scenario_id: String,
    pub choice_id: String,
    pub consent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PublicVerificationCatalogView<'a> {
    pub revision: &'a str,
    pub notice: &'a str,
    pub retention_policy: crate::PublicVerificationRetentionPolicy,
    pub scenarios: Vec<PublicVerificationScenarioView<'a>>,
    pub examples: Vec<crate::PublicVerificationExampleView<'a>>,
}

#[derive(Debug, Serialize)]
pub struct PublicVerificationScenarioView<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub choices: Vec<PublicVerificationChoiceView<'a>>,
}

#[derive(Debug, Serialize)]
pub struct PublicVerificationChoiceView<'a> {
    pub id: &'a str,
    pub label: &'a str,
}

impl PublicVerificationCatalog {
    pub(crate) fn organization_id(&self) -> &str {
        &self.config.organization_id
    }

    pub(crate) fn has_examples(&self) -> bool {
        !self.config.examples.is_empty()
    }

    pub(crate) fn origin(&self) -> &str {
        &self.config.application_origin
    }

    /// Canonical launch preparation after consent. Persistence/idempotent
    /// reconciliation and quotas belong to the HTTP/repository adapter.
    pub async fn prepare_selection(
        &self,
        providers: &crate::FlowProviderRegistry,
        callbacks: &mmf_push::WebhookDestinationRegistry,
        definition: &FlowDefinitionRecord,
        options: &crate::VerificationStartOptions,
        invocation: PublicVerificationStartInvocation<'_>,
    ) -> Result<crate::PreparedVerificationStart, PublicVerificationStartError> {
        self.require_origin(Some(invocation.browser_origin))?;
        let choice = self.select(invocation.selection)?;
        // A request-local gateway API actor must never turn an anonymous
        // capability into organization management authority.
        if providers.gateway_api_key_actor.is_some()
            || invocation.context.principal_id.trim().is_empty()
        {
            return Err(PublicVerificationStartError::InvalidOperator);
        }
        choice.definition.validate(definition)?;
        if definition.presentation_policy_id.as_deref()
            != Some(choice.presentation_policy_id.as_str())
        {
            return Err(PublicVerificationCatalogError::ConfigurationChanged.into());
        }
        providers
            .authorize(
                invocation.context.principal_id,
                &self.config.organization_id,
                "flow-instance:start",
                false,
            )
            .await?;
        crate::validate_definition_references(
            providers,
            invocation.context.principal_id,
            &self.config.organization_id,
            &crate::definition_references(definition),
            true,
        )
        .await?;
        // PostgreSQL persists timestamps at microsecond precision. Normalize
        // before constructing both the canonical instance and private access
        // deadline so a reloaded retry has exactly the same lifetime.
        let mut context = invocation.context;
        context.now = chrono::DateTime::from_timestamp_micros(context.now.timestamp_micros())
            .ok_or(crate::DefinedVerificationError::Start(
                crate::FlowVerificationStartError::InvalidClock,
            ))?;
        let mut prepared =
            crate::defined_verification::prepare_admitted_defined_verification_start(
                providers,
                callbacks,
                definition,
                &choice.definition,
                invocation.issuer_did,
                options,
                context,
                invocation.session_key.instance_id(
                    &self.config.organization_id,
                    &self.config.application_origin,
                ),
                Some(&choice.policy_configuration_digest),
            )
            .await?;
        if invocation
            .selection
            .request_digest
            .as_deref()
            .is_some_and(|expected| {
                prepared.instance.context[crate::defined_verification::REQUEST_DIGEST].as_str()
                    != Some(expected)
            })
        {
            return Err(PublicVerificationCatalogError::ConfigurationChanged.into());
        }
        invocation.session_key.bind(
            &mut prepared.instance,
            &self.config.application_origin,
            invocation.selection,
        )?;
        Ok(prepared)
    }

    pub fn from_json(
        contents: &str,
        allow_http_loopback: bool,
    ) -> Result<Self, PublicVerificationCatalogError> {
        use PublicVerificationCatalogError::InvalidConfiguration;
        if contents.len() > MAXIMUM_CONFIG_BYTES {
            return Err(InvalidConfiguration);
        }
        let config: PublicVerificationCatalogConfig =
            serde_json::from_str(contents).map_err(|_| InvalidConfiguration)?;
        if !bounded_text(&config.organization_id, 128)
            || !bounded_text(&config.notice, 2_048)
            || !valid_origin(&config.application_origin, allow_http_loopback)
            || config.scenarios.is_empty()
            || config.scenarios.len() > MAXIMUM_SCENARIOS
        {
            return Err(InvalidConfiguration);
        }
        let mut scenarios = BTreeSet::new();
        for scenario in &config.scenarios {
            if !slug(&scenario.id)
                || !scenarios.insert(&scenario.id)
                || !bounded_text(&scenario.label, 120)
                || scenario.choices.is_empty()
                || scenario.choices.len() > MAXIMUM_CHOICES
            {
                return Err(InvalidConfiguration);
            }
            let mut choices = BTreeSet::new();
            for choice in &scenario.choices {
                if !slug(&choice.id)
                    || !choices.insert(&choice.id)
                    || !bounded_text(&choice.label, 160)
                    || choice.definition.organization_id != config.organization_id
                    || !bounded_text(&choice.definition.definition_id, 128)
                    || choice.definition.version == 0
                    || !bounded_text(&choice.presentation_policy_id, 128)
                    || !valid_policy_digest(&choice.policy_configuration_digest)
                {
                    return Err(InvalidConfiguration);
                }
            }
        }
        crate::public_verification_example::validate_examples(&config.examples, &scenarios)?;
        let revision = marty_oid4vp_contract::digest_domain_json(
            "marty.public-verification/catalog/v2",
            &serde_json::json!({"catalog": &config, "retention_policy":crate::PublicVerificationRetentionPolicy::default()}),
        )
        .map_err(|_| InvalidConfiguration)?;
        Ok(Self { config, revision })
    }

    #[must_use]
    pub fn public_view(&self) -> PublicVerificationCatalogView<'_> {
        PublicVerificationCatalogView {
            revision: &self.revision,
            notice: &self.config.notice,
            retention_policy: crate::PublicVerificationRetentionPolicy::default(),
            examples: self
                .config
                .examples
                .iter()
                .map(|example| example.public_view())
                .collect(),
            scenarios: self
                .config
                .scenarios
                .iter()
                .map(|scenario| PublicVerificationScenarioView {
                    id: &scenario.id,
                    label: &scenario.label,
                    choices: scenario
                        .choices
                        .iter()
                        .map(|choice| PublicVerificationChoiceView {
                            id: &choice.id,
                            label: &choice.label,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Require the actual browser Origin on state-changing launch requests.
    /// Same-origin catalog GETs may omit Origin; the HTTP adapter should serve
    /// that non-sensitive projection using its explicit CORS policy instead.
    pub fn require_origin(
        &self,
        origin: Option<&str>,
    ) -> Result<(), PublicVerificationCatalogError> {
        if origin == Some(self.config.application_origin.as_str()) {
            Ok(())
        } else {
            Err(PublicVerificationCatalogError::OriginRejected)
        }
    }

    pub(crate) fn example(
        &self,
        scenario_id: &str,
        id: &str,
    ) -> Result<&crate::PublicVerificationExampleConfig, PublicVerificationCatalogError> {
        self.config
            .examples
            .iter()
            .find(|example| example.id == id && example.scenario_id == scenario_id)
            .ok_or(PublicVerificationCatalogError::ChoiceUnavailable)
    }

    pub fn select(
        &self,
        selection: &PublicVerificationSelection,
    ) -> Result<&PublicVerificationChoiceConfig, PublicVerificationCatalogError> {
        if !selection.consent {
            return Err(PublicVerificationCatalogError::ConsentRequired);
        }
        if selection.catalog_revision != self.revision {
            return Err(PublicVerificationCatalogError::CatalogChanged);
        }
        if let Some(id) = &selection.example_id {
            self.example(&selection.scenario_id, id)?;
        }
        self.config
            .scenarios
            .iter()
            .find(|scenario| scenario.id == selection.scenario_id)
            .and_then(|scenario| {
                scenario
                    .choices
                    .iter()
                    .find(|choice| choice.id == selection.choice_id)
            })
            .ok_or(PublicVerificationCatalogError::ChoiceUnavailable)
    }
}

impl PublicVerificationChoiceConfig {
    /// Validate both the versioned graph and the exact policy advertised to the
    /// visitor. The canonical starter must independently admit/check the same
    /// digest at request construction and policy evaluation.
    pub fn validate_definition(
        &self,
        definition: &FlowDefinitionRecord,
        actual_policy_digest: &str,
    ) -> Result<(), PublicVerificationCatalogError> {
        if self.definition.validate(definition).is_err()
            || definition.presentation_policy_id.as_deref()
                != Some(self.presentation_policy_id.as_str())
            || actual_policy_digest != self.policy_configuration_digest
        {
            return Err(PublicVerificationCatalogError::ConfigurationChanged);
        }
        Ok(())
    }
}

pub(crate) fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_origin(origin: &str, allow_http_loopback: bool) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    if url.origin().ascii_serialization() != origin
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return false;
    }
    url.scheme() == "https"
        || (allow_http_loopback
            && url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host == "localhost"
                    || host
                        .trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }))
}
