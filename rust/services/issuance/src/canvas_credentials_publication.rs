//! Canvas Credentials publication candidate, without route or worker activation.
//! Delivery configuration, network policy and lossless codecs have shared owners.
use crate::{
    canvas_credentials_delivery_config::{
        config_value, error, metadata_sources, CanvasCredentialsDeliveryConfig,
        CanvasCredentialsProviderError, DeliveryConfiguration,
    },
    canvas_credentials_protocol::{quote_identifier, response_excerpt, truncate_text},
    canvas_credentials_transport::{
        CanvasCredentialsRequest, CanvasCredentialsTransport, HttpCanvasCredentialsTransport,
    },
    canvas_credentials_urls::assertion_url,
    canvas_credentials_validation::CanvasCredentialsSecretResolver,
    canvas_lti_launch::{CanvasLtiClock, SystemCanvasLtiClock},
    canvas_operator_secret::{CanvasOperatorSecretReader, FileCanvasOperatorSecretReader},
    canvas_provider_http::CanvasOriginPolicy,
    canvas_response_text::response_text,
    credential::CredentialTransaction,
    lossless_json::{LosslessJson, LosslessObject},
    owned_json_value::OwnedJsonValue,
    python_text::PythonText,
    python_value::{
        python_string, python_truthy, strip, PythonJsonValue, PythonValueNode, PythonValueView,
    },
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Eq, PartialEq)]
pub struct CanvasCredentialsPublicationConfig {
    pub delivery: CanvasCredentialsDeliveryConfig,
    pub assertion_url_template: Option<String>,
    pub provenance_base_url: Option<String>,
    pub assertion_narrative: Option<String>,
    pub recipient_hashed: bool,
    pub allow_duplicate_awards: bool,
}
impl Default for CanvasCredentialsPublicationConfig {
    fn default() -> Self {
        Self {
            delivery: Default::default(),
            assertion_url_template: None,
            provenance_base_url: None,
            assertion_narrative: None,
            recipient_hashed: true,
            allow_duplicate_awards: false,
        }
    }
}
impl std::fmt::Debug for CanvasCredentialsPublicationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanvasCredentialsPublicationConfig")
            .field("delivery", &self.delivery)
            .field(
                "assertion_url_template_configured",
                &self.assertion_url_template.is_some(),
            )
            .field(
                "provenance_base_url_configured",
                &self.provenance_base_url.is_some(),
            )
            .field(
                "assertion_narrative_configured",
                &self.assertion_narrative.is_some(),
            )
            .field("recipient_hashed", &self.recipient_hashed)
            .field("allow_duplicate_awards", &self.allow_duplicate_awards)
            .finish()
    }
}
impl CanvasCredentialsPublicationConfig {
    pub(crate) fn from_environment(
        delivery: CanvasCredentialsDeliveryConfig,
        values: &BTreeMap<String, String>,
    ) -> Self {
        let optional = |key: &str| values.get(key).cloned();
        let flag = |key: &str, default| {
            values
                .get(key)
                .map(|value| {
                    matches!(
                        strip(value).to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
                .unwrap_or(default)
        };
        Self {
            delivery,
            assertion_url_template: optional("CANVAS_CREDENTIALS_ASSERTION_URL_TEMPLATE"),
            provenance_base_url: [
                "CANVAS_CREDENTIALS_PROVENANCE_BASE_URL",
                "MARTY_ISSUER_BASE_URL",
                "ISSUER_BASE_URL",
                "PUBLIC_API_URL",
                "PUBLIC_BASE_URL",
            ]
            .iter()
            .filter_map(|key| values.get(*key))
            .map(|value| strip(value).trim_end_matches('/'))
            .find(|value| !value.is_empty())
            .map(str::to_owned),
            assertion_narrative: optional("CANVAS_CREDENTIALS_ASSERTION_NARRATIVE"),
            recipient_hashed: flag("CANVAS_CREDENTIALS_RECIPIENT_HASHED", true),
            allow_duplicate_awards: flag("CANVAS_CREDENTIALS_ALLOW_DUPLICATE_AWARDS", false),
        }
    }
}

/// Borrow the complete persisted credential projection: the lifecycle-only
/// ManagedCredential and signing IssuedCredential do not represent nullable
/// issuer/expiry and all publication fields. The transaction remains its shared
/// typed owner. Callers retain the OwnedJsonValue lifetime for JSON projections.
#[derive(Clone, Copy)]
pub struct CanvasPublicationContext<'a> {
    pub credential: &'a Value,
    pub transaction: &'a CredentialTransaction,
    pub platform: &'a Value,
    pub delivery: &'a Value,
}

/// No Debug or implicit wire conversion: returned IDs may contain Python
/// codepoints, and the original response may contain non-finite JSON values.
pub struct CanvasPublicationResult {
    pub external_credential_id: Option<PythonText>,
    pub external_issuer_id: Option<PythonText>,
    pub metadata: LosslessObject,
}

#[derive(Clone)]
pub struct CanvasCredentialsPublicationService {
    config: CanvasCredentialsPublicationConfig,
    secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    operator_secrets: Arc<dyn CanvasOperatorSecretReader>,
    transport: Arc<dyn CanvasCredentialsTransport>,
    clock: Arc<dyn CanvasLtiClock>,
}

impl CanvasCredentialsPublicationService {
    pub fn new(
        config: CanvasCredentialsPublicationConfig,
        secrets: Arc<dyn CanvasCredentialsSecretResolver>,
        transport: Arc<dyn CanvasCredentialsTransport>,
    ) -> Self {
        Self {
            config,
            secrets,
            operator_secrets: Arc::new(FileCanvasOperatorSecretReader),
            transport,
            clock: Arc::new(SystemCanvasLtiClock),
        }
    }
    pub fn with_clock(mut self, clock: Arc<dyn CanvasLtiClock>) -> Self {
        self.clock = clock;
        self
    }
    pub fn from_runtime(
        config: &crate::config::IssuanceServiceConfig,
        secrets: Arc<dyn CanvasCredentialsSecretResolver>,
    ) -> Self {
        Self::new(
            config.canvas_credentials_publication.clone(),
            secrets,
            Arc::new(HttpCanvasCredentialsTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    private_origin_allowlist: config.canvas_private_origin_allowlist.clone(),
                    allow_private_networks: config.canvas_allow_private_base_urls,
                    allow_http_localhost: config.canvas_allow_http_localhost_base_urls,
                },
                config.canvas_credentials_publish_timeout,
            )),
        )
    }
    fn delivery_configuration(&self) -> DeliveryConfiguration<'_> {
        DeliveryConfiguration {
            config: &self.config.delivery,
            secrets: &self.secrets,
            operator_secrets: &self.operator_secrets,
        }
    }
    pub async fn publish(
        &self,
        context: CanvasPublicationContext<'_>,
    ) -> Result<CanvasPublicationResult, CanvasCredentialsProviderError> {
        self.validate_context(context)?;
        let sources = metadata_sources(&context.delivery["metadata"]);
        let configuration = self.delivery_configuration();
        let delivery_organization = context.delivery["organization_id"]
            .as_str()
            .unwrap_or_default();
        let real = matches!(
            configuration.provider(&sources).as_str(),
            "badgr_api" | "canvas_credentials_api"
        );
        let issuer_id = || {
            let value = config_value(
                &sources,
                &[
                    "canvas_credentials_issuer_id",
                    "issuer_id",
                    "external_issuer_id",
                ],
                self.config.delivery.provider.issuer_id.as_deref(),
            );
            (!value.is_empty()).then_some(value)
        };
        let (url, token, issuer, payload, badgr_metadata) = if real {
            let token = configuration.token(delivery_organization, &sources).await?.ok_or_else(|| error("CANVAS_CREDENTIALS_API_TOKEN is required for real Canvas Credentials publish"))?;
            let base = configuration.base_url(&sources)?;
            let scope = config_value(
                &sources,
                &["assertion_scope", "canvas_credentials_assertion_scope"],
                self.config.delivery.provider.assertion_scope.as_deref(),
            );
            let scope = if scope.is_empty() {
                "badgeclasses".into()
            } else {
                scope.to_lowercase()
            };
            if !matches!(scope.as_str(), "badgeclasses" | "issuers") {
                return Err(error(
                    "CANVAS_CREDENTIALS_ASSERTION_SCOPE must be 'badgeclasses' or 'issuers'",
                ));
            }
            let badge = config_value(
                &sources,
                &["canvas_credentials_badgeclass_id", "badgeclass_id"],
                self.config.delivery.provider.badgeclass_id.as_deref(),
            );
            if badge.is_empty() {
                return Err(error("CANVAS_CREDENTIALS_BADGECLASS_ID is required for real Canvas Credentials publish"));
            }
            let issuer = issuer_id();
            let template = self
                .config
                .assertion_url_template
                .as_deref()
                .map(|value| PythonText::from(value.to_owned()));
            let base_text = PythonText::from(base.clone());
            let scope_text = PythonText::from(scope.clone());
            let badge_text = PythonText::from(badge.clone());
            let issuer_text = issuer.as_ref().map(|value| PythonText::from(value.clone()));
            let url = assertion_url(
                template.as_ref(),
                &base_text,
                &scope_text,
                Some(&badge_text),
                issuer_text.as_ref(),
            )
            .map_err(|failure| match failure.into_scalar_message() {
                Ok(message) => error(message),
                Err(message) => CanvasCredentialsProviderError::NonScalarRuntime(message),
            })?
            .into_scalar()
            .map_err(CanvasCredentialsProviderError::NonScalarRuntime)?;
            let payload = self.badgr_payload(context, &badge, &scope)?;
            (
                url,
                Some(token),
                issuer,
                payload,
                Some((base, scope, badge)),
            )
        } else {
            let url = self
                .config
                .delivery
                .provider
                .publish_url
                .as_deref()
                .map(strip)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| error("CANVAS_CREDENTIALS_PUBLISH_URL is not configured"))?
                .to_owned();
            let token = configuration.token(delivery_organization, &sources).await?;
            let issuer = issuer_id();
            let payload = self.bridge_payload(context, &issuer)?;
            (url, token, issuer, payload, None)
        };
        let operation = if real { "assertion publish" } else { "publish" };
        let response = self
            .transport
            .send(CanvasCredentialsRequest {
                method: reqwest::Method::POST,
                url: url.clone(),
                token,
                body: payload,
            })
            .await
            .map_err(|detail| {
                error(format!(
                    "Canvas Credentials {operation} request failed: {detail}"
                ))
            })?;
        if !(200..300).contains(&response.status) {
            let text = response_text(&response.body, response.content_type.as_deref())?;
            let excerpt = truncate_text(&text);
            let prefix = format!(
                "Canvas Credentials {operation} failed (HTTP {}): ",
                response.status
            );
            let message = PythonText::from_codepoints(
                prefix.chars().map(u32::from).chain(excerpt.codepoints()),
            )
            .expect("valid Python codepoints");
            return Err(match message.into_scalar() {
                Ok(value) => error(value),
                Err(value) => CanvasCredentialsProviderError::NonScalarRuntime(value),
            });
        }
        let response_payload = response_excerpt(&response.body, response.content_type.as_deref())?;
        let view = match &response_payload {
            LosslessJson::Parsed(tree) if tree.is_object() => {
                Some(PythonJsonValue::Tree(tree, tree.root()))
            }
            _ => None,
        };
        let fallback = issuer.as_ref().map(|value| Value::String(value.clone()));
        let fallback = fallback.as_ref().map(PythonJsonValue::Scalar);
        let (credential_id, external_issuer, public_url) = if real {
            let assertion = view.and_then(badgr_result);
            let field = |name| assertion.and_then(|value| value.field(name));
            let reference = field("assertionRef").and_then(|value| value.field("assertionUrl"));
            let id = as_python_text(or_values([
                field("entityId"),
                field("id"),
                field("openBadgeId"),
                reference,
            ]));
            if id
                .as_ref()
                .is_none_or(|value| value.codepoints().next().is_none())
            {
                return Err(error(
                    "Canvas Credentials assertion publish response did not include an assertion id",
                ));
            }
            (
                id,
                as_python_text(or_values([
                    field("issuer"),
                    field("issuerOpenBadgeId"),
                    fallback,
                ])),
                as_python_text(or_values([
                    field("openBadgeId"),
                    reference,
                    field("sourceUrl"),
                ])),
            )
        } else {
            let field = |name| view.and_then(|value| value.field(name));
            (
                as_python_text(or_values([
                    field("credential_id"),
                    field("id"),
                    field("credential").and_then(|value| value.field("id")),
                    field("data").and_then(|value| value.field("id")),
                ])),
                as_python_text(or_values([
                    field("issuer_id"),
                    field("issuer").and_then(|value| value.field("id")),
                    field("data").and_then(|value| value.field("issuer_id")),
                    fallback,
                ])),
                None,
            )
        };
        let now = crate::canvas_legacy_ingest::timestamp_string(self.clock.now());
        let mut metadata = crate::lossless_json::object(json!({"publish_url":url,"published_at":now,"http_status":response.status,"request_id":response.request_id}).as_object().unwrap().clone());
        metadata.insert("publish_response".into(), response_payload);
        if let Some((base, scope, badge)) = badgr_metadata {
            for (key, value) in [
                ("provider", json!("badgr_api")),
                ("api_base_url", json!(base)),
                ("assertion_scope", json!(scope)),
                ("badgeclass_id", json!(badge)),
                ("provenance_url", json!(self.provenance_url(context)?)),
            ] {
                metadata.insert(key.into(), value.into());
            }
            for key in ["credential_url", "open_badge_id"] {
                metadata.insert(
                    key.into(),
                    public_url
                        .clone()
                        .map(LosslessJson::Text)
                        .unwrap_or_else(|| Value::Null.into()),
                );
            }
        }
        Ok(CanvasPublicationResult {
            external_credential_id: credential_id,
            external_issuer_id: external_issuer,
            metadata,
        })
    }
    fn validate_context(
        &self,
        context: CanvasPublicationContext<'_>,
    ) -> Result<(), CanvasCredentialsProviderError> {
        let organization = context.delivery["organization_id"]
            .as_str()
            .unwrap_or_default();
        if !self.config.delivery.portable_enabled
            || strip(organization).is_empty()
            || !self
                .config
                .delivery
                .pilot_organizations
                .contains(strip(organization))
        {
            return Err(error(
                "Portable Canvas delivery is not enabled for this organization",
            ));
        }
        if strip(organization)
            != strip(
                context.credential["organization_id"]
                    .as_str()
                    .unwrap_or_default(),
            )
            || strip(organization)
                != strip(
                    context.platform["organization_id"]
                        .as_str()
                        .unwrap_or_default(),
                )
            || strip(organization) != strip(&context.transaction.organization_id)
            || context.delivery["credential_id"] != context.credential["id"]
            || context.delivery["transaction_id"] != context.credential["transaction_id"]
            || context.credential["transaction_id"].as_str()
                != Some(context.transaction.id.as_str())
            || context.delivery["transaction_id"].as_str() != Some(context.transaction.id.as_str())
        {
            return Err(error("Canvas delivery resources are unavailable"));
        }
        Ok(())
    }
    fn provenance_url(
        &self,
        context: CanvasPublicationContext<'_>,
    ) -> Result<String, CanvasCredentialsProviderError> {
        let base = self.config.provenance_base_url.as_deref().filter(|value| !value.is_empty())
            .ok_or_else(|| error("Canvas Credentials verification base URL is required; set CANVAS_CREDENTIALS_PROVENANCE_BASE_URL or a public issuer/base URL"))?;
        let mut fields = vec![
            ("delivery_record_id", &context.delivery["id"]),
            ("credential_id", &context.credential["id"]),
        ];
        for (key, value) in [
            ("canvas_account_id", &context.platform["canvas_account_id"]),
            ("organization_id", &context.credential["organization_id"]),
        ] {
            if python_truthy(value) {
                fields.push((key, value));
            }
        }
        let query = fields
            .into_iter()
            .map(|(key, value)| {
                let text = python_string(value).expect("scalar stored JSON");
                format!("{key}={}", quote_identifier(&text).replace("%20", "+"))
            })
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!("{base}/console/org/operate/verify?{query}"))
    }
    fn bridge_payload(
        &self,
        context: CanvasPublicationContext<'_>,
        issuer: &Option<String>,
    ) -> Result<Value, CanvasCredentialsProviderError> {
        let c = context.credential;
        let t = context.transaction;
        let issuer_did = c
            .get("issuer_did")
            .filter(|value| python_truthy(value))
            .cloned()
            .unwrap_or_else(|| json!(t.issuer_did));
        Ok(json!({
            "issuer_id": issuer, "organization_id": c.get("organization_id").filter(|value| python_truthy(value)).cloned().unwrap_or_else(|| json!(t.organization_id)),
            "canvas_platform_id": context.platform["id"],
            "canvas_program_binding_id": context.delivery["metadata"]["canvas_program_binding_id"],
            "canvas_account_id": context.platform["canvas_account_id"], "canvas_base_url": context.platform["canvas_base_url"],
            "credential": {
                "id": c["id"], "transaction_id": t.id, "credential_template_id": c["credential_template_id"],
                "format": if t.credential_payload_format.is_empty() { "w3c_vcdm_v2_sd_jwt" } else { &t.credential_payload_format },
                "jwt": c["credential_jwt"], "hash": c["credential_hash"], "issuer_did": issuer_did,
                "revocation_profile_id": c["revocation_profile_id"], "status_list_entries": c["status_list_entries"],
                "issued_at": required_timestamp(&c["issued_at"])? , "expires_at": optional_timestamp(&c["expires_at"])? ,
            },
            "recipient": {
                "applicant_id": c.get("applicant_id").filter(|value| python_truthy(value)).cloned().unwrap_or_else(|| json!(t.applicant_id)),
                "subject_did": c.get("subject_did").filter(|value| python_truthy(value)).cloned().unwrap_or_else(|| json!(t.subject_did)),
            },
            "source": {"delivery_record_id": context.delivery["id"], "delivery_mode": context.delivery["delivery_mode"], "application_id": t.application_id},
            "metadata": sanitized_metadata(&context.delivery["metadata"]),
        }))
    }
    fn badgr_payload(
        &self,
        context: CanvasPublicationContext<'_>,
        badge: &str,
        scope: &str,
    ) -> Result<Value, CanvasCredentialsProviderError> {
        let metadata = &context.delivery["metadata"];
        let claims = &context.transaction.claims;
        let provenance = self.provenance_url(context)?;
        let narrative = self
            .config
            .assertion_narrative
            .as_deref()
            .map(strip)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                first_string([
                    claims.get("achievement_description"),
                    claims.get("description"),
                ])
            })
            .unwrap_or_else(|| "Issued by ElevenID from verified Canvas course activity.".into());
        let recipient = first_string([
            metadata.get("recipient_email"), metadata.get("learner_email"), metadata.get("canvas_learner_email"),
            claims.get("email"), claims.get("learner_email"), claims.get("recipient_email"), claims.get("holder_email"),
            claims.get("lis_person_contact_email_primary"),
        ]).ok_or_else(|| error("Canvas Credentials publish requires a recipient email in transaction claims or delivery metadata"))?;
        let mut payload = json!({
            "issuedOn": required_timestamp(&context.credential["issued_at"])? ,
            "recipient": {"identity":recipient,"type":"email","hashed":self.config.recipient_hashed},
            "allowDuplicateAwards": self.config.allow_duplicate_awards, "narrative": narrative,
            "evidence": [{
                "url": provenance, "name":"ElevenID canonical credential record",
                "description":"Links this Canvas Credentials badge to the canonical ElevenID issuance, issuer DID, and lifecycle status.",
                "narrative":"Canvas was the learning context; ElevenID holds the signed credential, issuer identity, and revocation status.",
                "genre":"Credential provenance","audience":"Verifiers and employers",
            }],
            "extensions":{"value":{"elevenid":{
                "credential_id":context.credential["id"],"credential_hash":context.credential["credential_hash"],
                "issuer_did": context.credential.get("issuer_did").filter(|value| python_truthy(value)).cloned().unwrap_or_else(|| json!(context.transaction.issuer_did)),
                "delivery_record_id":context.delivery["id"],"canvas_account_id":context.platform["canvas_account_id"],"provenance_url":provenance,
            }}},
        });
        if scope == "issuers" {
            payload["badgeclass"] = json!(badge);
        }
        if let Some(expiry) = optional_timestamp(&context.credential["expires_at"])? {
            payload["expires"] = json!(expiry);
        }
        if let Some(value) = claims
            .get("ob3AwardProperties")
            .filter(|value| value.is_object())
        {
            payload["ob3AwardProperties"] = value.clone();
        }
        Ok(payload)
    }
}

fn required_timestamp(value: &Value) -> Result<String, CanvasCredentialsProviderError> {
    value
        .as_str()
        .and_then(crate::canvas_legacy_ingest::timestamp_projection)
        .ok_or(CanvasCredentialsProviderError::InvalidStoredData)
}

fn optional_timestamp(value: &Value) -> Result<Option<String>, CanvasCredentialsProviderError> {
    if value.is_null() {
        Ok(None)
    } else {
        required_timestamp(value).map(Some)
    }
}

fn first_string<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .filter(|value| !value.is_null())
        .filter_map(python_string)
        .map(|value| strip(&value).to_owned())
        .find(|value| !value.is_empty())
}

fn sanitized_metadata(value: &Value) -> Value {
    const SECRET_KEYS: &[&str] = &[
        "api_token",
        "canvas_credentials_api_token",
        "api_token_env",
        "api_token_secret_env",
        "canvas_credentials_api_token_env",
        "api_token_file",
        "api_token_secret_file",
        "canvas_credentials_api_token_file",
        "api_token_secret_id",
        "api_token_secret_ref",
        "api_token_ref",
        "canvas_credentials_api_token_secret_id",
        "canvas_credentials_api_token_secret_ref",
    ];
    let mut owned = OwnedJsonValue::copy(value);
    let mut pending = vec![&mut *owned];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(fields) => {
                fields.retain(|key, _| !SECRET_KEYS.contains(&key.as_str()));
                pending.extend(fields.values_mut());
            }
            Value::Array(values) => pending.extend(values.iter_mut()),
            _ => (),
        }
    }
    owned.take()
}

fn as_python_text(value: Option<PythonJsonValue<'_>>) -> Option<PythonText> {
    let value = value?;
    if matches!(value.view(), PythonValueNode::Null) {
        return None;
    }
    Some(PythonText::from_codepoints(value.string_points()).expect("valid Python codepoints"))
}
fn or_values<'a>(
    values: impl IntoIterator<Item = Option<PythonJsonValue<'a>>>,
) -> Option<PythonJsonValue<'a>> {
    let mut last = None;
    for value in values {
        last = value;
        if value.is_some_and(PythonValueView::truthy) {
            break;
        }
    }
    last
}
fn badgr_result(value: PythonJsonValue<'_>) -> Option<PythonJsonValue<'_>> {
    for name in ["result", "data"] {
        if let Some(field) = value.field(name) {
            if let Some(first) = field.first() {
                return first.is_object().then_some(first);
            }
            if field.is_object() {
                return Some(field);
            }
        }
    }
    value.is_object().then_some(value)
}

#[cfg(test)]
mod timestamp_invariant_tests {
    use super::*;

    #[test]
    fn malformed_projected_timestamp_is_distinct_closed_internal_data_error() {
        for value in [
            Value::Null,
            json!(false),
            json!(17),
            json!("synthetic-private-invalid-date"),
        ] {
            let error = required_timestamp(&value).unwrap_err();
            assert!(matches!(
                error,
                CanvasCredentialsProviderError::InvalidStoredData
            ));
            assert_eq!(
                error.message().as_scalar(),
                Some("Canvas publication stored data is invalid")
            );
            assert!(!format!("{error:?}").contains("synthetic-private"));
            assert!(!error.to_string().contains("synthetic-private"));
        }
        assert_eq!(optional_timestamp(&Value::Null).unwrap(), None);
        assert!(matches!(
            optional_timestamp(&json!(false)),
            Err(CanvasCredentialsProviderError::InvalidStoredData)
        ));
    }
}
