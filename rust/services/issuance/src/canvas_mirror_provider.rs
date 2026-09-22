//! Canvas mirror provider port backed by the existing publication owner.

use async_trait::async_trait;
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use crate::{
    canvas_credentials_publication::{
        CanvasCredentialsPublicationService, CanvasPublicationContext,
    },
    canvas_credentials_status::CanvasCredentialsStatusService,
    canvas_lifecycle_delivery::CanvasLifecycleCredential,
    canvas_network_timeout::CanvasNetworkTimeout,
    canvas_operation_http::CanvasOperationHttpClient,
    canvas_provider_http::{CanvasHttpClientPolicy, CanvasOriginPolicy},
    credential::CredentialTransaction,
    credential_management::{
        CredentialLifecycleAction, ManagedCredential, ManagedCredentialStatus,
    },
    lossless_json::postgres_object,
};

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasMirrorPublicationOutcome {
    pub external_credential_id: Option<String>,
    pub external_issuer_id: Option<String>,
    pub metadata: Map<String, Value>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{0}")]
pub struct CanvasMirrorProviderError(pub String);

#[async_trait]
pub trait CanvasMirrorPublicationProvider: Send + Sync {
    async fn publish(
        &self,
        credential: &Value,
        transaction: &CredentialTransaction,
        platform: &Value,
        delivery: &Value,
    ) -> Result<CanvasMirrorPublicationOutcome, CanvasMirrorProviderError>;
}

#[async_trait]
pub trait CanvasMirrorStatusProvider: Send + Sync {
    async fn synchronize(
        &self,
        credential: &Value,
        transaction_id: &str,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<Map<String, Value>, CanvasMirrorProviderError>;
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CanvasMirrorAlertWebhookError {
    #[error("Canvas mirror alert webhook URL is invalid")]
    InvalidUrl,
    #[error("Canvas mirror alert webhook URL contains embedded credentials")]
    EmbeddedCredentials,
    #[error("Canvas mirror alert webhook payload could not be serialized")]
    Serialization,
    #[error("Canvas mirror alert webhook transport failed")]
    Transport,
    #[error("Canvas mirror alert webhook returned a non-success response")]
    HttpStatus,
}

impl CanvasMirrorAlertWebhookError {
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_url",
            Self::EmbeddedCredentials => "embedded_credentials_refused",
            Self::Serialization => "serialization_failed",
            Self::Transport => "transport_failed",
            Self::HttpStatus => "non_success_status",
        }
    }
}

#[async_trait]
pub trait CanvasMirrorAlertWebhook: Send + Sync {
    async fn post(&self, payload: Value) -> Result<(), CanvasMirrorAlertWebhookError>;
}

/// Uses the same DNS pinning, redirect refusal, timeout, and private-network
/// policy as every other Canvas-owned outbound request.
pub struct TransportCanvasMirrorAlertWebhook {
    client: CanvasOperationHttpClient,
    url: String,
}

impl TransportCanvasMirrorAlertWebhook {
    #[must_use]
    pub fn new(policy: CanvasHttpClientPolicy, url: String) -> Self {
        let timeout = CanvasNetworkTimeout::from_seconds(policy.timeout.as_secs_f64());
        Self {
            client: CanvasOperationHttpClient::new(CanvasOriginPolicy::from(&policy), timeout),
            url,
        }
    }
}

#[async_trait]
impl CanvasMirrorAlertWebhook for TransportCanvasMirrorAlertWebhook {
    async fn post(&self, payload: Value) -> Result<(), CanvasMirrorAlertWebhookError> {
        let url = Url::parse(&self.url).map_err(|_| CanvasMirrorAlertWebhookError::InvalidUrl)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CanvasMirrorAlertWebhookError::EmbeddedCredentials);
        }
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let body = serde_json::to_vec(&payload)
            .map_err(|_| CanvasMirrorAlertWebhookError::Serialization)?;
        let response = self
            .client
            .send(http::Method::POST, url, headers, body)
            .await
            .map_err(|_| CanvasMirrorAlertWebhookError::Transport)?;
        if response.response.status().is_success() {
            Ok(())
        } else {
            Err(CanvasMirrorAlertWebhookError::HttpStatus)
        }
    }
}

#[async_trait]
impl CanvasMirrorStatusProvider for CanvasCredentialsStatusService {
    async fn synchronize(
        &self,
        credential: &Value,
        transaction_id: &str,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<Map<String, Value>, CanvasMirrorProviderError> {
        let credential = managed_credential(credential)?;
        let outcome = self
            .synchronize_provider(
                CanvasLifecycleCredential {
                    credential: &credential,
                    transaction_id,
                },
                platform,
                delivery,
                action,
                reason,
            )
            .await
            .map_err(|failure| {
                CanvasMirrorProviderError(
                    failure
                        .message()
                        .as_scalar()
                        .unwrap_or("Canvas Credentials status provider failed")
                        .to_owned(),
                )
            })?;
        postgres_object(&outcome).map_err(|_| {
            CanvasMirrorProviderError(
                "Canvas Credentials status provider returned unpersistable metadata".to_owned(),
            )
        })
    }
}

#[async_trait]
impl CanvasMirrorPublicationProvider for CanvasCredentialsPublicationService {
    async fn publish(
        &self,
        credential: &Value,
        transaction: &CredentialTransaction,
        platform: &Value,
        delivery: &Value,
    ) -> Result<CanvasMirrorPublicationOutcome, CanvasMirrorProviderError> {
        let result = CanvasCredentialsPublicationService::publish(
            self,
            CanvasPublicationContext {
                credential,
                transaction,
                platform,
                delivery,
            },
        )
        .await
        .map_err(|failure| {
            CanvasMirrorProviderError(
                failure
                    .message()
                    .as_scalar()
                    .unwrap_or("Canvas Credentials provider failed")
                    .to_owned(),
            )
        })?;
        Ok(CanvasMirrorPublicationOutcome {
            external_credential_id: result
                .external_credential_id
                .and_then(|value| value.as_scalar().map(str::to_owned)),
            external_issuer_id: result
                .external_issuer_id
                .and_then(|value| value.as_scalar().map(str::to_owned)),
            metadata: postgres_object(&result.metadata).map_err(|_| {
                CanvasMirrorProviderError(
                    "Canvas Credentials provider returned unpersistable metadata".to_owned(),
                )
            })?,
        })
    }
}

fn managed_credential(value: &Value) -> Result<ManagedCredential, CanvasMirrorProviderError> {
    let required = |key: &str| {
        value[key].as_str().map(str::to_owned).ok_or_else(|| {
            CanvasMirrorProviderError("Canvas lifecycle stored credential is invalid".to_owned())
        })
    };
    let optional = |key: &str| value[key].as_str().map(str::to_owned);
    let status = match value["status"].as_str() {
        Some("active") => ManagedCredentialStatus::Active,
        Some("suspended") => ManagedCredentialStatus::Suspended,
        Some("revoked") => ManagedCredentialStatus::Revoked,
        _ => {
            return Err(CanvasMirrorProviderError(
                "Canvas lifecycle stored credential is invalid".to_owned(),
            ))
        }
    };
    let date = |key: &str| {
        value[key]
            .as_str()
            .and_then(|date| date.parse().ok())
            .ok_or_else(|| {
                CanvasMirrorProviderError(
                    "Canvas lifecycle stored credential is invalid".to_owned(),
                )
            })
    };
    let optional_date = |key: &str| {
        value[key]
            .as_str()
            .map(|date| {
                date.parse().map_err(|_| {
                    CanvasMirrorProviderError(
                        "Canvas lifecycle stored credential is invalid".to_owned(),
                    )
                })
            })
            .transpose()
    };
    Ok(ManagedCredential {
        id: required("id")?,
        transaction_id: required("transaction_id")?,
        organization_id: required("organization_id")?,
        credential_template_id: required("credential_template_id")?,
        issuer_did: optional("issuer_did"),
        status,
        status_updated_at: date("status_updated_at")?,
        revoked: value["revoked"]
            .as_bool()
            .unwrap_or(status == ManagedCredentialStatus::Revoked),
        revoked_at: optional_date("revoked_at")?,
        revocation_reason: optional("revocation_reason"),
        revocation_profile_id: optional("revocation_profile_id"),
        status_list_entries: value["status_list_entries"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    })
}
