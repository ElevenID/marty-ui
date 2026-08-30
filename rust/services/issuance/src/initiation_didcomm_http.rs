use std::{fmt, sync::Arc};

use async_trait::async_trait;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    initiation_didcomm::{
        NativeInitiationDidcommDelivery, NativeInitiationDidcommDeliveryError,
        NativeInitiationDidcommDeliveryReceipt,
    },
    management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DidcommDeliverRequest {
    pub organization_id: String,
    pub transaction_id: String,
    pub holder_did: String,
}

#[async_trait]
pub trait DirectDidcommDelivery: Send + Sync {
    async fn deliver_for_organization(
        &self,
        organization_id: &str,
        transaction_id: &str,
        holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError>;
}

#[async_trait]
impl DirectDidcommDelivery for NativeInitiationDidcommDelivery {
    async fn deliver_for_organization(
        &self,
        organization_id: &str,
        transaction_id: &str,
        holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        NativeInitiationDidcommDelivery::deliver_for_organization(
            self,
            organization_id,
            transaction_id,
            holder_did,
        )
        .await
    }
}

#[derive(Clone)]
pub struct InitiationDidcommHttpService {
    delivery: Arc<dyn DirectDidcommDelivery>,
    security: ManagementSecurity,
}

impl fmt::Debug for InitiationDidcommHttpService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InitiationDidcommHttpService")
            .finish_non_exhaustive()
    }
}

impl InitiationDidcommHttpService {
    #[must_use]
    pub fn new(delivery: Arc<dyn DirectDidcommDelivery>, management_api_key: Option<&str>) -> Self {
        Self {
            delivery,
            security: ManagementSecurity::new(management_api_key),
        }
    }

    pub async fn deliver(
        &self,
        headers: &HeaderMap,
        request: &DidcommDeliverRequest,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, InitiationDidcommHttpError> {
        self.authorize(headers)?;
        self.deliver_authorized(request).await
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), InitiationDidcommHttpError> {
        self.security
            .authorize(header(headers, "X-API-Key"))
            .map_err(Into::into)
    }

    pub async fn deliver_authorized(
        &self,
        request: &DidcommDeliverRequest,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, InitiationDidcommHttpError> {
        self.delivery
            .deliver_for_organization(
                &request.organization_id,
                &request.transaction_id,
                &request.holder_did,
            )
            .await
            .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitiationDidcommHttpError {
    Security(TransactionReadError),
    Delivery(NativeInitiationDidcommDeliveryError),
}

impl From<TransactionReadError> for InitiationDidcommHttpError {
    fn from(value: TransactionReadError) -> Self {
        Self::Security(value)
    }
}

impl From<NativeInitiationDidcommDeliveryError> for InitiationDidcommHttpError {
    fn from(value: NativeInitiationDidcommDeliveryError) -> Self {
        Self::Delivery(value)
    }
}

impl IntoResponse for InitiationDidcommHttpError {
    fn into_response(self) -> Response {
        let (status, detail) = self.failure();
        (status, Json(json!({"detail": detail}))).into_response()
    }
}

impl InitiationDidcommHttpError {
    fn failure(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Security(TransactionReadError::ApiKeyNotConfigured) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server",
            ),
            Self::Security(TransactionReadError::ApiKeyMissing) => {
                (StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
            }
            Self::Security(TransactionReadError::InvalidApiKey) => {
                (StatusCode::UNAUTHORIZED, "Invalid API Key")
            }
            Self::Security(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Management authentication is unavailable",
            ),
            Self::Delivery(NativeInitiationDidcommDeliveryError::InvalidRequest) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid DIDComm delivery request",
            ),
            Self::Delivery(NativeInitiationDidcommDeliveryError::TransactionNotFound) => {
                (StatusCode::NOT_FOUND, "Issuance transaction not found")
            }
            Self::Delivery(
                NativeInitiationDidcommDeliveryError::InvalidTransactionState
                | NativeInitiationDidcommDeliveryError::ConcurrentDelivery,
            ) => (
                StatusCode::CONFLICT,
                "Issuance transaction is not available for DIDComm delivery",
            ),
            Self::Delivery(NativeInitiationDidcommDeliveryError::TransportFailed) => {
                (StatusCode::BAD_GATEWAY, "DIDComm delivery failed")
            }
            Self::Delivery(
                NativeInitiationDidcommDeliveryError::InvalidConfiguration
                | NativeInitiationDidcommDeliveryError::DidcommUnavailable
                | NativeInitiationDidcommDeliveryError::CredentialUnavailable
                | NativeInitiationDidcommDeliveryError::PostIssuanceUnavailable
                | NativeInitiationDidcommDeliveryError::RetryStateUnavailable,
            ) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "DIDComm delivery is unavailable",
            ),
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_stable_and_does_not_expose_internal_errors() {
        for (error, expected) in [
            (
                NativeInitiationDidcommDeliveryError::InvalidRequest,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                NativeInitiationDidcommDeliveryError::TransactionNotFound,
                StatusCode::NOT_FOUND,
            ),
            (
                NativeInitiationDidcommDeliveryError::ConcurrentDelivery,
                StatusCode::CONFLICT,
            ),
            (
                NativeInitiationDidcommDeliveryError::DidcommUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (status, _) = InitiationDidcommHttpError::Delivery(error).failure();
            assert_eq!(status, expected);
        }
    }

    #[test]
    fn public_request_rejects_unknown_provider_and_resolver_selectors() {
        assert!(serde_json::from_value::<DidcommDeliverRequest>(json!({
            "organization_id":"org-1",
            "transaction_id":"transaction-1",
            "holder_did":"did:example:holder",
            "universal_resolver_url":"https://attacker.example"
        }))
        .is_err());
    }
}
