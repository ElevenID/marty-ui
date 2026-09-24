use std::{fmt, sync::Arc};

use async_trait::async_trait;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use crate::{
    credential::CredentialTransactionStatus,
    initiation_didcomm::{
        NativeDidcommError, NativeInitiationDidcommDelivery, NativeInitiationDidcommDeliveryError,
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
        self.deliver_authorized(headers, request).await
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), InitiationDidcommHttpError> {
        self.security
            .authorize(header(headers, "X-API-Key"))
            .map_err(Into::into)
    }

    pub async fn deliver_authorized(
        &self,
        headers: &HeaderMap,
        request: &DidcommDeliverRequest,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, InitiationDidcommHttpError> {
        self.security.require_organization(
            header(headers, "X-Organization-ID"),
            &request.organization_id,
            true,
        )?;
        let result = self
            .delivery
            .deliver_for_organization(
                &request.organization_id,
                &request.transaction_id,
                &request.holder_did,
            )
            .await;
        match &result {
            Ok(receipt)
                if receipt.status
                    == crate::initiation_didcomm::NativeDidcommDeliveryStatus::Delivered =>
            {
                info!(
                    didcomm_owner = "direct",
                    didcomm_outcome = "delivered",
                    "DIDComm direct delivery completed"
                );
            }
            Ok(receipt) => {
                warn!(
                    didcomm_owner = "direct",
                    didcomm_outcome = "delivery_failed",
                    failure_class = receipt_failure_class(receipt),
                    "DIDComm direct delivery failed"
                );
            }
            Err(error) => {
                warn!(
                    didcomm_owner = "direct",
                    didcomm_outcome = "unavailable",
                    error_class = delivery_error_class(error),
                    "DIDComm direct delivery failed"
                );
            }
        }
        result.map_err(Into::into)
    }
}

fn receipt_failure_class(receipt: &NativeInitiationDidcommDeliveryReceipt) -> &'static str {
    match receipt.error.as_deref() {
        Some(error) if error.starts_with("HTTP ") => "http_status",
        _ => "transport_exception",
    }
}

fn delivery_error_class(error: &NativeInitiationDidcommDeliveryError) -> &'static str {
    match error {
        NativeInitiationDidcommDeliveryError::InvalidConfiguration => "invalid_configuration",
        NativeInitiationDidcommDeliveryError::InvalidRequest => "invalid_request",
        NativeInitiationDidcommDeliveryError::TransactionNotFound => "transaction_not_found",
        NativeInitiationDidcommDeliveryError::InvalidTransactionState(_) => {
            "invalid_transaction_state"
        }
        NativeInitiationDidcommDeliveryError::DidcommUnavailable => "didcomm_unavailable",
        NativeInitiationDidcommDeliveryError::Prerequisite(_) => "prerequisite_unavailable",
        NativeInitiationDidcommDeliveryError::CredentialUnavailable => "credential_unavailable",
        NativeInitiationDidcommDeliveryError::ConcurrentDelivery => "concurrent_delivery",
        NativeInitiationDidcommDeliveryError::DeliveryOutcomeUnknown => "delivery_outcome_unknown",
        NativeInitiationDidcommDeliveryError::TransportFailed => "transport_failed",
        NativeInitiationDidcommDeliveryError::PostIssuanceUnavailable => {
            "post_issuance_unavailable"
        }
        NativeInitiationDidcommDeliveryError::RetryStateUnavailable => "retry_state_unavailable",
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
            Self::Security(TransactionReadError::TrustedOrganizationRequired) => (
                StatusCode::FORBIDDEN,
                "Trusted organization context is required",
            ),
            Self::Security(TransactionReadError::ResourceNotFound) => {
                (StatusCode::NOT_FOUND, "Resource not found")
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
            Self::Delivery(NativeInitiationDidcommDeliveryError::InvalidTransactionState(
                state,
            )) => {
                match state {
                    CredentialTransactionStatus::Issued => {
                        (StatusCode::CONFLICT, "Credential already issued")
                    }
                    CredentialTransactionStatus::Signing => {
                        (StatusCode::BAD_REQUEST, "Transaction in signing state")
                    }
                    CredentialTransactionStatus::Failed => {
                        (StatusCode::BAD_REQUEST, "Transaction in failed state")
                    }
                    CredentialTransactionStatus::Expired => {
                        (StatusCode::BAD_REQUEST, "Transaction in expired state")
                    }
                    CredentialTransactionStatus::Revoked => {
                        (StatusCode::BAD_REQUEST, "Transaction in revoked state")
                    }
                    // The native eligibility check never rejects these states.
                    CredentialTransactionStatus::Pending
                    | CredentialTransactionStatus::Authorized => (
                        StatusCode::CONFLICT,
                        "Issuance transaction is not available for DIDComm delivery",
                    ),
                }
            }
            Self::Delivery(NativeInitiationDidcommDeliveryError::ConcurrentDelivery) => (
                StatusCode::CONFLICT,
                "Issuance transaction is not available for DIDComm delivery",
            ),
            Self::Delivery(NativeInitiationDidcommDeliveryError::DeliveryOutcomeUnknown) => (
                StatusCode::CONFLICT,
                "DIDComm delivery outcome requires reconciliation",
            ),
            Self::Delivery(NativeInitiationDidcommDeliveryError::TransportFailed) => {
                (StatusCode::BAD_GATEWAY, "DIDComm delivery failed")
            }
            Self::Delivery(NativeInitiationDidcommDeliveryError::Prerequisite(reason)) => {
                match reason {
                    NativeDidcommError::MissingEndpoint => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Holder DID has no DIDComm service endpoint",
                    ),
                    NativeDidcommError::InvalidEndpoint => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DIDComm service endpoint is invalid",
                    ),
                    NativeDidcommError::HttpsRequired => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DIDComm service endpoint must use HTTPS",
                    ),
                    NativeDidcommError::EndpointUnresolvable => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DIDComm service endpoint could not be resolved",
                    ),
                    NativeDidcommError::EndpointNotPublic => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DIDComm service endpoint is not publicly routable",
                    ),
                    NativeDidcommError::IncompatibleKeyAgreement => (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Holder DID does not provide a compatible DIDComm key agreement method",
                    ),
                    NativeDidcommError::EncryptionPolicyUnavailable
                    | NativeDidcommError::SenderAuthenticationUnavailable => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DIDComm sender-authentication configuration is unavailable",
                    ),
                    NativeDidcommError::TlsUnavailable => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DIDComm TLS trust configuration is unavailable",
                    ),
                    _ => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DIDComm delivery is unavailable",
                    ),
                }
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
                NativeInitiationDidcommDeliveryError::DeliveryOutcomeUnknown,
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

    #[test]
    fn direct_owner_diagnostics_use_only_fixed_error_classes() {
        for (error, expected) in [
            (
                NativeInitiationDidcommDeliveryError::Prerequisite(
                    NativeDidcommError::TransportUnavailable,
                ),
                "prerequisite_unavailable",
            ),
            (
                NativeInitiationDidcommDeliveryError::DeliveryOutcomeUnknown,
                "delivery_outcome_unknown",
            ),
            (
                NativeInitiationDidcommDeliveryError::RetryStateUnavailable,
                "retry_state_unavailable",
            ),
        ] {
            assert_eq!(delivery_error_class(&error), expected);
        }
        let mut receipt = NativeInitiationDidcommDeliveryReceipt {
            transaction_id: "private-transaction".into(),
            credential_id: "private-credential".into(),
            holder_did: "did:example:private".into(),
            service_endpoint: "https://private.example/inbox".into(),
            didcomm_message_id: "private-message".into(),
            status: crate::initiation_didcomm::NativeDidcommDeliveryStatus::DeliveryFailed,
            error: Some("HTTP 502".into()),
        };
        assert_eq!(receipt_failure_class(&receipt), "http_status");
        receipt.error = Some("DIDComm transport failed".into());
        assert_eq!(receipt_failure_class(&receipt), "transport_exception");
    }
}
