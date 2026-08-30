use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use marty_oid4vci::issuer::create_credential_offer;
use serde::Serialize;
use thiserror::Error;
use tracing::warn;

use crate::{
    credential::{
        credential_configuration_id_for_format, CredentialTransaction, CredentialTransactionStatus,
    },
    initiation::{InitiationRequest, InitiationReservation},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InitiationOfferResponse {
    pub id: String,
    pub organization_id: String,
    pub credential_template_id: String,
    pub status: String,
    pub credential_offer_uri: String,
    pub credential_offer_uris: BTreeMap<String, String>,
    pub credential_offer_labels: BTreeMap<String, String>,
    pub pre_auth_code: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiationDidcommDeliveryReceipt {
    pub service_endpoint: String,
}

#[async_trait]
pub trait InitiationDidcommDelivery: Send + Sync {
    async fn deliver(
        &self,
        transaction: &CredentialTransaction,
        holder_did: &str,
    ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError>;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("DIDComm delivery failed")]
pub struct InitiationDidcommDeliveryError;

#[derive(Clone)]
pub struct InitiationOfferProjector {
    issuer_base_url: Arc<str>,
    didcomm: Arc<dyn InitiationDidcommDelivery>,
}

impl std::fmt::Debug for InitiationOfferProjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitiationOfferProjector")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl InitiationOfferProjector {
    pub fn new(
        issuer_base_url: impl Into<Arc<str>>,
        didcomm: Arc<dyn InitiationDidcommDelivery>,
    ) -> Result<Self, InitiationOfferProjectionError> {
        let issuer_base_url = issuer_base_url.into();
        if issuer_base_url.trim().is_empty() {
            return Err(InitiationOfferProjectionError::InvalidIssuerBaseUrl);
        }
        Ok(Self {
            issuer_base_url: Arc::from(issuer_base_url.trim_end_matches('/')),
            didcomm,
        })
    }

    pub async fn project(
        &self,
        reservation: InitiationReservation,
        request: &InitiationRequest,
    ) -> Result<InitiationOfferResponse, InitiationOfferProjectionError> {
        let transaction = reservation.transaction;
        let credential_type = transaction
            .credential_type
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("default");
        let default_configuration_id = credential_configuration_id_for_format(
            credential_type,
            &transaction.credential_payload_format,
        );
        let offer = self.offer_json(
            &transaction.organization_id,
            None,
            &default_configuration_id,
            &transaction.pre_authorized_code,
        )?;
        let credential_offer_uri = format!(
            "openid-credential-offer://?credential_offer={}",
            python_quote(&offer)
        );
        let mut credential_offer_uris = BTreeMap::new();
        let mut credential_offer_labels = BTreeMap::new();
        for wallet in &transaction.wallet_configs {
            let Some(wallet) = wallet.as_object() else {
                continue;
            };
            let Some(wallet_id) = wallet
                .get("wallet_id")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let variant = wallet
                .get("format_variant")
                .and_then(serde_json::Value::as_str);
            let uri = if variant == Some("didcomm_v2") {
                self.didcomm_uri(&transaction, request).await
            } else {
                let configuration_id = credential_configuration_id_for_format(
                    credential_type,
                    variant.unwrap_or_default(),
                );
                let offer = self.offer_json(
                    &transaction.organization_id,
                    variant,
                    &configuration_id,
                    &transaction.pre_authorized_code,
                )?;
                let scheme = wallet
                    .get("deep_link_scheme")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                    .unwrap_or("openid-credential-offer://");
                let separator = if scheme.contains('?') { '&' } else { '?' };
                format!(
                    "{scheme}{separator}credential_offer={}",
                    python_quote(&offer)
                )
            };
            credential_offer_uris.insert(wallet_id.to_owned(), uri);
            if let Some(label) = wallet
                .get("display_name")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
            {
                credential_offer_labels.insert(wallet_id.to_owned(), label.to_owned());
            }
        }
        Ok(InitiationOfferResponse {
            id: transaction.id,
            organization_id: transaction.organization_id,
            credential_template_id: transaction.credential_template_id,
            status: transaction_status(transaction.status).to_owned(),
            credential_offer_uri,
            credential_offer_uris,
            credential_offer_labels,
            pre_auth_code: transaction.pre_authorized_code,
            expires_at: transaction
                .expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false),
        })
    }

    fn offer_json(
        &self,
        organization_id: &str,
        variant: Option<&str>,
        configuration_id: &str,
        pre_authorized_code: &str,
    ) -> Result<String, InitiationOfferProjectionError> {
        let suffix = match variant {
            Some("credential-manager") => "/credential-manager",
            Some("apple-wallet") => "/apple-wallet",
            _ => "",
        };
        let issuer_url = format!("{}/org/{organization_id}{suffix}", self.issuer_base_url);
        create_credential_offer(
            &issuer_url,
            &[configuration_id.to_owned()],
            Some(pre_authorized_code),
            false,
        )
        .map_err(|_| InitiationOfferProjectionError::OfferUnavailable)
    }

    async fn didcomm_uri(
        &self,
        transaction: &CredentialTransaction,
        request: &InitiationRequest,
    ) -> String {
        let holder_did = request
            .holder_did
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                request
                    .subject_did
                    .as_deref()
                    .filter(|value| !value.is_empty())
            });
        if let Some(holder_did) = holder_did {
            match self.didcomm.deliver(transaction, holder_did).await {
                Ok(receipt) if !receipt.service_endpoint.is_empty() => {
                    return format!("didcomm://{}", receipt.service_endpoint)
                }
                Ok(_) | Err(_) => {
                    warn!(
                        didcomm_stage = "auto-delivery",
                        "DIDComm auto-delivery failed"
                    );
                }
            }
        }
        format!("didcomm://pending?transaction_id={}", transaction.id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InitiationOfferProjectionError {
    #[error("issuer base URL is required")]
    InvalidIssuerBaseUrl,
    #[error("credential offer is unavailable")]
    OfferUnavailable,
}

fn transaction_status(status: CredentialTransactionStatus) -> &'static str {
    match status {
        CredentialTransactionStatus::Pending => "pending",
        CredentialTransactionStatus::Authorized => "authorized",
        CredentialTransactionStatus::Signing => "signing",
        CredentialTransactionStatus::Issued => "issued",
        CredentialTransactionStatus::Failed => "failed",
        CredentialTransactionStatus::Expired => "expired",
        CredentialTransactionStatus::Revoked => "revoked",
    }
}

fn python_quote(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'~' | b'/') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(output, "%{byte:02X}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    #[derive(Clone)]
    struct TestDidcomm {
        receipt: Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError>,
    }

    #[async_trait]
    impl InitiationDidcommDelivery for TestDidcomm {
        async fn deliver(
            &self,
            _transaction: &CredentialTransaction,
            holder_did: &str,
        ) -> Result<InitiationDidcommDeliveryReceipt, InitiationDidcommDeliveryError> {
            assert_eq!(holder_did, "did:key:holder");
            self.receipt.clone()
        }
    }

    fn reservation(wallet_configs: Vec<serde_json::Value>) -> InitiationReservation {
        InitiationReservation {
            created: true,
            transaction: CredentialTransaction {
                id: "transaction-1".into(),
                organization_id: "org-1".into(),
                credential_template_id: "template-1".into(),
                revocation_profile_id: Some("profile-1".into()),
                renewal_of_credential_id: None,
                applicant_id: None,
                application_id: None,
                subject_did: Some("did:key:holder".into()),
                idempotency_key_hash: None,
                idempotency_request_hash: None,
                status: CredentialTransactionStatus::Pending,
                pre_authorized_code: "pre-auth-code".into(),
                nonce: None,
                claims: Default::default(),
                credential_type: Some("EmployeeCredential".into()),
                selective_disclosure_claims: Vec::new(),
                zk_predicate_claims: Vec::new(),
                credential_payload_format: "w3c_vcdm_v2_sd_jwt".into(),
                wallet_configs,
                validity_days: 365,
                renewable: false,
                renewal_window_days: 30,
                delivery_mode: "wallet_only".into(),
                issuer_profile_id: Some("issuer-profile-1".into()),
                issuer_mode: "org_managed".into(),
                issuer_did: Some("did:web:issuer.example".into()),
                issuer_algorithm: Some("ES256".into()),
                signing_service_id: Some("signer-1".into()),
                reserved_credential_id: None,
                oid4vci_client_id: None,
                created_at: Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).unwrap(),
                expires_at: Utc.with_ymd_and_hms(2026, 9, 6, 12, 0, 0).unwrap(),
            },
        }
    }

    fn request() -> InitiationRequest {
        serde_json::from_value(json!({
            "organization_id": "org-1",
            "credential_template_id": "template-1",
            "subject_did": "did:key:holder",
            "issuer_did": "did:web:issuer.example"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn projects_wallet_variants_from_the_committed_snapshot() {
        let projector = InitiationOfferProjector::new(
            "https://issuer.example/",
            Arc::new(TestDidcomm {
                receipt: Ok(InitiationDidcommDeliveryReceipt {
                    service_endpoint: "agent.example/inbox".into(),
                }),
            }),
        )
        .unwrap();
        let response = projector
            .project(
                reservation(vec![
                    json!({
                        "wallet_id":"credential-manager",
                        "display_name":"Android",
                        "deep_link_scheme":"openid4vp://launch?source=marty",
                        "format_variant":"credential-manager"
                    }),
                    json!({
                        "wallet_id":"apple",
                        "format_variant":"apple-wallet"
                    }),
                    json!({
                        "wallet_id":"didcomm",
                        "format_variant":"didcomm_v2"
                    }),
                ]),
                &request(),
            )
            .await
            .unwrap();

        assert_eq!(response.status, "pending");
        assert_eq!(response.expires_at, "2026-09-06T12:00:00+00:00");
        assert!(response.credential_offer_uri.starts_with(
            "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A//issuer.example/org/org-1%22"
        ));
        assert!(response.credential_offer_uris["credential-manager"]
            .starts_with("openid4vp://launch?source=marty&credential_offer="));
        assert!(
            response.credential_offer_uris["credential-manager"].contains("/credential-manager")
        );
        assert!(response.credential_offer_uris["apple"].contains("/apple-wallet"));
        assert_eq!(
            response.credential_offer_uris["didcomm"],
            "didcomm://agent.example/inbox"
        );
        assert_eq!(
            response.credential_offer_labels["credential-manager"],
            "Android"
        );
    }

    #[tokio::test]
    async fn didcomm_failure_and_missing_holder_use_the_stable_pending_uri() {
        let projector = InitiationOfferProjector::new(
            "https://issuer.example",
            Arc::new(TestDidcomm {
                receipt: Err(InitiationDidcommDeliveryError),
            }),
        )
        .unwrap();
        let response = projector
            .project(
                reservation(vec![json!({
                    "wallet_id":"didcomm",
                    "format_variant":"didcomm_v2"
                })]),
                &request(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.credential_offer_uris["didcomm"],
            "didcomm://pending?transaction_id=transaction-1"
        );
    }

    #[test]
    fn percent_encoding_matches_python_quote_safe_slash_behavior() {
        assert_eq!(
            python_quote(r#"{"issuer":"https://issuer.example/org/1","value":"a b"}"#),
            "%7B%22issuer%22%3A%22https%3A//issuer.example/org/1%22%2C%22value%22%3A%22a%20b%22%7D"
        );
    }
}
