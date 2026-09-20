//! Language-neutral issuance-offer projection for internal Applications.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use marty_oid4vci::issuer::create_credential_offer;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    canvas_lti_launch::CanvasLtiClock, credential::CredentialTransaction,
    initiation_response::python_quote, internal_application_domain::python_datetime,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredOfferWallet {
    pub id: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub platforms: Vec<String>,
}

#[async_trait]
pub trait InternalApplicationWalletCatalog: Send + Sync {
    /// Wallet discovery is intentionally best-effort, matching the published
    /// Python boundary: an unavailable registry yields an offer without wallet
    /// buttons rather than failing the credential offer itself.
    async fn wallets(&self, credential_template_id: &str) -> Vec<RegisteredOfferWallet>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuanceOfferWallet {
    pub id: String,
    pub name: String,
    pub logo_url: Option<String>,
    pub deep_link_url: String,
    pub platforms: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct IssuanceOfferResponse {
    pub offer_url: String,
    pub qr_payload: String,
    pub wallets: Vec<IssuanceOfferWallet>,
    pub email_payload: Map<String, Value>,
    pub expires_at: String,
    pub transaction_id: String,
    pub status: String,
    pub credential_offer_uris: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationOfferProjectionError {
    #[error("issuance offer is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct InternalApplicationOfferProjector {
    issuer_base_url: Arc<str>,
    wallets: Arc<dyn InternalApplicationWalletCatalog>,
    clock: Arc<dyn CanvasLtiClock>,
}

impl std::fmt::Debug for InternalApplicationOfferProjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InternalApplicationOfferProjector")
            .field("issuer_base_url", &self.issuer_base_url)
            .finish_non_exhaustive()
    }
}

impl InternalApplicationOfferProjector {
    pub fn new(
        issuer_base_url: impl Into<Arc<str>>,
        wallets: Arc<dyn InternalApplicationWalletCatalog>,
        clock: Arc<dyn CanvasLtiClock>,
    ) -> Result<Self, InternalApplicationOfferProjectionError> {
        let issuer_base_url = issuer_base_url.into();
        let issuer_base_url = issuer_base_url.trim().trim_end_matches('/');
        if issuer_base_url.is_empty() {
            return Err(InternalApplicationOfferProjectionError::Unavailable);
        }
        Ok(Self {
            issuer_base_url: Arc::from(issuer_base_url),
            wallets,
            clock,
        })
    }

    pub async fn project(
        &self,
        organization_id: &str,
        credential_template_id: Option<&str>,
        transaction: &CredentialTransaction,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferProjectionError> {
        if organization_id.is_empty() || transaction.organization_id != organization_id {
            return Err(InternalApplicationOfferProjectionError::Unavailable);
        }
        let credential_type = transaction
            .credential_type
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("default");
        let issuer_url = format!("{}/org/{organization_id}", self.issuer_base_url);
        let offer_url = encoded_offer_uri(
            "openid-credential-offer://",
            &issuer_url,
            credential_type,
            &transaction.pre_authorized_code,
        )?;
        let mut credential_offer_uris = BTreeMap::new();
        for configuration in &transaction.wallet_configs {
            let Some(configuration) = configuration.as_object() else {
                continue;
            };
            let Some(wallet_id) = configuration
                .get("wallet_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let scheme = configuration
                .get("deep_link_scheme")
                .and_then(Value::as_str)
                .unwrap_or("openid-credential-offer://");
            let configuration_id = if configuration.get("format_variant").and_then(Value::as_str)
                == Some("mso_mdoc")
            {
                format!("{credential_type}#mdoc")
            } else {
                credential_type.to_owned()
            };
            credential_offer_uris.insert(
                wallet_id.to_owned(),
                encoded_offer_uri(
                    scheme,
                    &issuer_url,
                    &configuration_id,
                    &transaction.pre_authorized_code,
                )?,
            );
        }

        let registered = match credential_template_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(template_id) => self.wallets.wallets(template_id).await,
            None => Vec::new(),
        };
        let wallets = registered
            .into_iter()
            .map(|wallet| IssuanceOfferWallet {
                id: wallet.id,
                name: wallet.name,
                logo_url: wallet.logo_url,
                deep_link_url: offer_url.clone(),
                platforms: wallet.platforms,
            })
            .collect();
        let email_payload = Map::from_iter([
            ("subject".to_owned(), Value::String("Your credential is ready".to_owned())),
            (
                "body".to_owned(),
                Value::String(format!(
                    "Your credential has been approved and is ready to add to your wallet.\n\nClick the link below to receive your credential:\n{offer_url}\n\nOr scan the QR code from another device."
                )),
            ),
            ("offer_url".to_owned(), Value::String(offer_url.clone())),
        ]);
        Ok(IssuanceOfferResponse {
            qr_payload: offer_url.clone(),
            offer_url,
            wallets,
            email_payload,
            expires_at: python_datetime(transaction.expires_at),
            transaction_id: transaction.id.clone(),
            status: if self.clock.now() > transaction.expires_at {
                "expired"
            } else {
                "active"
            }
            .to_owned(),
            credential_offer_uris,
        })
    }
}

fn encoded_offer_uri(
    scheme: &str,
    issuer_url: &str,
    configuration_id: &str,
    pre_authorized_code: &str,
) -> Result<String, InternalApplicationOfferProjectionError> {
    let offer = create_credential_offer(
        issuer_url,
        &[configuration_id.to_owned()],
        Some(pre_authorized_code),
        false,
    )
    .map_err(|_| InternalApplicationOfferProjectionError::Unavailable)?;
    let separator = if scheme.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{scheme}{separator}credential_offer={}",
        python_quote(&offer)
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::credential::CredentialTransactionStatus;

    struct Catalog(Vec<RegisteredOfferWallet>);

    #[async_trait]
    impl InternalApplicationWalletCatalog for Catalog {
        async fn wallets(&self, credential_template_id: &str) -> Vec<RegisteredOfferWallet> {
            assert_eq!(credential_template_id, "credential-template-1");
            self.0.clone()
        }
    }

    struct Clock(DateTime<Utc>);

    impl CanvasLtiClock for Clock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn transaction(now: DateTime<Utc>) -> CredentialTransaction {
        CredentialTransaction {
            id: "transaction-1".into(),
            organization_id: "org-123".into(),
            credential_template_id: "credential-template-1".into(),
            revocation_profile_id: Some("revocation-profile-1".into()),
            renewal_of_credential_id: None,
            applicant_id: Some("applicant-1".into()),
            application_id: Some("application-1".into()),
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Issued,
            pre_authorized_code: "pre-authorized-code".into(),
            nonce: None,
            claims: Map::new(),
            credential_type: Some("EmployeeCredential".into()),
            selective_disclosure_claims: Vec::new(),
            zk_predicate_claims: Vec::new(),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".into(),
            wallet_configs: vec![json!({
                "wallet_id":"wallet-1",
                "deep_link_scheme":"example-wallet://open?source=elevenid",
                "format_variant":"mso_mdoc"
            })],
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
            delivery_mode: "wallet_only".into(),
            issuer_profile_id: Some("issuer-profile-1".into()),
            issuer_mode: "org_managed".into(),
            issuer_did: Some("did:web:issuer.example:org-123".into()),
            issuer_algorithm: Some("ES256".into()),
            signing_service_id: Some("kms-service-1".into()),
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: now,
            expires_at: now + Duration::minutes(10),
        }
    }

    #[tokio::test]
    async fn issued_transaction_remains_active_and_projects_frozen_offer_shape() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let projector = InternalApplicationOfferProjector::new(
            "https://issuer.example/",
            Arc::new(Catalog(vec![RegisteredOfferWallet {
                id: "wallet-1".into(),
                name: "Example Wallet".into(),
                logo_url: Some("https://wallet.example/logo.svg".into()),
                platforms: vec!["ios".into(), "android".into()],
            }])),
            Arc::new(Clock(now)),
        )
        .unwrap();
        let response = projector
            .project("org-123", Some("credential-template-1"), &transaction(now))
            .await
            .unwrap();

        assert_eq!(response.status, "active");
        assert_eq!(response.offer_url, response.qr_payload);
        assert!(response.offer_url.starts_with(
            "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A//issuer.example/org/org-123%22"
        ));
        assert_eq!(response.wallets[0].deep_link_url, response.offer_url);
        assert_eq!(
            response.email_payload["subject"],
            "Your credential is ready"
        );
        assert!(response.credential_offer_uris["wallet-1"]
            .starts_with("example-wallet://open?source=elevenid&credential_offer="));
        assert!(response.credential_offer_uris["wallet-1"].contains("EmployeeCredential%23mdoc"));

        let value = serde_json::to_value(&response).unwrap();
        let fields = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-internal-applications.json"
        ))
        .unwrap();
        assert_eq!(
            fields,
            contract["response_models"]["IssuanceOfferResponse"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<BTreeSet<_>>()
        );
    }

    #[tokio::test]
    async fn expiry_depends_on_time_not_transaction_lifecycle_status() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let projector = InternalApplicationOfferProjector::new(
            "https://issuer.example",
            Arc::new(Catalog(Vec::new())),
            Arc::new(Clock(now + Duration::minutes(11))),
        )
        .unwrap();
        let response = projector
            .project("org-123", None, &transaction(now))
            .await
            .unwrap();
        assert_eq!(response.status, "expired");
        assert!(response.wallets.is_empty());
    }
}
