//! Language-neutral issuance-offer projection for internal Applications.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use marty_oid4vci::issuer::create_credential_offer;
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    canvas_lti_launch::CanvasLtiClock,
    credential::CredentialTransaction,
    initiation::{hash_idempotency_key, hash_idempotency_request},
    initiation_response::python_quote,
    internal_application_approval::InternalApplicationTransactionPreparer,
    internal_application_domain::{python_datetime, ApplicationRecord, IssuanceEventRecord},
    internal_application_service::InternalApplicationApprovalError,
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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum InternalApplicationOfferError {
    #[error(transparent)]
    Approval(#[from] InternalApplicationApprovalError),
    #[error("Credential Template is required.")]
    CredentialTemplateRequired,
    #[error("Application issuance offer changed concurrently")]
    ConcurrentChange,
    #[error("Wallet invite has not been generated yet. Please contact the issuer.")]
    MissingTransactionBinding,
    #[error("Issuance transaction not found")]
    TransactionNotFound,
    #[error("Application issuance offer is temporarily unavailable")]
    Unavailable,
}

#[async_trait]
pub trait InternalApplicationOfferRepository: Send + Sync {
    /// Lock the application and either refresh its reusable pending transaction
    /// or atomically reserve and bind the supplied generation. The returned
    /// transaction is authoritative when concurrent callers propose different
    /// random IDs and pre-authorized codes for the same generation anchor.
    async fn reserve_or_refresh_offer(
        &self,
        application: &ApplicationRecord,
        prepared: &CredentialTransaction,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError>;

    async fn get_offer_transaction(
        &self,
        transaction_id: &str,
        organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError>;

    async fn append_offer_event(
        &self,
        event: &IssuanceEventRecord,
    ) -> Result<(), InternalApplicationOfferError>;
}

#[async_trait]
pub trait InternalApplicationOfferCoordinator: Send + Sync {
    async fn generate(
        &self,
        application: &ApplicationRecord,
        local_template: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError>;

    async fn get(
        &self,
        application: &ApplicationRecord,
        local_template: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError>;
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

#[derive(Clone)]
pub struct NativeInternalApplicationOfferCoordinator {
    repository: Arc<dyn InternalApplicationOfferRepository>,
    preparer: Arc<dyn InternalApplicationTransactionPreparer>,
    projector: InternalApplicationOfferProjector,
    clock: Arc<dyn CanvasLtiClock>,
}

impl std::fmt::Debug for NativeInternalApplicationOfferCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeInternalApplicationOfferCoordinator")
            .finish_non_exhaustive()
    }
}

impl NativeInternalApplicationOfferCoordinator {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InternalApplicationOfferRepository>,
        preparer: Arc<dyn InternalApplicationTransactionPreparer>,
        projector: InternalApplicationOfferProjector,
        clock: Arc<dyn CanvasLtiClock>,
    ) -> Self {
        Self {
            repository,
            preparer,
            projector,
            clock,
        }
    }

    async fn project_and_record(
        &self,
        application: &ApplicationRecord,
        local_template: Option<&ApplicationTemplateRecord>,
        transaction: &CredentialTransaction,
        generated: bool,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError> {
        let credential_template_id =
            local_template.and_then(|template| template.credential_template_id.as_deref());
        let response = self
            .projector
            .project(
                &application.organization_id,
                credential_template_id,
                transaction,
            )
            .await
            .map_err(|_| InternalApplicationOfferError::Unavailable)?;
        let event_type = if generated {
            "offer_generated"
        } else if response.status == "expired" {
            "offer_expired"
        } else {
            "offer_viewed"
        };
        let metadata = if generated {
            Map::from_iter([
                (
                    "expires_at".to_owned(),
                    Value::String(response.expires_at.clone()),
                ),
                (
                    "wallet_count".to_owned(),
                    Value::from(response.wallets.len()),
                ),
            ])
        } else {
            Map::from_iter([(
                "expired".to_owned(),
                Value::Bool(response.status == "expired"),
            )])
        };
        self.repository
            .append_offer_event(&IssuanceEventRecord {
                id: uuid::Uuid::new_v4().to_string(),
                transaction_id: Some(transaction.id.clone()),
                application_id: Some(application.id.clone()),
                event_type: event_type.to_owned(),
                metadata,
                created_at: self.clock.now(),
            })
            .await?;
        Ok(response)
    }
}

#[async_trait]
impl InternalApplicationOfferCoordinator for NativeInternalApplicationOfferCoordinator {
    async fn generate(
        &self,
        application: &ApplicationRecord,
        local_template: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError> {
        let local_template = local_template
            .filter(|template| {
                template
                    .credential_template_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            })
            .ok_or(InternalApplicationOfferError::CredentialTemplateRequired)?;
        let mut prepared = self
            .preparer
            .prepare_transaction(application, local_template)
            .await?;
        let generation_anchor = application
            .issuance_transaction_id
            .as_deref()
            .unwrap_or("initial");
        prepared.idempotency_key_hash = Some(hash_idempotency_key(&format!(
            "internal-application-offer:{}:{generation_anchor}",
            application.id
        )));
        let semantics = serde_json::json!({
            "purpose": "internal_application_offer",
            "generation_anchor": generation_anchor,
            "organization_id": prepared.organization_id,
            "application_id": prepared.application_id,
            "credential_template_id": prepared.credential_template_id,
            "applicant_id": prepared.applicant_id,
            "delivery_mode": prepared.delivery_mode,
            "claims": prepared.claims,
            "credential_type": prepared.credential_type,
            "credential_payload_format": prepared.credential_payload_format,
            "revocation_profile_id": prepared.revocation_profile_id,
            "wallet_configs": prepared.wallet_configs,
            "selective_disclosure_claims": prepared.selective_disclosure_claims,
            "zk_predicate_claims": prepared.zk_predicate_claims,
            "validity_days": prepared.validity_days,
            "renewable": prepared.renewable,
            "renewal_window_days": prepared.renewal_window_days,
            "issuer_profile_id": prepared.issuer_profile_id,
            "issuer_did_override": prepared.issuer_did,
            "issuer_algorithm": prepared.issuer_algorithm,
            "signing_service_id": prepared.signing_service_id,
        });
        prepared.idempotency_request_hash = Some(
            hash_idempotency_request(&semantics)
                .map_err(|_| InternalApplicationOfferError::Unavailable)?,
        );
        let transaction = self
            .repository
            .reserve_or_refresh_offer(application, &prepared, self.clock.now())
            .await?
            .ok_or(InternalApplicationOfferError::ConcurrentChange)?;
        self.project_and_record(application, Some(local_template), &transaction, true)
            .await
    }

    async fn get(
        &self,
        application: &ApplicationRecord,
        local_template: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError> {
        let transaction_id = application
            .issuance_transaction_id
            .as_deref()
            .ok_or(InternalApplicationOfferError::MissingTransactionBinding)?;
        let transaction = self
            .repository
            .get_offer_transaction(transaction_id, &application.organization_id)
            .await?
            .filter(|transaction| {
                transaction.application_id.as_deref() == Some(application.id.as_str())
            })
            .ok_or(InternalApplicationOfferError::TransactionNotFound)?;
        self.project_and_record(application, local_template, &transaction, false)
            .await
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
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{
        application_template_domain::ApplicationTemplateStatus,
        credential::CredentialTransactionStatus, internal_application_domain::ApplicationStatus,
    };

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

    #[derive(Default)]
    struct OfferRepository {
        transaction: Mutex<Option<CredentialTransaction>>,
        proposed: Mutex<Vec<CredentialTransaction>>,
        events: Mutex<Vec<IssuanceEventRecord>>,
    }

    #[async_trait]
    impl InternalApplicationOfferRepository for OfferRepository {
        async fn reserve_or_refresh_offer(
            &self,
            _application: &ApplicationRecord,
            prepared: &CredentialTransaction,
            _now: DateTime<Utc>,
        ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError> {
            self.proposed.lock().unwrap().push(prepared.clone());
            let mut transaction = self.transaction.lock().unwrap();
            if transaction.is_none() {
                *transaction = Some(prepared.clone());
            }
            Ok(transaction.clone())
        }

        async fn get_offer_transaction(
            &self,
            transaction_id: &str,
            organization_id: &str,
        ) -> Result<Option<CredentialTransaction>, InternalApplicationOfferError> {
            Ok(self
                .transaction
                .lock()
                .unwrap()
                .clone()
                .filter(|transaction| {
                    transaction.id == transaction_id
                        && transaction.organization_id == organization_id
                }))
        }

        async fn append_offer_event(
            &self,
            event: &IssuanceEventRecord,
        ) -> Result<(), InternalApplicationOfferError> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct Preparer {
        calls: AtomicUsize,
        now: DateTime<Utc>,
    }

    #[async_trait]
    impl InternalApplicationTransactionPreparer for Preparer {
        async fn prepare_transaction(
            &self,
            application: &ApplicationRecord,
            local_template: &ApplicationTemplateRecord,
        ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let mut transaction = transaction(self.now);
            transaction.id = format!("transaction-{call}");
            transaction.pre_authorized_code = format!("pre-authorized-code-{call}");
            transaction.status = CredentialTransactionStatus::Pending;
            transaction.application_id = Some(application.id.clone());
            transaction.organization_id = application.organization_id.clone();
            transaction.credential_template_id = local_template
                .credential_template_id
                .clone()
                .expect("credential template binding");
            Ok(transaction)
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

    fn application(now: DateTime<Utc>) -> ApplicationRecord {
        ApplicationRecord {
            id: "application-1".into(),
            organization_id: "org-123".into(),
            application_template_id: "application-template-1".into(),
            applicant_identifier: "applicant-1".into(),
            form_data: Map::new(),
            evidence_submissions: Vec::new(),
            integration_context: Map::new(),
            status: ApplicationStatus::Approved,
            review_notes: None,
            reviewer_id: Some("issuance-management-api".into()),
            rejection_reason: None,
            derived_claims: Map::new(),
            created_at: now,
            updated_at: now,
            submitted_at: now,
            reviewed_at: Some(now),
            expires_at: now + Duration::days(30),
            issuance_transaction_id: None,
            credential_id: None,
        }
    }

    fn application_template(now: DateTime<Utc>) -> ApplicationTemplateRecord {
        ApplicationTemplateRecord {
            id: "application-template-1".into(),
            organization_id: "org-123".into(),
            name: "Employee application".into(),
            description: None,
            credential_template_id: Some("credential-template-1".into()),
            form_fields: Vec::new(),
            evidence_requirements: Vec::new(),
            claim_collection_rules: Vec::new(),
            required_checks: Vec::new(),
            approval_strategy: "manual".into(),
            approval_policy_set_id: None,
            application_validity_days: 30,
            ui_config: Map::new(),
            notification_config: Map::new(),
            status: ApplicationTemplateStatus::Active,
            version: 1,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn concurrent_generation_reuses_one_hashed_reservation_and_records_each_request() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(OfferRepository::default());
        let coordinator = NativeInternalApplicationOfferCoordinator::new(
            repository.clone(),
            Arc::new(Preparer {
                calls: AtomicUsize::new(0),
                now,
            }),
            InternalApplicationOfferProjector::new(
                "https://issuer.example",
                Arc::new(Catalog(Vec::new())),
                Arc::new(Clock(now)),
            )
            .unwrap(),
            Arc::new(Clock(now)),
        );
        let application = application(now);
        let template = application_template(now);

        let (first, second) = tokio::join!(
            coordinator.generate(&application, Some(&template)),
            coordinator.generate(&application, Some(&template))
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.transaction_id, second.transaction_id);
        assert_eq!(first.offer_url, second.offer_url);
        let proposed = repository.proposed.lock().unwrap();
        assert_eq!(proposed.len(), 2);
        for transaction in proposed.iter() {
            assert_eq!(
                transaction.idempotency_key_hash.as_deref().unwrap().len(),
                64
            );
            assert_eq!(
                transaction
                    .idempotency_request_hash
                    .as_deref()
                    .unwrap()
                    .len(),
                64
            );
            assert_ne!(
                transaction.idempotency_key_hash.as_deref(),
                Some("internal-application-offer:application-1:initial")
            );
        }
        assert_eq!(
            repository
                .events
                .lock()
                .unwrap()
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            ["offer_generated", "offer_generated"]
        );
    }

    #[tokio::test]
    async fn issued_transaction_remains_readable_and_records_view_event() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(OfferRepository::default());
        *repository.transaction.lock().unwrap() = Some(transaction(now));
        let coordinator = NativeInternalApplicationOfferCoordinator::new(
            repository.clone(),
            Arc::new(Preparer {
                calls: AtomicUsize::new(0),
                now,
            }),
            InternalApplicationOfferProjector::new(
                "https://issuer.example",
                Arc::new(Catalog(Vec::new())),
                Arc::new(Clock(now)),
            )
            .unwrap(),
            Arc::new(Clock(now)),
        );
        let mut application = application(now);
        application.issuance_transaction_id = Some("transaction-1".into());

        let response = coordinator
            .get(&application, Some(&application_template(now)))
            .await
            .unwrap();
        assert_eq!(response.status, "active");
        assert_eq!(
            repository.events.lock().unwrap()[0].event_type,
            "offer_viewed"
        );
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
