//! Native ordinary-application approval orchestration.
//!
//! Platform dependency checks, issuer resolution, transaction preparation,
//! and atomic application/transaction reservation.

use crate::application_issuance::{issuer_diagnostic_category, resolve_and_attach_required_issuer};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Utc};
use serde_json::Value;

use crate::{
    application_issuance::{ApplicationClock, ApprovalSeedGenerator},
    application_template_domain::ApplicationTemplateRecord,
    credential::{CredentialTransaction, CredentialTransactionStatus, IssuerContextResolver},
    internal_application_diagnostics::{
        warn_application_failure, InternalApplicationDiagnosticStage,
    },
    internal_application_domain::ApplicationRecord,
    internal_application_service::{InternalApplicationApprovalError, InternalApplicationApprover},
    python_value::{python_string, python_truthy},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalApplicationCredentialTemplate {
    pub organization_id: String,
    pub status: String,
    pub credential_type: String,
    pub vct: Option<String>,
    pub credential_payload_format: String,
    pub revocation_profile_id: Option<String>,
    pub wallet_configs: Vec<Value>,
    pub selective_disclosure_claims: Vec<String>,
    pub zk_predicate_claims: Vec<String>,
    pub validity_days: i64,
    pub renewable: bool,
    pub renewal_window_days: i64,
    pub issuer_did: String,
    pub issuer_algorithm: String,
}

#[async_trait]
pub trait InternalApplicationApprovalDependencies: Send + Sync {
    async fn credential_template(
        &self,
        template_id: &str,
    ) -> Result<Option<InternalApplicationCredentialTemplate>, InternalApplicationApprovalError>;

    async fn validate_revocation_profile(
        &self,
        organization_id: &str,
        profile_id: Option<&str>,
    ) -> Result<(), InternalApplicationApprovalError>;
}

#[async_trait]
pub trait InternalApplicationApprovalRepository: Send + Sync {
    async fn reserve_ordinary_approval(
        &self,
        application: &ApplicationRecord,
        transaction: &CredentialTransaction,
        reviewer_id: &str,
        review_notes: Option<&str>,
        reviewed_at: DateTime<Utc>,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError>;
}

#[async_trait]
pub trait InternalApplicationTransactionPreparer: Send + Sync {
    async fn prepare_transaction(
        &self,
        application: &ApplicationRecord,
        local_template: &ApplicationTemplateRecord,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError>;
}

#[async_trait]
pub trait InternalApplicationApprovalReader: Send + Sync {
    async fn reload_approved_application(
        &self,
        application_id: &str,
    ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError>;
}

#[derive(Clone)]
pub struct OrdinaryInternalApplicationApprover {
    repository: Arc<dyn InternalApplicationApprovalRepository>,
    dependencies: Arc<dyn InternalApplicationApprovalDependencies>,
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    seeds: Arc<dyn ApprovalSeedGenerator>,
    clock: Arc<dyn ApplicationClock>,
    issuer_base_url: Arc<str>,
    offer_ttl_minutes: i64,
}

impl std::fmt::Debug for OrdinaryInternalApplicationApprover {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrdinaryInternalApplicationApprover")
            .field("issuer_base_url", &self.issuer_base_url)
            .field("offer_ttl_minutes", &self.offer_ttl_minutes)
            .finish_non_exhaustive()
    }
}

impl OrdinaryInternalApplicationApprover {
    #[must_use]
    pub fn new(
        repository: Arc<dyn InternalApplicationApprovalRepository>,
        dependencies: Arc<dyn InternalApplicationApprovalDependencies>,
        issuer_resolver: Arc<dyn IssuerContextResolver>,
        seeds: Arc<dyn ApprovalSeedGenerator>,
        clock: Arc<dyn ApplicationClock>,
        issuer_base_url: impl Into<Arc<str>>,
        offer_ttl_minutes: i64,
    ) -> Self {
        Self {
            repository,
            dependencies,
            issuer_resolver,
            seeds,
            clock,
            issuer_base_url: issuer_base_url.into(),
            offer_ttl_minutes,
        }
    }

    fn expires_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, InternalApplicationApprovalError> {
        Duration::try_minutes(self.offer_ttl_minutes)
            .and_then(|duration| now.checked_add_signed(duration))
            .filter(|expires| (1..=9999).contains(&expires.year()))
            .ok_or(InternalApplicationApprovalError::Unavailable)
    }

    fn validate_template(
        &self,
        application: &ApplicationRecord,
        template: InternalApplicationCredentialTemplate,
    ) -> Result<InternalApplicationCredentialTemplate, InternalApplicationApprovalError> {
        if template.organization_id != application.organization_id {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template is not owned by this organization".to_owned(),
            ));
        }
        if !template.status.trim().eq_ignore_ascii_case("active") {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must be active".to_owned(),
            ));
        }
        if template.credential_type.trim().is_empty() {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must define a credential type".to_owned(),
            ));
        }
        if template
            .credential_payload_format
            .eq_ignore_ascii_case(marty_jwt_vc_issuance::DIRECT_PAYLOAD_FORMAT)
        {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "explicit JWT-VC application issuance is unavailable".into(),
            ));
        }
        if template.credential_payload_format.trim().is_empty() {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must define a credential payload format".to_owned(),
            ));
        }
        if !template.issuer_did.trim().starts_with("did:") {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must define an issuer DID".to_owned(),
            ));
        }
        if !matches!(
            template.issuer_algorithm.trim(),
            "ES256" | "ES384" | "RS256" | "EdDSA"
        ) {
            return Err(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must define a supported issuer algorithm".to_owned(),
            ));
        }
        Ok(template)
    }

    fn transaction(
        &self,
        application: &ApplicationRecord,
        local_template: &ApplicationTemplateRecord,
        credential: &InternalApplicationCredentialTemplate,
        now: DateTime<Utc>,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
        let seed = self.seeds.generate();
        let mut claims = application.form_data.clone();
        claims.remove("_credential_type");
        let vct = credential_vct(
            credential.vct.as_deref(),
            &credential.credential_type,
            &self.issuer_base_url,
        );
        claims.insert("_vct".to_owned(), Value::String(vct));
        let credential_template_id = local_template
            .credential_template_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(InternalApplicationApprovalError::Unavailable)?;
        Ok(CredentialTransaction {
            jwt_vc_profile: None,
            jwt_vc_signing_timing: None,

            id: seed.transaction_id,
            organization_id: application.organization_id.clone(),
            credential_template_id: credential_template_id.to_owned(),
            revocation_profile_id: credential.revocation_profile_id.clone(),
            renewal_of_credential_id: None,
            applicant_id: Some(application.applicant_identifier.clone()),
            application_id: Some(application.id.clone()),
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Pending,
            pre_authorized_code: seed.pre_authorized_code,
            nonce: None,
            claims,
            credential_type: Some(credential.credential_type.clone()),
            selective_disclosure_claims: credential.selective_disclosure_claims.clone(),
            zk_predicate_claims: credential.zk_predicate_claims.clone(),
            credential_payload_format: credential.credential_payload_format.clone(),
            wallet_configs: credential.wallet_configs.clone(),
            validity_days: credential.validity_days.max(1),
            renewable: credential.renewable,
            renewal_window_days: credential.renewal_window_days.max(1),
            delivery_mode: delivery_mode(&application.integration_context),
            issuer_profile_id: None,
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some(credential.issuer_did.clone()),
            issuer_algorithm: Some(credential.issuer_algorithm.clone()),
            signing_service_id: None,
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: now,
            expires_at: self.expires_at(now)?,
        })
    }
}

#[async_trait]
impl InternalApplicationTransactionPreparer for OrdinaryInternalApplicationApprover {
    async fn prepare_transaction(
        &self,
        application: &ApplicationRecord,
        local_template: &ApplicationTemplateRecord,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
        if unsupported_integration_context(application) {
            return Err(InternalApplicationApprovalError::UnsupportedIntegrationContext);
        }
        let credential_template_id = local_template
            .credential_template_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template is required.".to_owned(),
            ))?;
        let credential = self
            .dependencies
            .credential_template(credential_template_id)
            .await?
            .ok_or(InternalApplicationApprovalError::CredentialTemplateNotFound)?;
        let credential = self.validate_template(application, credential)?;
        self.dependencies
            .validate_revocation_profile(
                &application.organization_id,
                credential.revocation_profile_id.as_deref(),
            )
            .await?;
        let now = self.clock.now();
        let mut transaction = self.transaction(application, local_template, &credential, now)?;
        resolve_and_attach_required_issuer(self.issuer_resolver.as_ref(), &mut transaction)
            .await
            .map_err(|error| {
                warn_application_failure(
                    InternalApplicationDiagnosticStage::OrdinaryIssuerContext,
                    issuer_diagnostic_category(&error),
                    &application.id,
                );
                InternalApplicationApprovalError::IssuerContextUnavailable
            })?;
        Ok(transaction)
    }
}

#[async_trait]
impl InternalApplicationApprover for OrdinaryInternalApplicationApprover {
    async fn approve(
        &self,
        application: &ApplicationRecord,
        local_template: &ApplicationTemplateRecord,
        reviewer_id: &str,
        review_notes: Option<&str>,
    ) -> Result<ApplicationRecord, InternalApplicationApprovalError> {
        let transaction = self
            .prepare_transaction(application, local_template)
            .await?;
        let now = transaction.created_at;
        self.repository
            .reserve_ordinary_approval(application, &transaction, reviewer_id, review_notes, now)
            .await?
            .ok_or(InternalApplicationApprovalError::ConcurrentChange)
    }
}

fn delivery_mode(integration_context: &serde_json::Map<String, Value>) -> String {
    let nested = integration_context
        .get("delivery")
        .and_then(Value::as_object);
    integration_context
        .get("delivery_mode")
        .filter(|value| python_truthy(value))
        .or_else(|| {
            nested
                .and_then(|delivery| delivery.get("mode"))
                .filter(|value| python_truthy(value))
        })
        .and_then(python_string)
        .unwrap_or_else(|| "wallet_only".to_owned())
}

/// Provider-owned context cannot authorize the platform's ordinary approval path.
/// Only generic delivery hints are understood here; canonical external evidence
/// must enter through the public observation API and platform-owned policy.
pub(crate) fn unsupported_integration_context(application: &ApplicationRecord) -> bool {
    application
        .integration_context
        .keys()
        .any(|key| !matches!(key.as_str(), "delivery" | "delivery_mode"))
}

fn credential_vct(raw: Option<&str>, credential_type: &str, issuer_base_url: &str) -> String {
    let raw = raw.map(str::trim).unwrap_or_default();
    if !raw.is_empty() && url::Url::parse(raw).is_ok_and(|value| !value.scheme().is_empty()) {
        raw.to_owned()
    } else {
        format!(
            "{}/credentials/{}",
            issuer_base_url.trim_end_matches('/'),
            credential_type
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    use chrono::TimeZone;
    use serde_json::{json, Map};

    use super::*;
    use crate::{
        application_issuance::ApprovalSeed,
        application_template_domain::ApplicationTemplateStatus,
        credential::{CredentialIssuanceError, IssuerContext},
        internal_application_domain::ApplicationStatus,
    };

    #[derive(Clone)]
    struct Dependencies {
        template: Option<InternalApplicationCredentialTemplate>,
        revocation_error: Option<InternalApplicationApprovalError>,
        revocation_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl InternalApplicationApprovalDependencies for Dependencies {
        async fn credential_template(
            &self,
            _template_id: &str,
        ) -> Result<Option<InternalApplicationCredentialTemplate>, InternalApplicationApprovalError>
        {
            Ok(self.template.clone())
        }

        async fn validate_revocation_profile(
            &self,
            _organization_id: &str,
            _profile_id: Option<&str>,
        ) -> Result<(), InternalApplicationApprovalError> {
            self.revocation_calls.fetch_add(1, Ordering::SeqCst);
            self.revocation_error.clone().map_or(Ok(()), Err)
        }
    }

    #[derive(Default)]
    struct Repository {
        transactions: Mutex<Vec<CredentialTransaction>>,
    }

    #[async_trait]
    impl InternalApplicationApprovalRepository for Repository {
        async fn reserve_ordinary_approval(
            &self,
            application: &ApplicationRecord,
            transaction: &CredentialTransaction,
            reviewer_id: &str,
            review_notes: Option<&str>,
            reviewed_at: DateTime<Utc>,
        ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError> {
            self.transactions.lock().unwrap().push(transaction.clone());
            let mut application = application.clone();
            application
                .approve_reserved(
                    transaction.id.clone(),
                    review_notes.map(str::to_owned),
                    reviewer_id,
                    reviewed_at,
                )
                .unwrap();
            Ok(Some(application))
        }
    }

    #[derive(Clone)]
    struct Resolver {
        fail: bool,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl IssuerContextResolver for Resolver {
        async fn resolve(
            &self,
            _transaction: &CredentialTransaction,
            _credential_format: &str,
            _force: bool,
        ) -> Result<IssuerContext, CredentialIssuanceError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(CredentialIssuanceError::RepositoryUnavailable);
            }
            Ok(IssuerContext {
                issuer_profile_id: "issuer-profile-1".into(),
                issuer_did: "did:web:kms.example:org-1".into(),
                signing_service_id: "kms-service-1".into(),
                algorithm: "ES256".into(),
                verification_method_id: Some("did:web:kms.example:org-1#key-1".into()),
                public_jwk: None,
                certificate_chain: Vec::new(),
                raw_context: json!({
                    "issuer_profile_id":"issuer-profile-1",
                    "issuer_did":"did:web:kms.example:org-1",
                    "algorithm":"ES256",
                    "signing_service_id":"kms-service-1",
                    "verification_method_id":"did:web:kms.example:org-1#key-1",
                    "signing_key_reference":"kms://issuer-profile-1/key-1"
                }),
            })
        }
    }

    struct Seeds;

    impl ApprovalSeedGenerator for Seeds {
        fn generate(&self) -> ApprovalSeed {
            ApprovalSeed {
                transaction_id: "transaction-1".into(),
                pre_authorized_code: "pre-authorized-code".into(),
            }
        }
    }

    struct Clock(DateTime<Utc>);

    impl ApplicationClock for Clock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn credential_template() -> InternalApplicationCredentialTemplate {
        InternalApplicationCredentialTemplate {
            organization_id: "org-1".into(),
            status: "ACTIVE".into(),
            credential_type: "EmployeeCredential".into(),
            vct: Some("https://credentials.example/employee".into()),
            credential_payload_format: "w3c_vcdm_v2_sd_jwt".into(),
            revocation_profile_id: Some("revocation-profile-1".into()),
            wallet_configs: vec![json!({"wallet_id":"wallet-1"})],
            selective_disclosure_claims: vec!["email".into()],
            zk_predicate_claims: vec!["age".into()],
            validity_days: 365,
            renewable: true,
            renewal_window_days: 30,
            issuer_did: "did:web:template.example:org-1".into(),
            issuer_algorithm: "ES256".into(),
        }
    }

    fn application(now: DateTime<Utc>) -> ApplicationRecord {
        ApplicationRecord {
            id: "application-1".into(),
            organization_id: "org-1".into(),
            application_template_id: "application-template-1".into(),
            applicant_identifier: "applicant@example.test".into(),
            form_data: Map::from_iter([
                ("name".into(), json!("Ada")),
                ("_credential_type".into(), json!("caller-controlled")),
            ]),
            evidence_submissions: Vec::new(),
            integration_context: Map::from_iter([(
                "delivery".into(),
                json!({"mode":"wallet_plus_email"}),
            )]),
            status: ApplicationStatus::Pending,
            review_notes: None,
            reviewer_id: None,
            rejection_reason: None,
            derived_claims: Map::new(),
            created_at: now,
            updated_at: now,
            submitted_at: now,
            reviewed_at: None,
            expires_at: now + Duration::days(30),
            issuance_transaction_id: None,
            credential_id: None,
        }
    }

    fn application_template(now: DateTime<Utc>) -> ApplicationTemplateRecord {
        ApplicationTemplateRecord {
            id: "application-template-1".into(),
            organization_id: "org-1".into(),
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

    fn service(
        repository: Arc<Repository>,
        dependencies: Dependencies,
        resolver: Resolver,
        now: DateTime<Utc>,
    ) -> OrdinaryInternalApplicationApprover {
        OrdinaryInternalApplicationApprover::new(
            repository,
            Arc::new(dependencies),
            Arc::new(resolver),
            Arc::new(Seeds),
            Arc::new(Clock(now)),
            "https://issuer.example",
            10_080,
        )
    }

    #[tokio::test]
    async fn unsupported_provider_context_cannot_fall_through_to_ordinary_approval() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(Repository::default());
        let revocation_calls = Arc::new(AtomicUsize::new(0));
        let issuer_calls = Arc::new(AtomicUsize::new(0));
        let approver = service(
            repository.clone(),
            Dependencies {
                template: Some(credential_template()),
                revocation_error: None,
                revocation_calls: revocation_calls.clone(),
            },
            Resolver {
                fail: false,
                calls: issuer_calls.clone(),
            },
            now,
        );
        for key in ["canvas", "unrecognized_provider"] {
            let mut candidate = application(now);
            candidate
                .integration_context
                .insert(key.into(), json!({"eligible": true}));
            assert!(matches!(
                approver
                    .prepare_transaction(&candidate, &application_template(now))
                    .await,
                Err(InternalApplicationApprovalError::UnsupportedIntegrationContext)
            ));
            assert!(matches!(
                approver
                    .approve(&candidate, &application_template(now), "reviewer", None)
                    .await,
                Err(InternalApplicationApprovalError::UnsupportedIntegrationContext)
            ));
        }
        assert_eq!(revocation_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issuer_calls.load(Ordering::SeqCst), 0);
        assert!(repository.transactions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn approval_prepares_kms_resolved_transaction_and_commits_server_review() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(Repository::default());
        let revocation_calls = Arc::new(AtomicUsize::new(0));
        let issuer_calls = Arc::new(AtomicUsize::new(0));
        let approved = service(
            repository.clone(),
            Dependencies {
                template: Some(credential_template()),
                revocation_error: None,
                revocation_calls: revocation_calls.clone(),
            },
            Resolver {
                fail: false,
                calls: issuer_calls.clone(),
            },
            now,
        )
        .approve(
            &application(now),
            &application_template(now),
            "issuance-management-api",
            Some("Reviewed"),
        )
        .await
        .unwrap();

        assert_eq!(approved.status, ApplicationStatus::Approved);
        assert_eq!(
            approved.reviewer_id.as_deref(),
            Some("issuance-management-api")
        );
        assert_eq!(approved.review_notes.as_deref(), Some("Reviewed"));
        assert_eq!(
            approved.issuance_transaction_id.as_deref(),
            Some("transaction-1")
        );
        assert_eq!(revocation_calls.load(Ordering::SeqCst), 1);
        assert_eq!(issuer_calls.load(Ordering::SeqCst), 1);
        let transactions = repository.transactions.lock().unwrap();
        let transaction = transactions.first().unwrap();
        assert_eq!(transaction.application_id.as_deref(), Some("application-1"));
        assert_eq!(transaction.delivery_mode, "wallet_plus_email");
        assert_eq!(transaction.claims.get("name"), Some(&json!("Ada")));
        assert!(!transaction.claims.contains_key("_credential_type"));
        assert_eq!(
            transaction.claims.get("_vct"),
            Some(&json!("https://credentials.example/employee"))
        );
        assert_eq!(
            transaction.issuer_profile_id.as_deref(),
            Some("issuer-profile-1")
        );
        assert_eq!(
            transaction.issuer_did.as_deref(),
            Some("did:web:kms.example:org-1")
        );
        assert_eq!(
            transaction.signing_service_id.as_deref(),
            Some("kms-service-1")
        );
        assert_eq!(transaction.expires_at, now + Duration::minutes(10_080));
    }

    #[tokio::test]
    async fn invalid_template_stops_before_revocation_issuer_and_persistence() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(Repository::default());
        let revocation_calls = Arc::new(AtomicUsize::new(0));
        let issuer_calls = Arc::new(AtomicUsize::new(0));
        let mut credential = credential_template();
        credential.issuer_algorithm = "HS256".into();
        let error = service(
            repository.clone(),
            Dependencies {
                template: Some(credential),
                revocation_error: None,
                revocation_calls: revocation_calls.clone(),
            },
            Resolver {
                fail: false,
                calls: issuer_calls.clone(),
            },
            now,
        )
        .approve(
            &application(now),
            &application_template(now),
            "issuance-management-api",
            None,
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            InternalApplicationApprovalError::CredentialTemplateInvalid(
                "Credential Template must define a supported issuer algorithm".into()
            )
        );
        assert_eq!(revocation_calls.load(Ordering::SeqCst), 0);
        assert_eq!(issuer_calls.load(Ordering::SeqCst), 0);
        assert!(repository.transactions.lock().unwrap().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn issuer_failure_is_redacted_and_never_reserves() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let repository = Arc::new(Repository::default());
        let (error, diagnostics) =
            crate::internal_application_diagnostics::capture_test_internal_application_diagnostics(
                async {
                    service(
                        repository.clone(),
                        Dependencies {
                            template: Some(credential_template()),
                            revocation_error: None,
                            revocation_calls: Arc::new(AtomicUsize::new(0)),
                        },
                        Resolver {
                            fail: true,
                            calls: Arc::new(AtomicUsize::new(0)),
                        },
                        now,
                    )
                    .approve(
                        &application(now),
                        &application_template(now),
                        "issuance-management-api",
                        None,
                    )
                    .await
                    .unwrap_err()
                },
            )
            .await;

        assert_eq!(
            error,
            InternalApplicationApprovalError::IssuerContextUnavailable
        );
        assert!(repository.transactions.lock().unwrap().is_empty());
        assert_eq!(
            diagnostics,
            ["event=internal_application_failure;stage=ordinary_issuer_context;category=dependency_unavailable;application_correlation_sha256=50628eaf14873bdb37923059f54d64838adfad3ea3f9c63a39ac3c1a57fbf39a;check_correlation_sha256=;resource_correlation_sha256=".to_owned()]
        );
    }

    #[test]
    fn delivery_mode_preserves_python_truthiness_and_stringification() {
        assert_eq!(
            delivery_mode(&Map::from_iter([("delivery_mode".into(), json!(7))])),
            "7"
        );
        assert_eq!(
            delivery_mode(&Map::from_iter([
                ("delivery_mode".into(), json!(false)),
                ("delivery".into(), json!({"mode": true})),
            ])),
            "True"
        );
        assert_eq!(
            delivery_mode(&Map::from_iter([("delivery_mode".into(), json!([]))])),
            "wallet_only"
        );
    }
}
