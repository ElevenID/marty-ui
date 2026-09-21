//! Native ordinary-application approval orchestration.
//!
//! Canvas-bound applications use the existing Canvas readiness service through
//! a separate composite adapter. This service owns the non-Canvas dependency
//! checks, KMS issuer resolution, transaction preparation, and atomic
//! application/transaction reservation.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Utc};
use serde_json::Value;

use crate::{
    application_template_domain::ApplicationTemplateRecord,
    canvas_award_candidate_approval::{
        issuer_diagnostic_category, resolve_and_attach_required_issuer,
        CanvasApplicationApprovalError, CanvasApplicationApprovalService,
        CanvasAwardApprovalSeedGenerator,
    },
    canvas_lti_launch::CanvasLtiClock,
    credential::{CredentialTransaction, CredentialTransactionStatus, IssuerContextResolver},
    internal_application_diagnostics::{
        warn_application_failure, InternalApplicationDiagnosticStage,
    },
    internal_application_domain::ApplicationRecord,
    internal_application_service::{InternalApplicationApprovalError, InternalApplicationApprover},
    python_value::{python_string, python_truthy, strip},
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

#[async_trait]
pub trait InternalCanvasApplicationApprover: Send + Sync {
    async fn approve_canvas_application(
        &self,
        organization_id: &str,
        application_id: &str,
        reviewer_id: &str,
        review_notes: Option<&str>,
    ) -> Result<String, InternalApplicationApprovalError>;
}

#[async_trait]
pub trait InternalCanvasApplicationOfferPreparer: Send + Sync {
    async fn prepare_canvas_offer(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError>;
}

#[async_trait]
impl InternalCanvasApplicationApprover for CanvasApplicationApprovalService {
    async fn approve_canvas_application(
        &self,
        organization_id: &str,
        application_id: &str,
        reviewer_id: &str,
        review_notes: Option<&str>,
    ) -> Result<String, InternalApplicationApprovalError> {
        self.approve_as(organization_id, application_id, reviewer_id, review_notes)
            .await
            .map(|result| result.issuance_transaction_id)
            .map_err(|error| match error {
                CanvasApplicationApprovalError::Unavailable => {
                    InternalApplicationApprovalError::Unavailable
                }
                CanvasApplicationApprovalError::NotFound
                | CanvasApplicationApprovalError::RolloutDisabled
                | CanvasApplicationApprovalError::InvalidStatus
                | CanvasApplicationApprovalError::NotReady => {
                    InternalApplicationApprovalError::CanvasNotReady
                }
            })
    }
}

#[async_trait]
impl InternalCanvasApplicationOfferPreparer for CanvasApplicationApprovalService {
    async fn prepare_canvas_offer(
        &self,
        organization_id: &str,
        application_id: &str,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
        self.prepare_offer(organization_id, application_id)
            .await
            .map_err(|error| match error {
                CanvasApplicationApprovalError::Unavailable => {
                    InternalApplicationApprovalError::Unavailable
                }
                CanvasApplicationApprovalError::NotFound
                | CanvasApplicationApprovalError::RolloutDisabled
                | CanvasApplicationApprovalError::InvalidStatus
                | CanvasApplicationApprovalError::NotReady => {
                    InternalApplicationApprovalError::CanvasNotReady
                }
            })
    }
}

#[derive(Clone)]
pub struct CompositeInternalApplicationTransactionPreparer {
    ordinary: Arc<dyn InternalApplicationTransactionPreparer>,
    canvas: Arc<dyn InternalCanvasApplicationOfferPreparer>,
}

impl std::fmt::Debug for CompositeInternalApplicationTransactionPreparer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeInternalApplicationTransactionPreparer")
            .finish_non_exhaustive()
    }
}

impl CompositeInternalApplicationTransactionPreparer {
    #[must_use]
    pub fn new(
        ordinary: Arc<dyn InternalApplicationTransactionPreparer>,
        canvas: Arc<dyn InternalCanvasApplicationOfferPreparer>,
    ) -> Self {
        Self { ordinary, canvas }
    }
}

#[async_trait]
impl InternalApplicationTransactionPreparer for CompositeInternalApplicationTransactionPreparer {
    async fn prepare_transaction(
        &self,
        application: &ApplicationRecord,
        local_template: &ApplicationTemplateRecord,
    ) -> Result<CredentialTransaction, InternalApplicationApprovalError> {
        if !canvas_bound_application(application) {
            return self
                .ordinary
                .prepare_transaction(application, local_template)
                .await;
        }
        self.canvas
            .prepare_canvas_offer(&application.organization_id, &application.id)
            .await
    }
}

#[derive(Clone)]
pub struct CompositeInternalApplicationApprover {
    ordinary: Arc<dyn InternalApplicationApprover>,
    canvas: Arc<dyn InternalCanvasApplicationApprover>,
    reader: Arc<dyn InternalApplicationApprovalReader>,
}

impl std::fmt::Debug for CompositeInternalApplicationApprover {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeInternalApplicationApprover")
            .finish_non_exhaustive()
    }
}

impl CompositeInternalApplicationApprover {
    #[must_use]
    pub fn new(
        ordinary: Arc<dyn InternalApplicationApprover>,
        canvas: Arc<dyn InternalCanvasApplicationApprover>,
        reader: Arc<dyn InternalApplicationApprovalReader>,
    ) -> Self {
        Self {
            ordinary,
            canvas,
            reader,
        }
    }
}

#[async_trait]
impl InternalApplicationApprover for CompositeInternalApplicationApprover {
    async fn approve(
        &self,
        application: &ApplicationRecord,
        template: &ApplicationTemplateRecord,
        reviewer_id: &str,
        review_notes: Option<&str>,
    ) -> Result<ApplicationRecord, InternalApplicationApprovalError> {
        if !canvas_bound_application(application) {
            return self
                .ordinary
                .approve(application, template, reviewer_id, review_notes)
                .await;
        }
        let transaction_id = self
            .canvas
            .approve_canvas_application(
                &application.organization_id,
                &application.id,
                reviewer_id,
                review_notes,
            )
            .await?;
        self.reader
            .reload_approved_application(&application.id)
            .await?
            .filter(|current| {
                current.organization_id == application.organization_id
                    && current.status.as_str() == "approved"
                    && current.issuance_transaction_id.as_deref() == Some(transaction_id.as_str())
            })
            .ok_or(InternalApplicationApprovalError::ConcurrentChange)
    }
}

#[derive(Clone)]
pub struct OrdinaryInternalApplicationApprover {
    repository: Arc<dyn InternalApplicationApprovalRepository>,
    dependencies: Arc<dyn InternalApplicationApprovalDependencies>,
    issuer_resolver: Arc<dyn IssuerContextResolver>,
    seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
    clock: Arc<dyn CanvasLtiClock>,
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
        seeds: Arc<dyn CanvasAwardApprovalSeedGenerator>,
        clock: Arc<dyn CanvasLtiClock>,
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

pub(crate) fn canvas_bound_application(application: &ApplicationRecord) -> bool {
    let Some(canvas) = application
        .integration_context
        .get("canvas")
        .and_then(Value::as_object)
    else {
        return false;
    };
    let text = |name: &str| {
        canvas
            .get(name)
            .filter(|value| python_truthy(value))
            .and_then(python_string)
            .unwrap_or_default()
    };
    [
        "canvas_platform_id",
        "canvas_program_binding_id",
        "canvas_account_id",
    ]
    .into_iter()
    .any(|name| !strip(&text(name)).is_empty())
        || strip(&text("source")).to_lowercase().starts_with("canvas")
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
        application_template_domain::ApplicationTemplateStatus,
        canvas_award_candidate_approval::CanvasAwardApprovalSeed,
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

    #[derive(Default)]
    struct OrdinarySpy {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl InternalApplicationApprover for OrdinarySpy {
        async fn approve(
            &self,
            application: &ApplicationRecord,
            _template: &ApplicationTemplateRecord,
            reviewer_id: &str,
            review_notes: Option<&str>,
        ) -> Result<ApplicationRecord, InternalApplicationApprovalError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut approved = application.clone();
            approved
                .approve_reserved(
                    "ordinary-transaction".into(),
                    review_notes.map(str::to_owned),
                    reviewer_id,
                    approved.updated_at + Duration::minutes(1),
                )
                .unwrap();
            Ok(approved)
        }
    }

    type CanvasCall = (String, String, String, Option<String>);

    struct CanvasSpy {
        calls: Mutex<Vec<CanvasCall>>,
        result: Result<String, InternalApplicationApprovalError>,
    }

    #[async_trait]
    impl InternalCanvasApplicationApprover for CanvasSpy {
        async fn approve_canvas_application(
            &self,
            organization_id: &str,
            application_id: &str,
            reviewer_id: &str,
            review_notes: Option<&str>,
        ) -> Result<String, InternalApplicationApprovalError> {
            self.calls.lock().unwrap().push((
                organization_id.to_owned(),
                application_id.to_owned(),
                reviewer_id.to_owned(),
                review_notes.map(str::to_owned),
            ));
            self.result.clone()
        }
    }

    struct Reader(Option<ApplicationRecord>);

    #[async_trait]
    impl InternalApplicationApprovalReader for Reader {
        async fn reload_approved_application(
            &self,
            _application_id: &str,
        ) -> Result<Option<ApplicationRecord>, InternalApplicationApprovalError> {
            Ok(self.0.clone())
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

    impl CanvasAwardApprovalSeedGenerator for Seeds {
        fn generate(&self) -> CanvasAwardApprovalSeed {
            CanvasAwardApprovalSeed {
                transaction_id: "transaction-1".into(),
                pre_authorized_code: "pre-authorized-code".into(),
            }
        }
    }

    struct Clock(DateTime<Utc>);

    impl CanvasLtiClock for Clock {
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
        let (error, diagnostics) = crate::internal_application_diagnostics::
            capture_test_internal_application_diagnostics(
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

    #[tokio::test]
    async fn composite_routes_canvas_without_changing_internal_reviewer_or_null_note() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let mut canvas_application = application(now);
        canvas_application.integration_context = Map::from_iter([(
            "canvas".into(),
            json!({"source":"Canvas LTI", "canvas_platform_id":"platform-1"}),
        )]);
        let mut persisted = canvas_application.clone();
        persisted
            .approve_reserved(
                "canvas-transaction".into(),
                None,
                "issuance-management-api",
                now + Duration::minutes(1),
            )
            .unwrap();
        let ordinary = Arc::new(OrdinarySpy::default());
        let canvas = Arc::new(CanvasSpy {
            calls: Mutex::new(Vec::new()),
            result: Ok("canvas-transaction".into()),
        });
        let composite = CompositeInternalApplicationApprover::new(
            ordinary.clone(),
            canvas.clone(),
            Arc::new(Reader(Some(persisted.clone()))),
        );

        let approved = composite
            .approve(
                &canvas_application,
                &application_template(now),
                "issuance-management-api",
                None,
            )
            .await
            .unwrap();

        assert_eq!(approved, persisted);
        assert_eq!(ordinary.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            canvas.calls.lock().unwrap().as_slice(),
            &[(
                "org-1".into(),
                "application-1".into(),
                "issuance-management-api".into(),
                None,
            )]
        );
    }

    #[test]
    fn canvas_detection_matches_python_truthy_string_boundaries() {
        let now = Utc.with_ymd_and_hms(2026, 9, 20, 12, 0, 0).unwrap();
        let mut candidate = application(now);
        assert!(!canvas_bound_application(&candidate));
        candidate.integration_context =
            Map::from_iter([("canvas".into(), json!({"canvas_platform_id": 7}))]);
        assert!(canvas_bound_application(&candidate));
        candidate.integration_context =
            Map::from_iter([("canvas".into(), json!({"source": "  CANVAS import  "}))]);
        assert!(canvas_bound_application(&candidate));
    }
}
