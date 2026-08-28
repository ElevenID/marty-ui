use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_applicant::{
    issuance::IssuanceOffer,
    service::{
        ApplicantService, ApplicationEvent, ApplicationTemplate, ApprovalAuthorizer, ApprovalFacts,
        EventPublisher, FlowProvider, Identity, MmfApprovalAuthorizer, ProviderError, ServiceError,
        StorePersistence, TemplateProvider,
    },
    store::StoreDocument,
    Application, ClaimState, LifecycleStatus,
};
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Clone)]
struct TemplateMock(ApplicationTemplate);

#[async_trait]
impl TemplateProvider for TemplateMock {
    async fn get(&self, _: &str) -> Result<ApplicationTemplate, ProviderError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct FlowMock {
    calls: Mutex<Vec<(Uuid, Map<String, Value>)>>,
    fail_count: AtomicUsize,
}

#[async_trait]
impl FlowProvider for FlowMock {
    async fn issue(
        &self,
        _: &Application,
        _: &marty_applicant::Applicant,
        claims: &Map<String, Value>,
        attempt_id: Uuid,
    ) -> Result<IssuanceOffer, ProviderError> {
        self.calls.lock().await.push((attempt_id, claims.clone()));
        if self.fail_count.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ProviderError::Unavailable("uncertain transport".into()));
        }
        Ok(IssuanceOffer {
            id: Some("transaction-1".into()),
            credential_offer_uri: Some("openid-credential-offer://offer-1".into()),
            credential_offer_uris: Map::new(),
            credential_offer_labels: Map::new(),
            expires_at: Some("2026-08-21T12:05:00Z".into()),
            status: "pending".into(),
            flow_instance_id: Some("flow-instance-1".into()),
            flow_definition_id: Some("flow-1".into()),
            source: Some("flow".into()),
        })
    }
}

#[derive(Default)]
struct AuthorizerMock(Mutex<Vec<ApprovalFacts>>);

#[async_trait]
impl ApprovalAuthorizer for AuthorizerMock {
    async fn authorize(&self, facts: &ApprovalFacts) -> Result<(), ProviderError> {
        self.0.lock().await.push(facts.clone());
        Ok(())
    }
}

#[derive(Default)]
struct EventsMock(Mutex<Vec<ApplicationEvent>>);

#[async_trait]
impl EventPublisher for EventsMock {
    async fn publish(&self, event: &ApplicationEvent) -> Result<(), ProviderError> {
        self.0.lock().await.push(event.clone());
        Ok(())
    }
}

#[derive(Default)]
struct PersistenceMock(StdMutex<Vec<StoreDocument>>);

impl StorePersistence for PersistenceMock {
    fn persist(&self, store: &StoreDocument) -> Result<(), ProviderError> {
        self.0.lock().unwrap().push(store.clone());
        Ok(())
    }
}

fn template() -> ApplicationTemplate {
    serde_json::from_value(json!({
        "id":"application-template-1",
        "organization_id":"issuer-org",
        "status":"ACTIVE",
        "credential_template_id":"credential-template-1",
        "name":"Member credential",
        "description":"Verified organization membership",
        "form_fields":[{"field_id":"email","required":true}],
        "required_checks":[{"check_type":"identity_verification","is_required":true,"order":1}],
        "approval_strategy":"MANUAL",
        "claim_collection_rules":[
            {"claim_name":"subject_email","source":"FORM_FIELD","source_config":{"field_id":"email"}},
            {"claim_name":"application_id","source":"SYSTEM","source_config":{"system_field":"application.id"}},
            {"claim_name":"achievement_description","source":"SYSTEM","source_config":{"system_field":"template.description"}}
        ]
    }))
    .unwrap()
}

type Harness = (
    ApplicantService,
    Arc<FlowMock>,
    Arc<AuthorizerMock>,
    Arc<EventsMock>,
    Arc<PersistenceMock>,
);

fn service() -> Harness {
    let flow = Arc::new(FlowMock::default());
    let authorizer = Arc::new(AuthorizerMock::default());
    let events = Arc::new(EventsMock::default());
    let persistence = Arc::new(PersistenceMock::default());
    (
        ApplicantService::with_persistence(
            Arc::new(RwLock::new(StoreDocument::default())),
            Arc::new(TemplateMock(template())),
            flow.clone(),
            authorizer.clone(),
            events.clone(),
            persistence.clone(),
        ),
        flow,
        authorizer,
        events,
        persistence,
    )
}

fn identity() -> Identity {
    Identity {
        user_id: "user-1".into(),
        organization_id: "holder-org".into(),
    }
}

async fn draft(service: &ApplicantService) -> Application {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    service
        .upsert_profile(
            &identity(),
            "ada@example.com",
            Some("Ada".into()),
            Some("Lovelace".into()),
            None,
            now,
        )
        .await
        .unwrap();
    let form: Map<String, Value> = serde_json::from_value(json!({
        "email":"ada@example.com",
        "organization_id":"attacker-org",
        "risk_score":2
    }))
    .unwrap();
    // Unknown fields fail closed, so use only the released template field here.
    let mut allowed = Map::new();
    allowed.insert("email".into(), form["email"].clone());
    service
        .create_application(
            &identity(),
            "issuer-org",
            "application-template-1",
            allowed,
            Map::new(),
            now,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn profile_upsert_tracks_subject_and_email_without_split_identity_loss() {
    let (service, _, _, _, _) = service();
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let created = service
        .upsert_profile(
            &identity(),
            "ada@example.com",
            Some("Ada".into()),
            Some("Lovelace".into()),
            None,
            now,
        )
        .await
        .unwrap();
    let renamed_email = service
        .upsert_profile(&identity(), "ada.new@example.com", None, None, None, now)
        .await
        .unwrap();
    assert_eq!(renamed_email.id, created.id);
    assert_eq!(renamed_email.email, "ada.new@example.com");
    assert_eq!(renamed_email.given_name.as_deref(), Some("Ada"));

    let other_identity = Identity {
        user_id: "user-2".into(),
        organization_id: "holder-org".into(),
    };
    service
        .upsert_profile(
            &other_identity,
            "grace@example.com",
            Some("Grace".into()),
            None,
            None,
            now,
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .upsert_profile(&identity(), "grace@example.com", None, None, None, now,)
            .await,
        Err(ServiceError::ApplicantIdentityConflict)
    ));
}

#[tokio::test]
async fn profile_vetting_patch_merges_without_erasing_owned_data() {
    let (service, _, _, _, _) = service();
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap();
    let created = service
        .upsert_profile(&identity(), "ada@example.com", None, None, None, now)
        .await
        .unwrap();
    service
        .set_profile_vetting_data(&created.id, json!({"preserved": true}), now)
        .await
        .unwrap();
    let patched = service
        .patch_profile_vetting_data(&created.id, &json!({"last_login_at": "now"}), now)
        .await
        .unwrap();
    assert_eq!(patched.vetting_data["preserved"], true);
    assert_eq!(patched.vetting_data["last_login_at"], "now");
}

#[tokio::test]
async fn creation_is_profile_bound_duplicate_safe_and_submission_creates_checks() {
    let (service, _, _, _, _) = service();
    let application = draft(&service).await;
    assert_eq!(application.organization_id, "issuer-org");
    assert!(matches!(
        service
            .create_application(
                &identity(),
                "issuer-org",
                "application-template-1",
                serde_json::from_value(json!({"email":"ada@example.com"})).unwrap(),
                Map::new(),
                application.created_at,
            )
            .await,
        Err(ServiceError::DuplicateApplication(_))
    ));
    let submitted = service
        .submit(&application.id, application.created_at)
        .await
        .unwrap();
    assert_eq!(submitted.status, LifecycleStatus::Submitted);
    assert_eq!(service.store().read().await.checks.len(), 1);
}

#[tokio::test]
async fn approval_requires_lock_and_uses_persisted_issuer_scope() {
    let (service, _, authorizer, events, _) = service();
    let application = draft(&service).await;
    service
        .submit(&application.id, application.created_at)
        .await
        .unwrap();
    assert!(matches!(
        service
            .review(
                &application.id,
                "reviewer-1",
                true,
                None,
                None,
                application.created_at
            )
            .await,
        Err(ServiceError::ReviewerLockRequired)
    ));
    service
        .acquire_lock(
            &application.id,
            "reviewer-1",
            "Reviewer",
            application.created_at,
        )
        .await
        .unwrap();
    let approved = service
        .review(
            &application.id,
            "reviewer-1",
            true,
            None,
            None,
            application.created_at,
        )
        .await
        .unwrap();
    assert_eq!(approved.status, LifecycleStatus::Approved);
    assert_eq!(authorizer.0.lock().await[0].organization_id, "issuer-org");
    assert_eq!(events.0.lock().await[0].organization_id, "issuer-org");
}

#[tokio::test]
async fn prior_credential_status_does_not_block_a_new_application_review() {
    let (service, _, _, _, _) = service();
    let prior = draft(&service).await;
    {
        let mut store = service.store().write().await;
        store
            .applications
            .iter_mut()
            .find(|application| application.id == prior.id)
            .unwrap()
            .status = LifecycleStatus::Withdrawn;
        store
            .applicants
            .iter_mut()
            .find(|applicant| applicant.id == prior.applicant_id)
            .unwrap()
            .status = LifecycleStatus::Credentialed;
    }

    let application = draft(&service).await;
    service
        .submit(&application.id, application.created_at)
        .await
        .unwrap();
    let pending = service
        .request_information(
            &application.id,
            vec!["updated evidence".into()],
            "Supply current evidence".into(),
            None,
            application.created_at,
        )
        .await
        .unwrap();
    assert_eq!(pending.status, LifecycleStatus::PendingInformation);
    service
        .submit(&application.id, application.created_at)
        .await
        .unwrap();
    service
        .acquire_lock(
            &application.id,
            "reviewer-1",
            "Reviewer",
            application.created_at,
        )
        .await
        .unwrap();
    let approved = service
        .review(
            &application.id,
            "reviewer-1",
            true,
            None,
            None,
            application.created_at,
        )
        .await
        .unwrap();

    assert_eq!(approved.status, LifecycleStatus::Approved);
    assert_eq!(
        service
            .store()
            .read()
            .await
            .applicant(&application.applicant_id)
            .unwrap()
            .status,
        LifecycleStatus::Credentialed
    );
}

#[tokio::test]
async fn uncertain_flow_retry_reuses_attempt_and_complete_claim_snapshot() {
    let (service, flow, _, _, persistence) = service();
    let application = draft(&service).await;
    service
        .submit(&application.id, application.created_at)
        .await
        .unwrap();
    service
        .acquire_lock(
            &application.id,
            "reviewer-1",
            "Reviewer",
            application.created_at,
        )
        .await
        .unwrap();
    service
        .review(
            &application.id,
            "reviewer-1",
            true,
            None,
            None,
            application.created_at,
        )
        .await
        .unwrap();
    assert!(matches!(
        service.issue(&application.id, application.created_at).await,
        Err(ServiceError::Provider(ProviderError::Unavailable(_)))
    ));
    {
        let persisted = persistence.0.lock().unwrap();
        let active = &persisted
            .last()
            .unwrap()
            .application(&application.id)
            .unwrap()
            .system_data["active_issuance_attempt"];
        assert!(active["id"].as_str().is_some());
    }
    let offered = service
        .issue(&application.id, application.created_at)
        .await
        .unwrap();
    assert_eq!(offered.status, LifecycleStatus::Offered);
    assert_eq!(offered.claim_state, ClaimState::OfferReady);
    let calls = flow.calls.lock().await;
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0].1["subject_email"], "ada@example.com");
    assert_eq!(calls[0].1["application_id"], application.id);
    assert_eq!(
        calls[0].1["achievement_description"],
        "Verified organization membership"
    );
    drop(calls);
    let persisted = persistence.0.lock().unwrap();
    assert!(persisted
        .last()
        .unwrap()
        .application(&application.id)
        .unwrap()
        .system_data
        .get("active_issuance_attempt")
        .is_none());
}

#[tokio::test]
async fn no_op_issuance_reconciliation_preserves_application_ordering_metadata() {
    let (service, _, _, _, persistence) = service();
    let application = draft(&service).await;
    let persisted_before = persistence.0.lock().unwrap().len();
    let later = application.created_at + chrono::Duration::hours(1);

    let reconciled = service
        .reconcile_issuance(&application.id, None, None, later)
        .await
        .unwrap();

    assert_eq!(reconciled.updated_at, application.updated_at);
    assert_eq!(persistence.0.lock().unwrap().len(), persisted_before);
}

#[tokio::test]
async fn production_authorizer_uses_the_canonical_mmf_policy() {
    let authorizer = MmfApprovalAuthorizer::new().unwrap();
    let facts = ApprovalFacts {
        reviewer_id: "reviewer-1".into(),
        organization_id: "issuer-org".into(),
        application_id: "application-1".into(),
        status: LifecycleStatus::Submitted,
        risk_score: 10,
        document_verification_passed: true,
        biometric_match_score: 95,
        evidence_count: 1,
        applicant_country: "US".into(),
    };
    authorizer.authorize(&facts).await.unwrap();
    let mut invalid = facts;
    invalid.risk_score = -1;
    assert!(matches!(
        authorizer.authorize(&invalid).await,
        Err(ProviderError::Denied(_))
    ));
}
