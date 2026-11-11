use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_applicant::{
    issuance::IssuanceOffer,
    service::{
        ApplicantService, ApplicationEvent, ApplicationTemplate, ApprovalAuthorizer, ApprovalFacts,
        EventPublisher, FlowProvider, Identity, MmfApprovalAuthorizer, ProviderError,
        ReviewRequestContext, ServiceError, StorePersistence, TemplateProvider,
    },
    store::StoreDocument,
    Application, ClaimState, LifecycleStatus,
};
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};
use tokio::sync::{Mutex, Notify, RwLock};
use uuid::Uuid;

#[derive(Clone)]
struct TemplateMock(ApplicationTemplate);

#[async_trait]
impl TemplateProvider for TemplateMock {
    async fn get(&self, _: &str, _: &str) -> Result<ApplicationTemplate, ProviderError> {
        Ok(self.0.clone())
    }
}

struct RetirableTemplate(StdMutex<ApplicationTemplate>);

#[async_trait]
impl TemplateProvider for RetirableTemplate {
    async fn get(&self, _: &str, _: &str) -> Result<ApplicationTemplate, ProviderError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn retired_template_blocks_new_claim_cached_offer_and_reissuance_without_mutation() {
    let templates = Arc::new(RetirableTemplate(StdMutex::new(template())));
    let flow = Arc::new(FlowMock::default());
    let persistence = Arc::new(PersistenceMock::default());
    let service = ApplicantService::with_persistence(
        Arc::new(RwLock::new(StoreDocument::default())),
        templates.clone(),
        flow.clone(),
        Arc::new(AuthorizerMock::default()),
        Arc::new(EventsMock::default()),
        persistence.clone(),
    );
    let application = draft(&service).await;
    for template_status in ["DEPRECATED", "DRAFT"] {
        templates.0.lock().unwrap().status = template_status.into();
        for status in [
            LifecycleStatus::Approved,
            LifecycleStatus::Offered,
            LifecycleStatus::Credentialed,
        ] {
            {
                let mut store = service.store().write().await;
                let application = &mut store.applications[0];
                application.status = status;
                application.claim_state = ClaimState::OfferReady;
                application.issued_at = Some(application.created_at);
                application.system_data.insert(
                    "credential_offer_uri".into(),
                    json!("openid-credential-offer://existing-offer"),
                );
                application.system_data.insert(
                    "offer_expires_at".into(),
                    json!((application.created_at + chrono::Duration::hours(1)).to_rfc3339()),
                );
            }
            let before = serde_json::to_value(service.store().read().await.clone()).unwrap();
            let persisted_before = persistence.0.lock().unwrap().len();
            assert!(matches!(
                service.issue(&application.id, application.created_at).await,
                Err(ServiceError::InactiveTemplate)
            ));
            assert!(matches!(
                service.claim(&application.id, application.created_at).await,
                Err(ServiceError::InactiveTemplate)
            ));
            assert_eq!(
                serde_json::to_value(service.store().read().await.clone()).unwrap(),
                before,
                "Retirement must not rewrite status, offer, issued_at or attempt state"
            );
            assert_eq!(persistence.0.lock().unwrap().len(), persisted_before);
            assert!(flow.calls.lock().await.is_empty());
        }
    }
}

#[tokio::test]
async fn retired_template_blocks_uncertain_flow_retry_without_losing_reserved_attempt() {
    let templates = Arc::new(RetirableTemplate(StdMutex::new(template())));
    let flow = Arc::new(FlowMock::default());
    let persistence = Arc::new(PersistenceMock::default());
    let service = ApplicantService::with_persistence(
        Arc::new(RwLock::new(StoreDocument::default())),
        templates.clone(),
        flow.clone(),
        Arc::new(AuthorizerMock::default()),
        Arc::new(EventsMock::default()),
        persistence.clone(),
    );
    let application = draft(&service).await;
    service.store().write().await.applications[0].status = LifecycleStatus::Approved;
    assert!(matches!(
        service.issue(&application.id, application.created_at).await,
        Err(ServiceError::Provider(ProviderError::Unavailable(_)))
    ));
    templates.0.lock().unwrap().status = "DEPRECATED".into();
    let before = serde_json::to_value(service.store().read().await.clone()).unwrap();
    let persisted_before = persistence.0.lock().unwrap().len();
    for claim in [false, true] {
        let result = if claim {
            service.claim(&application.id, application.created_at).await
        } else {
            service.issue(&application.id, application.created_at).await
        };
        assert!(matches!(result, Err(ServiceError::InactiveTemplate)));
    }
    assert_eq!(flow.calls.lock().await.len(), 1);
    assert_eq!(persistence.0.lock().unwrap().len(), persisted_before);
    assert_eq!(
        serde_json::to_value(service.store().read().await.clone()).unwrap(),
        before
    );
}

#[derive(Default)]
struct FlowMock {
    calls: Mutex<Vec<(Uuid, Map<String, Value>)>>,
    fail_count: AtomicUsize,
    pause: Option<(Arc<Notify>, Arc<Notify>)>,
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
        if let Some((entered, resume)) = &self.pause {
            entered.notify_one();
            resume.notified().await;
        }
        if self.fail_count.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ProviderError::Unavailable("uncertain transport".into()));
        }
        Ok(flow_offer())
    }
}

fn flow_offer() -> IssuanceOffer {
    IssuanceOffer {
        id: Some("transaction-1".into()),
        credential_offer_uri: Some("openid-credential-offer://offer-1".into()),
        credential_offer_uris: Map::new(),
        credential_offer_labels: Map::new(),
        expires_at: Some("2026-08-21T12:05:00Z".into()),
        status: "pending".into(),
        flow_instance_id: Some("flow-instance-1".into()),
        flow_definition_id: Some("flow-1".into()),
        source: Some("flow".into()),
    }
}

struct ConcurrentFlow {
    calls: Mutex<Vec<(Uuid, Map<String, Value>)>>,
    entered: Notify,
    release: [Notify; 2],
    second_offer: Option<IssuanceOffer>,
}

#[async_trait]
impl FlowProvider for ConcurrentFlow {
    async fn issue(
        &self,
        _: &Application,
        _: &marty_applicant::Applicant,
        claims: &Map<String, Value>,
        attempt_id: Uuid,
    ) -> Result<IssuanceOffer, ProviderError> {
        let index = {
            let mut calls = self.calls.lock().await;
            let index = calls.len();
            calls.push((attempt_id, claims.clone()));
            index
        };
        self.entered.notify_one();
        self.release[index].notified().await;
        if index == 0 {
            Ok(flow_offer())
        } else {
            self.second_offer.clone().ok_or(ProviderError::NoActiveFlow)
        }
    }
}

type ClaimTask = tokio::task::JoinHandle<Result<Application, ServiceError>>;

async fn concurrent_claims(
    second_offer: Option<IssuanceOffer>,
) -> (
    Arc<ApplicantService>,
    Arc<ConcurrentFlow>,
    Application,
    Arc<PersistenceMock>,
    [ClaimTask; 2],
) {
    let flow = Arc::new(ConcurrentFlow {
        calls: Mutex::new(Vec::new()),
        entered: Notify::new(),
        release: [Notify::new(), Notify::new()],
        second_offer,
    });
    let persistence = Arc::new(PersistenceMock::default());
    let service = Arc::new(ApplicantService::with_persistence(
        Arc::new(RwLock::new(StoreDocument::default())),
        Arc::new(TemplateMock(template())),
        flow.clone(),
        Arc::new(AuthorizerMock::default()),
        Arc::new(EventsMock::default()),
        persistence.clone(),
    ));
    let application = draft(&service).await;
    service.store().write().await.applications[0].status = LifecycleStatus::Approved;
    let mut tasks = Vec::new();
    for index in 0..2 {
        let service = service.clone();
        let id = application.id.clone();
        let now = application.created_at + chrono::Duration::seconds(index + 1);
        tasks.push(tokio::spawn(async move { service.issue(&id, now).await }));
        tokio::time::timeout(std::time::Duration::from_secs(5), flow.entered.notified())
            .await
            .unwrap();
    }
    let calls = flow.calls.lock().await;
    assert_eq!(
        calls[0], calls[1],
        "Concurrent requests must share the reserved attempt and frozen claims"
    );
    drop(calls);
    (
        service,
        flow,
        application,
        persistence,
        tasks.try_into().unwrap(),
    )
}

async fn completed(task: ClaimTask) -> Result<Application, ServiceError> {
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn completed_claim_reply_preserves_reconciled_success_and_expiry_without_writes() {
    for status in [None, Some("issued"), Some("expired")] {
        let (service, flow, application, persistence, [first, second]) =
            concurrent_claims(Some(flow_offer())).await;
        flow.release[0].notify_one();
        completed(first).await.unwrap();
        if let Some(status) = status {
            service
                .reconcile_issuance(
                    &application.id,
                    Some("transaction-1"),
                    Some(status),
                    None,
                    application.created_at + chrono::Duration::minutes(6),
                )
                .await
                .unwrap();
        }
        let before = service.store().read().await.clone();
        let writes = persistence.0.lock().unwrap().len();
        flow.release[1].notify_one();
        let current = completed(second).await.unwrap();
        assert_eq!(current, before.applications[0]);
        assert_eq!(*service.store().read().await, before);
        assert_eq!(persistence.0.lock().unwrap().len(), writes);
    }
}

#[tokio::test]
async fn completed_claim_reply_rejects_changed_offer_transaction_and_flow_identity() {
    for changed in 0..4 {
        let mut mismatched = flow_offer();
        match changed {
            0 => mismatched.id = Some("different-transaction".into()),
            1 => mismatched.flow_instance_id = Some("different-flow".into()),
            2 => {
                mismatched.credential_offer_uri =
                    Some("openid-credential-offer://different-offer".into())
            }
            _ => mismatched.flow_definition_id = None,
        }
        let (service, flow, _, persistence, [first, second]) =
            concurrent_claims(Some(mismatched)).await;
        flow.release[0].notify_one();
        completed(first).await.unwrap();
        let before = service.store().read().await.clone();
        let writes = persistence.0.lock().unwrap().len();
        flow.release[1].notify_one();
        assert!(completed(second).await.is_err());
        assert_eq!(*service.store().read().await, before);
        assert_eq!(persistence.0.lock().unwrap().len(), writes);
    }
}

#[tokio::test]
async fn completed_claim_reply_refuses_malformed_markers_and_a_new_active_attempt() {
    for replacement in [json!(42), json!("invalid-attempt"), Value::Null] {
        let (service, flow, application, persistence, [first, second]) =
            concurrent_claims(Some(flow_offer())).await;
        flow.release[0].notify_one();
        completed(first).await.unwrap();
        {
            let mut store = service.store().write().await;
            if replacement.is_null() {
                marty_applicant::issuance::reserve_attempt(
                    &mut store.applications[0],
                    Map::new(),
                    application.created_at + chrono::Duration::minutes(1),
                )
                .unwrap();
            } else {
                store.applications[0]
                    .system_data
                    .insert("last_issuance_attempt_id".into(), replacement);
            }
        }
        let before = service.store().read().await.clone();
        let writes = persistence.0.lock().unwrap().len();
        flow.release[1].notify_one();
        assert!(completed(second).await.is_err());
        assert_eq!(*service.store().read().await, before);
        assert_eq!(persistence.0.lock().unwrap().len(), writes);
    }
}

#[tokio::test]
async fn completed_claim_is_not_overwritten_by_a_late_no_flow_error() {
    let (service, flow, application, persistence, [first, second]) = concurrent_claims(None).await;
    flow.release[0].notify_one();
    completed(first).await.unwrap();
    service
        .reconcile_issuance(
            &application.id,
            Some("transaction-1"),
            Some("issued"),
            None,
            application.created_at + chrono::Duration::seconds(3),
        )
        .await
        .unwrap();
    let before = service.store().read().await.clone();
    let writes = persistence.0.lock().unwrap().len();
    flow.release[1].notify_one();
    assert!(completed(second).await.is_err());
    assert_eq!(*service.store().read().await, before);
    assert_eq!(persistence.0.lock().unwrap().len(), writes);
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
struct FlakyEvents {
    calls: Mutex<Vec<ApplicationEvent>>,
    attempts: AtomicUsize,
}

#[async_trait]
impl EventPublisher for FlakyEvents {
    async fn publish(&self, event: &ApplicationEvent) -> Result<(), ProviderError> {
        self.calls.lock().await.push(event.clone());
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(ProviderError::Unavailable(
                "notification unavailable".into(),
            ))
        } else {
            Ok(())
        }
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
    service_with_flow(Arc::new(FlowMock::default()))
}

fn service_with_flow(flow: Arc<FlowMock>) -> Harness {
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

fn review_context() -> ReviewRequestContext<'static> {
    ReviewRequestContext {
        reviewer_id: "reviewer-1",
        correlation_id: "11111111-1111-4111-8111-111111111111",
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
async fn withdrawal_refuses_issuance_states_without_changing_records_or_persistence() {
    for organization in [false, true] {
        for status in [
            LifecycleStatus::Approved,
            LifecycleStatus::Offered,
            LifecycleStatus::Credentialed,
            LifecycleStatus::Suspended,
        ] {
            let (service, _, _, _, persistence) = service();
            let application = draft(&service).await;
            service.store().write().await.applications[0].status = status;
            let before = service.store().read().await.encode().unwrap();
            let writes = persistence.0.lock().unwrap().len();
            let result = if organization {
                service
                    .withdraw_by_organization(&application.id, Some("retire".into()), Utc::now())
                    .await
            } else {
                service
                    .withdraw(&application.id, Some("retire".into()), Utc::now())
                    .await
            };
            assert!(
                result.is_err(),
                "organization={organization}, status={status:?}"
            );
            assert_eq!(service.store().read().await.encode().unwrap(), before);
            assert_eq!(persistence.0.lock().unwrap().len(), writes);
        }
    }
}

#[tokio::test]
async fn withdrawal_refuses_retained_issuance_markers_even_on_early_or_terminal_states() {
    let markers = [
        json!({"active_issuance_attempt":{"id":"uncertain-attempt"}}),
        json!({"issuance_transaction_id":"transaction-1"}),
        json!({"credential_offer_uri":"openid-credential-offer://offer-1"}),
        json!({"credential_offer_uris":{"wallet":"openid-credential-offer://offer-1"}}),
        json!({"flow_instance_id":"flow-instance-1"}),
        json!({"issuance_status":"revoked"}),
        json!({"issuance_transaction_id":42}),
        json!({"active_issuance_attempt":{}}),
    ];
    for organization in [false, true] {
        for status in [LifecycleStatus::Draft, LifecycleStatus::Withdrawn] {
            for marker in &markers {
                let (service, _, _, _, persistence) = service();
                let application = draft(&service).await;
                {
                    let mut store = service.store().write().await;
                    store.applications[0].status = status;
                    store.applications[0].system_data = marker.as_object().unwrap().clone();
                }
                let before = service.store().read().await.encode().unwrap();
                let writes = persistence.0.lock().unwrap().len();
                let result = if organization {
                    service
                        .withdraw_by_organization(&application.id, None, Utc::now())
                        .await
                } else {
                    service.withdraw(&application.id, None, Utc::now()).await
                };
                assert!(
                    result.is_err(),
                    "organization={organization}, status={status:?}, marker={marker}"
                );
                assert_eq!(service.store().read().await.encode().unwrap(), before);
                assert_eq!(persistence.0.lock().unwrap().len(), writes);
            }
        }
    }
}

#[tokio::test]
async fn withdrawal_preserves_safe_self_and_organization_decisions() {
    for organization in [false, true] {
        for status in [
            LifecycleStatus::Draft,
            LifecycleStatus::Submitted,
            LifecycleStatus::UnderReview,
            LifecycleStatus::PendingInformation,
            LifecycleStatus::Rejected,
            LifecycleStatus::Withdrawn,
        ] {
            let (service, _, _, _, persistence) = service();
            let application = draft(&service).await;
            service.store().write().await.applications[0].status = status;
            let before = service.store().read().await.encode().unwrap();
            let writes = persistence.0.lock().unwrap().len();
            let reason = "Application no longer required";
            let now = application.created_at + chrono::Duration::minutes(1);
            let result = if organization {
                service
                    .withdraw_by_organization(&application.id, Some(reason.into()), now)
                    .await
            } else {
                service
                    .withdraw(&application.id, Some(reason.into()), now)
                    .await
            };
            if !organization
                && matches!(
                    status,
                    LifecycleStatus::UnderReview | LifecycleStatus::Rejected
                )
            {
                assert!(result.is_err());
                assert_eq!(service.store().read().await.encode().unwrap(), before);
                assert_eq!(persistence.0.lock().unwrap().len(), writes);
                continue;
            }
            let withdrawn = result.unwrap();
            assert_eq!(withdrawn.id, application.id);
            assert_eq!(withdrawn.organization_id, application.organization_id);
            assert_eq!(withdrawn.status, LifecycleStatus::Withdrawn);
            assert_eq!(withdrawn.system_data["withdrawal_reason"], reason);
            assert_eq!(withdrawn.updated_at, now);
            assert_eq!(persistence.0.lock().unwrap().len(), writes + 1);
        }
    }
}

#[tokio::test]
async fn withdrawal_cannot_hide_a_reserved_in_flight_offer() {
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let flow = Arc::new(FlowMock {
        fail_count: AtomicUsize::new(1),
        pause: Some((entered.clone(), resume.clone())),
        ..Default::default()
    });
    let (service, _, _, _, persistence) = service_with_flow(flow);
    let service = Arc::new(service);
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
            review_context(),
            true,
            None,
            None,
            application.created_at,
        )
        .await
        .unwrap();

    let issuing_service = service.clone();
    let id = application.id.clone();
    let now = application.created_at;
    let issuing = tokio::spawn(async move { issuing_service.issue(&id, now).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let before = service.store().read().await.encode().unwrap();
    assert!(service.store().read().await.applications[0]
        .system_data
        .contains_key("active_issuance_attempt"));
    let writes = persistence.0.lock().unwrap().len();
    let withdrawal = service
        .withdraw_by_organization(&application.id, None, now)
        .await;
    let after = service.store().read().await.encode().unwrap();
    let writes_after = persistence.0.lock().unwrap().len();
    resume.notify_one();
    let offer = tokio::time::timeout(std::time::Duration::from_secs(5), issuing)
        .await
        .unwrap()
        .unwrap();

    assert!(
        withdrawal.is_err(),
        "Withdrawal must not abandon an in-flight issuance"
    );
    assert_eq!(after, before);
    assert_eq!(writes_after, writes);
    let offered = offer.unwrap();
    assert_eq!(offered.status, LifecycleStatus::Offered);
    assert_eq!(offered.claim_state, ClaimState::OfferReady);
    assert_eq!(
        offered.system_data["issuance_transaction_id"],
        "transaction-1"
    );
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
                review_context(),
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
            review_context(),
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
    assert_eq!(
        events.0.lock().await[0].correlation_id,
        "11111111-1111-4111-8111-111111111111"
    );
}

#[tokio::test]
async fn review_commits_a_stable_event_id_and_retries_failed_delivery() {
    let events = Arc::new(FlakyEvents::default());
    let persistence = Arc::new(PersistenceMock::default());
    let service = ApplicantService::with_persistence(
        Arc::new(RwLock::new(StoreDocument::default())),
        Arc::new(TemplateMock(template())),
        Arc::new(FlowMock::default()),
        Arc::new(AuthorizerMock::default()),
        events.clone(),
        persistence.clone(),
    );
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
            review_context(),
            true,
            None,
            None,
            application.created_at,
        )
        .await
        .unwrap();

    assert_eq!(
        service
            .store()
            .read()
            .await
            .pending_application_events
            .len(),
        1
    );
    assert_eq!(service.publish_pending_events().await.unwrap(), 1);
    assert!(service
        .store()
        .read()
        .await
        .pending_application_events
        .is_empty());
    let calls = events.calls.lock().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].event_id, calls[1].event_id);
    assert_eq!(calls[0].correlation_id, calls[1].correlation_id);
    assert!(persistence
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|snapshot| !snapshot.pending_application_events.is_empty()));
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
            review_context(),
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
            review_context(),
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
async fn issuance_reconciliation_checks_transaction_binding_before_local_expiry() {
    for previous_transaction in [None, Some(""), Some("local-old"), Some("old-transaction")] {
        let (service, flow, _, _, persistence) = service();
        let application = draft(&service).await;
        {
            let mut store = service.store().write().await;
            store.applications[0].status = LifecycleStatus::Approved;
            if let Some(previous_transaction) = previous_transaction {
                store.applications[0].system_data.insert(
                    "issuance_transaction_id".into(),
                    json!(previous_transaction),
                );
            }
        }
        flow.fail_count.store(1, Ordering::SeqCst);
        service
            .issue(&application.id, application.created_at)
            .await
            .unwrap();
        let before = service.store().read().await.clone();
        let writes = persistence.0.lock().unwrap().len();
        let later = application.created_at + chrono::Duration::hours(1);
        let current = service
            .reconcile_issuance(&application.id, previous_transaction, None, None, later)
            .await
            .unwrap();
        assert_eq!(current, before.applications[0]);
        assert_eq!(*service.store().read().await, before);
        assert_eq!(persistence.0.lock().unwrap().len(), writes);

        let current = service
            .reconcile_issuance(&application.id, Some("transaction-1"), None, None, later)
            .await
            .unwrap();
        assert_eq!(current.claim_state, ClaimState::Expired);
        assert_eq!(current.claim_blocker.unwrap()["code"], "OFFER_EXPIRED");
        assert_eq!(persistence.0.lock().unwrap().len(), writes + 1);
    }
}

#[tokio::test]
async fn no_op_issuance_reconciliation_preserves_application_ordering_metadata() {
    let (service, _, _, _, persistence) = service();
    let application = draft(&service).await;
    let persisted_before = persistence.0.lock().unwrap().len();
    let later = application.created_at + chrono::Duration::hours(1);

    let reconciled = service
        .reconcile_issuance(&application.id, None, None, None, later)
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

struct LifetimeAuthority {
    maximum: StdMutex<Option<u64>>,
    calls: AtomicUsize,
}
#[async_trait]
impl TemplateProvider for LifetimeAuthority {
    async fn get(&self, _: &str, _: &str) -> Result<ApplicationTemplate, ProviderError> {
        Ok(template())
    }
    async fn validate_offer_lifetime(
        &self,
        organization: &str,
        seconds: u64,
    ) -> Result<(), ProviderError> {
        assert_eq!(organization, "issuer-org");
        self.calls.fetch_add(1, Ordering::SeqCst);
        match *self.maximum.lock().unwrap() {
            Some(maximum) if (60..=maximum).contains(&seconds) => Ok(()),
            Some(_) => Err(ProviderError::InvalidOfferLifetime),
            None => Err(ProviderError::Unavailable(
                "issuer validation unknown".into(),
            )),
        }
    }
}
#[tokio::test]
async fn offer_lifetime_authority_precedes_reservation_and_corrected_request_is_recoverable() {
    let authority = Arc::new(LifetimeAuthority {
        maximum: StdMutex::new(Some(60)),
        calls: AtomicUsize::new(0),
    });
    let flow = Arc::new(FlowMock::default());
    let events = Arc::new(EventsMock::default());
    let persistence = Arc::new(PersistenceMock::default());
    let service = ApplicantService::with_persistence(
        Arc::new(RwLock::new(StoreDocument::default())),
        authority.clone(),
        flow.clone(),
        Arc::new(AuthorizerMock::default()),
        events.clone(),
        persistence.clone(),
    );
    let application = draft(&service).await;
    let now = application.created_at;
    service.store().write().await.applications[0].status = LifecycleStatus::Approved;
    let before = service.store().read().await.clone();
    let writes = persistence.0.lock().unwrap().len();
    let events_before = events.0.lock().await.len();
    for seconds in [59, 120] {
        assert!(matches!(
            service
                .issue_with_lifetime(&application.id, now, Some(seconds))
                .await,
            Err(ServiceError::Provider(ProviderError::InvalidOfferLifetime))
        ));
        assert_eq!(*service.store().read().await, before);
        assert_eq!(persistence.0.lock().unwrap().len(), writes);
        assert!(flow.calls.lock().await.is_empty());
        assert_eq!(events.0.lock().await.len(), events_before);
    }
    *authority.maximum.lock().unwrap() = None;
    assert!(service
        .issue_with_lifetime(&application.id, now, Some(60))
        .await
        .is_err());
    assert_eq!(*service.store().read().await, before);
    assert!(flow.calls.lock().await.is_empty());
    *authority.maximum.lock().unwrap() = Some(60);
    // A corrected value is now reserved, then a simulated uncertain Flow transport occurs.
    assert!(service
        .issue_with_lifetime(&application.id, now, Some(60))
        .await
        .is_err());
    assert_eq!(flow.calls.lock().await.len(), 1);
    let first = flow.calls.lock().await[0].0;
    let validations = authority.calls.load(Ordering::SeqCst);
    *authority.maximum.lock().unwrap() = None;
    assert!(service
        .issue_with_lifetime(&application.id, now, Some(120))
        .await
        .is_err());
    assert_eq!(flow.calls.lock().await.len(), 1);
    // Exact valid reservations retry without changing lifetime or requiring new policy admission.
    service
        .issue_with_lifetime(&application.id, now, Some(60))
        .await
        .unwrap();
    assert_eq!(flow.calls.lock().await[1].0, first);
    assert_eq!(authority.calls.load(Ordering::SeqCst), validations);
}
