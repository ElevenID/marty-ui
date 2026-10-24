use super::*;
use marty_issuance_service::{
    canvas_lti_claim,
    canvas_lti_evidence::{
        CanvasLtiEvidenceApplication, CanvasLtiEvidenceBinding, CanvasLtiEvidenceError,
        CanvasLtiEvidencePlatform, CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceRepository,
        CanvasLtiEvidenceScope, CanvasLtiEvidenceService,
    },
    canvas_lti_experience::{
        sha256_hex, CanvasLtiExperienceSessionContext, CanvasLtiExperienceSessionService,
    },
    canvas_lti_launch::{
        CanvasLtiLaunchPlanError, CanvasLtiLaunchStateRepository, CanvasLtiStoredLaunchState,
    },
};

struct Sessions(CanvasLtiStoredLaunchState);
#[async_trait]
impl CanvasLtiLaunchStateRepository for Sessions {
    async fn get_launch_state(
        &self,
        state: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        Ok((state == self.0.state).then(|| self.0.clone()))
    }
    async fn consume_launch_state(
        &self,
        _: &str,
    ) -> Result<Option<CanvasLtiStoredLaunchState>, CanvasLtiLaunchPlanError> {
        panic!("claim must not consume launch state")
    }
}
struct Scopes(CanvasLtiEvidenceScope);
#[async_trait]
impl CanvasLtiEvidenceRepository for Scopes {
    async fn load_scope(
        &self,
        _: &CanvasLtiExperienceSessionContext,
    ) -> Result<Option<CanvasLtiEvidenceScope>, CanvasLtiEvidenceError> {
        Ok(Some(self.0.clone()))
    }
    async fn load_projection_data(
        &self,
        _: &CanvasLtiEvidenceScope,
    ) -> Result<CanvasLtiEvidenceProjectionData, CanvasLtiEvidenceError> {
        panic!("claim uses shared offer checks")
    }
}
#[derive(Default)]
struct Offers(Mutex<(usize, usize)>);
#[async_trait]
impl InternalApplicationOfferCoordinator for Offers {
    async fn generate(
        &self,
        app: &ApplicationRecord,
        _: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError> {
        assert_eq!(app.id, "canvas-app");
        self.0.lock().unwrap().0 += 1;
        Ok(offer_response())
    }
    async fn get(
        &self,
        app: &ApplicationRecord,
        _: Option<&ApplicationTemplateRecord>,
    ) -> Result<IssuanceOfferResponse, InternalApplicationOfferError> {
        assert_eq!(app.id, "canvas-app");
        self.0.lock().unwrap().1 += 1;
        Ok(offer_response())
    }
}
fn fixture() -> (
    CanvasLtiStoredLaunchState,
    CanvasLtiEvidenceScope,
    ApplicationRecord,
) {
    let mut app = application("canvas-app", "org-123", ApplicationStatus::Approved);
    app.applicant_identifier = "canvas_lti:learner-1".into();
    app.integration_context = json!({"canvas": {
        "canvas_platform_id": "platform-1", "canvas_program_binding_id": "binding-1", "lti_state": "launch-1"
    }}).as_object().unwrap().clone();
    let session = CanvasLtiStoredLaunchState {
        id: "session-1".into(),
        platform_id: "platform-1".into(),
        organization_id: "org-123".into(),
        canvas_account_id: "account-1".into(),
        state: sha256_hex("valid-token"),
        nonce: "nonce".into(),
        redirect_uri: "https://ui.example/canvas/lti/experience".into(),
        status: "session".into(),
        expired: false,
        metadata: json!({"kind":"canvas_lti_experience_session", "launch_state":"launch-1",
            "verified_launch": {"subject":"learner-1", "roles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
                "raw_claims":{"https://purl.imsglobal.org/spec/lti/claim/message_type":"LtiResourceLinkRequest"}},
            "mip_primitives":{"context":{"canvas_platform_id":"platform-1","canvas_program_binding_id":"binding-1","application_id":"canvas-app"}}}),
    };
    let scope = CanvasLtiEvidenceScope {
        application: CanvasLtiEvidenceApplication {
            id: app.id.clone(),
            organization_id: app.organization_id.clone(),
            application_template_id: app.application_template_id.clone(),
            status: "approved".into(),
            credential_id: None,
            integration_context: Value::Object(app.integration_context.clone()),
        },
        binding: CanvasLtiEvidenceBinding {
            id: "binding-1".into(),
            organization_id: "org-123".into(),
            platform_id: "platform-1".into(),
            application_template_id: "template-1".into(),
            evidence_requirements: vec![],
            config_version: 1,
        },
        platform: CanvasLtiEvidencePlatform {
            id: "platform-1".into(),
            organization_id: "org-123".into(),
        },
    };
    (session, scope, app)
}
fn router(
    session: CanvasLtiStoredLaunchState,
    scope: CanvasLtiEvidenceScope,
    app: ApplicationRecord,
    enabled: bool,
) -> (axum::Router, Arc<MemoryRepository>, Arc<Offers>) {
    let repo = Arc::new(MemoryRepository::default());
    repo.seed_application(app);
    repo.seed_template(template("org-123", ApplicationTemplateStatus::Active));
    let offers = Arc::new(Offers::default());
    let apps = service(repo.clone(), Some("unavailable-to-learner-internal-key"))
        .with_offers(offers.clone());
    let evidence = CanvasLtiEvidenceService::new(
        CanvasLtiExperienceSessionService::new(Arc::new(Sessions(session))),
        Arc::new(Scopes(scope)),
        enabled,
        BTreeSet::from(["org-123".into()]),
    );
    (canvas_lti_claim::router(evidence, apps), repo, offers)
}
async fn call(
    app: &axum::Router,
    method: Method,
    token: Option<&str>,
    options: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri("/v1/integrations/canvas/lti/experience-sessions/current/claim");
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let result = app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    options.map(|v| v.to_string()).unwrap_or_default(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.headers()["cache-control"], "private, no-store");
    let status = result.status();
    let body = result.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn canvas_claim_uses_canonical_offer_and_read_only_completion_without_applicant_copy() {
    let (session, scope, app) = fixture();
    let (router, repo, offers) = router(session, scope, app.clone(), true);
    let (status, generated) =
        call(&router, Method::POST, Some("valid-token"), Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{generated}");
    assert_eq!(generated["id"], "canvas-app");
    assert_eq!(generated["organization_id"], "org-123");
    assert_eq!(generated["transaction_id"], "transaction-1");
    assert_eq!(generated["claim_state"], "OFFER_READY");
    let (_, read) = call(&router, Method::GET, Some("valid-token"), None).await;
    assert_eq!(read["transaction_id"], generated["transaction_id"]);
    assert_eq!(*offers.0.lock().unwrap(), (1, 1));
    let mut claimed = app;
    claimed.credential_id = Some("actual-credential".into());
    repo.seed_application(claimed);
    for method in [Method::GET, Method::POST] {
        let (status, claimed) = call(&router, method, Some("valid-token"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(claimed["claim_state"], "CLAIMED");
        assert!(claimed.get("offer_url").is_none());
    }
    assert_eq!(*offers.0.lock().unwrap(), (1, 1));
}

#[tokio::test]
async fn canvas_claim_rejects_missing_expired_staff_foreign_and_unbound_authority() {
    for case in [
        "missing",
        "unknown",
        "expired",
        "staff",
        "deep-link",
        "subject",
        "tenant",
        "template",
        "platform",
        "binding",
        "state",
        "disabled",
    ] {
        let (mut session, mut scope, mut app) = fixture();
        match case {
            "expired" => session.expired = true,
            "staff" => {
                session.metadata["verified_launch"]["roles"] =
                    json!(["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"])
            }
            "deep-link" => {
                session.metadata["verified_launch"]["raw_claims"]
                    ["https://purl.imsglobal.org/spec/lti/claim/message_type"] =
                    json!("LtiDeepLinkingRequest")
            }
            "subject" => app.applicant_identifier = "canvas_lti:other-learner".into(),
            "tenant" => app.organization_id = "foreign".into(),
            "template" => app.application_template_id = "foreign-template".into(),
            "platform" => scope.platform.id = "foreign-platform".into(),
            "binding" => scope.binding.id = "foreign-binding".into(),
            "state" => {
                scope.application.integration_context["canvas"]["lti_state"] = json!("other-launch")
            }
            _ => (),
        }
        let (router, _, offers) = router(session, scope, app, case != "disabled");
        let token = match case {
            "missing" => None,
            "unknown" => Some("unknown"),
            _ => Some("valid-token"),
        };
        for method in [Method::GET, Method::POST] {
            let (status, body) = call(&router, method, token, None).await;
            assert!(
                matches!(
                    status,
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
                ),
                "{case}: {status} {body}"
            );
            assert!(body.get("offer_url").is_none());
        }
        assert_eq!(*offers.0.lock().unwrap(), (0, 0), "{case}");
    }
}

#[tokio::test]
async fn canvas_claim_never_overrides_authority_or_approves_pending_applications() {
    let (session, scope, mut app) = fixture();
    app.status = ApplicationStatus::Pending;
    let (router, _, offers) = router(session, scope, app, true);
    for body in [
        json!({"application_id":"other"}),
        json!({"organization_id":"foreign"}),
        json!({"wallet_id":"wallet"}),
        json!({"mirror":true}),
        json!([]),
        Value::Null,
    ] {
        assert_eq!(
            call(&router, Method::POST, Some("valid-token"), Some(body))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(&router, Method::POST, Some("valid-token"), Some(json!({})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, read) = call(&router, Method::GET, Some("valid-token"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["claim_state"], "BLOCKED");
    assert!(read.get("offer_url").is_none());
    assert_eq!(*offers.0.lock().unwrap(), (0, 0));
}
