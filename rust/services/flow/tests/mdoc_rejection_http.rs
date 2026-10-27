//! Focused real HTTP/PostgreSQL contract, using synthetic policy ports only.
//! Run explicitly against an owned disposable loopback database; never demo evidence.
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use chrono::{Duration, Utc};
use marty_flow::*;
use marty_oid4vp_contract::{
    BoundAuthenticationDiagnosticV1, CertificateTrustFailure, MdocAuthenticationDiagnosticV1,
    MdocDiagnosticFormat,
};
use marty_verification::flow::FlowInstanceStatus;
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, PgPool};
use std::{
    collections::BTreeSet,
    error::Error,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
struct Members;
#[async_trait]
impl TenantMembershipProvider for Members {
    async fn membership(
        &self,
        principal: &str,
        tenant: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        Ok(
            (principal == "member-1" && tenant == "org-1").then(|| TenantMembership {
                principal_id: principal.into(),
                tenant_id: tenant.into(),
                status: "active".into(),
                role_names: BTreeSet::from(["member".into()]),
                permissions: BTreeSet::from(["flow-instance:view".into()]),
                is_owner: false,
            }),
        )
    }
}
struct Policies {
    mode: AtomicUsize,
    repository: PostgresFlowRepository,
    cancel: Mutex<Option<String>>,
}
#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements: vec![],
        })
    }
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        let mode = self.mode.load(Ordering::SeqCst);
        let cancel = self.cancel.lock().unwrap().clone();
        if let Some(id) = cancel {
            self.repository
                .cancel_instance(&id, "owned-test-cancel", Utc::now())
                .await
                .map_err(|_| FlowProviderError::Unavailable {
                    provider: "test_repository",
                })?;
        }
        let mut diagnostic = BoundAuthenticationDiagnosticV1::bind(
            &request.policy_id,
            &request.nonce,
            &request.presentation,
            1,
            MdocAuthenticationDiagnosticV1 {
                format: MdocDiagnosticFormat::MsoMdoc,
                document_count: 1,
                document_type: "org.iso.18013.5.1.mDL".into(),
                issuer_signature_valid: true,
                certificate_trust_passed: false,
                device_authentication_valid: true,
                certificate_trust_failures: vec![CertificateTrustFailure::CertificateChainRejected],
                issuer_certificate_sha256: "1".repeat(64),
            },
        )
        .unwrap();
        if mode == 2 {
            diagnostic.nonce_sha256 = "f".repeat(64);
        }
        Ok(PresentationEvaluationResult {
            result: if mode == 1 { "passed" } else { "failed" }.into(),
            decision: if mode == 1 { "allow" } else { "deny" }.into(),
            decision_reason: Some("Synthetic policy port for controller contract".into()),
            verified_claims: if mode == 1 {
                [("age_over_21".into(), json!(true))].into()
            } else {
                Default::default()
            },
            credential_results: vec![
                json!({"signature_valid":mode==1,"trust_check_passed":mode==1}),
            ],
            authentication_diagnostic: (mode != 1).then_some(diagnostic),
            error_codes: vec![],
            warnings: vec![],
        })
    }
}
fn instance(id: &str) -> FlowInstanceRecord {
    let now = Utc::now();
    FlowInstanceRecord {
        id: id.into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({"flow_type":"verification","nonce":format!("owned-nonce-{id}-1234567890"),"oid4vp_expected_state":"state-1","presentation_policy_id":"policy-1","_marty_verification_principal_id":"member-1","verification_audience":"did:web:verifier.example"}),
        step_history: vec![],
        state_history: vec![],
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(now + Duration::minutes(15)),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    }
}
async fn send(
    app: &Router,
    id: &str,
    token: Option<&str>,
    principal: Option<&str>,
) -> Result<(u16, Value), Box<dyn Error + Send + Sync>> {
    let path = format!(
        "/v1/flows/instances/{id}{}",
        if token.is_some() { "/submit" } else { "" }
    );
    let mut request = if token.is_some() {
        Request::post(path).header("content-type", "application/x-www-form-urlencoded")
    } else {
        Request::get(path)
    };
    if let Some(principal) = principal {
        request = request.header("x-user-id", principal);
    }
    let body = token
        .map(|value| format!("vp_token={value}&state=state-1"))
        .unwrap_or_default();
    let response = app.clone().oneshot(request.body(Body::from(body))?).await?;
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 65536).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn assert_rejection_history_is_minimal(public_instance: &Value, prior_attempt: &Value) {
    let events = public_instance["state_history"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["event"] == "verification_submission_rejected")
        .collect::<Vec<_>>();
    assert!(
        !events.is_empty(),
        "rejection event must survive reset/recovery"
    );
    for event in events {
        let fields = event.as_object().unwrap();
        let expected = BTreeSet::from([
            "prior_state",
            "new_state",
            "timestamp",
            "actor",
            "event",
            "retryable",
        ]);
        assert_eq!(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(event["retryable"], true);
        let encoded = serde_json::to_string(event).unwrap();
        // Scope this check to the rejection event. Fresh accepted issuer data
        // elsewhere in the result is legitimate and must remain available.
        for key in ["nonce_sha256", "submission_digest", "vp_token_sha256"] {
            assert!(!encoded.contains(prior_attempt[key].as_str().unwrap()));
        }
        assert!(!encoded.contains(
            prior_attempt["authentication"]["issuer_certificate_sha256"]
                .as_str()
                .unwrap()
        ));
    }
}

async fn authority_counts(pool: &PgPool, id: &str) -> Result<(i64, i64), sqlx::Error> {
    let nonces = sqlx::query_scalar(
        "SELECT COUNT(*) FROM flow_service.flow_nonce_consumptions WHERE flow_instance_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let callbacks = sqlx::query_scalar(
        "SELECT COUNT(*) FROM flow_service.flow_callback_outbox WHERE flow_instance_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok((nonces, callbacks))
}

#[tokio::test]
#[ignore = "requires explicit owned disposable loopback FLOW_MDOC_REJECTION_TEST_URL"]
async fn retryable_mdoc_rejection_survives_http_readback_recovery_and_terminal_race() -> TestResult
{
    let url = std::env::var("FLOW_MDOC_REJECTION_TEST_URL")
        .expect("explicit owned PostgreSQL fixture required");
    let options = PgConnectOptions::from_str(&url)?;
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("marty_mdoc_rejection_test"));
    let pool = PgPool::connect_with(options).await?;
    migrate_flow_schema(&pool).await?;
    let repository = PostgresFlowRepository::new(pool.clone());
    let policy = Arc::new(Policies {
        mode: AtomicUsize::new(0),
        repository: repository.clone(),
        cancel: Mutex::new(None),
    });
    let state = FlowHttpState {
        service_authenticator: None,
        repository: repository.clone(),
        providers: Arc::new(FlowProviderRegistry {
            tenant_membership: Some(Arc::new(Members)),
            presentation_policy: Some(policy.clone()),
            ..Default::default()
        }),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: FlowHttpApplicationApprovalOptions::default(),
    };
    let app = flow_read_router(state);
    let id = "90000000-0000-0000-0000-000000000921";
    let existing: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM flow_service.flow_instances WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(existing, 0, "owned disposable fixture must start fresh");
    let original = instance(id);
    repository.save_instance(&original).await?;
    let (status, rejected) = send(&app, id, Some("rejected-mdoc"), None).await?;
    assert_eq!(status, 200);
    assert_eq!(rejected["decision"], "deny");
    assert_eq!(rejected["verified_claims"], json!({}));
    let attempt = rejected["last_presentation_attempt"].clone();
    assert!(attempt.is_object());
    let stored = repository.instance(id).await?.unwrap();
    assert_eq!(stored.status, original.status);
    assert_eq!(stored.completed_at, None);
    assert_eq!(stored.context["nonce"], original.context["nonce"]);
    let history = stored.state_history.len();
    assert_eq!(authority_counts(&pool, id).await?, (0, 0));
    let (status, read) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200);
    assert_eq!(read["last_presentation_attempt"], attempt);
    assert_eq!(send(&app, id, None, Some("foreign-member")).await?.0, 403);
    let (status, repeated) = send(&app, id, Some("rejected-mdoc"), None).await?;
    assert_eq!(status, 200);
    assert_eq!(repeated["last_presentation_attempt"], attempt);
    assert_eq!(
        repository.instance(id).await?.unwrap().state_history.len(),
        history
    );
    // A nonce reset under this same instance cannot inherit the old diagnostic.
    let mut reset = repository.instance(id).await?.unwrap();
    let prior = reset.clone();
    reset.context["nonce"] = json!("fresh-reset-owned-nonce-1234567890");
    reset.updated_at = Utc::now().max(prior.updated_at + Duration::microseconds(1));
    assert!(
        repository
            .compare_and_swap_instance(&reset, prior.status, prior.updated_at)
            .await?
    );
    let (status, reset_public) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200);
    assert!(reset_public.get("last_presentation_attempt").is_none());
    assert_rejection_history_is_minimal(&reset_public, &attempt);
    policy.mode.store(1, Ordering::SeqCst);
    assert_eq!(send(&app, id, Some("recovered-mdoc"), None).await?.0, 200);
    let recovered = repository.instance(id).await?.unwrap();
    assert_eq!(recovered.status, FlowInstanceStatus::Completed);
    assert!(recovered.projection()?.last_presentation_attempt.is_none());
    assert!(recovered.state_history.len() > history);
    let (status, recovered_public) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200);
    assert!(recovered_public.get("last_presentation_attempt").is_none());
    assert_rejection_history_is_minimal(&recovered_public, &attempt);
    assert_eq!(authority_counts(&pool, id).await?, (1, 0));
    // Refuse a swapped policy diagnostic and do not persist any fingerprint.
    let wrong = "90000000-0000-0000-0000-000000000922";
    repository.save_instance(&instance(wrong)).await?;
    policy.mode.store(2, Ordering::SeqCst);
    let (_, response) = send(&app, wrong, Some("wrong-bound-mdoc"), None).await?;
    assert!(response.get("last_presentation_attempt").is_none());
    assert!(repository.instance(wrong).await?.unwrap().result.is_none());
    // Deterministic interleaving: cancellation wins while policy is evaluating.
    let race = "90000000-0000-0000-0000-000000000923";
    repository.save_instance(&instance(race)).await?;
    policy.mode.store(0, Ordering::SeqCst);
    *policy.cancel.lock().unwrap() = Some(race.into());
    assert_eq!(send(&app, race, Some("racing-mdoc"), None).await?.0, 409);
    let cancelled = repository.instance(race).await?.unwrap();
    assert_eq!(cancelled.status, FlowInstanceStatus::Cancelled);
    assert!(cancelled.result.is_none());
    pool.close().await;
    Ok(())
}
