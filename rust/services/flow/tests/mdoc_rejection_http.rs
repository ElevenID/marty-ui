//! Focused real HTTP/PostgreSQL contract, using synthetic policy ports only.
//! Run explicitly against an owned disposable loopback database; never demo evidence.
#[path = "support/presentation_snapshot.rs"]
mod presentation_snapshot;

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
    pool: PgPool,
    cancel: Mutex<Option<String>>,
    replace: Mutex<Option<String>>,
}
#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            policy_revision: presentation_snapshot::revision(id),
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
        if mode == 5 {
            return Err(FlowProviderError::PolicyRevisionMismatch);
        }
        let cancel = self.cancel.lock().unwrap().clone();
        if let Some(id) = cancel {
            self.repository
                .cancel_instance(&id, "owned-test-cancel", Utc::now())
                .await
                .map_err(|_| FlowProviderError::Unavailable {
                    provider: "test_repository",
                })?;
        }
        if mode == 4 {
            let id = self
                .replace
                .lock()
                .unwrap()
                .clone()
                .expect("owned replacement race selected");
            let mut current = self
                .repository
                .instance(&id)
                .await
                .map_err(|_| FlowProviderError::Unavailable {
                    provider: "test_repository",
                })?
                .expect("owned race instance exists");
            current.context["nonce"] = json!("replacement-request-nonce-1234567890");
            presentation_snapshot::freeze_default(&mut current);
            presentation_snapshot::emit_query(
                &mut current,
                "dcql_query",
                json!({"credentials": [{"id": "member"}]}),
            );
            // Deliberately leave the timestamp unchanged: context equality
            // must protect the nonce/policy snapshot even at the same instant.
            sqlx::query("UPDATE flow_service.flow_instances SET context=$1 WHERE id=$2")
                .bind(&current.context)
                .bind(&id)
                .execute(&self.pool)
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
        let accepted = matches!(mode, 1 | 3 | 4);
        let mut revision = presentation_snapshot::revision("policy-1");
        if mode == 3 {
            revision.version += 1;
        }
        Ok(PresentationEvaluationResult {
            policy_revision: revision,
            result: if accepted { "passed" } else { "failed" }.into(),
            decision: if accepted { "allow" } else { "deny" }.into(),
            decision_reason: Some("Synthetic policy port for controller contract".into()),
            verified_claims: if accepted {
                [("age_over_21".into(), json!(true))].into()
            } else {
                Default::default()
            },
            credential_results: vec![
                json!({"signature_valid":accepted,"trust_check_passed":accepted}),
            ],
            authentication_diagnostic: (!accepted).then_some(diagnostic),
            error_codes: vec![],
            warnings: vec![],
        })
    }
}
fn instance(id: &str) -> FlowInstanceRecord {
    let now = Utc::now();
    let mut instance = FlowInstanceRecord {
        id: id.into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({"flow_type":"verification","nonce":format!("owned-nonce-{id}-1234567890"),"oid4vp_expected_state":"state-1","presentation_policy_id":"policy-1","_marty_verification_principal_id":"member-1","verification_audience":"did:web:verifier.example","oid4vp_verifier_context":true,"oid4vp_client_id":"did:web:verifier.example"}),
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
    };
    presentation_snapshot::freeze_default(&mut instance);
    presentation_snapshot::emit_query(
        &mut instance,
        "dcql_query",
        json!({"credentials": [{"id": "member"}]}),
    );
    instance
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

fn dc_api_instance(id: &str) -> FlowInstanceRecord {
    let mut value = instance(id);
    value
        .context
        .as_object_mut()
        .unwrap()
        .remove("oid4vp_expected_state");
    value.context["dc_api_expected_origins"] = json!(["https://verifier.example"]);
    value
}

async fn send_dc_api(app: &Router, id: &str) -> Result<(u16, Value), Box<dyn Error + Send + Sync>> {
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/v1/flows/instances/{id}/submit/dc-api"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "protocol": "openid4vp-v1-signed",
                        "origin": "https://verifier.example",
                        "data": {"vp_token": "accepted-dc-api-mdoc"},
                    })
                    .to_string(),
                ))?,
        )
        .await?;
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
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
        pool: pool.clone(),
        cancel: Mutex::new(None),
        replace: Mutex::new(None),
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
    // OID4VP direct_post rejects this attempt at the protocol boundary even
    // though its nonterminal snapshot is persisted for authenticated polling.
    let (status, rejection_error) = send(&app, id, Some("rejected-mdoc"), None).await?;
    assert_eq!(status, 400, "{rejection_error}");
    assert_eq!(rejection_error["error"], "invalid_presentation");
    assert_eq!(rejection_error["detail"]["error"], "invalid_presentation");
    assert!(rejection_error.get("verified_claims").is_none());
    let (status, rejected) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200, "{rejected}");
    let attempt = rejected["last_presentation_attempt"].clone();
    assert!(attempt.is_object());
    let bound_attempt: marty_oid4vp_contract::RejectedPresentationAttemptV1 =
        serde_json::from_value(attempt.clone())?;
    assert!(bound_attempt.matches_session(
        id,
        "policy-1",
        original.context["nonce"].as_str().unwrap()
    ));
    let stored = repository.instance(id).await?.unwrap();
    let rejected_result = stored
        .result
        .as_ref()
        .expect("retryable snapshot persisted");
    assert!(rejected_result.get("decision").is_none());
    assert_eq!(stored.verification_projection()?.verified_claims, json!({}));
    assert_eq!(stored.status, original.status);
    assert_eq!(stored.completed_at, None);
    assert_eq!(stored.context["nonce"], original.context["nonce"]);
    let history = stored.state_history.len();
    assert_eq!(authority_counts(&pool, id).await?, (0, 0));
    let (status, read) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200);
    assert_eq!(read["last_presentation_attempt"], attempt);
    assert_eq!(send(&app, id, None, Some("foreign-member")).await?.0, 403);
    let (status, repeated_error) = send(&app, id, Some("rejected-mdoc"), None).await?;
    assert_eq!(status, 400, "{repeated_error}");
    assert_eq!(repeated_error["error"], "invalid_presentation");
    let (status, repeated) = send(&app, id, None, Some("member-1")).await?;
    assert_eq!(status, 200, "{repeated}");
    assert_eq!(repeated["last_presentation_attempt"], attempt);
    assert_eq!(
        repository.instance(id).await?.unwrap().state_history.len(),
        history
    );
    // A nonce reset under this same instance cannot inherit the old diagnostic.
    let mut reset = repository.instance(id).await?.unwrap();
    let prior = reset.clone();
    reset.context["nonce"] = json!("fresh-reset-owned-nonce-1234567890");
    // This trusted fixture issues a fresh request authority with the reset.
    // Merely changing the public nonce cannot authorize a new submission.
    presentation_snapshot::freeze_default(&mut reset);
    presentation_snapshot::emit_query(
        &mut reset,
        "dcql_query",
        json!({"credentials": [{"id": "member"}]}),
    );
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
    // An allow result under another policy revision cannot consume a nonce,
    // alter the stored active instance or produce a durable callback.
    let revised = "90000000-0000-0000-0000-000000000924";
    let revision_original = instance(revised);
    repository.save_instance(&revision_original).await?;
    let revision_before = repository.instance(revised).await?.unwrap();
    policy.mode.store(3, Ordering::SeqCst);
    assert_eq!(
        send(&app, revised, Some("revision-mismatch-mdoc"), None)
            .await?
            .0,
        409
    );
    let revision_stored = repository.instance(revised).await?.unwrap();
    assert_eq!(revision_stored.status, revision_original.status);
    assert_eq!(revision_stored.updated_at, revision_before.updated_at);
    assert!(revision_stored.result.is_none());
    assert_eq!(authority_counts(&pool, revised).await?, (0, 0));
    // Historical active sessions have no reconstructable request snapshot.
    let legacy = "90000000-0000-0000-0000-000000000925";
    let mut legacy_instance = instance(legacy);
    legacy_instance
        .context
        .as_object_mut()
        .unwrap()
        .remove(presentation_snapshot::SNAPSHOT_KEY);
    repository.save_instance(&legacy_instance).await?;
    policy.mode.store(1, Ordering::SeqCst);
    assert_eq!(send(&app, legacy, Some("legacy-mdoc"), None).await?.0, 409);
    assert_eq!(authority_counts(&pool, legacy).await?, (0, 0));
    assert!(repository.instance(legacy).await?.unwrap().result.is_none());
    let replaced = "90000000-0000-0000-0000-000000000926";
    repository.save_instance(&instance(replaced)).await?;
    let replacement_before = repository.instance(replaced).await?.unwrap();
    policy.mode.store(4, Ordering::SeqCst);
    *policy.replace.lock().unwrap() = Some(replaced.into());
    let (status, replacement_error) =
        send(&app, replaced, Some("racing-replacement-mdoc"), None).await?;
    assert_eq!(status, 409, "{replacement_error}");
    assert!(replacement_error
        .to_string()
        .contains("verification_request_changed"));
    let replacement_after = repository.instance(replaced).await?.unwrap();
    assert_eq!(replacement_after.status, replacement_before.status);
    assert_eq!(replacement_after.updated_at, replacement_before.updated_at);
    assert_eq!(
        replacement_after.context["nonce"],
        "replacement-request-nonce-1234567890"
    );
    assert!(replacement_after.result.is_none());
    assert_eq!(authority_counts(&pool, replaced).await?, (0, 0));
    // DC API origin observations are replacement fields; the original loaded
    // context must remain the expected CAS preimage for a valid first success.
    let dc_success = "90000000-0000-0000-0000-000000000927";
    repository
        .save_instance(&dc_api_instance(dc_success))
        .await?;
    policy.mode.store(1, Ordering::SeqCst);
    let (status, dc_response) = send_dc_api(&app, dc_success).await?;
    assert_eq!(status, 200, "{dc_response}");
    let dc_completed = repository.instance(dc_success).await?.unwrap();
    assert_eq!(dc_completed.status, FlowInstanceStatus::Completed);
    assert_eq!(
        dc_completed.context["dc_api_last_origin"],
        "https://verifier.example"
    );
    assert_eq!(authority_counts(&pool, dc_success).await?, (1, 0));
    let dc_race = "90000000-0000-0000-0000-000000000928";
    repository.save_instance(&dc_api_instance(dc_race)).await?;
    let dc_before = repository.instance(dc_race).await?.unwrap();
    policy.mode.store(4, Ordering::SeqCst);
    *policy.replace.lock().unwrap() = Some(dc_race.into());
    let (status, dc_race_response) = send_dc_api(&app, dc_race).await?;
    assert_eq!(status, 409, "{dc_race_response}");
    assert!(dc_race_response
        .to_string()
        .contains("verification_request_changed"));
    let dc_after = repository.instance(dc_race).await?.unwrap();
    assert_eq!(dc_after.updated_at, dc_before.updated_at);
    assert_eq!(
        dc_after.context["nonce"],
        "replacement-request-nonce-1234567890"
    );
    assert!(dc_after.context.get("dc_api_last_origin").is_none());
    assert!(dc_after.result.is_none());
    assert_eq!(authority_counts(&pool, dc_race).await?, (0, 0));
    let stale = "90000000-0000-0000-0000-000000000929";
    repository.save_instance(&instance(stale)).await?;
    policy.mode.store(5, Ordering::SeqCst);
    let (status, stale_response) = send(&app, stale, Some("stale-policy-mdoc"), None).await?;
    assert_eq!(status, 409, "{stale_response}");
    assert!(stale_response
        .to_string()
        .contains("verification_restart_required"));
    assert_eq!(authority_counts(&pool, stale).await?, (0, 0));
    assert!(repository.instance(stale).await?.unwrap().result.is_none());
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
