//! Owner-bound issuance prerequisite admission and PostgreSQL fencing.
//! These tests qualify Flow routing/persistence. The cross-owner managed
//! Policy fixture separately qualifies native credential verification.

#[path = "support/presentation_snapshot.rs"]
mod presentation_snapshot;

use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use marty_flow::*;
use marty_oid4vp_contract::issuance_prerequisite::*;
use marty_verification::flow::FlowInstanceStatus;
use mmf_security::{
    SecurityError, ServiceTokenAuthenticator, TenantMembership, TenantMembershipProvider,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use tower::ServiceExt;

const ISSUANCE_TOKEN: &str = "issuance-only-owner-token-at-least-32-bytes";
const GENERAL_TOKEN: &str = "general-service-token-at-least-32-bytes";

struct FixtureProviders;

struct PausedMembership {
    entered: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl TenantMembershipProvider for PausedMembership {
    async fn membership(
        &self,
        principal: &str,
        tenant: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        self.entered.notify_one();
        self.resume.notified().await;
        FixtureProviders.membership(principal, tenant).await
    }
}

#[async_trait]
impl TenantMembershipProvider for FixtureProviders {
    async fn membership(
        &self,
        principal: &str,
        tenant: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        Ok(
            (principal == "initiator-1" && tenant == "org-1").then(|| TenantMembership {
                principal_id: principal.into(),
                tenant_id: tenant.into(),
                status: "active".into(),
                role_names: ["member".into()].into(),
                permissions: ["flow-instance:start".into()].into(),
                is_owner: false,
            }),
        )
    }
}

#[async_trait]
impl PresentationPolicyProvider for FixtureProviders {
    async fn configuration_digest(&self, _: &str) -> Result<String, FlowProviderError> {
        Ok(presentation_snapshot::revision("policy-1").content_digest)
    }
    async fn get_policy(
        &self,
        policy: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            holder_binding_required: true,
            prerequisite_evidence_profile: Some("managed_sd_jwt_dcql_v1".into()),
            credential_authority: Some(presentation_snapshot::authority("org-1")),
            policy_revision: presentation_snapshot::revision(policy),
            id: policy.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements: vec![
                json!({"id":"member", "credential_template_id":"template-1",
                "requested_claims":[{"claim_name":"given_name","required":true}]}),
            ],
        })
    }
    async fn evaluate(
        &self,
        _: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        panic!("admission/persistence fixtures never fabricate managed policy evidence")
    }
}

#[async_trait]
impl CredentialTemplateProvider for FixtureProviders {
    async fn get_template(
        &self,
        id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            jwt_vc_profile: None,
            id: id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_type: "MemberCredential".into(),
            vct: "https://credentials.example/member".into(),
            doctype: String::new(),
            supported_formats: vec!["dc+sd-jwt".into()],
            claims: vec![CredentialClaimReference {
                name: "given_name".into(),
                display_name: "Given name".into(),
                description: String::new(),
                required: true,
                mdoc_namespace: String::new(),
                mdoc_element_identifier: String::new(),
            }],
            issuer_did: "did:web:issuer.example".into(),
            credential_format: "dc+sd-jwt".into(),
            issuance_protocol: "OID4VCI_PRE_AUTH".into(),
            wallet_configurations: vec![],
            issuer_algorithm: Some("ES256".into()),
        })
    }
    async fn wallet_formats(&self, _: &str) -> Result<Vec<String>, FlowProviderError> {
        Ok(vec!["dc+sd-jwt".into()])
    }
}

#[async_trait]
impl FlowReferenceProvider for FixtureProviders {
    async fn resolve(
        &self,
        kind: FlowReferenceKind,
        id: &str,
        principal: &str,
        org: &str,
    ) -> Result<FlowReference, FlowProviderError> {
        assert_eq!(principal, "initiator-1");
        assert_eq!(org, "org-1");
        assert_eq!(id, "trust-1");
        Ok(FlowReference {
            kind,
            id: id.into(),
            organization_id: Some(org.into()),
            status: "active".into(),
            system_owned: false,
        })
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

#[async_trait]
impl SigningIdentityProvider for FixtureProviders {
    async fn resolve(
        &self,
        org: &str,
        did: &str,
        purpose: &str,
        format: &str,
        _: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        let point = signing_key().verifying_key().to_sec1_point(false);
        Ok(SigningIdentity {
            organization_id:org.into(),issuer_did:did.into(),verification_method_id:format!("{did}#request"),
            signing_key_reference:"managed-request-key".into(),
            public_jwk:serde_json::from_value(json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})).unwrap(),
            key_purpose:purpose.into(),credential_format:format.into(),algorithm:"ES256".into(),
        })
    }
    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        let signature: Signature =
            signing_key().sign(&URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap());
        Ok(SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: "ES256".into(),
            signature_raw_b64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

fn state(pool: PgPool, configured: bool) -> FlowHttpState {
    FlowHttpState {
        service_authenticator: Some(Arc::new(
            ServiceTokenAuthenticator::new(Some(GENERAL_TOKEN.into()), true).unwrap(),
        )),
        issuance_prerequisite_authenticator: configured.then(|| {
            Arc::new(ServiceTokenAuthenticator::new(Some(ISSUANCE_TOKEN.into()), true).unwrap())
        }),
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(FlowProviderRegistry {
            tenant_membership: Some(Arc::new(FixtureProviders)),
            presentation_policy: Some(Arc::new(FixtureProviders)),
            credential_template: Some(Arc::new(FixtureProviders)),
            reference_catalog: Some(Arc::new(FixtureProviders)),
            signing_identity: Some(Arc::new(FixtureProviders)),
            ..Default::default()
        }),
        public_base_url: "https://verifier.example".into(),
        verification: FlowHttpVerificationOptions::default(),
        application_approval: Default::default(),
    }
}

async fn send(router: &Router, path: &str, payload: &str, tokens: &[&str]) -> Response {
    let mut request = Request::post(path).header("content-type", "application/json");
    for token in tokens {
        request = request.header("x-service-token", *token);
    }
    router
        .clone()
        .oneshot(request.body(Body::from(payload.to_owned())).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap()
}

fn start_payload(intent: &IssuanceIntentBindingV1) -> String {
    serde_json::to_string(&IssuancePrerequisiteStartRequestV1 {
        contract: ISSUANCE_PREREQUISITE_START_REQUEST_V1.into(),
        intent: intent.clone(),
    })
    .unwrap()
}

fn evidence_payload(intent: &IssuanceIntentBindingV1) -> String {
    serde_json::to_string(&IssuancePrerequisiteEvidenceRequestV1 {
        contract: ISSUANCE_PREREQUISITE_EVIDENCE_REQUEST_V1.into(),
        intent: intent.clone(),
    })
    .unwrap()
}

fn path(intent: &IssuanceIntentBindingV1, operation: &str) -> String {
    format!(
        "/internal/v1/issuance-prerequisites/{}/{operation}",
        intent.transaction_id
    )
}

fn intent(definition: &FlowDefinitionRecord, now: DateTime<Utc>) -> IssuanceIntentBindingV1 {
    IssuanceIntentBindingV1 {
        contract: ISSUANCE_INTENT_CONTRACT_V1.into(),
        organization_id: "org-1".into(),
        transaction_id: uuid::Uuid::new_v4().to_string(),
        initiating_principal_id: "initiator-1".into(),
        applicant_id: Some("applicant-1".into()),
        application_id: None,
        subject_did: None,
        credential_template_id: "template-to-issue".into(),
        credential_template_version: 1,
        credential_configuration_id: "Member_sd_jwt_vc".into(),
        credential_payload_format: "SD_JWT_VC".into(),
        issuer_did: "did:web:issuer.example".into(),
        dataset_digest: format!("sha256:{}", "c".repeat(64)),
        prerequisite: IssuancePrerequisitePolicyV1 {
            profile: IssuancePrerequisiteProfileV1::ManagedSdJwtDcqlSameHolderV1,
            flow_definition_id: definition.id.clone(),
            flow_definition_version: definition.version,
            policy: presentation_snapshot::revision("policy-1"),
            verifier_issuer_did: "did:web:verifier.example".into(),
            ttl_seconds: 300,
        },
        flow_instance_id: uuid::Uuid::new_v4().to_string(),
        created_at_epoch_micros: now.timestamp_micros(),
        expires_at_epoch_micros: (now + Duration::seconds(300)).timestamp_micros(),
        intent_digest: String::new(),
    }
    .seal()
    .unwrap()
}

#[tokio::test]
async fn issuance_owner_routes_require_a_distinct_exact_single_service_token() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost:1/unreachable")
        .unwrap();
    let state = state(pool, true);
    let public = flow_read_router(state.clone());
    let owner = flow_wallet_authority_router(state.clone());
    for operation in ["start", "evidence"] {
        let path = format!("/internal/v1/issuance-prerequisites/transaction-1/{operation}");
        assert_eq!(
            send(&public, &path, "{}", &[ISSUANCE_TOKEN]).await.status(),
            StatusCode::NOT_FOUND
        );
        for tokens in [
            vec![],
            vec![GENERAL_TOKEN],
            vec!["incorrect"],
            vec![ISSUANCE_TOKEN, ISSUANCE_TOKEN],
            vec![" issuance-only-owner-token-at-least-32-bytes"],
        ] {
            assert_eq!(
                send(&owner, &path, "{}", &tokens).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            send(&owner, &path, "{}", &[ISSUANCE_TOKEN]).await.status(),
            StatusCode::BAD_REQUEST
        );
        let mut disabled = state.clone();
        disabled.issuance_prerequisite_authenticator = None;
        assert_eq!(
            send(
                &flow_wallet_authority_router(disabled),
                &path,
                "{}",
                &[ISSUANCE_TOKEN]
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
#[ignore = "requires FLOW_ISSUANCE_PREREQUISITE_TEST_URL pointing to local w05_flow_test PostgreSQL"]
async fn issuance_prerequisite_postgres_start_retry_binding_and_lock_freshness() {
    let url = std::env::var("FLOW_ISSUANCE_PREREQUISITE_TEST_URL")
        .expect("explicit local test database required");
    let options = PgConnectOptions::from_str(&url).unwrap();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    assert_eq!(options.get_database(), Some("w05_flow_test"));
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::raw_sql("DROP SCHEMA IF EXISTS flow_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migrate_flow_schema(&pool).await.unwrap();
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let mut definition=create_definition_record(parse_request(json!({
        "organization_id":"org-1","name":"Issuance prerequisite","flow_type":"oid4vp_presentation",
        "presentation_policy_id":"policy-1","trust_profile_id":"trust-1"
    })).unwrap(),now).unwrap();
    definition.status = DefinitionStatus::Active;
    definition.default_timeout_seconds = 600;
    let state = state(pool.clone(), true);
    let repository = state.repository.clone();
    repository.save_definition(&definition).await.unwrap();
    let owner = flow_wallet_authority_router(state.clone());
    let original = intent(&definition, now);
    let request = start_payload(&original);
    let route = path(&original, "start");
    let (first, second) = tokio::join!(
        send(&owner, &route, &request, &[ISSUANCE_TOKEN]),
        send(&owner, &route, &request, &[ISSUANCE_TOKEN])
    );
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "{}",
        json_body(second).await
    );
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first = json_body(first).await;
    assert_eq!(
        first,
        json_body(second).await,
        "idempotent start must return the original wallet request"
    );
    let response: IssuancePrerequisiteStartResponseV1 =
        serde_json::from_value(first.clone()).unwrap();
    response
        .validate_for_intent(&original, Utc::now().timestamp_micros())
        .unwrap();
    assert_eq!(
        response.expires_at_epoch_micros, original.expires_at_epoch_micros,
        "definition timeout must be clamped"
    );
    assert!(!first.to_string().contains("applicant-1"));
    assert!(!first.to_string().contains(&original.dataset_digest));
    let stored = repository
        .instance(&original.flow_instance_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.context[ISSUANCE_PREREQUISITE_CONTEXT_V1],
        serde_json::to_value(&original).unwrap()
    );
    assert!(public_context(&stored.context)
        .get(ISSUANCE_PREREQUISITE_CONTEXT_V1)
        .is_none());

    // Every selection component is immutable, even when the caller recomputes
    // a perfectly valid public intent digest for the replacement.
    for change in [
        ("dataset", 0),
        ("flow_instance", 1),
        ("policy_version", 2),
        ("principal", 3),
    ] {
        let mut changed = original.clone();
        match change.1 {
            0 => changed.dataset_digest = format!("sha256:{}", "d".repeat(64)),
            1 => changed.flow_instance_id = uuid::Uuid::new_v4().to_string(),
            2 => changed.prerequisite.policy.version += 1,
            _ => changed.initiating_principal_id = "not-authorized".into(),
        }
        let changed = changed.seal().unwrap();
        assert!(
            !send(
                &owner,
                &path(&changed, "start"),
                &start_payload(&changed),
                &[ISSUANCE_TOKEN]
            )
            .await
            .status()
            .is_success(),
            "{}",
            change.0
        );
    }
    let mut stale = intent(&definition, Utc::now());
    stale.prerequisite.policy.version += 1;
    let stale = stale.seal().unwrap();
    assert_eq!(
        send(
            &owner,
            &path(&stale, "start"),
            &start_payload(&stale),
            &[ISSUANCE_TOKEN]
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert!(repository
        .instance(&stale.flow_instance_id)
        .await
        .unwrap()
        .is_none());

    // Generic writers may preserve a bound instance during normal wallet
    // progress, but cannot inject, strip or replace the private intent.
    assert!(repository
        .save_started_instance(&stored, None)
        .await
        .is_err());
    let mut stripped = stored.clone();
    stripped
        .context
        .as_object_mut()
        .unwrap()
        .remove(ISSUANCE_PREREQUISITE_CONTEXT_V1);
    stripped.updated_at += Duration::microseconds(1);
    assert!(!repository.save_instance(&stripped).await.unwrap());
    assert!(!repository
        .compare_and_swap_instance(&stripped, stored.status, stored.updated_at)
        .await
        .unwrap());
    let mut replaced = stored.clone();
    let mut replacement = original.clone();
    replacement.dataset_digest = format!("sha256:{}", "e".repeat(64));
    replaced.context[ISSUANCE_PREREQUISITE_CONTEXT_V1] =
        serde_json::to_value(replacement.seal().unwrap()).unwrap();
    replaced.updated_at += Duration::microseconds(1);
    assert!(!repository.save_instance(&replaced).await.unwrap());
    assert!(!repository
        .compare_and_swap_instance(&replaced, stored.status, stored.updated_at)
        .await
        .unwrap());
    let mut forged = stored.clone();
    let mut forged_intent = original.clone();
    forged_intent.transaction_id = uuid::Uuid::new_v4().to_string();
    forged_intent.flow_instance_id = uuid::Uuid::new_v4().to_string();
    forged.id = forged_intent.flow_instance_id.clone();
    forged.context["_marty_presentation_request_v1"]["instance_id"] = json!(forged.id);
    forged.context[ISSUANCE_PREREQUISITE_CONTEXT_V1] =
        serde_json::to_value(forged_intent.seal().unwrap()).unwrap();
    assert!(!repository.save_instance(&forged).await.unwrap());
    assert!(repository.instance(&forged.id).await.unwrap().is_none());

    let public = flow_read_router(state.clone());
    let signed = public
        .oneshot(
            Request::get(format!("/v1/flows/instances/{}/request", stored.id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signed.status(), StatusCode::OK);
    let current = repository.instance(&stored.id).await.unwrap().unwrap();
    assert_eq!(
        current.context[ISSUANCE_PREREQUISITE_CONTEXT_V1],
        stored.context[ISSUANCE_PREREQUISITE_CONTEXT_V1]
    );
    assert_eq!(current.expires_at, stored.expires_at);
    let waiting = send(
        &owner,
        &path(&original, "evidence"),
        &evidence_payload(&original),
        &[ISSUANCE_TOKEN],
    )
    .await;
    assert_eq!(waiting.status(), StatusCode::CONFLICT);
    assert!(!json_body(waiting)
        .await
        .to_string()
        .contains("policy_evidence"));

    // A historical/unbound verification cannot be attached to a later intent.
    let mut historical = stored.clone();
    historical.id = uuid::Uuid::new_v4().to_string();
    historical
        .context
        .as_object_mut()
        .unwrap()
        .remove(ISSUANCE_PREREQUISITE_CONTEXT_V1);
    historical.context["_marty_presentation_request_v1"]["instance_id"] = json!(historical.id);
    assert!(repository
        .save_started_instance(&historical, None)
        .await
        .unwrap());
    let mut attach = intent(&definition, Utc::now());
    attach.flow_instance_id = historical.id;
    let attach = attach.seal().unwrap();
    assert_eq!(
        send(
            &owner,
            &path(&attach, "start"),
            &start_payload(&attach),
            &[ISSUANCE_TOKEN]
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );

    // Fresh database time is sampled after waiting for the row lock. A request
    // that began while live must fail when the prerequisite expires meanwhile.
    let mut short = intent(&definition, Utc::now());
    short.expires_at_epoch_micros = (Utc::now() + Duration::seconds(2)).timestamp_micros();
    let short = short.seal().unwrap();
    assert_eq!(
        send(
            &owner,
            &path(&short, "start"),
            &start_payload(&short),
            &[ISSUANCE_TOKEN]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM flow_service.flow_instances WHERE id=$1 FOR UPDATE")
        .bind(&short.flow_instance_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let owner_clone = owner.clone();
    let evidence_route = path(&short, "evidence");
    let evidence_request = evidence_payload(&short);
    let waiting = tokio::spawn(async move {
        send(
            &owner_clone,
            &evidence_route,
            &evidence_request,
            &[ISSUANCE_TOKEN],
        )
        .await
    });
    // The idempotent start path must also refresh time after slow authority
    // checks. It must not return its original QR using the pre-PDP timestamp.
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let mut paused_state = state.clone();
    Arc::make_mut(&mut paused_state.providers).tenant_membership =
        Some(Arc::new(PausedMembership {
            entered: entered.clone(),
            resume: resume.clone(),
        }));
    let paused_owner = flow_wallet_authority_router(paused_state);
    let retry_route = path(&short, "start");
    let retry_request = start_payload(&short);
    let retry = tokio::spawn(async move {
        send(
            &paused_owner,
            &retry_route,
            &retry_request,
            &[ISSUANCE_TOKEN],
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!waiting.is_finished());
    assert!(!retry.is_finished());
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    blocker.commit().await.unwrap();
    resume.notify_one();
    assert_eq!(waiting.await.unwrap().status(), StatusCode::CONFLICT);
    assert_eq!(retry.await.unwrap().status(), StatusCode::GONE);

    let live = repository.instance(&stored.id).await.unwrap().unwrap();
    assert!(matches!(
        live.status,
        FlowInstanceStatus::AwaitingWallet | FlowInstanceStatus::InProgress
    ));
    assert_eq!(
        live.context[ISSUANCE_PREREQUISITE_CONTEXT_V1],
        serde_json::to_value(original).unwrap()
    );
}
