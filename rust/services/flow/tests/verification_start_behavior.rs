use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_flow::{
    prepare_profiled_verification_start, prepare_verification_start, CredentialClaimReference,
    CredentialTemplateProvider, CredentialTemplateReference, FlowKeyEnvelopeProvider,
    FlowProviderError, FlowProviderRegistry, FlowVerificationStartError, Oid4vpClientIdScheme,
    Oid4vpProfile, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, RequestTransport, RequestUriMethod,
    SigningIdentity, SigningIdentityProvider, SigningRequest, SigningResult,
    StartVerificationFlowRequest, VerificationResponseType, VerificationStartContext,
    VerificationStartOptions,
};
#[path = "support/haip_remote_fixture.rs"]
mod haip_remote_fixture;
use mmf_push::WebhookDestinationRegistry;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    nonce_entropy_bytes: usize,
    initial_status: String,
    callback_policy: String,
    principal_binding: String,
    policy_binding: Vec<String>,
    signing_identity_binding: Vec<String>,
    request_uri_transport: String,
    request_object_transport: String,
    url_query_transport: String,
    siop_transport: String,
    persistence: String,
    failure_behavior: String,
}

struct Policies {
    organization_id: &'static str,
}

mod public_session {
    use super::*;
    use chrono::Duration;
    use marty_flow::{
        PublicVerificationCatalog, PublicVerificationSelection,
        PublicVerificationSessionError as SessionError, PublicVerificationSessionKey,
        PublicVerificationSessionStatus as Status, PublicVerificationStartInvocation,
    };
    use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};

    struct Operator;

    #[async_trait]
    impl TenantMembershipProvider for Operator {
        async fn membership(
            &self,
            principal_id: &str,
            tenant_id: &str,
        ) -> Result<Option<TenantMembership>, SecurityError> {
            Ok(
                (principal_id == "website-operator" && tenant_id == "org-1").then(|| {
                    TenantMembership {
                        principal_id: principal_id.into(),
                        tenant_id: tenant_id.into(),
                        status: "active".into(),
                        role_names: ["member".into()].into(),
                        permissions: ["flow-instance:start".into()].into(),
                        is_owner: false,
                    }
                }),
            )
        }
    }

    struct References;
    #[async_trait]
    impl marty_flow::FlowReferenceProvider for References {
        async fn resolve(
            &self,
            kind: marty_flow::FlowReferenceKind,
            id: &str,
            principal: &str,
            organization: &str,
        ) -> Result<marty_flow::FlowReference, FlowProviderError> {
            assert_eq!(principal, "website-operator");
            assert_eq!(organization, "org-1");
            assert!(id == "trust-demo" || id == "deployment-demo");
            Ok(marty_flow::FlowReference {
                kind,
                id: id.into(),
                organization_id: Some(organization.into()),
                status: "active".into(),
                system_owned: false,
            })
        }
    }

    struct MutablePolicy(Arc<std::sync::atomic::AtomicBool>);

    #[async_trait]
    impl PresentationPolicyProvider for MutablePolicy {
        async fn configuration_digest(&self, _id: &str) -> Result<String, FlowProviderError> {
            let value = if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                "b"
            } else {
                "a"
            };
            Ok(format!("sha256:{}", value.repeat(64)))
        }

        async fn get_policy(
            &self,
            id: &str,
        ) -> Result<PresentationPolicyReference, FlowProviderError> {
            Policies {
                organization_id: "org-1",
            }
            .get_policy(id)
            .await
        }

        async fn evaluate(
            &self,
            _request: &PresentationEvaluationRequest,
        ) -> Result<PresentationEvaluationResult, FlowProviderError> {
            unreachable!("public HTTP orchestration does not replace canonical wallet evaluation")
        }
    }

    fn setup(
        digest_character: char,
    ) -> (
        PublicVerificationCatalog,
        marty_flow::FlowDefinitionRecord,
        FlowProviderRegistry,
    ) {
        let mut definition = website_definition();
        definition.trust_profile_id = Some("trust-demo".into());
        definition.deployment_profile_id = Some("deployment-demo".into());
        let catalog = PublicVerificationCatalog::from_json(&json!({
            "organization_id": "org-1", "application_origin": "https://site.example",
            "notice": "Present a synthetic example credential.",
            "scenarios": [{ "id": "age", "label": "Age requirement", "choices": [{
                "id": "over-18", "label": "18 or older",
                "definition": { "organization_id": "org-1", "definition_id": definition.id, "version": definition.version },
                "presentation_policy_id": "policy-1", "policy_configuration_digest": format!("sha256:{}", digest_character.to_string().repeat(64))
            }]}]
        }).to_string(), false).unwrap();
        let mut registry = providers("org-1");
        registry.tenant_membership = Some(Arc::new(Operator));
        registry.reference_catalog = Some(Arc::new(References));
        (catalog, definition, registry)
    }

    fn selection(catalog: &PublicVerificationCatalog) -> PublicVerificationSelection {
        PublicVerificationSelection {
            catalog_revision: catalog.public_view().revision.into(),
            scenario_id: "age".into(),
            choice_id: "over-18".into(),
            consent: true,
            example_id: None,
        }
    }

    fn key(byte: u8) -> PublicVerificationSessionKey {
        PublicVerificationSessionKey::parse(&URL_SAFE_NO_PAD.encode([byte; 32])).unwrap()
    }

    async fn prepare(
        catalog: &PublicVerificationCatalog,
        definition: &marty_flow::FlowDefinitionRecord,
        registry: &FlowProviderRegistry,
        selection: &PublicVerificationSelection,
        key: &PublicVerificationSessionKey,
        principal: &str,
    ) -> Result<marty_flow::PreparedVerificationStart, marty_flow::PublicVerificationStartError>
    {
        catalog
            .prepare_selection(
                registry,
                &WebhookDestinationRegistry::default(),
                definition,
                &VerificationStartOptions::default(),
                PublicVerificationStartInvocation {
                    selection,
                    browser_origin: "https://site.example",
                    issuer_did: "did:web:verifier.example",
                    context: VerificationStartContext {
                        public_base_url: "https://verifier.example",
                        allow_http_loopback: false,
                        principal_id: principal,
                        now: now(),
                    },
                    session_key: key,
                },
            )
            .await
    }

    #[tokio::test]
    async fn public_selection_prepares_the_canonical_bound_session_with_safe_projection() {
        let (catalog, definition, registry) = setup('a');
        let selection = selection(&catalog);
        let key = key(1);
        let prepared = prepare(
            &catalog,
            &definition,
            &registry,
            &selection,
            &key,
            "website-operator",
        )
        .await
        .unwrap();
        assert_eq!(
            prepared.instance.id,
            key.instance_id("org-1", "https://site.example").to_string()
        );
        assert_eq!(prepared.instance.flow_definition_id, definition.id);
        let view = key
            .view(&prepared.instance, "org-1", "https://site.example", now())
            .unwrap();
        assert_eq!(view.status, Status::AwaitingWallet);
        assert!(view.verified.is_none());
        let uri = url::Url::parse(view.wallet_uri.as_ref().unwrap()).unwrap();
        let params: BTreeMap<_, _> = uri.query_pairs().into_owned().collect();
        assert_eq!(
            params["request_uri"],
            format!(
                "https://verifier.example/v1/flows/instances/{}/request",
                prepared.instance.id
            )
        );
        let raw = serde_json::to_value(view).unwrap().to_string();
        for private in [
            "website-operator",
            "policy-1",
            "trust-demo",
            "deployment-demo",
            "key_hash",
            "nonce",
            "verified_claims",
        ] {
            assert!(!raw.contains(private), "leaked {private}");
        }
        let context = prepared.instance.context.to_string();
        assert!(!context.contains(&URL_SAFE_NO_PAD.encode([1; 32])));
        let public = marty_flow::public_context(&prepared.instance.context).to_string();
        assert!(!public.contains("key_hash"));
        key.require_same_selection(
            &prepared.instance,
            "org-1",
            "https://site.example",
            &selection,
            now(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn public_launch_rechecks_operator_references_and_pinned_policy() {
        let (catalog, definition, registry) = setup('a');
        let selected = selection(&catalog);
        assert!(matches!(
            prepare(
                &catalog,
                &definition,
                &registry,
                &selected,
                &key(1),
                "revoked-operator"
            )
            .await,
            Err(marty_flow::PublicVerificationStartError::Provider(_))
        ));
        let mut without_references = registry.clone();
        without_references.reference_catalog = None;
        assert!(matches!(
            prepare(
                &catalog,
                &definition,
                &without_references,
                &selected,
                &key(1),
                "website-operator"
            )
            .await,
            Err(marty_flow::PublicVerificationStartError::Provider(
                FlowProviderError::Unavailable { .. }
            ))
        ));
        let (stale, definition, registry) = setup('b');
        assert!(matches!(
            prepare(
                &stale,
                &definition,
                &registry,
                &selection(&stale),
                &key(1),
                "website-operator"
            )
            .await,
            Err(marty_flow::PublicVerificationStartError::Definition(
                marty_flow::DefinedVerificationError::ConfigurationChanged
            ))
        ));
    }

    #[tokio::test]
    async fn capability_is_tenant_origin_instance_and_selection_bound() {
        let (catalog, definition, registry) = setup('a');
        let selected = selection(&catalog);
        let key = key(1);
        let mut prepared = prepare(
            &catalog,
            &definition,
            &registry,
            &selected,
            &key,
            "website-operator",
        )
        .await
        .unwrap();
        assert!(matches!(
            super::public_session::key(2).view(
                &prepared.instance,
                "org-1",
                "https://site.example",
                now()
            ),
            Err(SessionError::Unavailable)
        ));
        assert!(matches!(
            key.view(
                &prepared.instance,
                "other-org",
                "https://site.example",
                now()
            ),
            Err(SessionError::Unavailable)
        ));
        assert!(matches!(
            key.view(&prepared.instance, "org-1", "https://other.example", now()),
            Err(SessionError::Unavailable)
        ));
        let mut changed = selected.clone();
        changed.choice_id = "over-21".into();
        assert_eq!(
            key.require_same_selection(
                &prepared.instance,
                "org-1",
                "https://site.example",
                &changed,
                now()
            ),
            Err(SessionError::SelectionConflict)
        );
        changed = selected.clone();
        changed.catalog_revision = "different".into();
        assert_eq!(
            key.require_same_selection(
                &prepared.instance,
                "org-1",
                "https://site.example",
                &changed,
                now()
            ),
            Err(SessionError::SelectionConflict)
        );
        prepared.instance.id = uuid::Uuid::new_v4().to_string();
        assert!(matches!(
            key.view(&prepared.instance, "org-1", "https://site.example", now()),
            Err(SessionError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn public_result_is_canonical_bounded_and_redacts_all_claims_and_errors() {
        let (catalog, definition, registry) = setup('a');
        let key = key(1);
        let mut instance = prepare(
            &catalog,
            &definition,
            &registry,
            &selection(&catalog),
            &key,
            "website-operator",
        )
        .await
        .unwrap()
        .instance;
        instance.result = Some(json!({ "evaluation_result": "passed", "decision": "allow",
            "verified_claims": { "name": "private-holder" }, "credential_results": [{"secret":"secret-result"}],
            "error_codes": ["private-error"], "warnings": ["private-warning"] }));
        instance.error = Some("private-provider-error".into());
        instance.status = marty_verification::flow::FlowInstanceStatus::Completed;
        let view = key
            .view(&instance, "org-1", "https://site.example", now())
            .unwrap();
        assert_eq!(view.verified, Some(true));
        assert!(view.wallet_uri.is_none());
        assert!(!serde_json::to_string(&view).unwrap().contains("private"));
        instance.status = marty_verification::flow::FlowInstanceStatus::Failed;
        assert!(matches!(
            key.view(&instance, "org-1", "https://site.example", now()),
            Err(SessionError::InvalidState)
        ));
        instance.result.as_mut().unwrap()["decision"] = json!("deny");
        assert_eq!(
            key.view(&instance, "org-1", "https://site.example", now())
                .unwrap()
                .verified,
            Some(false)
        );
        instance.status = marty_verification::flow::FlowInstanceStatus::AwaitingWallet;
        let expiry = instance.expires_at.unwrap();
        let expired = key
            .view(&instance, "org-1", "https://site.example", expiry)
            .unwrap();
        assert_eq!(expired.status, Status::Expired);
        assert!(expired.verified.is_none() && expired.wallet_uri.is_none());
        assert!(matches!(
            key.view(
                &instance,
                "org-1",
                "https://site.example",
                expiry + Duration::seconds(600)
            ),
            Err(SessionError::Unavailable)
        ));
        instance.status = marty_verification::flow::FlowInstanceStatus::Cancelled;
        let cancelled = key
            .view(&instance, "org-1", "https://site.example", now())
            .unwrap();
        assert_eq!(cancelled.status, Status::Cancelled);
        assert!(cancelled.verified.is_none() && cancelled.wallet_uri.is_none());
    }

    #[test]
    fn capability_encoding_is_strict_and_domains_do_not_alias() {
        let raw = URL_SAFE_NO_PAD.encode([1; 32]);
        for malformed in [
            "".into(),
            format!("{raw}="),
            "a".repeat(42),
            "a".repeat(44),
            "!".repeat(43),
        ] {
            assert!(PublicVerificationSessionKey::parse(&malformed).is_err());
        }
        let key = key(1);
        assert_ne!(
            key.instance_id("org-1", "https://site.example"),
            key.instance_id("org-2", "https://site.example")
        );
        assert_ne!(
            key.instance_id("org-1", "https://site.example"),
            key.instance_id("org-1", "https://other.example")
        );
    }

    async fn call(
        router: &axum::Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        origin: Option<&str>,
        payload: Option<&serde_json::Value>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut request = axum::http::Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("x-verification-session", token);
        }
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        if payload.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(axum::body::Body::from(
                        payload.map_or_else(String::new, |v| v.to_string()),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16_384)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn public_http_is_disabled_without_operator_configuration() {
        let router = marty_flow::flow_read_router(marty_flow::FlowHttpState {
            service_authenticator: None,
            repository: marty_flow::PostgresFlowRepository::new(
                sqlx::postgres::PgPoolOptions::new()
                    .connect_lazy("postgres://localhost/unused")
                    .unwrap(),
            ),
            providers: Arc::new(FlowProviderRegistry::default()),
            public_base_url: "https://verifier.example".into(),
            verification: marty_flow::FlowHttpVerificationOptions::default(),
            application_approval: Default::default(),
        });
        let (status, _) = call(
            &router,
            "GET",
            "/v1/flows/public/verification/catalog",
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        let (status, _) = call(
            &router,
            "POST",
            "/v1/flows/public/verification/sessions",
            None,
            None,
            Some(&json!({})),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[ignore = "requires an explicitly supplied disposable local public-verification database"]
    async fn public_http_postgres_retry_quota_and_cancel_races() {
        use axum::http::StatusCode;
        use std::str::FromStr;
        let url =
            std::env::var("FLOW_PUBLIC_VERIFICATION_TEST_URL").expect("disposable DB URL required");
        let options = sqlx::postgres::PgConnectOptions::from_str(&url).unwrap();
        assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
        assert_eq!(
            options.get_database(),
            Some("marty_public_verification_test")
        );
        let pool = sqlx::PgPool::connect_with(options).await.unwrap();
        // This fixture requires a fresh, task-owned database. No schema drop or
        // reset is performed, and it refuses every shared runtime database name.
        sqlx::raw_sql("CREATE SCHEMA deployment_profile_service; CREATE TABLE deployment_profile_service.deployment_profiles (id text PRIMARY KEY, enabled_flow_ids jsonb NOT NULL DEFAULT '[]'::jsonb)")
            .execute(&pool).await.unwrap();
        marty_flow::migrate_flow_schema(&pool).await.unwrap();
        let repository = marty_flow::PostgresFlowRepository::new(pool.clone());
        let (_, definition, mut registry) = setup('a');
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        registry.presentation_policy = Some(Arc::new(MutablePolicy(changed.clone())));
        repository.save_definition(&definition).await.unwrap();
        let runtime = marty_flow::PublicVerificationOptions::from_json(&json!({
            "catalog": {
                "organization_id": "org-1", "application_origin": "https://site.example",
                "notice": "Present a synthetic example credential.",
                "scenarios": [{"id":"age", "label":"Age requirement", "choices":[{
                    "id":"over-18", "label":"18 or older", "definition": {
                        "organization_id":"org-1", "definition_id":definition.id, "version":definition.version
                    }, "presentation_policy_id":"policy-1", "policy_configuration_digest":format!("sha256:{}", "a".repeat(64))
                }]}]
            }, "principal_id":"website-operator", "issuer_did":"did:web:verifier.example",
            "limits":{"starts_per_minute":2, "starts_per_day":2, "maximum_active":1}
        }).to_string(), false).unwrap();
        let router = marty_flow::flow_read_router(marty_flow::FlowHttpState {
            service_authenticator: None,
            repository: repository.clone(),
            providers: Arc::new(registry),
            public_base_url: "https://verifier.example".into(),
            verification: marty_flow::FlowHttpVerificationOptions {
                public_verification: Some(runtime),
                ..Default::default()
            },
            application_approval: Default::default(),
        });
        let base = "/v1/flows/public/verification";
        let (status, catalog) =
            call(&router, "GET", &format!("{base}/catalog"), None, None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!catalog.to_string().contains("policy-1"));
        let payload = json!({"catalog_revision":catalog["revision"], "scenario_id":"age", "choice_id":"over-18", "consent":true});
        let first_key = URL_SAFE_NO_PAD.encode([1; 32]);
        let second_key = URL_SAFE_NO_PAD.encode([2; 32]);
        let third_key = URL_SAFE_NO_PAD.encode([3; 32]);
        let endpoint = format!("{base}/sessions");
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&first_key),
                None,
                Some(&payload)
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                None,
                Some("https://site.example"),
                Some(&payload)
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let mut injected = payload.clone();
        injected["organization_id"] = json!("foreign");
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&first_key),
                Some("https://site.example"),
                Some(&injected)
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (first, retry) = tokio::join!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&first_key),
                Some("https://site.example"),
                Some(&payload)
            ),
            call(
                &router,
                "POST",
                &endpoint,
                Some(&first_key),
                Some("https://site.example"),
                Some(&payload)
            )
        );
        assert!(
            (first.0 == StatusCode::CREATED && retry.0 == StatusCode::OK)
                || (retry.0 == StatusCode::CREATED && first.0 == StatusCode::OK),
            "first={first:?}, retry={retry:?}"
        );
        assert_eq!(first.1, retry.1);
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM flow_service.flow_instances WHERE organization_id='org-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        let id = first.1["session_id"].as_str().unwrap();
        let read = format!("{endpoint}/{id}");
        assert_eq!(
            call(&router, "GET", &read, Some(&second_key), None, None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                &router,
                "GET",
                &read,
                Some(&first_key),
                Some("https://evil.example"),
                None
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&router, "GET", &read, Some(&first_key), None, None)
                .await
                .0,
            StatusCode::OK
        );
        changed.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            call(&router, "GET", &read, Some(&first_key), None, None)
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(&router, "GET", &read, Some(&second_key), None, None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        changed.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&second_key),
                Some("https://site.example"),
                Some(&payload)
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let cancel = format!("{read}/cancel");
        let cancelled = call(
            &router,
            "POST",
            &cancel,
            Some(&first_key),
            Some("https://site.example"),
            None,
        )
        .await;
        assert_eq!(cancelled.1["status"], "cancelled");
        assert_eq!(
            call(
                &router,
                "POST",
                &cancel,
                Some(&first_key),
                Some("https://site.example"),
                None
            )
            .await
            .1,
            cancelled.1
        );
        // A terminal retry remains the same operation rather than reopening it.
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&first_key),
                Some("https://site.example"),
                Some(&payload)
            )
            .await
            .1["status"],
            "cancelled"
        );
        // Different keys race for the last slot. A check outside the insertion
        // transaction would admit both candidates.
        let (second, third) = tokio::join!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&second_key),
                Some("https://site.example"),
                Some(&payload)
            ),
            call(
                &router,
                "POST",
                &endpoint,
                Some(&third_key),
                Some("https://site.example"),
                Some(&payload)
            )
        );
        let (winner, winning_key) = if second.0 == StatusCode::CREATED {
            assert_eq!(third.0, StatusCode::TOO_MANY_REQUESTS);
            (&second, &second_key)
        } else {
            assert_eq!(second.0, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(third.0, StatusCode::CREATED);
            (&third, &third_key)
        };
        let second_id = winner.1["session_id"].as_str().unwrap();
        let mut completed = repository.instance(second_id).await.unwrap().unwrap();
        let expected_status = completed.status;
        let expected_updated_at = completed.updated_at;
        completed.status = marty_verification::flow::FlowInstanceStatus::Completed;
        completed.updated_at += Duration::microseconds(1);
        completed.completed_at = Some(completed.updated_at);
        completed.result = Some(json!({"evaluation_result":"passed", "decision":"allow"}));
        let cancel_second = format!("{endpoint}/{second_id}/cancel");
        let (cancel_response, finalized) = tokio::join!(
            call(
                &router,
                "POST",
                &cancel_second,
                Some(winning_key),
                Some("https://site.example"),
                None
            ),
            repository.compare_and_swap_instance(&completed, expected_status, expected_updated_at)
        );
        assert_eq!(cancel_response.0, StatusCode::OK);
        let stored = repository.instance(second_id).await.unwrap().unwrap();
        if finalized.unwrap() {
            assert_eq!(
                stored.status,
                marty_verification::flow::FlowInstanceStatus::Completed
            );
            assert_eq!(cancel_response.1["verified"], true);
        } else {
            assert_eq!(
                stored.status,
                marty_verification::flow::FlowInstanceStatus::Cancelled
            );
            assert_eq!(cancel_response.1["status"], "cancelled");
        }
        let fourth_key = URL_SAFE_NO_PAD.encode([4; 32]);
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&fourth_key),
                Some("https://site.example"),
                Some(&payload)
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Age both admissions past the minute window. Daily capacity must
        // still reject a new key even with no active session remaining.
        sqlx::query("UPDATE flow_service.flow_instances SET created_at=CURRENT_TIMESTAMP - INTERVAL '2 minutes' WHERE organization_id='org-1' AND context->'_marty_public_verification_session' IS NOT NULL")
            .execute(&pool).await.unwrap();
        assert_eq!(
            call(
                &router,
                "POST",
                &endpoint,
                Some(&fourth_key),
                Some("https://site.example"),
                Some(&payload)
            )
            .await
            .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        pool.close().await;
    }
}

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }

    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: policy_id.into(),
            organization_id: self.organization_id.into(),
            status: "active".into(),
            credential_requirements: vec![json!({
                "id": "member",
                "credential_template_id": "template-1",
                "requested_claims": [{"claim_name": "given_name", "required": true}]
            })],
        })
    }

    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        unreachable!("verification start does not evaluate presentations")
    }
}

struct Templates;

#[async_trait]
impl CredentialTemplateProvider for Templates {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        Ok(CredentialTemplateReference {
            id: template_id.into(),
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
            wallet_configurations: Vec::new(),
            issuer_algorithm: Some("ES256".into()),
        })
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        assert_eq!(organization_id, "org-1");
        Ok(vec!["dc+sd-jwt".into()])
    }
}

#[derive(Clone, Copy)]
enum BrokenTemplate {
    Missing,
    WrongOrganization,
    Inactive,
}

#[async_trait]
impl CredentialTemplateProvider for BrokenTemplate {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        if matches!(self, Self::Missing) {
            return Err(FlowProviderError::NotFound {
                provider: "credential_template",
                resource: template_id.into(),
            });
        }
        let mut template = Templates.get_template(template_id).await?;
        match self {
            Self::WrongOrganization => template.organization_id = "other-org".into(),
            Self::Inactive => template.status = "inactive".into(),
            Self::Missing => unreachable!(),
        }
        Ok(template)
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        Templates.wallet_formats(organization_id).await
    }
}

struct Signing;

#[async_trait]
impl SigningIdentityProvider for Signing {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
        key_purpose: &str,
        credential_format: &str,
        _algorithm: Option<&str>,
    ) -> Result<SigningIdentity, FlowProviderError> {
        Ok(SigningIdentity {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
            verification_method_id: format!("{issuer_did}#request-object"),
            signing_key_reference: "managed-key-1".into(),
            public_jwk: BTreeMap::from([
                ("kty".into(), json!("EC")),
                ("crv".into(), json!("P-256")),
                ("x".into(), json!("x")),
                ("y".into(), json!("y")),
            ]),
            key_purpose: key_purpose.into(),
            credential_format: credential_format.into(),
            algorithm: "ES256".into(),
        })
    }

    async fn sign(&self, request: &SigningRequest) -> Result<SigningResult, FlowProviderError> {
        Ok(SigningResult {
            issuer_did: request.issuer_did.clone(),
            verification_method_id: request.verification_method_id.clone(),
            algorithm: request.algorithm.clone(),
            signature_raw_b64url: "c2lnbmF0dXJl".into(),
        })
    }
}

struct Envelopes;

#[async_trait]
impl FlowKeyEnvelopeProvider for Envelopes {
    async fn create_haip_key(
        &self,
        organization_id: &str,
        flow_instance_id: &str,
    ) -> Result<marty_flow::HaipRemoteKey, FlowProviderError> {
        Ok(haip_remote_fixture::key(organization_id, flow_instance_id))
    }
}

fn providers(policy_organization: &'static str) -> FlowProviderRegistry {
    FlowProviderRegistry {
        presentation_policy: Some(Arc::new(Policies {
            organization_id: policy_organization,
        })),
        credential_template: Some(Arc::new(Templates)),
        signing_identity: Some(Arc::new(Signing)),
        flow_key_envelope: Some(Arc::new(Envelopes)),
        ..Default::default()
    }
}

fn request(transport: RequestTransport) -> StartVerificationFlowRequest {
    StartVerificationFlowRequest {
        presentation_policy_id: Some("policy-1".into()),
        organization_id: "org-1".into(),
        issuer_did: "did:web:verifier.example".into(),
        response_type: VerificationResponseType::VpToken,
        trust_profile_id: Some("trust-1".into()),
        deployment_profile_id: Some("deployment-1".into()),
        external_reference: Some("external-1".into()),
        callback_url: Some("https://callback.example/result?nonce=token-1234567890".into()),
        oid4vp_profile: Oid4vpProfile::Standard,
        request_transport: transport,
        request_uri_method: RequestUriMethod::Get,
        expiry_minutes: 15,
    }
}

fn callbacks() -> WebhookDestinationRegistry {
    WebhookDestinationRegistry::parse("org-1|https://callback.example/result?nonce=__MARTY_TOKEN__")
        .unwrap()
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

#[tokio::test]
async fn language_neutral_contract_preserves_all_start_transports() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-verification-start-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 2);
    assert_eq!(contract.nonce_entropy_bytes, 32);
    assert_eq!(contract.initial_status, "awaiting_wallet");
    assert_eq!(
        contract.callback_policy,
        "mmf_tenant_registered_destination"
    );
    assert_eq!(
        contract.principal_binding,
        "required_for_http_and_grpc_and_persisted_in_private_context"
    );
    assert_eq!(contract.policy_binding.len(), 4);
    assert_eq!(contract.signing_identity_binding.len(), 5);
    assert_eq!(contract.request_uri_transport, "openid4vp_request_uri");
    assert_eq!(
        contract.request_object_transport,
        "openid4vp_signed_by_value"
    );
    assert_eq!(
        contract.url_query_transport,
        "openid4vp_unsigned_bounded_dcql"
    );
    assert_eq!(contract.siop_transport, "openid_request_uri");
    assert_eq!(
        contract.persistence,
        "single_atomic_insert_after_side_effects"
    );
    assert_eq!(contract.failure_behavior, "no_instance_insert");

    for (transport, expected_fragment) in [
        (RequestTransport::RequestUri, "request_uri="),
        (RequestTransport::RequestObject, "request="),
        (RequestTransport::UrlQuery, "dcql_query="),
    ] {
        let prepared = prepare_verification_start(
            &providers("org-1"),
            &callbacks(),
            request(transport),
            "https://verifier.example",
            false,
            16_384,
            16_384,
            None,
            "user-1",
            now(),
        )
        .await
        .unwrap();
        assert_eq!(prepared.response.status, contract.initial_status);
        assert!(prepared.response.request_uri.contains(expected_fragment));
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&prepared.response.nonce)
                .unwrap()
                .len(),
            contract.nonce_entropy_bytes
        );
        assert_eq!(
            prepared.instance.context["auth_request"],
            prepared.response.request_uri
        );
        assert_eq!(
            prepared.instance.context["callback_url"],
            "https://callback.example/result?nonce=token-1234567890"
        );
        assert_eq!(
            prepared.instance.context["_marty_verification_principal_id"],
            "user-1"
        );
        assert_eq!(prepared.instance.organization_id, "org-1");
    }

    let mut siop = request(RequestTransport::RequestUri);
    siop.response_type = VerificationResponseType::IdToken;
    siop.presentation_policy_id = None;
    let prepared = prepare_verification_start(
        &providers("other-org"),
        &callbacks(),
        siop,
        "https://verifier.example",
        false,
        16_384,
        16_384,
        Some("https://verifier.example/client"),
        "user-1",
        now(),
    )
    .await
    .unwrap();
    assert!(prepared
        .response
        .request_uri
        .starts_with("openid://authorize?"));
    assert_eq!(prepared.response.presentation_policy_id, "");
    assert_eq!(
        prepared.instance.context["flow_definition_reference"],
        "__siop_v2__"
    );
}

#[tokio::test]
async fn rejected_callback_or_cross_tenant_policy_produces_no_prepared_instance() {
    let principal_error = prepare_verification_start(
        &providers("org-1"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        " ",
        now(),
    )
    .await
    .unwrap_err();
    assert!(principal_error.to_string().contains("PRINCIPAL_REQUIRED"));

    let callback_error = prepare_verification_start(
        &providers("org-1"),
        &WebhookDestinationRegistry::default(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        "user-1",
        now(),
    )
    .await
    .unwrap_err();
    assert!(callback_error.to_string().contains("CALLBACK_REJECTED"));

    let policy_error = prepare_verification_start(
        &providers("org-2"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        "https://verifier.example",
        false,
        16_384,
        16_384,
        None,
        "user-1",
        now(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        policy_error,
        FlowVerificationStartError::InvalidPolicyReference
    ));
}

#[tokio::test]
async fn stale_or_foreign_policy_template_fails_before_request_uri_is_advertised() {
    for broken in [
        BrokenTemplate::Missing,
        BrokenTemplate::WrongOrganization,
        BrokenTemplate::Inactive,
    ] {
        let mut registry = providers("org-1");
        registry.credential_template = Some(Arc::new(broken));
        let error = prepare_verification_start(
            &registry,
            &callbacks(),
            request(RequestTransport::RequestUri),
            "https://verifier.example",
            false,
            16_384,
            16_384,
            None,
            "user-1",
            now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            FlowVerificationStartError::InvalidPolicyReference
        ));
    }
}

#[tokio::test]
async fn configured_identity_and_haip_gates_apply_before_persistence() {
    let mut options = VerificationStartOptions::default();
    options.request_object.client_id_scheme = Oid4vpClientIdScheme::RedirectUri;
    let prepared = prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        request(RequestTransport::RequestUri),
        &options,
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "user-1",
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        prepared.instance.context["oid4vp_client_id"],
        format!(
            "redirect_uri:https://verifier.example/v1/flows/instances/{}/submit",
            prepared.instance.id
        )
    );

    let mut haip = request(RequestTransport::RequestUri);
    haip.oid4vp_profile = Oid4vpProfile::Haip;
    assert!(prepare_profiled_verification_start(
        &providers("org-1"),
        &callbacks(),
        haip,
        &options,
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "user-1",
            now: now(),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("HAIP_DISABLED"));
}

fn website_definition() -> marty_flow::FlowDefinitionRecord {
    let mut record = marty_flow::create_definition_record(
        marty_flow::parse_request(json!({
            "organization_id": "org-1", "name": "Website verification",
            "flow_type": "oid4vp_presentation", "presentation_policy_id": "policy-1"
        }))
        .unwrap(),
        now(),
    )
    .unwrap();
    record.status = marty_flow::DefinitionStatus::Active;
    record
}

#[tokio::test]
async fn selected_definition_uses_canonical_wallet_lifecycle_and_pins_its_version() {
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: definition.version,
    };
    let mut prepared = marty_flow::prepare_defined_verification_start(
        &providers("org-1"),
        &WebhookDestinationRegistry::default(),
        &definition,
        &binding,
        "did:web:verifier.example",
        &VerificationStartOptions::default(),
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "website-operator",
            now: now(),
        },
    )
    .await
    .unwrap();
    assert_eq!(prepared.instance.flow_definition_id, definition.id);
    assert_eq!(prepared.response.flow_definition_id, definition.id);
    assert_eq!(
        prepared.instance.context["_marty_verification_definition"]["binding"]["version"],
        1
    );
    assert!(prepared
        .response
        .qr_code_data
        .starts_with("openid4vp://authorize?"));
    assert_eq!(
        prepared.instance.context["presentation_policy_id"],
        "policy-1"
    );
    // Rebuilding the same query assigns a new query ID, but must preserve
    // the admitted claims/formats. Canonical request retrieval checks the pin.
    let retrieval = marty_flow::prepare_verification_request(
        &providers("org-1"),
        prepared.instance.clone(),
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        retrieval,
        marty_flow::PreparedVerificationRequest::Ready(_)
    ));
    let mut changed = prepared.instance.clone();
    changed.context["_marty_verification_request_digest"] = json!("changed-policy-query");
    assert!(marty_flow::prepare_verification_request(
        &providers("org-1"),
        changed,
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .is_err());
    assert_eq!(prepared.instance.step_history.len(), 2);
    assert_eq!(prepared.instance.step_history[0]["status"], "completed");
    let before = prepared.instance.step_history.clone();
    marty_flow::record_defined_verification_progress(&mut prepared.instance, false, now()).unwrap();
    let after_request = prepared.instance.step_history.clone();
    assert_eq!(after_request.len(), 3);
    assert_eq!(before[0], after_request[0]);
    marty_flow::record_defined_verification_progress(&mut prepared.instance, false, now()).unwrap();
    assert_eq!(prepared.instance.step_history, after_request);
    assert!(
        marty_flow::record_defined_verification_progress(&mut prepared.instance, true, now())
            .is_err()
    );
    prepared.instance.status = marty_verification::flow::FlowInstanceStatus::Failed;
    marty_flow::record_defined_verification_progress(&mut prepared.instance, true, now()).unwrap();
    assert_eq!(prepared.instance.step_history.len(), 4);
    assert_eq!(prepared.instance.step_history[3]["status"], "failed");
    assert!(prepared.instance.current_step_id.is_none());
    assert!(
        !serde_json::to_string(&prepared.instance.projection().unwrap())
            .unwrap()
            .contains("_marty_verification_definition")
    );
}

#[tokio::test]
async fn definition_binding_rejects_changes_or_extra_work_before_signing() {
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: definition.version,
    };
    for variant in 0..8 {
        let mut candidate = definition.clone();
        match variant {
            0 => candidate.organization_id = "foreign".into(),
            1 => candidate.version += 1,
            2 => candidate.status = marty_flow::DefinitionStatus::Paused,
            3 => {
                candidate
                    .hooks
                    .insert("on_start".into(), vec![json!({"action": "approval"})]);
            }
            4 => candidate.preconditions.push("approved".into()),
            5 => candidate.steps[1]["config"]["protocol_step"] = json!("approval"),
            6 => candidate.default_timeout_seconds = 61,
            _ => candidate.presentation_policy_id = None,
        }
        let result = marty_flow::prepare_defined_verification_start(
            &FlowProviderRegistry::default(),
            &WebhookDestinationRegistry::default(),
            &candidate,
            &binding,
            "did:web:verifier.example",
            &VerificationStartOptions::default(),
            VerificationStartContext {
                public_base_url: "https://verifier.example",
                allow_http_loopback: false,
                principal_id: "website-operator",
                now: now(),
            },
        )
        .await;
        assert!(
            matches!(
                result,
                Err(marty_flow::DefinedVerificationError::DefinitionUnavailable
                    | marty_flow::DefinedVerificationError::UnsupportedDefinition)
            ),
            "variant {variant}: {result:?}"
        );
    }
}

struct WebsiteEvaluation {
    allow: bool,
    seen: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl PresentationPolicyProvider for WebsiteEvaluation {
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!("sha256:{}", "a".repeat(64)))
    }

    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Policies {
            organization_id: "org-1",
        }
        .get_policy(id)
        .await
    }
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(request.organization_id, "org-1");
        assert_eq!(request.principal_id, "website-operator");
        assert_eq!(request.policy_id, "policy-1");
        assert_eq!(
            request.context["_marty_expected_policy_configuration_digest"],
            format!("sha256:{}", "a".repeat(64))
        );
        Ok(PresentationEvaluationResult {
            authentication_diagnostic: None,
            result: if self.allow { "passed" } else { "failed" }.into(),
            decision: if self.allow { "allow" } else { "deny" }.into(),
            decision_reason: None,
            verified_claims: [("given_name".into(), json!("Synthetic holder"))].into(),
            credential_results: vec![
                json!({"signature_valid": true, "trust_check_passed": self.allow}),
            ],
            error_codes: vec![],
            warnings: vec![],
        })
    }
}

#[tokio::test]
async fn selected_definition_completes_only_from_the_canonical_evaluator_and_scrubs_denied_claims()
{
    for allow in [true, false] {
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = providers("org-1");
        registry.presentation_policy = Some(Arc::new(WebsiteEvaluation {
            allow,
            seen: seen.clone(),
        }));
        let definition = website_definition();
        let binding = marty_flow::VerificationDefinitionBinding {
            organization_id: "org-1".into(),
            definition_id: definition.id.clone(),
            version: definition.version,
        };
        let prepared = marty_flow::prepare_defined_verification_start(
            &registry,
            &WebhookDestinationRegistry::default(),
            &definition,
            &binding,
            "did:web:verifier.example",
            &VerificationStartOptions::default(),
            VerificationStartContext {
                public_base_url: "https://verifier.example",
                allow_http_loopback: false,
                principal_id: "website-operator",
                now: now(),
            },
        )
        .await
        .unwrap();
        let marty_flow::PreparedVerificationRequest::Ready(request) =
            marty_flow::prepare_verification_request(
                &registry,
                prepared.instance,
                "https://verifier.example",
                &marty_flow::VerificationRequestRetrievalOptions::default(),
                now(),
            )
            .await
            .unwrap()
        else {
            panic!("fresh request expected")
        };
        let input = marty_flow::VerificationSubmissionInput {
            vp_token: "unit-test.presentation.token".into(),
            presentation_submission: None,
            state: request
                .instance
                .context
                .get("oid4vp_expected_state")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            audience_override: None,
        };
        let options = marty_flow::VerificationSubmissionOptions {
            callback_destinations: WebhookDestinationRegistry::default(),
            callback_secret: None,
            verifier_sender_id: "website-verifier".into(),
            nonce_ttl_seconds: 900,
            callback_retention_seconds: 900,
            callback_max_attempts: 10,
        };
        let mut changed = request.instance.clone();
        changed.context["_marty_verification_request_digest"] = json!("changed");
        assert!(marty_flow::prepare_verification_submission(
            &registry,
            changed,
            input.clone(),
            &options,
            now()
        )
        .await
        .is_err());
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
        let marty_flow::PreparedVerificationSubmission::Final(finalization) =
            marty_flow::prepare_verification_submission(
                &registry,
                request.instance,
                input,
                &options,
                now(),
            )
            .await
            .unwrap()
        else {
            panic!("canonical terminal evaluation expected")
        };
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(finalization.instance.flow_definition_id, definition.id);
        assert_eq!(finalization.instance.step_history.len(), 4);
        assert_eq!(
            finalization.instance.step_history[3]["status"],
            if allow { "completed" } else { "failed" }
        );
        assert_eq!(
            finalization.instance.result.as_ref().unwrap()["verified_claims"],
            if allow {
                json!({"given_name": "Synthetic holder"})
            } else {
                json!({})
            }
        );
        assert!(finalization.instance.current_step_id.is_none());
    }
}

struct ChangingRules(Arc<std::sync::atomic::AtomicUsize>);
#[async_trait]
impl PresentationPolicyProvider for ChangingRules {
    async fn configuration_digest(&self, _policy_id: &str) -> Result<String, FlowProviderError> {
        Ok(format!(
            "sha256:{}",
            if self.0.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                "a"
            } else {
                "b"
            }
            .repeat(64)
        ))
    }
    async fn get_policy(&self, id: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        Policies {
            organization_id: "org-1",
        }
        .get_policy(id)
        .await
    }
    async fn evaluate(
        &self,
        _request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        panic!("changed admission must not reach evaluation")
    }
}

#[tokio::test]
async fn unchanged_wallet_query_cannot_hide_a_changed_business_rule() {
    let generation = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = providers("org-1");
    registry.presentation_policy = Some(Arc::new(ChangingRules(generation.clone())));
    let definition = website_definition();
    let binding = marty_flow::VerificationDefinitionBinding {
        organization_id: "org-1".into(),
        definition_id: definition.id.clone(),
        version: 1,
    };
    let prepared = marty_flow::prepare_defined_verification_start(
        &registry,
        &WebhookDestinationRegistry::default(),
        &definition,
        &binding,
        "did:web:verifier.example",
        &VerificationStartOptions::default(),
        VerificationStartContext {
            public_base_url: "https://verifier.example",
            allow_http_loopback: false,
            principal_id: "website-operator",
            now: now(),
        },
    )
    .await
    .unwrap();
    let marty_flow::PreparedVerificationRequest::Ready(request) =
        marty_flow::prepare_verification_request(
            &registry,
            prepared.instance.clone(),
            "https://verifier.example",
            &marty_flow::VerificationRequestRetrievalOptions::default(),
            now(),
        )
        .await
        .unwrap()
    else {
        panic!("fresh request expected")
    };
    generation.store(1, std::sync::atomic::Ordering::SeqCst);
    assert!(marty_flow::prepare_verification_request(
        &registry,
        prepared.instance,
        "https://verifier.example",
        &marty_flow::VerificationRequestRetrievalOptions::default(),
        now(),
    )
    .await
    .is_err());
    let input = marty_flow::VerificationSubmissionInput {
        vp_token: "unit-test.presentation.token".into(),
        presentation_submission: None,
        state: request
            .instance
            .context
            .get("oid4vp_expected_state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        audience_override: None,
    };
    let options = marty_flow::VerificationSubmissionOptions {
        callback_destinations: WebhookDestinationRegistry::default(),
        callback_secret: None,
        verifier_sender_id: "website-verifier".into(),
        nonce_ttl_seconds: 900,
        callback_retention_seconds: 900,
        callback_max_attempts: 10,
    };
    assert!(marty_flow::prepare_verification_submission(
        &registry,
        request.instance,
        input,
        &options,
        now()
    )
    .await
    .is_err());
}
