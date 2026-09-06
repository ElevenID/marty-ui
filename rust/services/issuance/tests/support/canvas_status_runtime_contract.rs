//! Real configuration, tenant vault, credential/delivery persistence and HTTP.
//! Only canonical status publication is controlled; the mirror uses a local server.
use async_trait::async_trait;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use marty_issuance_service::{
    canvas_credentials_status::CanvasCredentialsStatusService,
    canvas_oauth::CanvasOAuthSecretVault,
    canvas_oauth_postgres::PostgresIntegrationSecretVault,
    config::IssuanceServiceConfig,
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleEvent, CredentialLifecycleEventSink,
        CredentialManagementPortError, CredentialManagementService, CredentialStatusPublisher,
        ManagedCredential,
    },
    credential_management_postgres::PostgresCredentialManagementRepository,
    integration_secret::{IntegrationSecretCipher, NewIntegrationSecret},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

struct RuntimeState {
    pool: PgPool,
    calls: Mutex<Vec<Value>>,
    events: Mutex<Vec<String>>,
    remove_delivery_before_response: AtomicBool,
    responses: Responses,
    response_override: Mutex<Option<Value>>,
}

#[derive(Clone, Copy)]
enum Responses {
    Baseline,
    Unicode,
    Charset,
    Iso2022,
    Ordinal,
    Utf7Label,
    Utf7Body,
}

impl Responses {
    fn case(self, action: &str) -> Option<&'static str> {
        Some(match (self, action) {
            (Self::Baseline | Self::Utf7Body, _) => return None,
            (Self::Unicode, "suspend") => "utf-16_missing_bom_200",
            (Self::Unicode, "reinstate") => "utf-32_missing_bom_403",
            (Self::Unicode, "revoke") => "utf16_json_first_200",
            (Self::Charset, "suspend") => "charset_mixed_continuation_text_200",
            (Self::Charset, "reinstate") => "charset_mixed_continuation_json_403",
            (Self::Charset, "revoke") => "charset_mixed_continuation_json_200",
            (Self::Iso2022, "suspend") => "iso2022_internal_200",
            (Self::Iso2022, "reinstate") => "iso2022_pending_200",
            (Self::Iso2022, "revoke") => "iso2022_label_json_200",
            (Self::Ordinal, "suspend") => "ordinal_text_200",
            (Self::Ordinal, "reinstate") => "ordinal_json_403",
            (Self::Ordinal, "revoke") => "ordinal_json_200",
            (Self::Utf7Label, "suspend") => "utf7_label_latin1_403",
            (Self::Utf7Label, "reinstate") => "utf7_label_null_200",
            (Self::Utf7Label, "revoke") => "utf7_label_json_200",
            _ => panic!("unexpected synthetic lifecycle action"),
        })
    }
}

#[async_trait]
impl CredentialStatusPublisher for RuntimeState {
    async fn publish(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        _: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        self.calls.lock().unwrap().push(json!({"port":"publication","action":action.as_str(),"status":credential.status.as_str()}));
        Ok(())
    }
}

#[async_trait]
impl CredentialLifecycleEventSink for RuntimeState {
    async fn emit(&self, event: CredentialLifecycleEvent) {
        self.events.lock().unwrap().push(event.event_type);
    }
}

async fn mirror(
    State(state): State<Arc<RuntimeState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let status: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.issued_credentials WHERE id='credential-review'",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap();
    state.calls.lock().unwrap().push(
        json!({"port":"mirror","body":body,"persisted_status":status,
        "authorization":headers.get("authorization").and_then(|value| value.to_str().ok())}),
    );
    if state.remove_delivery_before_response.load(Ordering::SeqCst) {
        // Deterministic fault in this disposable database only: external success
        // arrives after the selected delivery row has disappeared.
        sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id='delivery-provider' AND organization_id='org-review'")
            .execute(&state.pool).await.unwrap();
    }
    let response_override = state.response_override.lock().unwrap().clone();
    let reference_response = response_override.is_some();
    let case = response_override.or_else(|| {
        state
            .responses
            .case(body["lifecycle_action"].as_str().unwrap())
            .map(|name| {
                let scenarios: Value = serde_json::from_str(include_str!(
                    "../../../../../contracts/canvas-status-provider-scenarios.json"
                ))
                .unwrap();
                scenarios["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|case| case["name"] == name)
                    .unwrap()
                    .clone()
            })
    });
    let mut response = if let Some(case) = case {
        (
            StatusCode::from_u16(
                case["response_status"]
                    .as_u64()
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
            [(
                "content-type",
                case["response_content_type"].as_str().unwrap(),
            )],
            hex::decode(case["response_hex"].as_str().unwrap()).unwrap(),
        )
            .into_response()
    } else if body["lifecycle_action"] == "reinstate" {
        (StatusCode::SERVICE_UNAVAILABLE, "Synthetic runtime refusal").into_response()
    } else {
        Json(json!({"accepted":true})).into_response()
    };
    response.headers_mut().insert(
        "x-request-id",
        if reference_response {
            "synthetic-provider-request"
        } else {
            "synthetic-runtime-request"
        }
        .parse()
        .unwrap(),
    );
    response
}

struct AbortServer(tokio::task::AbortHandle);
impl Drop for AbortServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn run(pool: &PgPool) {
    run_scenario(pool, Responses::Baseline).await;
}

pub async fn run_unicode(pool: &PgPool) {
    run_scenario(pool, Responses::Unicode).await;
}

pub async fn run_charset(pool: &PgPool) {
    run_scenario(pool, Responses::Charset).await;
}

pub async fn run_iso2022(pool: &PgPool) {
    run_scenario(pool, Responses::Iso2022).await;
}

pub async fn run_ordinal(pool: &PgPool) {
    run_scenario(pool, Responses::Ordinal).await;
}

pub async fn run_utf7_label(pool: &PgPool) {
    run_scenario(pool, Responses::Utf7Label).await;
}

pub async fn run_utf7_body(pool: &PgPool) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-utf7-consumer-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-utf7-consumer-oracle.json"
    ))
    .unwrap();
    run_body(pool, &scenarios, &oracle, 12, false).await;
}

pub async fn run_json_body(pool: &PgPool) {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-consumer-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-consumer-oracle.json"
    ))
    .unwrap();
    run_body(pool, &scenarios, &oracle, 66, false).await;
}

pub async fn run_json_depth_body(pool: &PgPool) {
    let scenarios = super::canvas_json_depth_replay::scenarios();
    let oracle = super::canvas_json_depth_replay::oracle();
    run_body(pool, &scenarios, &oracle, 64, true).await;
}

async fn run_body(
    pool: &PgPool,
    scenarios: &Value,
    oracle: &Value,
    expected_cases: usize,
    depth: bool,
) {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use marty_issuance_service::{
        credential_management_http::CredentialManagementHttpService,
        http::router_with_credential_management, transport::TransportPolicy, IssuanceRuntime,
    };
    use marty_oid4vci::discovery::StaticDiscoveryDocuments;
    use tower::ServiceExt;

    let RuntimeFixture {
        state,
        service,
        config,
        url,
        stop,
        server,
        _cleanup,
    } = start_runtime(pool, Responses::Utf7Body).await;
    // The frozen full-route scenarios use the operator token, not a tenant
    // override. Existing runtime scenarios continue testing real tenant-vault use.
    sqlx::query("UPDATE issuance_service.canvas_program_bindings SET canvas_credentials='{}' WHERE id='binding-review'").execute(pool).await.unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    let app = router_with_credential_management(
        runtime.state(),
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name),
        TransportPolicy::new(config.cors_allowed_origins),
        CredentialManagementHttpService::new(service, Some("synthetic-validation-key")),
    );
    let cases = scenarios["provider"].as_array().unwrap();
    let observations = oracle["provider"]["observations"].as_array().unwrap();
    assert_eq!(cases.len(), expected_cases);
    assert_eq!(cases.len(), observations.len());
    let preserved_sql = "SELECT jsonb_build_object('transactions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM issuance_service.issuance_transactions t),'other_credentials',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM issuance_service.issued_credentials c WHERE id <> 'credential-review'))";
    let preserved: Value = sqlx::query_scalar(preserved_sql)
        .fetch_one(pool)
        .await
        .unwrap();
    let mut count = 0;
    for (case, observation) in cases.iter().zip(observations) {
        assert_eq!(case["name"], observation["name"]);
        *state.response_override.lock().unwrap() = Some(case.clone());
        let routes = observation["credential_routes"].as_array().unwrap();
        assert_eq!(routes.len(), 3);
        for expected in routes {
            let action = expected["action"].as_str().unwrap();
            sqlx::query("UPDATE issuance_service.issued_credentials SET status=$1,status_updated_at='2026-01-01T00:00:00Z',revoked=false,revoked_at=NULL,revocation_reason=NULL WHERE id='credential-review' AND organization_id='org-review'")
                .bind(if action == "reinstate" { "suspended" } else { "active" }).execute(pool).await.unwrap();
            let initial_delivery = &expected["delivery_before"];
            sqlx::query("UPDATE issuance_service.credential_delivery_records SET metadata=$1,external_credential_id='external-assertion',canvas_account_id=$2,last_error=NULL,updated_at='2026-01-01T00:00:00Z' WHERE id='delivery-provider' AND organization_id='org-review'")
                .bind(&initial_delivery["metadata"]).bind(initial_delivery["canvas_account_id"].as_str()).execute(pool).await.unwrap();
            let credential_before = credential_row(pool).await;
            let delivery_before = delivery_row(pool).await;
            assert_eq!(
                normalized(credential_before.clone(), &url, depth),
                expected["credential_before"],
                "{} {action} credential input",
                case["name"]
            );
            assert_eq!(
                normalized(delivery_before.clone(), &url, depth),
                *initial_delivery,
                "{} {action} delivery input",
                case["name"]
            );
            state.calls.lock().unwrap().clear();
            state.events.lock().unwrap().clear();
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!(
                            "/v1/issuance/credentials/credential-review/{action}"
                        ))
                        .header("x-api-key", "synthetic-validation-key")
                        .header("x-organization-id", "org-review")
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"reason":"synthetic reason"}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                u64::from(response.status().as_u16()),
                expected["http_status"].as_u64().unwrap(),
                "{} {action}",
                case["name"]
            );
            let content_type = response.headers()["content-type"]
                .to_str()
                .unwrap()
                .to_owned();
            assert_eq!(content_type, expected["content_type"].as_str().unwrap());
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let body = if content_type.starts_with("application/json") {
                normalized(
                    serde_json::from_slice::<Value>(&bytes).unwrap(),
                    &url,
                    depth,
                )
            } else {
                json!(std::str::from_utf8(&bytes).unwrap())
            };
            assert_eq!(body, expected["body"], "{} {action} response", case["name"]);
            let credential_after = credential_row(pool).await;
            let delivery_after = delivery_row(pool).await;
            let mut changed: Vec<_> = credential_before
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, value)| **value != credential_after[*key])
                .map(|(key, _)| key.clone())
                .collect();
            changed.sort();
            assert_eq!(json!(changed), expected["credential_changed_columns"]);
            assert_eq!(
                normalized(credential_after, &url, depth),
                expected["credential_after"]
            );
            assert_eq!(
                json!(delivery_before == delivery_after),
                expected["delivery_row_unchanged"]
            );
            assert_eq!(
                normalized(delivery_after, &url, depth),
                expected["delivery_after"],
                "{} {action} delivery",
                case["name"]
            );
            let calls = state.calls.lock().unwrap().clone();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0]["port"], "publication");
            assert_eq!(
                calls[0]["status"],
                expected["publication"][0]["persisted_status"]
            );
            assert_eq!(calls[1]["port"], "mirror");
            assert_eq!(
                calls[1]["persisted_status"],
                expected["credential_after"]["status"]
            );
            assert_eq!(
                normalized(calls[1]["body"].clone(), &url, depth),
                expected["requests"][0]["body"]
            );
            assert_eq!(
                calls[1]["authorization"],
                "Bearer synthetic-runtime-operator-token"
            );
            // Preserve the newer Rust success events; never emit them after a
            // failed delivery save. Published routes did not add these events.
            let events = state.events.lock().unwrap().clone();
            if expected["http_status"] == 500 {
                assert!(events.is_empty());
            } else {
                assert_eq!(
                    events,
                    vec![if action == "reinstate" {
                        "reinstated"
                    } else if action == "suspend" {
                        "suspended"
                    } else {
                        "revoked"
                    }]
                );
            }
            count += 1;
            if depth && case["response_status"] == 200 && action == "suspend" {
                // A later real consumer must read and retain the prior deep
                // response when the provider refuses its next transition.
                use marty_issuance_service::owned_json_value::OwnedJsonValue;
                let retained = delivery_row(pool).await;
                let response_before =
                    OwnedJsonValue::copy(&retained["metadata"]["status_sync_response"]);
                let expected_tree = super::canvas_json_depth_replay::witness_bytes(
                    &serde_json::to_vec(&response_before).unwrap(),
                );
                let previous_attempts = retained["metadata"]["status_sync_attempts"]
                    .as_u64()
                    .unwrap();
                let mut refusal = case.clone();
                refusal["response_status"] = json!(403);
                *state.response_override.lock().unwrap() = Some(refusal);
                state.calls.lock().unwrap().clear();
                state.events.lock().unwrap().clear();
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/v1/issuance/credentials/credential-review/reinstate")
                            .header("x-api-key", "synthetic-validation-key")
                            .header("x-organization-id", "org-review")
                            .header("content-type", "application/json")
                            .body(Body::from(json!({"reason":"synthetic reason"}).to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status().as_u16(),
                    200,
                    "later consumer {}",
                    case["name"]
                );
                let body: Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), 64 * 1024).await.unwrap(),
                )
                .unwrap();
                let reinstate = routes
                    .iter()
                    .find(|route| route["action"] == "reinstate")
                    .unwrap();
                assert_eq!(normalized(body, &url, depth), reinstate["body"]);
                let after = delivery_row(pool).await;
                let response_after =
                    OwnedJsonValue::copy(&after["metadata"]["status_sync_response"]);
                assert_eq!(
                    super::canvas_json_depth_replay::witness_bytes(
                        &serde_json::to_vec(&response_after).unwrap()
                    ),
                    expected_tree
                );
                assert_eq!(
                    after["metadata"]["status_sync_attempts"],
                    previous_attempts + 1
                );
                assert!(after["last_error"]
                    .as_str()
                    .unwrap()
                    .starts_with("Canvas Credentials status sync failed (HTTP 403): "));
                assert_eq!(*state.events.lock().unwrap(), vec!["reinstated"]);
                let calls = state.calls.lock().unwrap().clone();
                assert_eq!(calls.len(), 2);
                assert_eq!(calls[0]["port"], "publication");
                assert_eq!(calls[0]["status"], "suspended");
                assert_eq!(calls[1]["persisted_status"], "active");
                *state.response_override.lock().unwrap() = Some(case.clone());
            }
        }
    }
    assert_eq!(count, expected_cases * 3);
    assert_eq!(
        sqlx::query_scalar::<_, Value>(preserved_sql)
            .fetch_one(pool)
            .await
            .unwrap(),
        preserved
    );
    let _ = stop.send(());
    server.await.unwrap().unwrap();
}

async fn credential_row(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT to_jsonb(c) FROM issuance_service.issued_credentials c WHERE id='credential-review'").fetch_one(pool).await.unwrap()
}

async fn delivery_row(pool: &PgPool) -> marty_issuance_service::owned_json_value::OwnedJsonValue {
    sqlx::query_scalar("SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d WHERE id='delivery-provider'").fetch_one(pool).await.unwrap()
}

fn normalized(
    value: impl Into<marty_issuance_service::owned_json_value::OwnedJsonValue>,
    url: &str,
    depth: bool,
) -> Value {
    let mut value = value.into();
    if depth {
        if let Some(metadata) = value.get_mut("metadata").and_then(Value::as_object_mut) {
            if let Some(response) = metadata.remove("status_sync_response") {
                let response =
                    marty_issuance_service::owned_json_value::OwnedJsonValue::new(response);
                let witness = super::canvas_json_depth_replay::witness_bytes(
                    &serde_json::to_vec(&response).unwrap(),
                );
                metadata.insert("status_sync_response".into(), witness);
            }
        }
    }
    fn substitute(value: &mut Value, url: &str) {
        match value {
            Value::String(text) if text == url => {
                *text = "https://bridge.example.invalid/status".into()
            }
            Value::Object(values) => values.values_mut().for_each(|value| substitute(value, url)),
            Value::Array(values) => values.iter_mut().for_each(|value| substitute(value, url)),
            _ => (),
        }
    }
    substitute(&mut value, url);
    super::canvas_status_provider_replay::timestamps(&mut value);
    super::canvas_observation_values::scalar(&value)
}

struct RuntimeFixture {
    state: Arc<RuntimeState>,
    service: CredentialManagementService,
    config: IssuanceServiceConfig,
    url: String,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    _cleanup: AbortServer,
}

async fn start_runtime(pool: &PgPool, responses: Responses) -> RuntimeFixture {
    let vault = Arc::new(PostgresIntegrationSecretVault::new(
        pool.clone(),
        IntegrationSecretCipher::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .unwrap(),
    ));
    vault
        .save(NewIntegrationSecret {
            id: "runtime-secret".into(),
            organization_id: "org-review".into(),
            name: "Synthetic runtime secret".into(),
            provider: "canvas_credentials".into(),
            purpose: "api_token".into(),
            value: "synthetic-runtime-tenant-token".into(),
            metadata: json!({}),
        })
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.canvas_program_bindings SET canvas_credentials=$1 WHERE id='binding-review'")
        .bind(json!({"api_token_secret_id":"org_secret://org-review/runtime-secret"})).execute(pool).await.unwrap();
    sqlx::query("UPDATE issuance_service.credential_delivery_records SET metadata=$1,external_credential_id='external-assertion' WHERE id='delivery-provider'")
        .bind(json!({"canvas_program_binding_id":"binding-review","unrelated_marker":44})).execute(pool).await.unwrap();
    let state = Arc::new(RuntimeState {
        pool: pool.clone(),
        calls: Mutex::new(Vec::new()),
        events: Mutex::new(Vec::new()),
        remove_delivery_before_response: AtomicBool::new(false),
        responses,
        response_override: Mutex::new(None),
    });
    let application = Router::new()
        .route("/status", post(mirror))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/status", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, application)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
    });
    let _cleanup = AbortServer(server.abort_handle());
    let config = IssuanceServiceConfig::from_values(
        [
            ("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true"),
            ("CANVAS_PILOT_ORGANIZATION_IDS", "org-review"),
            ("CANVAS_CREDENTIALS_PROVIDER", "bridge"),
            (
                "CANVAS_CREDENTIALS_ISSUER_ID",
                if matches!(responses, Responses::Utf7Body) {
                    "configured-issuer"
                } else {
                    ""
                },
            ),
            (
                "CANVAS_CREDENTIALS_API_TOKEN",
                "synthetic-runtime-operator-token",
            ),
            ("CANVAS_CREDENTIALS_STATUS_SYNC_URL", url.as_str()),
            ("CANVAS_CREDENTIALS_STATUS_SYNC_TIMEOUT_SECONDS", "2.5"),
            ("CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS", "true"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned())),
    )
    .unwrap();
    let provider = Arc::new(CanvasCredentialsStatusService::from_runtime(&config, vault));
    let repository =
        PostgresCredentialManagementRepository::new(pool.clone()).with_canvas_lifecycle(provider);
    let service =
        CredentialManagementService::new(Arc::new(repository), state.clone(), state.clone());
    RuntimeFixture {
        state,
        service,
        config,
        url,
        stop,
        server,
        _cleanup,
    }
}

async fn run_scenario(pool: &PgPool, responses: Responses) {
    let RuntimeFixture {
        state,
        service,
        stop,
        server,
        _cleanup,
        ..
    } = start_runtime(pool, responses).await;
    let mut outcomes = Vec::new();
    let mut deliveries = Vec::new();
    for action in [
        CredentialLifecycleAction::Suspend,
        CredentialLifecycleAction::Reinstate,
        CredentialLifecycleAction::Revoke,
    ] {
        outcomes.push(
            service
                .transition(
                    "credential-review",
                    Some("org-review"),
                    action,
                    Some("runtime reason"),
                )
                .await,
        );
        let delivery: Value=sqlx::query_scalar("SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d WHERE id='delivery-provider'").fetch_one(pool).await.unwrap();
        deliveries.push(delivery);
    }
    let used:bool=sqlx::query_scalar("SELECT last_used_at IS NOT NULL FROM issuance_service.organization_integration_secrets WHERE id='runtime-secret' AND organization_id='org-review'").fetch_one(pool).await.unwrap();
    // A separate synthetic starting state, not a supported un-revoke operation.
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='suspended',revoked=false,revoked_at=NULL WHERE id='credential-review' AND organization_id='org-review'")
        .execute(pool).await.unwrap();
    state
        .remove_delivery_before_response
        .store(true, Ordering::SeqCst);
    let persistence_failure = service
        .transition(
            "credential-review",
            Some("org-review"),
            CredentialLifecycleAction::Revoke,
            Some("runtime persistence fault"),
        )
        .await;
    let persisted_status: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.issued_credentials WHERE id='credential-review'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    let delivery_exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.credential_delivery_records WHERE id='delivery-provider')").fetch_one(pool).await.unwrap();
    let _ = stop.send(());
    server.await.unwrap().unwrap();
    let outcomes = outcomes.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(
        matches!(persistence_failure, Err(marty_issuance_service::credential_management::CredentialManagementError::CanvasRetryUnavailable(ref detail)) if detail == "Canvas delivery record disappeared before synchronization could be persisted")
    );
    assert_eq!(persisted_status, "revoked");
    assert!(!delivery_exists);
    assert_eq!(
        outcomes
            .iter()
            .map(|view| view.status.as_str())
            .collect::<Vec<_>>(),
        ["suspended", "active", "revoked"]
    );
    assert!(used, "real vault lookup must update tenant secret usage");
    assert_eq!(
        *state.events.lock().unwrap(),
        ["suspended", "reinstated", "revoked"]
    );
    let calls = state.calls.lock().unwrap();
    assert_eq!(calls.len(), 8, "each transition publishes and then mirrors");
    assert_eq!(calls[6]["port"], "publication");
    assert_eq!(calls[7]["port"], "mirror");
    assert_eq!(calls[7]["persisted_status"], "revoked");
    for (index, status) in ["suspended", "active", "revoked"].into_iter().enumerate() {
        assert_eq!(calls[index * 2]["port"], "publication");
        let request = &calls[index * 2 + 1];
        assert_eq!(request["port"], "mirror");
        assert_eq!(request["persisted_status"], status);
        assert_eq!(request["body"]["credential"]["status"], status);
        assert_eq!(request["body"]["issuer_id"], Value::Null);
        assert_eq!(
            request["authorization"],
            "Bearer synthetic-runtime-tenant-token"
        );
        let delivery = &deliveries[index];
        assert_eq!(delivery["status"], "delivered");
        assert_eq!(delivery["metadata"]["status_sync_attempts"], index + 1);
        assert_eq!(delivery["metadata"]["unrelated_marker"], 44);
        assert_eq!(
            delivery["metadata"]["last_synced_credential_status"],
            status
        );
    }
    if !matches!(responses, Responses::Baseline) {
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-status-provider-oracle.json"
        ))
        .unwrap();
        for (index, action) in ["suspend", "reinstate"].into_iter().enumerate() {
            let name = responses.case(action).unwrap();
            let expected = oracle["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            assert_eq!(
                expected["error_class"],
                match responses {
                    Responses::Unicode => "UnicodeError",
                    Responses::Charset => "TypeError",
                    Responses::Ordinal => "ValueError",
                    Responses::Utf7Label if index == 0 => "RuntimeError",
                    Responses::Utf7Label => "ValueError",
                    Responses::Iso2022 if index == 0 => "RuntimeError",
                    Responses::Iso2022 => "UnicodeError",
                    Responses::Baseline | Responses::Utf7Body => unreachable!(),
                }
            );
            assert_eq!(deliveries[index]["last_error"], expected["error"]);
            assert_eq!(
                deliveries[index]["metadata"]["last_status_sync_error"],
                expected["error"]
            );
            chrono::DateTime::parse_from_rfc3339(
                deliveries[index]["metadata"]["last_status_sync_error_at"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            deliveries[2]["metadata"]["status_sync_response"],
            json!({"accepted":true})
        );
    } else {
        assert!(deliveries[0]["last_error"].is_null());
        let failure = "Canvas Credentials status sync failed (HTTP 503): Synthetic runtime refusal";
        assert_eq!(deliveries[1]["last_error"], failure);
        assert_eq!(deliveries[1]["metadata"]["last_status_sync_error"], failure);
    }
    assert!(deliveries[2]["last_error"].is_null());
    assert!(deliveries[2]["metadata"]["last_status_sync_error"].is_null());
    assert_eq!(
        deliveries[2]["metadata"]["status_sync_request_id"],
        "synthetic-runtime-request"
    );
}
