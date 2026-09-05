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
    let mut response = if body["lifecycle_action"] == "reinstate" {
        (StatusCode::SERVICE_UNAVAILABLE, "Synthetic runtime refusal").into_response()
    } else {
        Json(json!({"accepted":true})).into_response()
    };
    response
        .headers_mut()
        .insert("x-request-id", "synthetic-runtime-request".parse().unwrap());
    response
}

struct AbortServer(tokio::task::AbortHandle);
impl Drop for AbortServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn run(pool: &PgPool) {
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
    assert!(deliveries[0]["last_error"].is_null());
    let failure = "Canvas Credentials status sync failed (HTTP 503): Synthetic runtime refusal";
    assert_eq!(deliveries[1]["last_error"], failure);
    assert_eq!(deliveries[1]["metadata"]["last_status_sync_error"], failure);
    assert!(deliveries[2]["last_error"].is_null());
    assert!(deliveries[2]["metadata"]["last_status_sync_error"].is_null());
    assert_eq!(
        deliveries[2]["metadata"]["status_sync_request_id"],
        "synthetic-runtime-request"
    );
}
