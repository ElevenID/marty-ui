//! Executable gateway boundary inside the outer fixture's unpublished namespace.
//! Native owner reads are exercised behaviorally; selected legacy writes remain traps.
use std::{
    process::Child,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use serde_json::{json, Value};

use super::{
    didcomm_gateway_replay::OwnedHttp,
    issuance_named_peers::{API_KEY, CLIENT_KEY, FOREIGN_CLIENT_KEY, ORGANIZATION},
    issuance_process::{bounded_http_client, wait_for_health_with_client},
    resolved_runtime::ResolvedRuntime,
};

pub(super) const PUBLIC_INITIATION_PATH: &str = "/v1/issuance";

#[derive(Clone)]
struct LegacyState {
    attempts: Arc<Mutex<Vec<(String, String)>>>,
    accepted: Arc<Mutex<Vec<(String, String)>>>,
}

pub(super) struct LegacyFixture {
    server: OwnedHttp,
    state: LegacyState,
}

async fn legacy(
    State(state): State<LegacyState>,
    request: Request<Body>,
) -> axum::response::Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    state
        .attempts
        .lock()
        .unwrap()
        .push((method.clone(), path.clone()));
    let response = if method == "GET" && matches!(path.as_str(), "/health" | "/health/ready") {
        Json(json!({"status":"healthy"})).into_response()
    } else {
        // A positive unselected GET demonstrates the legacy endpoint exists;
        // every other path/method is an observed forbidden fallback.
        assert_eq!(request.headers()["x-api-key"], API_KEY);
        assert_eq!(method, "GET", "selected legacy writes are forbidden");
        assert_eq!(path, "/v1/issued-credentials");
        (StatusCode::IM_A_TEAPOT, Json(legacy_control_body())).into_response()
    };
    assert!(to_bytes(request.into_body(), 65536)
        .await
        .unwrap()
        .is_empty());
    state.accepted.lock().unwrap().push((method, path));
    response
}

fn legacy_control_body() -> Value {
    json!({"error":"owned_legacy_trap","error_description":"Synthetic unselected legacy list","message_id":"11111111-1111-4111-8111-111111111111"})
}

impl LegacyFixture {
    pub(super) async fn start() -> Self {
        let state = LegacyState {
            attempts: Arc::default(),
            accepted: Arc::default(),
        };
        let server =
            OwnedHttp::start(Router::new().fallback(legacy).with_state(state.clone())).await;
        Self { server, state }
    }

    pub(super) fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.server.port)
    }

    pub(super) fn assert_no_fallback(&self) {
        let attempts = self.state.attempts.lock().unwrap();
        assert_eq!(*attempts, *self.state.accepted.lock().unwrap());
        assert!(attempts.iter().all(|(method, _)| method == "GET"));
    }

    pub(super) async fn close(self) {
        self.assert_no_fallback();
        self.server.close().await;
    }
}

pub(super) struct GatewayFixture {
    child: Child,
    stop_attempted: bool,
    pub(super) origin: String,
    pub(super) client: reqwest::Client,
}

impl GatewayFixture {
    pub(super) async fn start(model: &ResolvedRuntime, port: u16) -> Self {
        let child = model
            .gateway_command()
            .spawn()
            .expect("required isolated gateway executable");
        let client = bounded_http_client(Duration::from_secs(20));
        let fixture = Self {
            child,
            stop_attempted: false,
            origin: format!("http://127.0.0.1:{port}"),
            client,
        };
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(15),
                wait_for_health_with_client(port, &fixture.client)
            )
            .await
            .unwrap(),
            Some(json!({"status":"healthy","service":"api-gateway"}))
        );
        let response = fixture
            .client
            .get(format!("{}/ready", fixture.origin))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ready");
        assert_eq!(body["service"], "api-gateway");
        let mut actual: Vec<_> = body["services"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: Vec<_> = model.gateway_environment["GATEWAY_REQUIRED_READY_SERVICES"]
            .split(',')
            .collect();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        assert!(body["services"]
            .as_object()
            .unwrap()
            .values()
            .all(|details| details["status"] == "healthy"));
        fixture
    }

    pub(super) async fn deny_invalid_client(&self) {
        let response = self
            .client
            // Exercise the public gateway contract. The gateway rewrites this
            // route to the native service's internal `/initiate` endpoint only
            // after authenticating the caller.
            .post(format!("{}{PUBLIC_INITIATION_PATH}", self.origin))
            .header("x-api-key", "synthetic-invalid-client-key")
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: Value = response.json().await.unwrap();
        assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
        assert_eq!(
            body,
            json!({"error":"unauthorized","error_description":"Invalid or expired API key","message_id":body["message_id"]})
        );
    }

    pub(super) async fn deny_foreign_owner(&self, source_id: &str) {
        let response = self
            .client
            .post(format!(
                "{}/v1/issued-credentials/{source_id}/renew",
                self.origin
            ))
            .header("x-api-key", FOREIGN_CLIENT_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({"detail":"API key does not have access to this organization"})
        );
    }

    pub(super) async fn legacy_control(&self) {
        let response = self
            .client
            .get(format!(
                "{}/v1/issued-credentials?organization_id={ORGANIZATION}",
                self.origin
            ))
            .header("x-api-key", CLIENT_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            legacy_control_body()
        );
    }

    pub(super) async fn native_unavailable(&self, source_id: &str, legacy: &LegacyFixture) {
        let response = self
            .client
            .post(format!(
                "{}/v1/issued-credentials/{source_id}/renew",
                self.origin
            ))
            .header("x-api-key", CLIENT_KEY)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = response.json().await.unwrap();
        assert!(uuid::Uuid::parse_str(body["message_id"].as_str().unwrap()).is_ok());
        assert_eq!(
            body,
            json!({"error":"service_unavailable","error_description":"Service unavailable","message_id":body["message_id"]})
        );
        legacy.assert_no_fallback();
    }

    fn stop(&mut self) -> std::io::Result<()> {
        if self.stop_attempted {
            return Ok(());
        }
        self.stop_attempted = true;
        super::bounded_fixture_command::stop_owned_child(&mut self.child)
            .map_err(|_| std::io::Error::other("owned gateway did not exit after kill"))
    }

    pub(super) fn close(mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        self.stop().expect("bounded owned gateway exit");
    }
}

impl Drop for GatewayFixture {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("Owned gateway cleanup failed: {error}");
        }
    }
}
