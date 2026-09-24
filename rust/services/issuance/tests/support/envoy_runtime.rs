//! Actual Envoy HTTP/gRPC selection on the shared real native-main graph.
//! Legacy endpoint is an explicitly counted transport control, not a claim of
//! legacy business implementation parity. Native effects use real PostgreSQL.
use super::{
    didcomm_gateway_replay::OwnedHttp,
    issuance_named_peers::{
        decode_request, grpc_response, PeerState, HOLDER, ISSUER, ORGANIZATION, TEMPLATE, TOKEN,
    },
    renewal_fresh_main::{assert_offer, stored},
};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use marty_issuance_service::issuance_proto::{
    issuance_service_client::IssuanceServiceClient, InitiateIssuanceRequest,
};
use marty_release_evidence::envoy_config::{HTTP_PATH, RPC_PATH, SERVICE};
use prost::Message;
use serde_json::{json, Value};
use std::{
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, PartialEq, prost::Message)]
struct Empty {}
#[derive(Clone)]
struct Legacy {
    calls: Arc<Mutex<Vec<(String, String, bool)>>>,
    health: Arc<Mutex<Vec<String>>>,
    health_service: &'static str,
    initiations: Arc<Mutex<Vec<InitiateIssuanceRequest>>>,
}

async fn legacy(State(state): State<Legacy>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_owned();
    let token = request
        .headers()
        .get("x-service-token")
        .is_some_and(|v| v == TOKEN);
    if path == "/grpc.health.v1.Health/Check" {
        let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
        let health: tonic_health::pb::HealthCheckRequest = decode_request(&bytes);
        let serving = health.service == state.health_service;
        state.health.lock().unwrap().push(health.service);
        return grpc_response(tonic_health::pb::HealthCheckResponse {
            status: if serving { 1 } else { 0 },
        });
    }
    let initiation = path == RPC_PATH
        && request.method() == "POST"
        && request
            .headers()
            .get("content-type")
            .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"));
    state
        .calls
        .lock()
        .unwrap()
        .push((request.method().to_string(), path, token));
    let bytes = to_bytes(request.into_body(), 256 * 1024).await.unwrap();
    if !token {
        return (StatusCode::UNAUTHORIZED, "controlled legacy token required").into_response();
    }
    if initiation {
        state
            .initiations
            .lock()
            .unwrap()
            .push(decode_request(&bytes));
    }
    grpc_response(Empty {})
}

pub(super) struct EnvoyFixture {
    client: reqwest::Client,
    legacy: OwnedHttp,
    auth: OwnedHttp,
    auth_health: Arc<Mutex<Vec<String>>>,
    legacy_health: Arc<Mutex<Vec<String>>>,
    legacy_initiations: Arc<Mutex<Vec<InitiateIssuanceRequest>>>,
    calls: Arc<Mutex<Vec<(String, String, bool)>>>,
}

fn authenticated<T>(body: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(body);
    request
        .metadata_mut()
        .insert("x-service-token", TOKEN.parse().unwrap());
    request.set_timeout(Duration::from_secs(10));
    request
}

fn grpc_web_body(message: &impl Message) -> Vec<u8> {
    let payload = message.encode_to_vec();
    let mut body = vec![0];
    body.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    body.extend(payload);
    body
}

fn grpc_web_frames(bytes: &[u8]) -> (Vec<Vec<u8>>, std::collections::BTreeMap<String, String>) {
    let mut remaining = bytes;
    let mut messages = Vec::new();
    let mut trailers = None;
    while !remaining.is_empty() {
        assert!(
            remaining.len() >= 5 && trailers.is_none(),
            "Complete frames; trailers terminate the stream"
        );
        let length = u32::from_be_bytes(remaining[1..5].try_into().unwrap()) as usize;
        assert!(length <= remaining.len() - 5);
        let payload = &remaining[5..5 + length];
        match remaining[0] {
            0 => messages.push(payload.to_vec()),
            128 => {
                let mut fields = std::collections::BTreeMap::new();
                let text = std::str::from_utf8(payload).unwrap();
                for line in text.split("\r\n").filter(|line| !line.is_empty()) {
                    let (key, value) = line.split_once(':').unwrap();
                    assert!(fields
                        .insert(key.to_owned(), value.trim_start().to_owned())
                        .is_none());
                }
                trailers = Some(fields);
            }
            flag => panic!("Unexpected gRPC-web frame flag {flag}"),
        }
        remaining = &remaining[5 + length..];
    }
    (
        messages,
        trailers.expect("Actual gRPC-web response includes terminal trailers"),
    )
}

#[test]
fn grpc_web_terminal_parser_rejects_truncation_duplicates_and_trailing_frames() {
    let trailer = b"grpc-status: 0\r\n";
    let mut valid = grpc_web_body(&Empty {});
    valid.push(128);
    valid.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
    valid.extend_from_slice(trailer);
    let (messages, fields) = grpc_web_frames(&valid);
    assert_eq!(messages, vec![Vec::<u8>::new()]);
    assert_eq!(
        fields,
        std::collections::BTreeMap::from([("grpc-status".into(), "0".into())])
    );
    let duplicate = b"grpc-status: 0\r\ngrpc-status: 16\r\n";
    let mut duplicate_frame = vec![128];
    duplicate_frame.extend_from_slice(&(duplicate.len() as u32).to_be_bytes());
    duplicate_frame.extend_from_slice(duplicate);
    let mut trailing = valid.clone();
    trailing.extend(grpc_web_body(&Empty {}));
    for invalid in [
        vec![0],
        vec![0, 0, 0, 0, 1],
        vec![1, 0, 0, 0, 0],
        grpc_web_body(&Empty {}),
        duplicate_frame,
        trailing,
    ] {
        assert!(std::panic::catch_unwind(|| grpc_web_frames(&invalid)).is_err());
    }
}

async fn transactions(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_transactions")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn full_state(
    pool: &sqlx::PgPool,
) -> marty_issuance_service::owned_json_value::OwnedJsonValue {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'transactions',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM issuance_service.issuance_transactions t),
      'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c),
      'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d),
      'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM issuance_service.issuance_events e))")
      .fetch_one(pool).await.unwrap()
}

fn peer_effects(peers: &PeerState) -> Value {
    json!({"signed":*peers.signed.lock().unwrap(),"allocations":*peers.allocations.lock().unwrap(),"publications":*peers.publications.lock().unwrap()})
}

impl EnvoyFixture {
    pub(super) async fn start() -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = Legacy {
            calls: calls.clone(),
            health: Arc::default(),
            health_service: SERVICE,
            initiations: Arc::default(),
        };
        let legacy_health = state.health.clone();
        let legacy_initiations = state.initiations.clone();
        let auth_health = Arc::default();
        let auth_state = Legacy {
            calls: Arc::default(),
            health: Arc::clone(&auth_health),
            health_service: "marty.ui.auth.v1.AuthService",
            initiations: Arc::default(),
        };
        let auth_listener = tokio::net::TcpListener::bind("127.0.0.1:19001")
            .await
            .unwrap();
        let auth = OwnedHttp::start_on(
            Router::new().fallback(legacy).with_state(auth_state),
            auth_listener,
        )
        .await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:19005")
            .await
            .unwrap();
        let legacy =
            OwnedHttp::start_on(Router::new().fallback(legacy).with_state(state), listener).await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let result = Self {
            client,
            legacy,
            auth,
            auth_health,
            legacy_health,
            legacy_initiations,
            calls,
        };
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut last_observed = Vec::new();
        loop {
            assert!(
                Instant::now() < deadline,
                "actual Envoy/native/legacy health deadline: {}; legacy health calls={:?}; auth health calls={:?}",
                last_observed.join(", "),
                *result.legacy_health.lock().unwrap(),
                *result.auth_health.lock().unwrap()
            );
            let mut healthy = true;
            let mut observed = Vec::new();
            for (port, names) in [
                (
                    9901,
                    &[
                        "cluster.issuance_native_grpc.membership_healthy",
                        "cluster.auth_grpc.membership_healthy",
                    ][..],
                ),
                (
                    19901,
                    &[
                        "cluster.issuance_grpc.membership_healthy",
                        "cluster.auth_grpc.membership_healthy",
                    ][..],
                ),
            ] {
                let response = result
                    .client
                    .get(format!(
                        "http://127.0.0.1:{port}/stats?format=json&filter=membership_healthy"
                    ))
                    .timeout(deadline.saturating_duration_since(Instant::now()))
                    .send()
                    .await;
                match response {
                    Ok(response) if response.status().is_success() => {
                        if let Ok(body) = response.json::<Value>().await {
                            if let Some(stats) = body["stats"].as_array() {
                                for name in names {
                                    let value = stats
                                        .iter()
                                        .find(|value| value["name"] == **name)
                                        .and_then(|value| value["value"].as_u64());
                                    observed.push(format!(
                                        "{port}:{name}={}",
                                        value.map_or_else(
                                            || "missing".into(),
                                            |value| value.to_string()
                                        )
                                    ));
                                    healthy &= value == Some(1);
                                }
                                continue;
                            }
                        }
                        observed.push(format!("{port}:invalid-json"));
                    }
                    Ok(response) => observed.push(format!("{port}:http-{}", response.status())),
                    Err(_) => observed.push(format!("{port}:unreachable")),
                }
                healthy = false;
            }
            last_observed = observed;
            if healthy {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "actual Envoy/native/legacy health deadline: {}; legacy health calls={:?}; auth health calls={:?}",
                last_observed.join(", "),
                *result.legacy_health.lock().unwrap(),
                *result.auth_health.lock().unwrap()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        result
    }

    async fn grpc(&self) -> IssuanceServiceClient<tonic::transport::Channel> {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9000")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .connect()
            .await
            .unwrap();
        IssuanceServiceClient::new(channel)
    }

    pub(super) async fn initiate_http(
        &self,
        body: &Value,
        token: Option<&str>,
    ) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("http://127.0.0.1:9000{HTTP_PATH}"))
            .json(body);
        if let Some(token) = token {
            request = request.header("x-service-token", token);
        }
        request.send().await.unwrap()
    }

    async fn observe_boundary(
        &self,
        port: u16,
        method: &str,
        path: &str,
        body: &Value,
    ) -> (Value, Vec<(String, String, bool)>) {
        let before = self.calls.lock().unwrap().len();
        let response = self
            .client
            .request(
                method.parse().unwrap(),
                format!("http://127.0.0.1:{port}{path}"),
            )
            .header("x-service-token", TOKEN)
            .header("origin", "https://synthetic-caller.example")
            .header("access-control-request-method", "POST")
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers: std::collections::BTreeMap<_, _> = [
            "content-type",
            "grpc-status",
            "grpc-message",
            "allow",
            "location",
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
        ]
        .into_iter()
        .filter_map(|name| {
            response
                .headers()
                .get(name)
                .map(|value| (name.to_owned(), value.as_bytes().to_vec()))
        })
        .collect();
        let body = response.bytes().await.unwrap().to_vec();
        let calls = self.calls.lock().unwrap()[before..].to_vec();
        (
            json!({"status":status,"headers":headers,"body":body}),
            calls,
        )
    }

    pub(super) async fn boundaries(&self, pool: &sqlx::PgPool, peers: &PeerState) {
        let initial = transactions(pool).await;
        let initial_state = full_state(pool).await;
        let effects = peer_effects(peers);
        let body = json!({"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,"holder_did":HOLDER,"claims_json":r#"{"given_name":"Synthetic"}"#});
        for token in [None, Some("synthetic-wrong-token")] {
            let response = self.initiate_http(&body, token).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let error: Value = response.json().await.unwrap();
            assert_eq!(error["code"], 16);
            assert_eq!(error["message"], "Missing or invalid service token");
            let mut request = tonic::Request::new(InitiateIssuanceRequest::default());
            if let Some(token) = token {
                request
                    .metadata_mut()
                    .insert("x-service-token", token.parse().unwrap());
            }
            assert_eq!(
                self.grpc()
                    .await
                    .initiate_issuance(request)
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
        }
        let response = self
            .client
            .post(format!("http://127.0.0.1:9000{HTTP_PATH}"))
            .header("authorization", "Bearer synthetic-not-service-token")
            .header("x-api-key", TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            self.calls.lock().unwrap().is_empty(),
            "Selected auth errors never fall back to legacy"
        );
        assert_eq!(transactions(pool).await, initial);
        assert_eq!(peer_effects(peers), effects);

        // The complete descriptor now belongs to native issuance. Exercise
        // every method through the actual Envoy listener; authentication must
        // be enforced by native without falling back to the counted legacy
        // transport. Executable smoke separately freezes the same service's
        // direct method boundary.
        let mut client = self.grpc().await;
        macro_rules! native_auth_boundary {
            ($method:ident) => {
                assert_eq!(
                    client
                        .$method(tonic::Request::new(Default::default()))
                        .await
                        .unwrap_err()
                        .code(),
                    tonic::Code::Unauthenticated,
                    stringify!($method)
                );
            };
        }
        native_auth_boundary!(exchange_token);
        native_auth_boundary!(issue_credential);
        native_auth_boundary!(get_offer);
        native_auth_boundary!(list_transactions);
        native_auth_boundary!(get_transaction);
        native_auth_boundary!(revoke_credential);
        native_auth_boundary!(suspend_credential);
        native_auth_boundary!(reinstate_credential);
        native_auth_boundary!(get_credential_status);
        native_auth_boundary!(stream_credential_events);
        native_auth_boundary!(health_check);
        macro_rules! native_method_present {
            ($method:ident) => {
                if let Err(status) = client.$method(authenticated(Default::default())).await {
                    assert!(
                        !matches!(
                            status.code(),
                            tonic::Code::Unauthenticated
                                | tonic::Code::Unimplemented
                                | tonic::Code::Unavailable
                        ),
                        "authenticated native {} returned {status}",
                        stringify!($method)
                    );
                }
            };
        }
        native_method_present!(exchange_token);
        native_method_present!(issue_credential);
        native_method_present!(get_offer);
        native_method_present!(list_transactions);
        native_method_present!(get_transaction);
        native_method_present!(revoke_credential);
        native_method_present!(suspend_credential);
        native_method_present!(reinstate_credential);
        native_method_present!(get_credential_status);
        native_method_present!(stream_credential_events);
        assert_eq!(
            client
                .health_check(authenticated(Default::default()))
                .await
                .unwrap()
                .into_inner()
                .status,
            "serving"
        );
        assert!(self.calls.lock().unwrap().is_empty());
        for (method, path) in [
            ("POST", "/v1/issuance/token"),
            ("POST", "/v1/issuance/credential"),
            ("GET", "/v1/issuance/offers/owned-control"),
            ("GET", "/v1/issuance/transactions"),
            ("GET", "/v1/issuance/transactions/owned-control"),
            ("POST", "/v1/issuance/credentials/owned-control/revoke"),
            ("POST", "/v1/issuance/credentials/owned-control/suspend"),
            ("POST", "/v1/issuance/credentials/owned-control/reinstate"),
            ("GET", "/v1/issuance/credentials/owned-control/status"),
            ("GET", "/v1/issuance/health"),
        ] {
            let mut request = self.client.request(
                method.parse().unwrap(),
                format!("http://127.0.0.1:9000{path}"),
            );
            if method == "POST" {
                request = request.json(&json!({}));
            }
            let response = request.send().await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
            let error: Value = response.json().await.unwrap();
            assert_eq!(error["code"], 16, "{method} {path}");
            assert!(self.calls.lock().unwrap().is_empty(), "{method} {path}");
        }
        let mut alias_body = body.clone();
        alias_body["idempotency_key"] = json!(format!("envoy-alias-{}", peers.source_id));
        for (method, path) in [
            ("GET", HTTP_PATH.to_owned()),
            ("DELETE", HTTP_PATH.to_owned()),
            ("HEAD", HTTP_PATH.to_owned()),
            ("POST", format!("{HTTP_PATH}/")),
            ("POST", format!("{HTTP_PATH}-other")),
            ("POST", "/v1/issuance/Initiate".into()),
            ("GET", RPC_PATH.into()),
            ("POST", format!("{RPC_PATH}/")),
            ("POST", format!("{RPC_PATH}Other")),
            ("POST", "/v1/issuance/%69nitiate".into()),
            ("POST", "/v1/issuance/initiate%2F".into()),
            ("POST", "/v1%2Fissuance/initiate".into()),
            ("POST", format!("{RPC_PATH}%2F")),
            ("OPTIONS", HTTP_PATH.into()),
        ] {
            let decoded_before = self.legacy_initiations.lock().unwrap().len();
            let baseline = self
                .observe_boundary(19000, method, &path, &alias_body)
                .await;
            let decoded_after_baseline = self.legacy_initiations.lock().unwrap().len();
            let candidate = self
                .observe_boundary(9000, method, &path, &alias_body)
                .await;
            let decoded_after_candidate = self.legacy_initiations.lock().unwrap().len();
            let baseline_decodes = decoded_after_baseline - decoded_before;
            let candidate_decodes = decoded_after_candidate - decoded_after_baseline;
            if baseline_decodes == 1 && candidate_decodes == 0 {
                // Actual baseline observation, not a hand-maintained URL alias
                // list, identifies normalization into the migrated operation.
                assert_eq!(method, "POST");
                assert_eq!(baseline.1, vec![("POST".into(), RPC_PATH.into(), true)]);
                assert_eq!(
                    self.legacy_initiations.lock().unwrap().last(),
                    Some(&InitiateIssuanceRequest {
                        organization_id: ORGANIZATION.into(),
                        credential_template_id: TEMPLATE.into(),
                        holder_did: HOLDER.into(),
                        claims_json: alias_body["claims_json"].as_str().unwrap().into(),
                        idempotency_key: alias_body["idempotency_key"].as_str().unwrap().into(),
                        ..Default::default()
                    })
                );
                let canonical = self
                    .observe_boundary(9000, "POST", HTTP_PATH, &alias_body)
                    .await;
                assert_eq!(canonical.0["status"],400,"Existing fresh keyed DIDComm rejection is the business oracle for normalized aliases");
                assert!(canonical.1.is_empty());
                assert_eq!(candidate,canonical,"Normalized initiation alias preserves exact native response and no-fallback effects: {path}");
            } else {
                assert_eq!(
                    candidate_decodes, 0,
                    "Native-owned candidate must never invoke legacy initiation for {method} {path}"
                );
                assert!(
                    candidate.1.is_empty(),
                    "Native-owned candidate must never reach legacy for {method} {path}"
                );
                if baseline.1.is_empty() {
                    assert_eq!(candidate.0,baseline.0,"Envoy-handled alias preserves response bytes and relevant headers for {method} {path}");
                } else {
                    assert_ne!(
                        candidate.0["status"], 503,
                        "Healthy native owner cannot be unavailable for {method} {path}"
                    );
                }
            }
        }
        let probe = "synthetic-generic-health-route";
        for port in [19000, 9000] {
            let channel =
                tonic::transport::Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
                    .unwrap()
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    .connect()
                    .await
                    .unwrap();
            let response = tonic_health::pb::health_client::HealthClient::new(channel)
                .check(tonic_health::pb::HealthCheckRequest {
                    service: probe.into(),
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response.status, 0,
                "Generic health route retains its controlled auth-cluster owner"
            );
        }
        assert_eq!(
            self.auth_health
                .lock()
                .unwrap()
                .iter()
                .filter(|service| *service == probe)
                .count(),
            2
        );
        assert!(!self
            .legacy_health
            .lock()
            .unwrap()
            .iter()
            .any(|service| service == probe));
        assert_eq!(transactions(pool).await, initial);
        assert_eq!(peer_effects(peers), effects);
        assert_eq!(full_state(pool).await,initial_state,"Every existing row in all four owned issuance tables is unchanged by rejected/legacy requests");
        let before = self.calls.lock().unwrap().len();
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:9000{HTTP_PATH}?unknown=one&unknown=two"
            ))
            .header("x-service-token", TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        let rejected = !response.status().is_success()
            || response
                .headers()
                .get("grpc-status")
                .is_some_and(|v| v != "0");
        let _ = response.bytes().await.unwrap();
        assert!(
            rejected,
            "Unknown query cannot silently bypass transcoder validation"
        );
        assert_eq!(
            self.calls.lock().unwrap().len(),
            before,
            "Exact selected path never falls back on transcoder rejection"
        );
        assert_eq!(transactions(pool).await, initial);
        // Fresh keyed DIDComm remains rejected without reservation/delivery.
        let mut keyed = body;
        keyed["idempotency_key"] = json!(format!("envoy-didcomm-{}", peers.source_id));
        assert_eq!(
            self.initiate_http(&keyed, Some(TOKEN)).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(transactions(pool).await, initial);
        assert_eq!(peer_effects(peers), effects);
        assert_eq!(full_state(pool).await, initial_state);
    }

    pub(super) async fn ordinary_rpc(&self, pool: &sqlx::PgPool, peers: &PeerState) {
        struct Reset<'a>(&'a std::sync::atomic::AtomicBool, bool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(self.1, Ordering::SeqCst);
            }
        }
        let _reset = Reset(
            &peers.ordinary_wallets,
            peers.ordinary_wallets.swap(true, Ordering::SeqCst),
        );
        let before = transactions(pool).await;
        let effects = peer_effects(peers);
        let calls = self.calls.lock().unwrap().clone();
        let request = InitiateIssuanceRequest {
            organization_id: ORGANIZATION.into(),
            credential_template_id: TEMPLATE.into(),
            issuer_did: ISSUER.into(),
            holder_did: HOLDER.into(),
            claims_json: r#"{"given_name":"Synthetic","nested":{"flag":true}}"#.into(),
            idempotency_key: format!("envoy-rpc-{}", peers.source_id),
            ..Default::default()
        };
        let mut client = self.grpc().await;
        let response = client
            .initiate_issuance(authenticated(request.clone()))
            .await
            .unwrap()
            .into_inner();
        let state = stored(pool, &response.id).await;
        let reservation_state = full_state(pool).await;
        uuid::Uuid::parse_str(&response.id).unwrap();
        assert_offer(
            &response.credential_offer_uri,
            &state["transaction"]["pre_auth_code"],
        );
        assert_eq!(
            response,
            marty_issuance_service::issuance_proto::IssuanceResponse {
                id: response.id.clone(),
                organization_id: ORGANIZATION.into(),
                credential_template_id: TEMPLATE.into(),
                status: "pending".into(),
                credential_offer_uri: response.credential_offer_uri.clone(),
                credential_offer_uris: Default::default(),
                credential_offer_labels: Default::default(),
                pre_auth_code: state["transaction"]["pre_auth_code"]
                    .as_str()
                    .unwrap()
                    .into(),
                expires_at: response.expires_at.clone()
            }
        );
        assert_eq!(state["transaction"]["status"], "pending");
        let typed:marty_issuance_service::initiation::InitiationRequest=serde_json::from_value(json!({
            "organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,"issuer_did":ISSUER,"holder_did":HOLDER,
            "delivery_mode":"","claims":serde_json::from_str::<Value>(&request.claims_json).unwrap()
        })).unwrap();
        let binding = marty_issuance_service::initiation::idempotency_binding(
            Some(&request.idempotency_key),
            &typed,
        )
        .unwrap()
        .unwrap();
        // The immediately preceding shared ordinary gate independently checks
        // this common binding owner against its frozen language-neutral vector.
        assert_eq!(
            state["transaction"]["idempotency_key_hash"],
            binding.key_hash
        );
        assert_eq!(
            state["transaction"]["idempotency_request_hash"],
            binding.request_hash
        );
        assert_eq!(
            state["transaction"]["claims"],
            json!({"given_name":"Synthetic","nested":{"flag":true},"_vct":"https://issuer.example/credentials/EmployeeCredential"})
        );
        let expiry: chrono::DateTime<chrono::Utc> = response.expires_at.parse().unwrap();
        let stored_expiry: chrono::DateTime<chrono::Utc> = state["transaction"]["expires_at"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let created: chrono::DateTime<chrono::Utc> = state["transaction"]["created_at"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(expiry, stored_expiry);
        assert_eq!((expiry - created).num_minutes(), 10080);
        assert_eq!(state["credentials"], json!([]));
        assert_eq!(state["deliveries"], json!([]));
        assert_eq!(state["events"], json!([]));
        assert_eq!(
            client
                .initiate_issuance(authenticated(request.clone()))
                .await
                .unwrap()
                .into_inner(),
            response
        );
        assert_eq!(stored(pool, &response.id).await, state);
        let mut conflict = request.clone();
        conflict.claims_json = r#"{"given_name":"Changed"}"#.into();
        assert_eq!(
            client
                .initiate_issuance(authenticated(conflict))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::AlreadyExists
        );
        // Empty query preserves exact HTTP path matching and recovers the same
        // genuine native keyed reservation, without gateway/Redis interception.
        let body = json!({"organization_id":request.organization_id,"credential_template_id":request.credential_template_id,"issuer_did":request.issuer_did,"holder_did":request.holder_did,"claims_json":request.claims_json,"idempotency_key":request.idempotency_key});
        let http = self
            .client
            .post(format!("http://127.0.0.1:9000{HTTP_PATH}?"))
            .header("x-service-token", TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(http.status(), StatusCode::OK);
        assert_eq!(
            http.json::<Value>().await.unwrap(),
            json!({"id":response.id,"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,"status":"pending","credential_offer_uri":response.credential_offer_uri,"credential_offer_uris":{},"credential_offer_labels":{},"pre_auth_code":response.pre_auth_code,"expires_at":response.expires_at})
        );
        let expected_http = json!({"id":response.id,"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE,"status":"pending","credential_offer_uri":response.credential_offer_uri,"credential_offer_uris":{},"credential_offer_labels":{},"pre_auth_code":response.pre_auth_code,"expires_at":response.expires_at});
        for query in [
            format!("organization_id={ORGANIZATION}"),
            format!("organization_id={ORGANIZATION}&organization_id={ORGANIZATION}"),
        ] {
            let before_legacy = self.calls.lock().unwrap().len();
            let before_decoded = self.legacy_initiations.lock().unwrap().len();
            let baseline = self
                .client
                .post(format!("http://127.0.0.1:19000{HTTP_PATH}?{query}"))
                .header("x-service-token", TOKEN)
                .json(&body)
                .send()
                .await
                .unwrap();
            let baseline_status = baseline.status();
            let baseline_content_type = baseline.headers().get("content-type").cloned();
            let baseline_bytes = baseline.bytes().await.unwrap();
            let candidate = self
                .client
                .post(format!("http://127.0.0.1:9000{HTTP_PATH}?{query}"))
                .header("x-service-token", TOKEN)
                .json(&body)
                .send()
                .await
                .unwrap();
            if self.legacy_initiations.lock().unwrap().len() == before_decoded + 1 {
                assert_eq!(baseline_status, StatusCode::OK);
                assert_eq!(
                    serde_json::from_slice::<Value>(&baseline_bytes).unwrap(),
                    json!({"id":"","organization_id":"","credential_template_id":"","status":"","credential_offer_uri":"","credential_offer_uris":{},"credential_offer_labels":{},"pre_auth_code":"","expires_at":""})
                );
                assert_eq!(self.legacy_initiations.lock().unwrap().last(),Some(&request),"Unchanged transcoder independently supplies the same canonical request for known query fields");
                assert_eq!(candidate.status(), StatusCode::OK);
                assert_eq!(candidate.json::<Value>().await.unwrap(), expected_http);
                assert_eq!(
                    self.calls.lock().unwrap().len(),
                    before_legacy + 1,
                    "Only the intentional baseline control reaches legacy"
                );
            } else {
                // body:* may reject query-field binding. Preserve the actual
                // unchanged filter outcome instead of asserting invented
                // acceptance; no native reservation or recovery is credited.
                assert_eq!(
                    self.legacy_initiations.lock().unwrap().len(),
                    before_decoded
                );
                assert!(
                    !baseline_status.is_success(),
                    "Known-query control must either transcode or explicitly reject"
                );
                assert_eq!(candidate.status(), baseline_status);
                assert_eq!(
                    candidate.headers().get("content-type"),
                    baseline_content_type.as_ref()
                );
                assert_eq!(candidate.bytes().await.unwrap(), baseline_bytes);
                assert_eq!(self.calls.lock().unwrap().len(), before_legacy);
            }
        }
        let after_query_calls = self.calls.lock().unwrap().clone();
        assert!(after_query_calls.starts_with(&calls));
        for token in [None, Some("synthetic-wrong-token"), Some(TOKEN)] {
            let mut web = self
                .client
                .post(format!("http://127.0.0.1:9000{RPC_PATH}"))
                .header("content-type", "application/grpc-web+proto")
                .header("x-grpc-web", "1")
                .body(grpc_web_body(&request));
            if let Some(token) = token {
                web = web.header("x-service-token", token);
            }
            let web = web.send().await.unwrap();
            assert_eq!(web.status(), StatusCode::OK);
            assert!(web.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/grpc-web"));
            let header_trailers: std::collections::BTreeMap<_, _> = ["grpc-status", "grpc-message"]
                .into_iter()
                .filter_map(|name| {
                    web.headers()
                        .get(name)
                        .map(|value| (name.to_owned(), value.to_str().unwrap().to_owned()))
                })
                .collect();
            let bytes = web.bytes().await.unwrap();
            let (messages, trailers) = if bytes.is_empty() {
                assert!(
                    header_trailers.contains_key("grpc-status"),
                    "an empty gRPC-web response must be a trailers-only response"
                );
                (Vec::new(), header_trailers)
            } else {
                assert!(
                    header_trailers.is_empty(),
                    "framed gRPC-web trailers must not be duplicated in response headers"
                );
                grpc_web_frames(&bytes)
            };
            if token == Some(TOKEN) {
                assert_eq!(trailers.get("grpc-status").map(String::as_str), Some("0"));
                assert_eq!(messages.len(), 1);
                assert_eq!(
                    marty_issuance_service::issuance_proto::IssuanceResponse::decode(
                        messages[0].as_slice()
                    )
                    .unwrap(),
                    response
                );
            } else {
                assert_eq!(trailers.get("grpc-status").map(String::as_str), Some("16"));
                assert!(
                    messages.is_empty(),
                    "Rejected gRPC-web authentication emits no success message"
                );
                assert_eq!(
                    percent_encoding::percent_decode_str(trailers.get("grpc-message").unwrap())
                        .decode_utf8()
                        .unwrap(),
                    "Missing or invalid service token"
                );
            }
        }
        assert_eq!(transactions(pool).await, before + 1);
        assert_eq!(stored(pool, &response.id).await, state);
        assert_eq!(peer_effects(peers), effects);
        assert_eq!(*self.calls.lock().unwrap(), after_query_calls);
        assert_eq!(full_state(pool).await, reservation_state);
    }

    pub(super) async fn native_unavailable(&self, pool: &sqlx::PgPool, peers: &PeerState) {
        let count = transactions(pool).await;
        let before = full_state(pool).await;
        let effects = peer_effects(peers);
        let calls = self.calls.lock().unwrap().clone();
        assert_eq!(
            self.initiate_http(
                &json!({"organization_id":ORGANIZATION,"credential_template_id":TEMPLATE}),
                Some(TOKEN)
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            self.grpc()
                .await
                .initiate_issuance(authenticated(InitiateIssuanceRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        assert_eq!(transactions(pool).await, count);
        assert_eq!(peer_effects(peers), effects);
        assert_eq!(*self.calls.lock().unwrap(), calls);
        assert_eq!(full_state(pool).await, before);
    }

    pub(super) async fn close(self) {
        self.legacy.close().await;
        self.auth.close().await;
    }
}
