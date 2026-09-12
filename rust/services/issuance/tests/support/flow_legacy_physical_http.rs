//! Counted synthetic legacy HTTP peer. All requests are recorded before route,
//! body or authorization validation, including any unexpected RPC traffic.
//! The native registry is manually assembled: this is not a configured legacy
//! RPC-target trap or rendered/deployed consumer-selection qualification.
use super::super::super::didcomm_gateway_replay::OwnedHttp;
use super::{definition, now, start, PUBLIC};
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    Json, Router,
};
use marty_flow::{
    apply_physical_advance_side_effect, prepare_instance_start, FlowProviderError,
    FlowProviderRegistry, HttpPhysicalDocumentProvider,
};
use marty_verification::flow::TransitionOutcome;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const KEY: &str = "synthetic-legacy-physical-api-key";
#[derive(Default)]
struct Peer {
    calls: Mutex<Vec<(String, String, Value)>>,
    flow: Mutex<Option<String>>,
}

async fn request(
    State(peer): State<Arc<Peer>>,
    request: Request<Body>,
) -> (StatusCode, Json<Value>) {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    // Count even malformed, unauthenticated and unexpected requests.
    let index = {
        let mut calls = peer.calls.lock().unwrap();
        let index = calls.len();
        calls.push((method.clone(), path.clone(), Value::Null));
        index
    };
    let authenticated = request
        .headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        == Some(KEY);
    let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        let Ok(body) = serde_json::from_slice(&bytes) else {
            return (StatusCode::BAD_REQUEST, Json(json!({})));
        };
        body
    };
    peer.calls.lock().unwrap()[index].2 = body.clone();
    if !authenticated {
        return (StatusCode::UNAUTHORIZED, Json(json!({})));
    }
    if method == "GET" && path == "/health" {
        return (StatusCode::OK, Json(json!({"status":"healthy"})));
    }
    if method == "POST" && path == "/v1/passport/applications" {
        assert_eq!(body["organization_id"], "org-1");
        let flow = body["flow_execution_id"].as_str().unwrap().to_owned();
        let mut stored = peer.flow.lock().unwrap();
        assert!(stored.is_none(), "physical initialization occurs once");
        *stored = Some(flow);
    } else {
        let expected = match path.strip_prefix("/v1/passport/applications/physical-app/") {
            Some("production-status") => "GET",
            Some(
                "generate-data-groups"
                | "generate-sod"
                | "submit-personalization"
                | "quality-verify"
                | "activate",
            ) => "POST",
            _ => return (StatusCode::NOT_FOUND, Json(json!({}))),
        };
        if method != expected {
            return (StatusCode::METHOD_NOT_ALLOWED, Json(json!({})));
        }
    }
    (
        StatusCode::OK,
        Json(
            json!({"application_id":"physical-app","flow_execution_id":peer.flow.lock().unwrap().clone(),"status":"complete"}),
        ),
    )
}

pub(super) struct Legacy {
    owned: OwnedHttp,
    peer: Arc<Peer>,
}
impl Legacy {
    pub(super) async fn start() -> Self {
        let peer = Arc::new(Peer::default());
        let owned =
            OwnedHttp::start(Router::new().fallback(request).with_state(peer.clone())).await;
        Self { owned, peer }
    }
    pub(super) fn assert_no_requests(&self) {
        assert!(
            self.peer.calls.lock().unwrap().is_empty(),
            "all issuance RPC success/failures stay off legacy HTTP"
        );
    }
    pub(super) fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.owned.port)
    }
    pub(super) fn assert_health_requests(&self, count: usize) {
        assert_eq!(
            *self.peer.calls.lock().unwrap(),
            vec![("GET".into(), "/health".into(), Value::Null); count]
        );
    }
    pub(super) async fn close(self) {
        self.owned.close().await;
    }
}

pub(super) async fn run(legacy: &Legacy) {
    let url = format!("http://127.0.0.1:{}", legacy.owned.port);
    let unauthorized = HttpPhysicalDocumentProvider::new(&url, "wrong-synthetic-key").unwrap();
    assert!(matches!(
        unauthorized.health_check().await,
        Err(FlowProviderError::Rejected {
            provider: "physical_document",
            ..
        })
    ));
    let provider = Arc::new(HttpPhysicalDocumentProvider::new(&url, KEY).unwrap());
    provider.health_check().await.unwrap();
    let providers = FlowProviderRegistry {
        physical_document: Some(provider),
        ..Default::default()
    };
    let definition = definition("physical_document_issuance");
    let physical = json!({"country_code":"USA","applicant":{"name":"Synthetic"},"mrz":{"line1":"P<USA"},"data_groups":{"DG1":"MQ==","DG2":"Mg=="}});
    let instance = start(
        &definition,
        json!({"physical_document":physical,"keep":"unchanged"}),
    );
    let prepared = prepare_instance_start(&providers, &definition, instance.clone(), PUBLIC, now())
        .await
        .unwrap();
    assert!(prepared.artifact.is_none());
    let response = json!({"application_id":"physical-app","flow_execution_id":instance.id,"status":"complete"});
    let mut expected = instance.clone();
    let expected_context = expected.context.as_object_mut().unwrap();
    assert!(expected_context.remove("physical_document").is_some());
    expected_context.insert("application_id".into(), json!("physical-app"));
    expected_context.insert("physical_document_job".into(), response);
    assert_eq!(
        prepared.instance, expected,
        "physical input is consumed; unrelated state preserved"
    );
    let mut current = prepared.instance;
    let mut expected_calls = vec![
        ("GET".into(), "/health".into(), Value::Null),
        ("GET".into(), "/health".into(), Value::Null),
        (
            "POST".into(),
            "/v1/passport/applications".into(),
            json!({
                "organization_id":"org-1","flow_execution_id":instance.id,
                "application_template_id":"application-template-1","credential_template_id":"template-1",
                "delivery_destination_profile_id":"destination-1","document_type":"TD3",
                "country_code":physical["country_code"],"applicant":physical["applicant"],
                "mrz":physical["mrz"],"data_groups":physical["data_groups"]
            }),
        ),
    ];
    for (step, suffix, method) in [
        ("generate_data_groups", "generate-data-groups", "POST"),
        ("sign_sod", "generate-sod", "POST"),
        (
            "submit_to_personalization",
            "submit-personalization",
            "POST",
        ),
        ("track_production", "production-status", "GET"),
        ("quality_verify", "quality-verify", "POST"),
        ("activate_credential", "activate", "POST"),
    ] {
        current.current_step_id = Some(
            definition
                .steps
                .iter()
                .find(|value| value["config"]["protocol_step"] == step)
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        let before = current.clone();
        current = apply_physical_advance_side_effect(
            &providers,
            &definition,
            current,
            TransitionOutcome::Success,
            &json!({"passed":true,"failure_codes":[]}),
        )
        .await
        .unwrap();
        assert_eq!(
            current, before,
            "controlled physical responses must preserve complete instance"
        );
        let body = if step == "quality_verify" {
            json!({"passed":true,"failure_codes":[]})
        } else {
            Value::Null
        };
        expected_calls.push((
            method.into(),
            format!("/v1/passport/applications/physical-app/{suffix}"),
            body,
        ));
    }
    assert_eq!(
        *legacy.peer.calls.lock().unwrap(),
        expected_calls,
        "exact seven physical operations, health/auth probes, and no unexpected RPC/HTTP attempts"
    );
}
