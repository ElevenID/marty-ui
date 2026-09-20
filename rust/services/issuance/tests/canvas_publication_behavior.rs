//! Actual publication service with frozen input rows and controlled HTTP/secret
//! ports. This is not the separately required real HTTPS/platform-trust gate.
#[path = "support/canvas_observation_values.rs"]
mod observations;
#[path = "support/renewal_reference_fixture.rs"]
#[allow(dead_code)] // Reuse the exact typed transaction decoder, not sibling fixtures.
mod reference_rows;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_credentials_publication::{
        CanvasCredentialsPublicationService, CanvasPublicationContext,
    },
    canvas_credentials_transport::{
        CanvasCredentialsRequest, CanvasCredentialsResponse, CanvasCredentialsTransport,
        HttpCanvasCredentialsTransport,
    },
    canvas_credentials_validation::CanvasCredentialsSecretResolver,
    canvas_lti_launch::CanvasLtiClock,
    canvas_provider_http::CanvasOriginPolicy,
    config::IssuanceServiceConfig,
    lossless_json::{LosslessJson, LosslessObject},
    lossless_json_tree::JsonTree,
    owned_json_value::OwnedJsonValue,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

struct Clock;
impl CanvasLtiClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        "2026-09-01T12:00:00+00:00".parse().unwrap()
    }
}
struct Ports {
    scenario: Value,
    trace: Mutex<Vec<Value>>,
    live: Option<Arc<dyn CanvasCredentialsTransport>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    cancelled: AtomicBool,
}
#[async_trait]
impl CanvasCredentialsSecretResolver for Ports {
    async fn secret_value(
        &self,
        organization: &str,
        identifier: &str,
    ) -> Result<Option<String>, ()> {
        self.trace
            .lock()
            .unwrap()
            .push(json!({"kind":"secret","organization":organization,"identifier":identifier}));
        if self.scenario["secret_failure"] == true {
            return Err(());
        }
        Ok(self.scenario["secrets"][identifier]
            .as_str()
            .map(str::to_owned))
    }
}
#[async_trait]
impl CanvasCredentialsTransport for Ports {
    async fn send(
        &self,
        request: CanvasCredentialsRequest,
    ) -> Result<CanvasCredentialsResponse, String> {
        let mut headers = json!({"accept":"application/json","content-type":"application/json"});
        if let Some(token) = &request.token {
            headers["authorization"] = json!(format!("Bearer {token}"));
        }
        self.trace.lock().unwrap().push(json!({"kind":"http","method":request.method.as_str(),"url":request.url,"headers":headers,"body":request.body}));
        if let Some(live) = &self.live {
            return live.send(request).await;
        }
        if self.scenario["cancel_provider"] == true {
            struct Dropped<'a>(&'a AtomicBool);
            impl Drop for Dropped<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _owned = Dropped(&self.cancelled);
            self.entered.notify_one();
            self.release.notified().await;
            self.trace
                .lock()
                .unwrap()
                .push(json!({"kind":"unexpected_continuation"}));
        }
        let text = self.scenario["provider_body"].as_str().map(str::to_owned).unwrap_or_else(|| {
            if self.scenario.get("provider").is_some() {
                r#"{"result":[{"entityId":"external-1","issuer":"issuer-elevenid","openBadgeId":"https://badges.example/assertion/external-1"}]}"#.into()
            } else { r#"{"id":"external-1","issuer_id":"issuer-elevenid"}"#.into() }
        });
        let body = if self.scenario["provider_encoding"] == "utf-16" {
            let mut bytes = vec![0xff, 0xfe];
            bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
            bytes
        } else {
            text.into_bytes()
        };
        Ok(CanvasCredentialsResponse {
            status: self.scenario["provider_status"]
                .as_u64()
                .unwrap_or(201)
                .try_into()
                .unwrap(),
            request_id: Some("synthetic-request-1".into()),
            content_type: Some(
                self.scenario["provider_content_type"]
                    .as_str()
                    .unwrap_or("application/json")
                    .into(),
            ),
            body,
        })
    }
}
fn configuration(scenario: &Value) -> IssuanceServiceConfig {
    let mut values: BTreeMap<String, String> = [
        ("ISSUANCE_API_KEY", "synthetic-mirror-management"),
        ("ISSUER_BASE_URL", "https://issuer.example"),
        ("PUBLIC_BASE_URL", "https://issuer.example"),
        ("CANVAS_PORTABLE_INTEGRATION_ENABLED", "true"),
        ("CANVAS_PILOT_ORGANIZATION_IDS", "org-1"),
        (
            "CANVAS_CREDENTIALS_PUBLISH_URL",
            "https://bridge.example/publish",
        ),
        (
            "CANVAS_CREDENTIALS_STATUS_SYNC_URL",
            "https://bridge.example/status",
        ),
        ("CANVAS_CREDENTIALS_API_TOKEN", "synthetic-provider-token"),
        ("CANVAS_CREDENTIALS_ISSUER_ID", "issuer-elevenid"),
        ("CANVAS_CREDENTIALS_BADGECLASS_ID", "badge-1"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect();
    if let Some(env) = scenario["env"].as_object() {
        values.extend(
            env.iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap().into())),
        );
    }
    IssuanceServiceConfig::from_values(values).unwrap()
}
#[tokio::test]
async fn frozen_publication_adapter_50_exact_one_closed_secret_projection() {
    run(Corpus::Initial, None, None, None).await;
}

#[tokio::test]
async fn frozen_publication_15_timestamp_cancellation_and_response_boundaries() {
    run(Corpus::Boundary, None, None, None).await;
}

#[derive(Clone, Copy)]
enum Corpus {
    Initial,
    Boundary,
}

// Only the owned Linux runner enables this child; normal unit runs retain the
// separate complete controlled graph. No platform-trust constructor is injected.
#[tokio::test]
async fn https_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_PUBLICATION_HTTPS_ORIGIN") else {
        return;
    };
    if !cfg!(target_os = "linux") {
        panic!("platform-trust gate requires Linux");
    }
    let parsed = url::Url::parse(&origin).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert!(parsed.port().is_some());
    assert_eq!(parsed.as_str(), format!("{origin}/"));
    let case = std::env::var("MARTY_CANVAS_PUBLICATION_HTTPS_CASE").unwrap();
    let failure = std::env::var("MARTY_CANVAS_PUBLICATION_HTTPS_FAILURE").ok();
    assert!(matches!(
        failure.as_deref(),
        None | Some("origin" | "trust")
    ));
    run(
        Corpus::Initial,
        Some(&origin),
        Some(&case),
        failure.as_deref(),
    )
    .await;
    println!("\nPUBLICATION_HTTPS_CASE_OK={case}");
}

fn rebase(value: &str, origin: &str) -> String {
    for known in ["https://bridge.example", "https://api.badgr.io"] {
        if let Some(path) = value.strip_prefix(known) {
            assert!(path.is_empty() || path.starts_with('/'));
            return format!("{origin}{path}");
        }
    }
    panic!("unowned reference origin must not be silently rebased")
}

async fn run(matrix: Corpus, origin: Option<&str>, selected: Option<&str>, failure: Option<&str>) {
    let (reference, scenarios, count) = match matrix {
        Corpus::Initial => (
            include_str!("../../../../contracts/canvas-mirror-adapter-reference.json"),
            include_str!("../../../../contracts/canvas-mirror-adapter-scenarios.json"),
            51,
        ),
        Corpus::Boundary => (
            include_str!("../../../../contracts/canvas-publication-boundary-reference.json"),
            include_str!("../../../../contracts/canvas-publication-boundary-scenarios.json"),
            15,
        ),
    };
    let corpus: Value = serde_json::from_str(reference).unwrap();
    let scenarios: Value = serde_json::from_str(scenarios).unwrap();
    assert_eq!(corpus["adapter"].as_array().unwrap().len(), count);
    let mut executed = 0;
    for case in corpus["adapter"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if selected.is_some_and(|selected| selected != id) {
            continue;
        }
        executed += 1;
        let scenario = scenarios["adapter"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["id"] == id)
            .unwrap();
        let state = OwnedJsonValue::copy(
            &corpus["snapshots"][case["before"]["snapshot_sha256"].as_str().unwrap()],
        );
        let before = OwnedJsonValue::copy(&state);
        let first = |key: &str| state[key].as_object().unwrap().values().next().unwrap();
        let transaction = reference_rows::transaction(first("transactions"));
        let transaction_before = transaction.clone();
        let mut credential_projection = OwnedJsonValue::copy(first("credentials"));
        // Exercise the actual raw persisted-JSON shape as well as the frozen
        // typed model's normalized before snapshot. Only the scenario's exact
        // datetime inputs are reapplied; all other input fields remain frozen.
        if matches!(matrix, Corpus::Boundary) {
            for field in ["issued_at", "expires_at"] {
                if let Some(value) = scenario["inputs"]["credential"].get(field) {
                    credential_projection.replace_field(field, OwnedJsonValue::copy(value));
                }
            }
        }
        let credential_before = OwnedJsonValue::copy(&credential_projection);
        let mut config = configuration(scenario);
        let live = origin.map(|origin| {
            let provider = &mut config.canvas_credentials_publication.delivery.provider;
            provider.publish_url = provider
                .publish_url
                .as_deref()
                .map(|url| rebase(url, origin));
            provider.api_base_url = Some(origin.into());
            Arc::new(HttpCanvasCredentialsTransport::with_operation_timeout(
                CanvasOriginPolicy {
                    private_origin_allowlist: if failure == Some("origin") {
                        Default::default()
                    } else {
                        [origin.to_owned()].into_iter().collect()
                    },
                    allow_private_networks: false,
                    allow_http_localhost: false,
                },
                config.canvas_credentials_publish_timeout,
            )) as Arc<dyn CanvasCredentialsTransport>
        });
        let ports = Arc::new(Ports {
            scenario: scenario.clone(),
            trace: Mutex::new(Vec::new()),
            live,
            entered: Default::default(),
            release: Default::default(),
            cancelled: AtomicBool::new(false),
        });
        let service = CanvasCredentialsPublicationService::new(
            config.canvas_credentials_publication,
            ports.clone(),
            ports.clone(),
        )
        .with_clock(Arc::new(Clock));
        let mut action = Box::pin(service.publish(CanvasPublicationContext {
            credential: &credential_projection,
            transaction: &transaction,
            platform: first("canvas_platforms"),
            delivery: first("delivery_records"),
        }));
        let actual = if scenario["cancel_provider"] == true {
            assert!(
                origin.is_none(),
                "real HTTPS cancellation needs an independent server receipt barrier"
            );
            tokio::select! {
                _ = &mut action => panic!("provider-held action completed before cancellation"),
                entered = tokio::time::timeout(std::time::Duration::from_secs(2), ports.entered.notified()) => entered.expect("provider entry deadline"),
            }
            drop(action);
            assert!(ports.cancelled.load(Ordering::SeqCst));
            ports.release.notify_waiters();
            tokio::task::yield_now().await;
            None
        } else {
            Some(action.await)
        };
        let expected = &case["responses"][0];
        if let Some(failure) = failure {
            let Some(Err(error)) = actual else {
                panic!("negative transport unexpectedly succeeded")
            };
            assert_eq!(error.message().as_scalar(), Some(match failure {
                "origin" => "Canvas Credentials publish request failed: Provider origin is unavailable or disallowed",
                "trust" => "Canvas Credentials publish request failed: Provider request unavailable",
                _ => unreachable!(),
            }));
            assert!(state == before);
            assert!(transaction == transaction_before);
            continue;
        }
        match actual {
            None => assert_eq!(expected, &json!({"outcome":"CancelledError"}), "{id}"),
            Some(Ok(result)) => {
                assert_eq!(expected["result_encoding"], "python-json-text", "{id}");
                let expected_tree = JsonTree::from_response_bytes(
                    expected["result_json"].as_str().unwrap().as_bytes(),
                )
                .unwrap();
                let actual = LosslessJson::Object(LosslessObject::from([
                    (
                        "external_credential_id".into(),
                        result
                            .external_credential_id
                            .map(LosslessJson::Text)
                            .unwrap_or_else(|| Value::Null.into()),
                    ),
                    (
                        "external_issuer_id".into(),
                        result
                            .external_issuer_id
                            .map(LosslessJson::Text)
                            .unwrap_or_else(|| Value::Null.into()),
                    ),
                    ("metadata".into(), LosslessJson::Object(result.metadata)),
                ]));
                let mut expected_observation =
                    observations::lossless(&LosslessJson::Parsed(Arc::new(expected_tree)));
                if let Some(origin) = origin {
                    for key in ["publish_url", "api_base_url"] {
                        if let Some(value) = expected_observation["metadata"][key].as_str() {
                            expected_observation["metadata"][key] = json!(rebase(value, origin));
                        }
                    }
                }
                assert_eq!(
                    observations::lossless(&actual),
                    expected_observation,
                    "{id}"
                );
            }
            Some(Err(error)) => {
                assert_eq!(expected["exception"], "RuntimeError", "{id}");
                let expected_message = if id == "secret_lookup_failure" {
                    // Governed privacy projection: the existing native secret
                    // port returns (), never an arbitrary source exception.
                    assert_eq!(expected["detail"], "synthetic secret lookup failure");
                    "Canvas Credentials secret lookup failed"
                } else {
                    expected["detail"].as_str().unwrap()
                };
                assert_eq!(
                    observations::text(&error.message()),
                    json!(expected_message),
                    "{id}"
                );
            }
        }
        let expected_trace: Vec<Value> = case["trace"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|call| matches!(call["kind"].as_str(), Some("http" | "secret")))
            .map(|call| {
                let mut call = call.clone();
                if call["kind"] == "http" {
                    call["body"] = serde_json::from_str(call["body"].as_str().unwrap()).unwrap();
                    if let Some(origin) = origin {
                        call["url"] = json!(rebase(call["url"].as_str().unwrap(), origin));
                    }
                }
                call
            })
            .collect();
        assert_eq!(*ports.trace.lock().unwrap(), expected_trace, "{id}");
        assert!(state == before, "{id}: input state mutated");
        assert!(
            credential_projection == credential_before,
            "{id}: projected credential mutated"
        );
        assert!(
            transaction == transaction_before,
            "{id}: typed transaction mutated"
        );
    }
    assert_eq!(executed, if selected.is_some() { 1 } else { count });
}
