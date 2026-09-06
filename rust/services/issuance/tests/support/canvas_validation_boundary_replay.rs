//! Full native management router and validator replay of the published app corpus.
//! Reuse the existing management repository fixture; only secret/file/HTTP ports
//! are controlled, matching the independent published observation boundary.
use super::*;
use marty_issuance_service::{
    canvas_credentials_validation::{
        CanvasCredentialsProviderResponse, CanvasCredentialsSecretResolver,
        CanvasCredentialsTransportError, CanvasCredentialsValidationService,
        CanvasCredentialsValidationTransport,
    },
    canvas_operator_secret::CanvasOperatorSecretReader,
};

struct Ports {
    case: Value,
    files: Mutex<Vec<Value>>,
    lookups: Arc<Mutex<Vec<Value>>>,
    requests: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasOperatorSecretReader for Ports {
    async fn read(&self, path: &str) -> Result<Vec<u8>, std::io::Error> {
        assert_eq!(path, "/synthetic/operator-token");
        let mut files = self.files.lock().unwrap();
        let values = self.case["files"].as_array().unwrap();
        assert!(
            files.len() < values.len(),
            "unexpected extra operator file read"
        );
        let kind = values[files.len()].as_str().unwrap();
        files.push(json!("operator-token"));
        Ok(match kind {
            "value" => b"synthetic-file\n".to_vec(),
            "empty" => Vec::new(),
            "invalid_utf8" => vec![0xff],
            _ => panic!("unknown fixture file"),
        })
    }
}

#[async_trait]
impl CanvasCredentialsSecretResolver for Ports {
    async fn secret_value(&self, organization: &str, id: &str) -> Result<Option<String>, ()> {
        assert_eq!((organization, id), ("org-review", "secret-review"));
        self.lookups
            .lock()
            .unwrap()
            .push(json!({"kind":"value", "organization_id":organization, "secret_id":id}));
        Ok(Some("synthetic-tenant".into()))
    }
}

#[async_trait]
impl CanvasCredentialsValidationTransport for Ports {
    async fn get(
        &self,
        origin: &str,
        url: &str,
        token: &str,
    ) -> Result<CanvasCredentialsProviderResponse, CanvasCredentialsTransportError> {
        assert_eq!(origin, "https://api.badgr.io");
        self.requests
            .lock()
            .unwrap()
            .push(json!({"method":"GET", "url":url, "authorization":format!("Bearer {token}")}));
        if let Some(body) = self.case["response_hex"].as_str() {
            return CanvasCredentialsProviderResponse::from_body(
                self.case["response_status"]
                    .as_u64()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                Some("synthetic-provider".into()),
                &hex::decode(body).unwrap(),
                self.case["response_content_type"].as_str(),
            )
            .map_err(Into::into);
        }
        Ok(CanvasCredentialsProviderResponse {
            status_code: 200,
            request_id: Some("synthetic-provider".into()),
            response_excerpt: None,
        })
    }
}

#[tokio::test]
async fn native_validation_matches_all_published_http_and_lookup_observations() {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-validation-boundary-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-validation-boundary-oracle.json"
    ))
    .unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    let expected = oracle["observations"].as_array().unwrap();
    assert_eq!(cases.len(), 47);
    replay(cases, expected).await;
}

#[tokio::test]
async fn native_validation_matches_utf7_body_rendering_and_success_bypass() {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-utf7-consumer-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-utf7-consumer-oracle.json"
    ))
    .unwrap();
    let cases = scenarios["validation"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    replay(
        cases,
        oracle["validation"]["observations"].as_array().unwrap(),
    )
    .await;
}

#[tokio::test]
async fn native_validation_matches_json_rendering_and_success_bypass() {
    let scenarios: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-consumer-scenarios.json"
    ))
    .unwrap();
    let oracle: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-json-consumer-oracle.json"
    ))
    .unwrap();
    let cases = scenarios["validation"].as_array().unwrap();
    assert_eq!(cases.len(), 66);
    replay(
        cases,
        oracle["validation"]["observations"].as_array().unwrap(),
    )
    .await;
}

// Parsing only into Value would silently accept duplicate rendered keys. Check
// the actual excerpt object entries as well as its language-neutral JSON value.
struct UniqueExcerpt;

impl<'de> serde::Deserialize<'de> for UniqueExcerpt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueExcerpt;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an excerpt object with unique rendered keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut keys = BTreeSet::new();
                while let Some((key, _)) =
                    map.next_entry::<String, Box<serde_json::value::RawValue>>()?
                {
                    if !keys.insert(key) {
                        return Err(serde::de::Error::custom("duplicate rendered excerpt key"));
                    }
                }
                Ok(UniqueExcerpt)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[derive(serde::Deserialize)]
struct WireExcerpt {
    response_excerpt: Option<UniqueExcerpt>,
}

#[test]
fn wire_excerpt_check_rejects_duplicate_keys_before_value_normalization() {
    for source in [
        r#"{"response_excerpt":{"key":1,"key":2}}"#,
        r#"{"response_excerpt":{"key":1,"\u006bey":2}}"#,
    ] {
        assert!(serde_json::from_str::<WireExcerpt>(source).is_err());
    }
    assert!(serde_json::from_str::<WireExcerpt>(
        r#"{"response_excerpt":{"key":1,"other":{"python_float":"nan"}}}"#
    )
    .is_ok());
}

async fn replay(cases: &[Value], expected: &[Value]) {
    replay_mode(cases, expected, false).await;
}

#[tokio::test]
async fn native_validation_matches_published_depth_boundaries() {
    let scenarios = super::canvas_json_depth_replay::scenarios();
    let oracle = super::canvas_json_depth_replay::oracle();
    let cases = scenarios["validation"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    replay_mode(
        cases,
        oracle["validation"]["observations"].as_array().unwrap(),
        true,
    )
    .await;
}

async fn replay_mode(cases: &[Value], expected: &[Value], depth: bool) {
    assert_eq!(cases.len(), expected.len());
    for (case, expected) in cases.iter().zip(expected) {
        assert_eq!(case["name"], expected["name"]);
        let mut environment = Vec::new();
        for (key, name, fallback) in [
            ("provider", "CANVAS_CREDENTIALS_PROVIDER", ""),
            (
                "publish_url",
                "CANVAS_CREDENTIALS_PUBLISH_URL",
                "https://bridge.example.invalid/publish",
            ),
            (
                "api_base_url",
                "CANVAS_CREDENTIALS_API_BASE_URL",
                "https://api.badgr.io",
            ),
            (
                "scope",
                "CANVAS_CREDENTIALS_ASSERTION_SCOPE",
                "badgeclasses",
            ),
            (
                "badgeclass_id",
                "CANVAS_CREDENTIALS_BADGECLASS_ID",
                "badge-review",
            ),
            ("issuer_id", "CANVAS_CREDENTIALS_ISSUER_ID", "issuer-review"),
            ("direct", "CANVAS_CREDENTIALS_API_TOKEN", ""),
        ] {
            environment.push((
                name.to_owned(),
                case[key].as_str().unwrap_or(fallback).to_owned(),
            ));
        }
        if case.get("files").is_some() {
            environment.push((
                "CANVAS_CREDENTIALS_API_TOKEN_FILE".into(),
                "/synthetic/operator-token".into(),
            ));
        }
        let config = IssuanceServiceConfig::from_values(environment).unwrap();
        let ports = Arc::new(Ports {
            case: case.clone(),
            files: Mutex::new(Vec::new()),
            lookups: Arc::new(Mutex::new(Vec::new())),
            requests: Mutex::new(Vec::new()),
        });
        let validator = CanvasCredentialsValidationService::new(
            config.canvas_credentials_validation,
            ports.clone(),
            ports.clone(),
        )
        .with_operator_secret_reader(ports.clone());
        let repository = Arc::new(MemoryRepository {
            validation_lookups: Some(ports.lookups.clone()),
            ..MemoryRepository::default()
        });
        *repository.validation_secret.lock().unwrap() = Some((
            case["secret_organization"]
                .as_str()
                .unwrap_or("org-review")
                .into(),
            "secret-review".into(),
        ));
        let app = app_with_validator(
            repository.clone(),
            Arc::new(SuccessfulProbe),
            Arc::new(validator),
        );
        let response = app.oneshot(Request::builder()
            .method("POST").uri("/v1/integrations/canvas/canvas-credentials/validate")
            .header("x-api-key", "management-key").header("x-organization-id", "org-review")
            .header("content-type", "application/json")
            .body(Body::from(json!({"organization_id":"org-review", "canvas_credentials":case.get("config").cloned().unwrap_or(json!({}))}).to_string())).unwrap()).await.unwrap();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let mut normalized_wire = std::str::from_utf8(&bytes).unwrap().to_owned();
        let body = if content_type.starts_with("application/json") {
            let mut value: Value = if depth {
                let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
                    serde_json::from_slice(&bytes).unwrap();
                Value::Object(
                    fields
                        .into_iter()
                        .map(|(key, value)| {
                            let value = if key == "response_excerpt" && value.get() != "null" {
                                super::canvas_json_depth_replay::witness_bytes(
                                    value.get().as_bytes(),
                                )
                            } else {
                                serde_json::from_str(value.get()).unwrap()
                            };
                            (key, value)
                        })
                        .collect(),
                )
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            if let Some(timestamp) = value.get("validated_at") {
                chrono::DateTime::parse_from_rfc3339(timestamp.as_str().unwrap()).unwrap();
                normalized_wire =
                    normalized_wire.replace(timestamp.as_str().unwrap(), "$timestamp");
                value["validated_at"] = json!("$timestamp");
            }
            value
        } else {
            json!(std::str::from_utf8(&bytes).unwrap())
        };
        let lookups = ports.lookups.lock().unwrap().clone();
        let mut actual = json!({"name":case["name"], "status":status, "content_type":content_type, "body":body,
            "files":*ports.files.lock().unwrap(), "lookups":lookups, "requests":*ports.requests.lock().unwrap()});
        let mut expected = expected.clone();
        if let Some(wire) = expected.as_object_mut().unwrap().remove("body_text") {
            let exceptions = expected
                .as_object_mut()
                .unwrap()
                .remove("exceptions")
                .unwrap();
            if content_type.starts_with("application/json") {
                assert_eq!(exceptions, json!([]));
                if depth {
                    assert_eq!(
                        super::canvas_json_depth_replay::witness_bytes(normalized_wire.as_bytes()),
                        super::canvas_json_depth_replay::witness_bytes(
                            wire.as_str().unwrap().as_bytes()
                        ),
                        "complete wire tree {}",
                        case["name"]
                    );
                } else {
                    let wire_value: Value = serde_json::from_str(wire.as_str().unwrap()).unwrap();
                    assert_eq!(
                        actual["body"], wire_value,
                        "wire values, including numeric types: {}",
                        case["name"]
                    );
                }
                let excerpt: WireExcerpt = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    excerpt.response_excerpt.is_some(),
                    !actual["body"]["response_excerpt"].is_null()
                );
                actual["body"] = super::canvas_observation_values::scalar(&actual["body"]);
            } else {
                assert_eq!(status, 500);
                assert_eq!(
                    exceptions,
                    json!([if depth {
                        "ValueError"
                    } else {
                        "UnicodeEncodeError"
                    }])
                );
                assert_eq!(actual["body"], wire);
            }
        }
        assert_eq!(actual, expected, "native validation case {}", case["name"]);
    }
}
