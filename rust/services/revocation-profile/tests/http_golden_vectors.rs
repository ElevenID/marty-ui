use async_trait::async_trait;
use axum::{body::Body, http::Request, Router};
use marty_revocation_profile::{
    Authorization, AuthorizationError, InMemoryProfileRepository, InMemoryStatusRepository,
    RevocationProfileHttp, RevocationProfileService,
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
struct Fixture {
    version: u8,
    cases: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    id: String,
    authorization: String,
    method: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<Value>,
    expected_status: u16,
    #[serde(default)]
    expected_body_subset: Option<Value>,
    #[serde(default)]
    expected_absent_fields: Vec<String>,
}

#[derive(Debug)]
struct VectorAuthorization {
    allow: bool,
}

#[async_trait]
impl Authorization for VectorAuthorization {
    async fn require_permission(
        &self,
        _user_id: &str,
        _organization_id: &str,
        _resource: &str,
        _action: &str,
    ) -> Result<(), AuthorizationError> {
        if self.allow {
            Ok(())
        } else {
            Err(AuthorizationError::Denied)
        }
    }
}

fn app(authorization: &str) -> Router {
    let service = RevocationProfileService::new(
        Arc::new(InMemoryProfileRepository::default()),
        Arc::new(InMemoryStatusRepository::default()),
        "https://status.example.com",
    )
    .unwrap();
    RevocationProfileHttp::new(
        service,
        Arc::new(VectorAuthorization {
            allow: authorization == "allow",
        }),
    )
    .router()
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/revocation_profile_http_vectors.json")
}

fn normalize_dynamic_fields(mut body: Value) -> Value {
    let Some(profile_id) = body
        .get("id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return body;
    };

    fn replace(value: &mut Value, profile_id: &str) {
        match value {
            Value::String(text) => *text = text.replace(profile_id, "{profile_id}"),
            Value::Array(values) => {
                for value in values {
                    replace(value, profile_id);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    replace(value, profile_id);
                }
            }
            _ => {}
        }
    }

    replace(&mut body, &profile_id);
    body
}

fn assert_subset(actual: &Value, expected: &Value, vector_id: &str) {
    if let Value::Object(expected) = expected {
        let actual = actual
            .as_object()
            .unwrap_or_else(|| panic!("{vector_id}: expected object, got {actual}"));
        for (key, expected_value) in expected {
            let actual_value = actual
                .get(key)
                .unwrap_or_else(|| panic!("{vector_id}: missing field {key}"));
            assert_subset(actual_value, expected_value, vector_id);
        }
    } else {
        assert_eq!(actual, expected, "{vector_id}");
    }
}

#[tokio::test]
async fn rust_adapter_matches_shared_revocation_http_vectors() {
    let fixture: Fixture =
        serde_json::from_str(&fs::read_to_string(fixture_path()).unwrap()).unwrap();
    assert_eq!(fixture.version, 1);

    for vector in fixture.cases {
        let mut request = Request::builder()
            .method(vector.method.as_str())
            .uri(&vector.path);
        for (name, value) in &vector.headers {
            request = request.header(name, value);
        }
        let body = match vector.body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        let response = app(&vector.authorization)
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            vector.expected_status,
            "{}",
            vector.id
        );
        let Some(expected) = vector.expected_body_subset else {
            continue;
        };
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let actual = normalize_dynamic_fields(serde_json::from_slice(&bytes).unwrap());
        assert_subset(&actual, &expected, &vector.id);
        let actual = actual
            .as_object()
            .expect("vector response must be an object");
        for field in vector.expected_absent_fields {
            assert!(
                !actual.contains_key(&field),
                "{}: unexpected field {field}",
                vector.id
            );
        }
    }
}
