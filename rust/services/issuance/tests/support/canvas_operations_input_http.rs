use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Shared native request recipe for fast rejection and real-database replay.
pub(crate) fn request_body(case: &Value) -> String {
    let mut payload = case.get("body").cloned().unwrap_or_else(|| json!({}));
    if let Some(length) = case["note_length"].as_u64() {
        payload["note"] = json!("n".repeat(usize::try_from(length).unwrap()));
    }
    case["raw_body"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| payload.to_string())
}

pub(crate) async fn request_case(router: &axum::Router, case: &Value) -> (u16, String, Value) {
    let mut headers = std::collections::BTreeMap::from([
        (
            "X-API-Key".to_owned(),
            "synthetic-operations-key".to_owned(),
        ),
        ("X-Organization-ID".to_owned(), "org-review".to_owned()),
    ]);
    if let Some(overrides) = case["headers"].as_object() {
        for (key, value) in overrides {
            headers.insert(key.clone(), value.as_str().unwrap().into());
        }
    }
    for key in case["omit_headers"].as_array().into_iter().flatten() {
        headers.remove(key.as_str().unwrap());
    }
    let mut request = Request::builder()
        .method(case["method"].as_str().unwrap_or("GET"))
        .uri(case["path"].as_str().unwrap());
    let body = request_body(case);
    if case["method"] == "POST" {
        let content_type = case
            .get("content_type")
            .map_or(Some("application/json"), Value::as_str);
        if let Some(value) = content_type {
            request = request.header("content-type", value);
        }
    }
    for (key, value) in headers {
        request = request.header(key, value);
    }
    let response = router
        .clone()
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
    (status, content_type, body)
}
