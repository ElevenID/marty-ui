use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_notification::{
    http::router,
    repository::{InMemoryNotificationRepository, NotificationRepository},
};
use serde_json::{json, Value};
use std::{
    env,
    sync::{Arc, LazyLock},
};
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENVIRONMENT: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
const FIXTURE: &str = include_str!("../../../../contracts/notification_behavior.json");

fn app(repository: Arc<dyn NotificationRepository>) -> axum::Router {
    router(repository)
}

fn request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("fixture JSON serializes"),
        ))
        .expect("request is valid")
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("body reads"),
    )
    .expect("body is JSON")
}

#[tokio::test]
async fn operational_endpoints_report_the_native_backend() {
    let app = app(Arc::new(InMemoryNotificationRepository::default()));
    let health = app
        .clone()
        .oneshot(request("GET", "/health", Value::Null))
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(json_body(health).await["backend"], "rust");
    let metrics = app
        .oneshot(request("GET", "/metrics", Value::Null))
        .await
        .unwrap();
    let body = to_bytes(metrics.into_body(), 65_536).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("marty_notification_backend_info"));
}

#[tokio::test]
async fn send_contract_preserves_shape_priority_and_explicit_delivery_truth() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let repository: Arc<dyn NotificationRepository> =
        Arc::new(InMemoryNotificationRepository::default());
    let response = app(repository.clone())
        .oneshot(request(
            "POST",
            "/v1/notifications/send",
            fixture["valid_send"].clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["title"], "Credential ready");
    assert_eq!(body["priority"], "CRITICAL");
    assert_eq!(body["target"]["channels"], json!(["FCM", "SSE"]));
    let stored = repository
        .get_notification(body["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.delivery_results.len(), 2);
    assert!(stored.delivery_results.iter().all(|result| !result.success));
    assert_eq!(
        stored.status,
        marty_notification::domain::NotificationStatus::Failed
    );
}

#[tokio::test]
async fn protected_credential_material_fails_closed() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let response = app(Arc::new(InMemoryNotificationRepository::default()))
        .oneshot(request(
            "POST",
            "/v1/notifications/send",
            fixture["protected_payload"].clone(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(json_body(response).await["detail"]
        .as_str()
        .unwrap()
        .contains("protected credential material"));
}

#[tokio::test]
async fn tenant_bound_read_and_unread_routes_preserve_behavior() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let app = app(Arc::new(InMemoryNotificationRepository::default()));
    let sent = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/notifications/send",
            fixture["valid_send"].clone(),
        ))
        .await
        .unwrap();
    let id = json_body(sent).await["id"].as_str().unwrap().to_owned();
    let wrong = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/notifications/{id}?organization_id=org-b"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::NOT_FOUND);
    let read = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/notifications/{id}/read?organization_id=org-a"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let count = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/notifications/unread-count?organization_id=org-a&recipient_id=user-a",
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(json_body(count).await, json!({"count":0}));
    let unread = app
        .oneshot(request(
            "DELETE",
            &format!("/v1/notifications/{id}/read?organization_id=org-a"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(unread.status(), StatusCode::OK);
}

#[tokio::test]
async fn webhook_secret_is_returned_only_on_creation_or_rotation() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let app = app(Arc::new(InMemoryNotificationRepository::default()));
    let created = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/webhooks",
            fixture["valid_webhook"].clone(),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = json_body(created).await;
    assert!(created.get("signing_secret").is_some());
    let id = created["id"].as_str().unwrap();
    let fetched = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/webhooks/{id}?organization_id=org-a"),
            Value::Null,
        ))
        .await
        .unwrap();
    assert!(json_body(fetched).await.get("signing_secret").is_none());
    let rotated = app
        .oneshot(request(
            "PATCH",
            &format!("/v1/webhooks/{id}?organization_id=org-a"),
            json!({"secret":"abcdef0123456789abcdef0123456789"}),
        ))
        .await
        .unwrap();
    assert_eq!(
        json_body(rotated).await["signing_secret"],
        "abcdef0123456789abcdef0123456789"
    );
}

#[tokio::test]
async fn subscriptions_are_tenant_bound_and_enqueue_each_logical_delivery_once() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let repository: Arc<dyn NotificationRepository> =
        Arc::new(InMemoryNotificationRepository::default());
    let app = app(repository.clone());
    let webhook = json_body(
        app.clone()
            .oneshot(request(
                "POST",
                "/v1/webhooks",
                fixture["valid_webhook"].clone(),
            ))
            .await
            .unwrap(),
    )
    .await;
    let mut subscription = fixture["valid_subscription"].clone();
    subscription["delivery_target_id"] = webhook["id"].clone();
    let subscription = app
        .clone()
        .oneshot(request("POST", "/v1/subscriptions", subscription))
        .await
        .unwrap();
    assert_eq!(subscription.status(), StatusCode::OK);
    let subscription = json_body(subscription).await;
    let wrong = app
        .clone()
        .oneshot(request(
            "GET",
            &format!(
                "/v1/subscriptions/{}?organization_id=org-b",
                subscription["id"].as_str().unwrap()
            ),
            Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::NOT_FOUND);

    let event: marty_notification::service::EventIngestRequest =
        serde_json::from_value(fixture["valid_internal_event"].clone()).unwrap();
    let service = marty_notification::service::NotificationService::new(repository.clone());
    assert_eq!(
        service.ingest_event(event.clone()).await.unwrap()["deliveries"],
        1
    );
    assert_eq!(service.ingest_event(event).await.unwrap()["deliveries"], 0);
}

#[tokio::test]
async fn internal_auth_is_checked_before_malformed_body() {
    let _guard = ENVIRONMENT.lock().await;
    env::set_var(
        "NOTIFICATION_APPLICANT_EVENT_TOKEN",
        "0123456789abcdef0123456789abcdef",
    );
    env::remove_var("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE");
    let app = app(Arc::new(InMemoryNotificationRepository::default()));
    let invalid = Request::builder()
        .method("POST")
        .uri("/internal/events")
        .header("content-type", "application/json")
        .body(Body::from("not-json"))
        .unwrap();
    let response = app.clone().oneshot(invalid).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let valid_auth_invalid_body = Request::builder()
        .method("POST")
        .uri("/internal/events")
        .header("content-type", "application/json")
        .header("x-marty-event-producer", "applicant")
        .header("x-service-token", "0123456789abcdef0123456789abcdef")
        .body(Body::from("not-json"))
        .unwrap();
    assert_eq!(
        app.oneshot(valid_auth_invalid_body).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    env::remove_var("NOTIFICATION_APPLICANT_EVENT_TOKEN");
}

#[tokio::test]
async fn webhook_urls_fail_closed_for_ambiguous_or_private_destinations() {
    let app = app(Arc::new(InMemoryNotificationRepository::default()));
    for url in [
        "http://example.com/hook",
        "https://127.0.0.1/hook",
        "https://user@example.com/hook",
        "https://example.com/hook#fragment",
    ] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/webhooks",
                json!({"organization_id":"org-a","name":"bad","url":url}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{url}");
    }
}
