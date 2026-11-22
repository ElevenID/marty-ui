use super::*;
use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const KEY: &str = "re_synthetic-private-key-0123456789";
const MESSAGE_ID: &str = "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794";

fn configuration() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("NOTIFICATION_EMAIL_PROVIDER".into(), "resend".into()),
        (
            "NOTIFICATION_EMAIL_FROM".into(),
            "notifications@example.test".into(),
        ),
        (
            "NOTIFICATION_RESEND_API_KEY_FILE".into(),
            "/run/secrets/notification_resend_api_key".into(),
        ),
    ])
}

#[test]
fn explicit_provider_requires_private_key_and_valid_sender_without_exposing_values() {
    marty_service_runtime::install_tls_crypto_provider();
    assert!(
        configured(&BTreeMap::new(), |_| panic!("disabled mail read a file"))
            .unwrap()
            .is_none()
    );
    assert!(configured(&configuration(), |_| Ok(format!("{KEY}\n")))
        .unwrap()
        .is_some());
    for (name, value) in [
        ("NOTIFICATION_EMAIL_PROVIDER", "smtp"),
        ("NOTIFICATION_EMAIL_PROVIDER", "disabled"),
        (
            "NOTIFICATION_EMAIL_FROM",
            "Name <notifications@example.test>",
        ),
        (
            "NOTIFICATION_EMAIL_FROM",
            "sender@example.test\r\nBcc: other@example.test",
        ),
        ("NOTIFICATION_EMAIL_FROM", ""),
        ("NOTIFICATION_RESEND_API_KEY_FILE", ""),
        ("NOTIFICATION_RESEND_API_KEY", KEY),
    ] {
        let mut values = configuration();
        values.insert(name.into(), value.into());
        let error = configured(&values, |_| Ok(KEY.into())).err().unwrap();
        assert_eq!(error, CONFIG_ERROR);
        assert!(!error.contains(KEY));
        assert!(!error.contains("/run/secrets"));
    }
    for key in [
        "",
        "re_short",
        "re_key with spaces",
        "re_key\r\nInjection: secret",
    ] {
        assert!(configured(&configuration(), |_| Ok(key.into())).is_err());
    }
    assert!(configured(&configuration(), |_| Err("private filename never returned")).is_err());
}

#[derive(Clone)]
struct Mock {
    status: StatusCode,
    body: String,
    seen: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
}

async fn receive(
    State(mock): State<Mock>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (
    StatusCode,
    [(reqwest::header::HeaderName, &'static str); 1],
    String,
) {
    mock.seen.lock().unwrap().push((headers, body));
    (
        mock.status,
        [(
            reqwest::header::LOCATION,
            "http://127.0.0.1:1/credential-target",
        )],
        mock.body,
    )
}

async fn mock(
    status: StatusCode,
    body: String,
) -> (
    ResendEmail,
    Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    tokio::task::JoinHandle<()>,
) {
    marty_service_runtime::install_tls_crypto_provider();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/emails", post(receive))
        .with_state(Mock {
            status,
            body,
            seen: seen.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/emails", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        ResendEmail::new("notifications@example.test", KEY, &endpoint).unwrap(),
        seen,
        handle,
    )
}

fn notification() -> Notification {
    Notification {
        organization_id: Some("org-a".into()),
        subject: "Your credential is ready".into(),
        body: "Open the application to view your credential.".into(),
        ..Notification::default()
    }
}

#[tokio::test]
async fn no_targets_and_over_limit_batches_are_rejected_before_provider_access() {
    let mut notification = notification();
    let result = deliver(&notification, Utc::now()).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].error_code.as_deref(), Some("NO_EMAIL_TARGETS"));
    notification.target = Some(crate::domain::NotificationTarget {
        email_addresses: (0..51)
            .map(|i| format!("recipient-{i}@example.test"))
            .collect(),
        channels: vec![ChannelType::Email],
        ..Default::default()
    });
    let result = deliver(&notification, Utc::now()).await;
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].error_code.as_deref(),
        Some("EMAIL_RECIPIENT_LIMIT")
    );
    assert_eq!(result[0].should_retry, Some(false));
}

#[tokio::test]
async fn provider_acceptance_sends_private_plain_text_with_repeatable_idempotency() {
    let (adapter, seen, handle) = mock(StatusCode::OK, json!({"id": MESSAGE_ID}).to_string()).await;
    let notification = notification();
    for recipient in ["one@example.test", "one@example.test", "two@example.test"] {
        let result = adapter.send(&notification, recipient, Utc::now()).await;
        assert!(result.success);
        assert!(result.delivered_at.is_some());
        assert_eq!(result.error_code, None);
        assert_eq!(result.should_retry, Some(false));
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0["authorization"], format!("Bearer {KEY}"));
    assert_eq!(seen[0].0["idempotency-key"], seen[1].0["idempotency-key"]);
    assert_ne!(seen[0].0["idempotency-key"], seen[2].0["idempotency-key"]);
    assert!(!seen[0].0["idempotency-key"]
        .to_str()
        .unwrap()
        .contains("example.test"));
    assert_eq!(
        seen[0].1,
        json!({"from":"notifications@example.test", "to":["one@example.test"],
        "subject":notification.subject, "text":notification.body})
    );
    handle.abort();
}

#[tokio::test]
async fn provider_errors_remain_redacted_and_redirects_are_not_followed() {
    for (status, code, retry) in [
        (
            StatusCode::UNAUTHORIZED,
            "EMAIL_PROVIDER_AUTH_FAILED",
            false,
        ),
        (StatusCode::FORBIDDEN, "EMAIL_PROVIDER_AUTH_FAILED", false),
        (
            StatusCode::TOO_MANY_REQUESTS,
            "EMAIL_PROVIDER_RATE_LIMITED",
            true,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "EMAIL_PROVIDER_UNAVAILABLE",
            true,
        ),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "EMAIL_PROVIDER_REJECTED",
            false,
        ),
        (
            StatusCode::TEMPORARY_REDIRECT,
            "EMAIL_PROVIDER_REDIRECT_REJECTED",
            false,
        ),
    ] {
        let (adapter, seen, handle) = mock(
            status,
            format!("{KEY}: one@example.test private provider detail"),
        )
        .await;
        let result = adapter
            .send(&notification(), "one@example.test", Utc::now())
            .await;
        assert!(!result.success);
        assert_eq!(result.delivered_at, None);
        assert_eq!(result.error_code.as_deref(), Some(code));
        assert_eq!(result.should_retry, Some(retry));
        assert!(!serde_json::to_string(&result).unwrap().contains(KEY));
        assert_eq!(seen.lock().unwrap().len(), 1);
        handle.abort();
    }
}

#[tokio::test]
async fn malformed_success_and_oversized_body_are_not_delivery_evidence() {
    for body in [
        json!({"ok":true}).to_string(),
        json!({"id":KEY}).to_string(),
        "x".repeat(4097),
    ] {
        let (adapter, _, handle) = mock(StatusCode::OK, body).await;
        let result = adapter
            .send(&notification(), "one@example.test", Utc::now())
            .await;
        assert!(!result.success);
        assert_eq!(result.error_code.as_deref(), Some("EMAIL_RESPONSE_INVALID"));
        assert!(!serde_json::to_string(&result).unwrap().contains(KEY));
        handle.abort();
    }
}

#[tokio::test]
async fn invalid_recipient_or_content_sends_no_request() {
    let (adapter, seen, handle) = mock(StatusCode::OK, json!({"id":MESSAGE_ID}).to_string()).await;
    let notification = notification();
    let result = adapter
        .send(
            &notification,
            "one@example.test, other@example.test",
            Utc::now(),
        )
        .await;
    assert_eq!(
        result.error_code.as_deref(),
        Some("EMAIL_RECIPIENT_INVALID")
    );
    let mut invalid = notification.clone();
    invalid.subject.push_str("\r\nBcc: other@example.test");
    let result = adapter.send(&invalid, "one@example.test", Utc::now()).await;
    assert_eq!(result.error_code.as_deref(), Some("EMAIL_CONTENT_INVALID"));
    assert!(seen.lock().unwrap().is_empty());
    handle.abort();
}
