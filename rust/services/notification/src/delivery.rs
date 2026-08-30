use crate::{
    domain::{ChannelType, DeliveryResult, Notification, WebhookDelivery},
    outbox::{is_webhook_test_event, webhook_retry_delay, WebhookOutboxEvent},
    repository::NotificationRepository,
    service::match_event_patterns,
    webhook::{
        canonical_signature, load_direct_webhook_signing_secret, pinned_client,
        resolve_webhook_destination, valid_webhook_signing_secret, WebhookError,
        WebhookSecretEnvelope,
    },
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Map, Value};
use std::{
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{task::JoinSet, time::sleep};

#[derive(Debug, Clone)]
pub struct WebhookAttempt {
    pub success: bool,
    pub retryable: bool,
    pub error_code: Option<String>,
    pub response_status_code: Option<i32>,
    pub response_time_ms: i32,
}

impl WebhookAttempt {
    fn failed(code: impl Into<String>, retryable: bool) -> Self {
        Self {
            success: false,
            retryable,
            error_code: Some(code.into()),
            response_status_code: None,
            response_time_ms: 0,
        }
    }
}

fn bounded(name: &str, default: i64, minimum: i64, maximum: i64) -> Result<i64, String> {
    let value = env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map_or(Ok(default), |value| {
            value
                .parse::<i64>()
                .map_err(|_| format!("{name} must be an integer"))
        })?;
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(format!("{name} must be between {minimum} and {maximum}"))
    }
}

pub fn outbox_retention_seconds() -> Result<i64, String> {
    bounded(
        "NOTIFICATION_WEBHOOK_OUTBOX_RETENTION_SECONDS",
        86_400,
        60,
        604_800,
    )
}
pub fn outbox_lease_seconds() -> Result<i64, String> {
    bounded("NOTIFICATION_WEBHOOK_OUTBOX_LEASE_SECONDS", 30, 5, 300)
}
pub fn outbox_poll_milliseconds() -> Result<u64, String> {
    bounded(
        "NOTIFICATION_WEBHOOK_OUTBOX_POLL_MILLISECONDS",
        1_000,
        100,
        60_000,
    )
    .and_then(|value| u64::try_from(value).map_err(|_| "poll interval is invalid".into()))
}
pub fn outbox_batch_size() -> Result<usize, String> {
    bounded("NOTIFICATION_WEBHOOK_OUTBOX_BATCH_SIZE", 25, 1, 100)
        .and_then(|value| usize::try_from(value).map_err(|_| "batch size is invalid".into()))
}

fn retryable_status(status: StatusCode) -> bool {
    status.is_server_error() || matches!(status.as_u16(), 408 | 425 | 429)
}

pub async fn attempt_webhook(
    payload: &Map<String, Value>,
    url: &str,
    secret: &str,
    delivery_id: &str,
    attempt: i32,
) -> WebhookAttempt {
    if !valid_webhook_signing_secret(secret) {
        return WebhookAttempt::failed("WEBHOOK_SIGNING_UNAVAILABLE", false);
    }
    let started = Instant::now();
    let (destination, addresses) = match resolve_webhook_destination(url).await {
        Ok(value) => value,
        Err(error) => return WebhookAttempt::failed(error.code(), error.retryable()),
    };
    let client = match pinned_client(&destination.hostname, &addresses) {
        Ok(value) => value,
        Err(error) => return WebhookAttempt::failed(error.code(), error.retryable()),
    };
    let mut request = client
        .post(destination.original)
        .json(payload)
        .header("X-MIP-Signature", canonical_signature(secret, payload))
        .header("X-MIP-Delivery-Id", delivery_id)
        .header("X-MIP-Delivery-Attempt", attempt.to_string());
    for (header, key) in [
        ("X-MIP-Event", "type"),
        ("X-MIP-Event-Id", "id"),
        ("X-MIP-Timestamp", "timestamp"),
    ] {
        if let Some(value) = payload.get(key).and_then(Value::as_str) {
            request = request.header(header, value);
        }
    }
    if let Some(event_type) = payload.get("event_type").and_then(Value::as_str) {
        request = request.header("X-MIP-Event-Type", event_type);
        if let Some(id) = payload.get("id").and_then(Value::as_str) {
            request = request.header("X-MIP-Notification-ID", id);
        }
    }
    let response = match request.send().await {
        Ok(value) => value,
        Err(_) => return WebhookAttempt::failed("WEBHOOK_DELIVERY_FAILED", true),
    };
    let elapsed = i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
    let code = i32::from(response.status().as_u16());
    if response.status().is_success() {
        return WebhookAttempt {
            success: true,
            retryable: false,
            error_code: None,
            response_status_code: Some(code),
            response_time_ms: elapsed,
        };
    }
    if response.status().is_redirection() {
        return WebhookAttempt {
            success: false,
            retryable: false,
            error_code: Some("WEBHOOK_REDIRECT_REJECTED".into()),
            response_status_code: Some(code),
            response_time_ms: elapsed,
        };
    }
    WebhookAttempt {
        success: false,
        retryable: retryable_status(response.status()),
        error_code: Some(format!("HTTP_{code}")),
        response_status_code: Some(code),
        response_time_ms: elapsed,
    }
}

pub async fn deliver_notification(
    notification: &Notification,
    now: DateTime<Utc>,
) -> Vec<DeliveryResult> {
    let Some(target) = &notification.target else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for channel in &target.channels {
        if *channel == ChannelType::Webhook {
            if target.webhook_endpoints.is_empty() {
                results.push(result(notification, *channel, now, "NO_WEBHOOK_TARGETS"));
                continue;
            }
            let Some(secret) = load_direct_webhook_signing_secret() else {
                results.extend(
                    target.webhook_endpoints.iter().map(|_| {
                        result(notification, *channel, now, "WEBHOOK_SIGNING_UNAVAILABLE")
                    }),
                );
                continue;
            };
            let payload = Map::from_iter([
                ("id".into(), Value::String(notification.id.clone())),
                ("title".into(), Value::String(notification.subject.clone())),
                ("body".into(), Value::String(notification.body.clone())),
                ("data".into(), Value::Object(notification.data.clone())),
                (
                    "event_type".into(),
                    Value::String(notification.event_type.clone()),
                ),
                (
                    "priority".into(),
                    Value::String(format!("{:?}", notification.priority).to_ascii_uppercase()),
                ),
                (
                    "correlation_id".into(),
                    notification
                        .correlation_id
                        .clone()
                        .map_or(Value::Null, Value::String),
                ),
                (
                    "created_at".into(),
                    Value::String(notification.created_at.to_rfc3339()),
                ),
            ]);
            let max_attempts = bounded("DIRECT_WEBHOOK_MAX_RETRIES", 3, 1, 10).unwrap_or(3) as i32;
            for endpoint in &target.webhook_endpoints {
                let mut outcome = WebhookAttempt::failed("WEBHOOK_DELIVERY_FAILED", false);
                for attempt in 1..=max_attempts {
                    outcome =
                        attempt_webhook(&payload, endpoint, &secret, &notification.id, attempt)
                            .await;
                    if outcome.success || !outcome.retryable {
                        break;
                    }
                    if attempt < max_attempts {
                        sleep(
                            Duration::from_secs(
                                1_u64 << u32::try_from(attempt - 1).unwrap_or_default(),
                            )
                            .min(Duration::from_secs(30)),
                        )
                        .await;
                    }
                }
                results.push(DeliveryResult {
                    notification_id: notification.id.clone(),
                    channel: *channel,
                    success: outcome.success,
                    attempted_at: now,
                    delivered_at: outcome.success.then(Utc::now),
                    error_code: outcome.error_code,
                    should_retry: Some(false),
                    retry_after: None,
                });
            }
            continue;
        }
        let error = match channel {
            ChannelType::Email if target.email_addresses.is_empty() => "NO_EMAIL_TARGETS",
            ChannelType::Email => "EMAIL_ADAPTER_UNAVAILABLE",
            ChannelType::Fcm | ChannelType::Sse | ChannelType::Sms
                if target.device_tokens.is_empty()
                    && target.user_id.is_none()
                    && target.organization_id.is_none() =>
            {
                "NO_DEVICE_TARGETS"
            }
            ChannelType::Fcm => "FCM_ADAPTER_UNAVAILABLE",
            ChannelType::Sse => "SSE_ADAPTER_UNAVAILABLE",
            ChannelType::Sms => "SMS_ADAPTER_UNAVAILABLE",
            ChannelType::Webhook => unreachable!(),
        };
        results.push(result(notification, *channel, now, error));
    }
    results
}

fn result(
    notification: &Notification,
    channel: ChannelType,
    now: DateTime<Utc>,
    code: &str,
) -> DeliveryResult {
    DeliveryResult {
        notification_id: notification.id.clone(),
        channel,
        success: false,
        attempted_at: now,
        delivered_at: None,
        error_code: Some(code.into()),
        should_retry: Some(false),
        retry_after: None,
    }
}

fn valid_payload(event: &WebhookOutboxEvent) -> bool {
    event.payload.get("id").and_then(Value::as_str) == Some(&event.event_id)
        && event.payload.get("type").and_then(Value::as_str) == Some(&event.event_type)
        && event.payload.get("organization_id").and_then(Value::as_str)
            == Some(&event.organization_id)
        && event
            .payload
            .get("timestamp")
            .and_then(Value::as_str)
            .is_some()
}

pub async fn process_outbox_event(
    repository: Arc<dyn NotificationRepository>,
    envelope: Arc<WebhookSecretEnvelope>,
    event: WebhookOutboxEvent,
    claimed_at: DateTime<Utc>,
) -> Option<&'static str> {
    let lease = event.lease_token.clone()?;
    let subscription = repository
        .get_subscription(&event.subscription_id)
        .await
        .ok()
        .flatten();
    let test_delivery = is_webhook_test_event(&event);
    let mut webhook = repository
        .get_webhook(&event.webhook_id)
        .await
        .ok()
        .flatten();
    let mut attempted = false;
    let mut circuit_until = None;
    let outcome = if !valid_payload(&event) {
        WebhookAttempt::failed("WEBHOOK_PAYLOAD_INVALID", false)
    } else if !test_delivery && subscription.is_none() {
        WebhookAttempt::failed("WEBHOOK_SUBSCRIPTION_MISSING", false)
    } else if !test_delivery
        && subscription.as_ref().is_some_and(|value| {
            !value.enabled
                || value.organization_id != event.organization_id
                || value.delivery_target_id.as_deref() != Some(&event.webhook_id)
                || !match_event_patterns(&value.event_types, &event.event_type)
        })
    {
        WebhookAttempt::failed("WEBHOOK_SUBSCRIPTION_INVALID", false)
    } else if webhook.is_none() {
        WebhookAttempt::failed("WEBHOOK_ENDPOINT_MISSING", false)
    } else if webhook.as_ref().is_some_and(|value| {
        !value.enabled
            || value.organization_id != event.organization_id
            || (!test_delivery
                && !value.event_types.is_empty()
                && !match_event_patterns(&value.event_types, &event.event_type))
    }) {
        WebhookAttempt::failed("WEBHOOK_ENDPOINT_INVALID", false)
    } else if webhook
        .as_ref()
        .and_then(|value| value.circuit_breaker_open_until)
        .is_some_and(|until| until > claimed_at)
    {
        circuit_until = webhook
            .as_ref()
            .and_then(|value| value.circuit_breaker_open_until);
        WebhookAttempt::failed("WEBHOOK_CIRCUIT_OPEN", true)
    } else {
        let value = webhook.as_ref().expect("validated webhook exists");
        let secret = if let Some(ciphertext) = &value.secret_envelope {
            envelope
                .unwrap(&value.organization_id, &value.id, ciphertext)
                .await
        } else if valid_webhook_signing_secret(&value.secret) {
            Ok(value.secret.clone())
        } else {
            Err(WebhookError::InvalidEnvelope(
                "Webhook signing secret is unavailable".into(),
            ))
        };
        match secret {
            Ok(secret) => {
                attempted = true;
                attempt_webhook(
                    &event.payload,
                    &value.url,
                    &secret,
                    &event.id,
                    event.attempt_count,
                )
                .await
            }
            Err(WebhookError::InvalidEnvelope(_)) => WebhookAttempt::failed(
                if value.secret_envelope.is_some() {
                    "WEBHOOK_SECRET_ENVELOPE_INVALID"
                } else {
                    "WEBHOOK_SIGNING_UNAVAILABLE"
                },
                false,
            ),
            Err(_) => WebhookAttempt::failed("WEBHOOK_SECRET_KMS_UNAVAILABLE", true),
        }
    };
    let completed = Utc::now();
    let terminal = !outcome.retryable
        || (circuit_until.is_none() && event.attempt_count >= event.max_attempts);
    let marked = if outcome.success {
        repository
            .mark_webhook_event_delivered(
                &event.id,
                &lease,
                completed,
                outcome.response_status_code.unwrap_or(200),
            )
            .await
            .ok()?
    } else {
        let mut next = completed + webhook_retry_delay(&event);
        if circuit_until.is_some_and(|until| until > next) {
            next = circuit_until.unwrap();
        }
        repository
            .mark_webhook_event_failed(
                &event.id,
                &lease,
                next,
                terminal,
                outcome
                    .error_code
                    .as_deref()
                    .unwrap_or("WEBHOOK_DELIVERY_FAILED"),
                outcome.response_status_code,
            )
            .await
            .ok()?
    };
    if !marked {
        return None;
    }
    if let Some(value) = webhook.as_mut().filter(|_| attempted) {
        if outcome.success {
            value.failure_count = 0;
            value.last_triggered_at = Some(completed);
            value.circuit_breaker_open_until = None;
        } else {
            value.failure_count += 1;
            value.last_failure_at = Some(completed);
            let threshold =
                bounded("WEBHOOK_CIRCUIT_BREAKER_THRESHOLD", 5, 1, 100).unwrap_or(5) as i32;
            if value.failure_count >= threshold {
                value.circuit_breaker_open_until = Some(completed + ChronoDuration::hours(1));
            }
        }
        value.updated_at = completed;
        let _ = repository.save_webhook(value.clone()).await;
    }
    if webhook
        .as_ref()
        .is_none_or(|value| value.organization_id == event.organization_id)
    {
        let _ = repository
            .save_webhook_delivery(WebhookDelivery {
                id: event.id.clone(),
                organization_id: event.organization_id.clone(),
                webhook_id: event.webhook_id.clone(),
                subscription_id: Some(event.subscription_id.clone()),
                event_id: event.event_id.clone(),
                event_type: event.event_type.clone(),
                correlation_id: event
                    .payload
                    .get("correlation_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                success: outcome.success,
                response_status_code: outcome.response_status_code,
                error_message: outcome.error_code,
                retry_count: (event.attempt_count - 1).max(0),
                response_time_ms: Some(outcome.response_time_ms),
                created_at: event.created_at,
            })
            .await;
    }
    Some(if outcome.success {
        "delivered"
    } else if terminal {
        "dead"
    } else {
        "retried"
    })
}

pub async fn process_due(
    repository: Arc<dyn NotificationRepository>,
    envelope: Arc<WebhookSecretEnvelope>,
    now: DateTime<Utc>,
) -> Result<Map<String, Value>, String> {
    let events = repository
        .claim_due_webhook_events(
            now,
            now + ChronoDuration::seconds(outbox_lease_seconds()?),
            outbox_batch_size()?,
        )
        .await
        .map_err(|error| error.to_string())?;
    let claimed = events.len();
    let mut set = JoinSet::new();
    for event in events {
        set.spawn(process_outbox_event(
            repository.clone(),
            envelope.clone(),
            event,
            now,
        ));
    }
    let mut delivered = 0;
    let mut retried = 0;
    let mut dead = 0;
    while let Some(result) = set.join_next().await {
        match result.ok().flatten() {
            Some("delivered") => delivered += 1,
            Some("retried") => retried += 1,
            Some("dead") => dead += 1,
            _ => {}
        }
    }
    Ok(Map::from_iter([
        ("claimed".into(), Value::from(claimed)),
        ("delivered".into(), Value::from(delivered)),
        ("retried".into(), Value::from(retried)),
        ("dead".into(), Value::from(dead)),
    ]))
}

pub async fn run_worker(
    repository: Arc<dyn NotificationRepository>,
    envelope: Arc<WebhookSecretEnvelope>,
) {
    let poll = outbox_poll_milliseconds().unwrap_or(1_000);
    loop {
        let _ = process_due(repository.clone(), envelope.clone(), Utc::now()).await;
        sleep(Duration::from_millis(poll)).await;
    }
}
