use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const OUTBOX_NAMESPACE: Uuid = Uuid::from_u128(0xb431_a1c8_dfd9_44fa_b042_b633_f7d9_ec6c);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct WebhookOutboxEvent {
    pub id: String,
    pub organization_id: String,
    pub webhook_id: String,
    pub subscription_id: String,
    pub event_id: String,
    pub event_type: String,
    pub payload: Map<String, Value>,
    pub max_attempts: i32,
    pub initial_backoff_seconds: i32,
    pub max_backoff_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub next_attempt_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub attempt_count: i32,
    pub lease_token: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub last_error_code: Option<String>,
    pub response_status_code: Option<i32>,
}

pub fn logical_webhook_delivery_id(
    event_id: &str,
    subscription_id: &str,
    webhook_id: &str,
) -> String {
    Uuid::new_v5(
        &OUTBOX_NAMESPACE,
        format!("{event_id}:{subscription_id}:{webhook_id}").as_bytes(),
    )
    .to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn new_webhook_outbox_event(
    organization_id: String,
    webhook_id: String,
    subscription_id: String,
    event_id: String,
    event_type: String,
    payload: Map<String, Value>,
    max_attempts: i32,
    initial_backoff_seconds: i32,
    max_backoff_seconds: i32,
    created_at: DateTime<Utc>,
    retention_seconds: i64,
) -> WebhookOutboxEvent {
    let id = logical_webhook_delivery_id(&event_id, &subscription_id, &webhook_id);
    WebhookOutboxEvent {
        id,
        organization_id,
        webhook_id,
        subscription_id,
        event_id,
        event_type,
        payload,
        max_attempts,
        initial_backoff_seconds,
        max_backoff_seconds,
        created_at,
        next_attempt_at: created_at,
        expires_at: created_at + Duration::seconds(retention_seconds),
        status: "pending".into(),
        attempt_count: 0,
        lease_token: None,
        lease_expires_at: None,
        delivered_at: None,
        last_error_code: None,
        response_status_code: None,
    }
}

pub fn webhook_retry_delay(event: &WebhookOutboxEvent) -> Duration {
    let exponent = (event.attempt_count - 1).clamp(0, 16);
    let multiplier = 1_i64 << u32::try_from(exponent).unwrap_or_default();
    let base = i64::from(event.max_backoff_seconds)
        .min(i64::from(event.initial_backoff_seconds).saturating_mul(multiplier));
    let digest = Sha256::digest(format!("{}:{}", event.id, event.attempt_count));
    let ratio = f64::from(u16::from_be_bytes([digest[0], digest[1]])) / 65_535.0;
    let room = i64::from(event.max_backoff_seconds).saturating_sub(base);
    #[allow(clippy::cast_possible_truncation)]
    let jitter = (base as f64 * 0.25 * ratio).min(room as f64) as i64;
    Duration::seconds(base.saturating_add(jitter.max(0)))
}
