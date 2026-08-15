use chrono::{Duration, Utc};
use marty_notification::{
    domain::RetryPolicy,
    outbox::{logical_webhook_delivery_id, new_webhook_outbox_event, webhook_retry_delay},
    repository::{InMemoryNotificationRepository, NotificationRepository},
    webhook::{canonical_signature, decode_bound_webhook_secret, encode_bound_webhook_secret},
};
use serde_json::{Map, Value};

fn event(now: chrono::DateTime<Utc>, id: &str) -> marty_notification::outbox::WebhookOutboxEvent {
    new_webhook_outbox_event(
        "org-a".into(),
        "webhook-a".into(),
        "subscription-a".into(),
        id.into(),
        "application.approved".into(),
        Map::from_iter([
            ("id".into(), Value::String(id.into())),
            ("type".into(), Value::String("application.approved".into())),
            ("timestamp".into(), Value::String(now.to_rfc3339())),
            ("organization_id".into(), Value::String("org-a".into())),
        ]),
        3,
        1,
        30,
        now,
        86_400,
    )
}

#[test]
fn deterministic_identity_and_retry_delay_are_stable_and_bounded() {
    let id = logical_webhook_delivery_id("event-a", "subscription-a", "webhook-a");
    assert_eq!(
        id,
        logical_webhook_delivery_id("event-a", "subscription-a", "webhook-a")
    );
    let mut item = event(Utc::now(), "event-a");
    item.attempt_count = 4;
    let first = webhook_retry_delay(&item);
    assert_eq!(first, webhook_retry_delay(&item));
    assert!(first >= Duration::seconds(8));
    assert!(first <= Duration::seconds(10));
    assert!(RetryPolicy {
        max_attempts: 11,
        ..RetryPolicy::default()
    }
    .validate()
    .is_err());
}

#[tokio::test]
async fn enqueue_is_idempotent_and_claims_are_exclusive() {
    let repository = InMemoryNotificationRepository::default();
    let now = Utc::now();
    let item = event(now, "event-a");
    assert!(repository
        .enqueue_webhook_event(item.clone())
        .await
        .unwrap());
    assert!(!repository.enqueue_webhook_event(item).await.unwrap());
    let (left, right) = tokio::join!(
        repository.claim_due_webhook_events(now, now + Duration::seconds(30), 25),
        repository.claim_due_webhook_events(now, now + Duration::seconds(30), 25)
    );
    assert_eq!(left.unwrap().len() + right.unwrap().len(), 1);
}

#[tokio::test]
async fn stale_lease_cannot_overwrite_newer_delivery() {
    let repository = InMemoryNotificationRepository::default();
    let now = Utc::now();
    repository
        .enqueue_webhook_event(event(now, "event-a"))
        .await
        .unwrap();
    let first = repository
        .claim_due_webhook_events(now, now + Duration::seconds(5), 1)
        .await
        .unwrap()
        .remove(0);
    let first_lease = first.lease_token.unwrap();
    let second = repository
        .claim_due_webhook_events(now + Duration::seconds(6), now + Duration::seconds(36), 1)
        .await
        .unwrap()
        .remove(0);
    let second_lease = second.lease_token.unwrap();
    assert!(!repository
        .mark_webhook_event_delivered(&first.id, &first_lease, Utc::now(), 200)
        .await
        .unwrap());
    assert!(repository
        .mark_webhook_event_delivered(&second.id, &second_lease, Utc::now(), 200)
        .await
        .unwrap());
    let stored = repository
        .get_webhook_outbox_event(&second.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, "delivered");
    assert!(stored.payload.is_empty());
}

#[tokio::test]
async fn expired_and_terminal_payloads_are_scrubbed() {
    let repository = InMemoryNotificationRepository::default();
    let now = Utc::now();
    let mut expired = event(now - Duration::seconds(120), "expired");
    expired.expires_at = now - Duration::seconds(1);
    repository
        .enqueue_webhook_event(expired.clone())
        .await
        .unwrap();
    assert!(repository
        .claim_due_webhook_events(now, now + Duration::seconds(30), 1)
        .await
        .unwrap()
        .is_empty());
    let expired = repository
        .get_webhook_outbox_event(&expired.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(expired.status, "expired");
    assert!(expired.payload.is_empty());
    let active = event(now, "active");
    repository
        .enqueue_webhook_event(active.clone())
        .await
        .unwrap();
    let claimed = repository
        .claim_due_webhook_events(now, now + Duration::seconds(30), 1)
        .await
        .unwrap()
        .remove(0);
    assert!(repository
        .mark_webhook_event_failed(
            &claimed.id,
            claimed.lease_token.as_deref().unwrap(),
            now,
            true,
            "permanent",
            None
        )
        .await
        .unwrap());
    assert!(repository
        .get_webhook_outbox_event(&active.id)
        .await
        .unwrap()
        .unwrap()
        .payload
        .is_empty());
}

#[test]
fn bound_secret_rejects_tenant_or_endpoint_replay() {
    let secret = "0123456789abcdef0123456789abcdef";
    let encoded = encode_bound_webhook_secret("org-a", "webhook-a", secret).unwrap();
    assert_eq!(
        decode_bound_webhook_secret(&encoded, "org-a", "webhook-a").unwrap(),
        secret
    );
    assert!(decode_bound_webhook_secret(&encoded, "org-b", "webhook-a").is_err());
    assert!(decode_bound_webhook_secret(&encoded, "org-a", "webhook-b").is_err());
}

#[test]
fn signature_matches_language_neutral_golden_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/notification_behavior.json"
    ))
    .unwrap();
    let vector = &fixture["webhook_signature"];
    assert_eq!(
        canonical_signature(
            vector["secret"].as_str().unwrap(),
            vector["payload"].as_object().unwrap()
        ),
        vector["expected"]
    );
}
