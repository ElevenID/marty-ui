use marty_notification::{
    migration,
    postgres::PgNotificationRepository,
    repository::NotificationRepository,
    service::{
        CreateSubscriptionRequest, CreateWebhookRequest, EventIngestRequest, NotificationService,
    },
    webhook::WebhookSecretEnvelope,
};
use serde_json::{Map, Value};
use sqlx::postgres::PgPoolOptions;
use std::{env, sync::Arc};

#[tokio::test]
async fn migrated_postgres_preserves_secret_and_outbox_contracts() {
    let Ok(database_url) = env::var("NOTIFICATION_TEST_DATABASE_URL") else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap();
    let envelope = Arc::new(WebhookSecretEnvelope::from_environment().unwrap());
    migration::migrate(&pool, &envelope).await.unwrap();
    migration::validate(&pool).await.unwrap();
    let concrete = PgNotificationRepository::new(pool.clone());
    let repository: Arc<dyn NotificationRepository> = Arc::new(concrete.clone());
    let service = NotificationService::with_envelope(repository.clone(), envelope);
    let created = service
        .create_webhook(CreateWebhookRequest {
            organization_id: "org-db".into(),
            name: "DB endpoint".into(),
            url: "https://example.com/marty".into(),
            description: None,
            event_types: vec!["application.approved".into()],
            secret: Some("0123456789abcdef0123456789abcdef".into()),
            enabled: true,
        })
        .await
        .unwrap();
    assert_eq!(
        created.signing_secret.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    let stored = repository.get_webhook(&created.id).await.unwrap().unwrap();
    assert!(stored.secret.is_empty());
    assert!(stored
        .secret_envelope
        .as_deref()
        .is_some_and(|value| value.starts_with("vault:")));
    let subscription = service
        .create_subscription(CreateSubscriptionRequest {
            organization_id: "org-db".into(),
            name: "Approvals".into(),
            description: None,
            event_types: vec!["application.approved".into()],
            delivery_channel: "WEBHOOK".into(),
            filter_config: Map::new(),
            retry_policy: Default::default(),
            delivery_target_id: Some(created.id.clone()),
            enabled: true,
        })
        .await
        .unwrap();
    let event = EventIngestRequest {
        event_id: "event-db-approved".into(),
        event_type: "application.approved".into(),
        aggregate_id: "application-db".into(),
        aggregate_type: "application".into(),
        organization_id: "org-db".into(),
        data: Map::from_iter([
            ("applicant_id".into(), Value::String("applicant-db".into())),
            (
                "application_id".into(),
                Value::String("application-db".into()),
            ),
            (
                "credential_template_id".into(),
                Value::String("template-db".into()),
            ),
            ("status".into(), Value::String("APPROVED".into())),
        ]),
        timestamp: None,
    };
    assert_eq!(
        service.ingest_event(event.clone()).await.unwrap()["deliveries"],
        1
    );
    assert_eq!(service.ingest_event(event).await.unwrap()["deliveries"], 0);
    let logical = marty_notification::outbox::logical_webhook_delivery_id(
        "event-db-approved",
        &subscription.id,
        &created.id,
    );
    assert!(repository
        .get_webhook_outbox_event(&logical)
        .await
        .unwrap()
        .is_some());
    let forbidden:i64=sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='notification_service' AND column_name IN ('secret','response_body')").fetch_one(&pool).await.unwrap();
    assert_eq!(forbidden, 0);
}
