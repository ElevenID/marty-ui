#[test]
fn final_schema_forbids_plaintext_secrets_and_receiver_bodies() {
    let sql = include_str!("../migrations/0001_notification_schema.sql").to_ascii_lowercase();
    let endpoint = sql
        .split("create table if not exists notification_service.webhook_endpoints")
        .nth(1)
        .unwrap()
        .split(");")
        .next()
        .unwrap();
    assert!(!endpoint
        .lines()
        .any(|line| line.trim_start().starts_with("secret ")));
    assert!(endpoint.contains("secret_envelope text not null"));
    assert!(endpoint.contains("secret_hint varchar(8) not null"));
    let delivery = sql
        .split("create table if not exists notification_service.webhook_deliveries")
        .nth(1)
        .unwrap()
        .split(");")
        .next()
        .unwrap();
    assert!(!delivery.contains("response_body"));
    assert!(sql.contains("drop column if exists response_body"));
}

#[test]
fn migration_has_one_explicit_compatible_head() {
    let sql = include_str!("../migrations/0001_notification_schema.sql");
    assert_eq!(sql.matches("20260808_0002").count(), 1);
    assert!(sql.contains("ux_webhook_outbox_logical_delivery"));
    assert!(sql.contains("ck_webhook_outbox_status"));
}
