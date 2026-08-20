#[test]
fn rust_schema_owns_every_flow_storage_surface() {
    let sql = include_str!("../migrations/0001_flow_schema.sql").to_ascii_lowercase();
    for table in [
        "flow_definitions",
        "flow_instances",
        "flow_nonce_consumptions",
        "flow_callback_outbox",
        "flow_application_event_receipts",
        "flow_instance_artifacts",
        "rust_schema_versions",
    ] {
        assert!(
            sql.contains(&format!("flow_service.{table}")),
            "missing {table}"
        );
    }
    assert!(sql.contains("state_history json not null default '[]'"));
    assert!(sql.contains("retry_cooldown_minutes integer not null default 5"));
    assert_eq!(sql.matches("rust_flow_0001").count(), 1);
}

#[test]
fn final_schema_preserves_atomicity_and_idempotency_indexes() {
    let sql = include_str!("../migrations/0001_flow_schema.sql").to_ascii_lowercase();
    for index in [
        "ux_flow_instances_org_application_flow_key",
        "ux_flow_instance_artifacts_issuance_transaction_id",
        "ix_flow_nonce_consumptions_expires_at",
        "ix_flow_callback_outbox_due",
    ] {
        assert!(sql.contains(index), "missing {index}");
    }
    assert!(sql.contains("nonce_digest varchar(64) primary key"));
    assert!(sql.contains("flow_instance_id varchar(36) not null unique"));
    assert!(sql.contains("on delete cascade"));
}
