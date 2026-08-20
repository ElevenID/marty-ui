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

#[test]
fn built_in_seed_contract_preserves_every_intended_flow() {
    let sql = include_str!("../migrations/0002_builtin_flows.sql").to_ascii_lowercase();
    let contract: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-seed-behavior.json"
    ))
    .expect("seed contract");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["conflict_behavior"], "preserve_existing");
    for definition in contract["definitions"].as_array().expect("definitions") {
        for field in [
            "id",
            "effective_type",
            "trigger_type",
            "event_type",
            "template_id",
        ] {
            let value = definition[field]
                .as_str()
                .expect("field")
                .to_ascii_lowercase();
            assert!(sql.contains(&value), "seed SQL is missing {field}={value}");
        }
    }
    for field in [
        "organization_id",
        "bootstrap_instance_id",
        "deployment_profile_id",
    ] {
        let value = contract[field]
            .as_str()
            .expect("field")
            .to_ascii_lowercase();
        assert!(sql.contains(&value), "seed SQL is missing {field}");
    }
    assert!(sql.contains("on conflict (id) do nothing"));
    assert!(sql.contains("to_regclass('deployment_profile_service.deployment_profiles')"));
    assert_eq!(sql.matches("rust_flow_seed_0001").count(), 1);
}
