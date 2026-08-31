use std::sync::Arc;

use marty_issuance_service::{
    canvas_event_status::{CanvasEventStatusError, CanvasEventStatusService},
    canvas_event_status_postgres::PostgresCanvasEventStatusRepository,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[tokio::test]
async fn receipt_status_uses_the_composite_key_and_hides_foreign_tenants() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas event status PostgreSQL contract without database URL");
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("Canvas event status PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "MARTY_ISSUANCE_POSTGRES_CONTRACT_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("Canvas event status PostgreSQL contract database must connect");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.canvas_event_receipts (
            id VARCHAR(64) PRIMARY KEY,
            provider_event_id VARCHAR(255) NOT NULL,
            organization_id VARCHAR(64) NOT NULL,
            credential_template_id VARCHAR(64) NOT NULL,
            canvas_account_id VARCHAR(255),
            payload_hash VARCHAR(64) NOT NULL,
            issuance_transaction_id VARCHAR(64),
            issuance_response JSON NOT NULL DEFAULT '{}',
            status VARCHAR(50) NOT NULL DEFAULT 'processed',
            error_summary TEXT,
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&pool)
    .await
    .unwrap();

    for (id, account, organization) in [
        ("status-contract-owned", "account-owned", "org-owned"),
        ("status-contract-decoy", "account-decoy", "org-decoy"),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.canvas_event_receipts
                (id, provider_event_id, organization_id, credential_template_id,
                 canvas_account_id, payload_hash, issuance_response, status,
                 first_seen_at, last_seen_at)
             VALUES ($1, 'shared-provider-event', $3, 'template-1', $2,
                     'payload-hash', $4, 'evidence_received',
                     '2026-08-30T01:02:03Z', '2026-08-30T02:03:04Z')
             ON CONFLICT (id) DO UPDATE SET organization_id = EXCLUDED.organization_id,
                 canvas_account_id = EXCLUDED.canvas_account_id,
                 issuance_response = EXCLUDED.issuance_response",
        )
        .bind(id)
        .bind(account)
        .bind(organization)
        .bind(json!({
            "application_id": format!("application-{account}"),
            "evidence_facts": [{"fact_type": "canvas.course_completion"}],
            "policy_decision": {"allowed": true}
        }))
        .execute(&pool)
        .await
        .unwrap();
    }

    let service = CanvasEventStatusService::new(
        Some("management-key"),
        Arc::new(PostgresCanvasEventStatusRepository::new(pool.clone())),
    );
    let owned = service
        .get(
            "account-owned",
            "shared-provider-event",
            Some("management-key"),
            Some("org-owned"),
        )
        .await
        .unwrap();
    assert_eq!(owned.id, "status-contract-owned");
    assert_eq!(
        owned.application_id.as_deref(),
        Some("application-account-owned")
    );
    assert_eq!(owned.evidence_facts.len(), 1);
    assert!(owned.replay_available);
    assert_eq!(
        service
            .get(
                "account-owned",
                "shared-provider-event",
                Some("management-key"),
                Some("org-decoy"),
            )
            .await,
        Err(CanvasEventStatusError::NotFound)
    );
    assert_eq!(
        service
            .get(
                "account-missing",
                "shared-provider-event",
                Some("management-key"),
                Some("org-owned"),
            )
            .await,
        Err(CanvasEventStatusError::NotFound)
    );

    sqlx::query(
        "DELETE FROM issuance_service.canvas_event_receipts
         WHERE id IN ('status-contract-owned', 'status-contract-decoy')",
    )
    .execute(&pool)
    .await
    .unwrap();
}
