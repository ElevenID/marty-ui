use chrono::{TimeDelta, Utc};
use marty_issuance_service::{
    canvas_mirror_domain::CanvasMirrorAlertEvent,
    canvas_mirror_postgres::PostgresCanvasMirrorRepository,
    canvas_mirror_repository::{
        CanvasMirrorDeliveryQuery, CanvasMirrorDeliveryStatus, CanvasMirrorRepository,
    },
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[tokio::test]
async fn selection_and_mutation_are_tenant_and_identity_qualified() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas mirror PostgreSQL contract without database URL");
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("Canvas mirror PostgreSQL contract URL must parse")
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
        .expect("Canvas mirror PostgreSQL contract database must connect");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.credential_delivery_records (
            id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
            organization_id TEXT NOT NULL, delivery_target TEXT NOT NULL,
            delivery_mode TEXT NOT NULL, status TEXT NOT NULL, canvas_account_id TEXT,
            external_credential_id TEXT, external_issuer_id TEXT, last_error TEXT,
            metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.issued_credentials (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, transaction_id TEXT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.issuance_events (
            id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, application_id TEXT,
            event_type TEXT NOT NULL, metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let ids = [
        "mirror-native-owned-pending",
        "mirror-native-owned-failed",
        "mirror-native-foreign",
        "mirror-native-other-target",
        "mirror-native-tie-a",
        "mirror-native-tie-b",
        "mirror-native-claim-pending",
        "mirror-native-claim-status",
    ];
    sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
        .bind(&ids[..])
        .execute(&pool)
        .await
        .unwrap();
    for (index, (id, organization, target, status)) in [
        (ids[0], "org-native", "canvas_credentials", "pending"),
        (ids[1], "org-native", "canvas_credentials", "failed"),
        (ids[2], "org-foreign", "canvas_credentials", "pending"),
        (ids[3], "org-native", "wallet", "pending"),
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query("INSERT INTO issuance_service.credential_delivery_records (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,canvas_account_id,external_credential_id,metadata,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'wallet_plus_canvas_mirror',$6,'account-native',$7,$8,$9::timestamptz,$9::timestamptz)")
            .bind(id)
            .bind(format!("credential-native-{index}"))
            .bind(format!("transaction-native-{index}"))
            .bind(organization)
            .bind(target)
            .bind(status)
            .bind(format!("external-native-{index}"))
            .bind(json!({"sequence":index}))
            .bind(format!("2026-09-01T00:00:0{index}Z"))
            .execute(&pool)
            .await
            .unwrap();
    }
    for id in [ids[5], ids[4]] {
        sqlx::query("INSERT INTO issuance_service.credential_delivery_records (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,canvas_account_id,external_credential_id,metadata,created_at,updated_at) VALUES ($1,'credential-native-tie','transaction-native-tie','org-native','canvas_credentials','wallet_plus_canvas_mirror','delivered','account-native','external-native-tie','{}','2026-09-01T00:00:09Z','2026-09-01T00:00:09Z')")
            .bind(id).execute(&pool).await.unwrap();
    }

    let repository = PostgresCanvasMirrorRepository::new(pool.clone());
    let records = repository
        .canvas_deliveries(CanvasMirrorDeliveryQuery {
            organization_id: Some("org-native".into()),
            statuses: vec![CanvasMirrorDeliveryStatus::Pending],
            limit: Some(10),
            status_sync_failures_only: false,
        })
        .await
        .unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        [ids[0]]
    );
    assert!(repository
        .delivery_by_external_credential("external-native-0", Some("account-foreign"), "org-native")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repository
            .delivery_by_external_credential(
                "external-native-tie",
                Some("account-native"),
                "org-native",
            )
            .await
            .unwrap()
            .unwrap()
            .id,
        ids[4]
    );
    let mut record = repository
        .delivery_by_external_credential("external-native-0", Some("account-native"), "org-native")
        .await
        .unwrap()
        .unwrap();
    record.status = "delivered".into();
    record.metadata.insert("saved".into(), json!(true));
    record.updated_at = "2026-09-01T12:00:00+00:00".into();
    repository.save_delivery(&record).await.unwrap();
    let persisted = repository
        .delivery_record(ids[0], "org-native")
        .await
        .unwrap()
        .unwrap();
    assert!(repository
        .delivery_record(ids[0], "org-foreign")
        .await
        .unwrap()
        .is_none());
    assert_eq!(persisted.status, "delivered");
    assert_eq!(persisted.metadata["saved"], true);

    let mut foreign_identity = persisted.clone();
    foreign_identity.organization_id = "org-foreign".into();
    assert!(repository.save_delivery(&foreign_identity).await.is_err());
    assert_eq!(
        repository
            .delivery_record(ids[0], "org-native")
            .await
            .unwrap()
            .unwrap()
            .organization_id,
        "org-native"
    );
    sqlx::query("DELETE FROM issuance_service.issued_credentials WHERE id='mirror-native-foreign-credential'")
        .execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM issuance_service.issuance_transactions WHERE id='mirror-native-foreign-transaction'")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.issued_credentials (id,organization_id,transaction_id) VALUES ('mirror-native-foreign-credential','org-foreign','mirror-native-foreign-transaction')")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO issuance_service.issuance_transactions (id,organization_id) VALUES ('mirror-native-foreign-transaction','org-foreign')")
        .execute(&pool).await.unwrap();
    assert!(repository
        .credential("mirror-native-foreign-credential", "org-native")
        .await
        .unwrap()
        .is_none());
    assert!(repository
        .transaction("mirror-native-foreign-transaction", "org-native")
        .await
        .unwrap()
        .is_none());

    sqlx::query("INSERT INTO issuance_service.credential_delivery_records (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,metadata,created_at,updated_at) VALUES ($1,'credential-native-claim','transaction-native-claim','org-native','canvas_credentials','wallet_plus_canvas_mirror','pending','{}','2026-09-01T00:01:00Z','2026-09-01T00:01:00Z'),($2,'credential-native-status','transaction-native-status','org-native','canvas_credentials','wallet_plus_canvas_mirror','delivered','{\"last_status_sync_error\":\"retry\"}','2026-09-01T00:01:01Z','2026-09-01T00:01:01Z')")
        .bind(ids[6])
        .bind(ids[7])
        .execute(&pool)
        .await
        .unwrap();
    let lease_expires_at = Utc::now() + TimeDelta::minutes(15);
    let pending_query = CanvasMirrorDeliveryQuery {
        organization_id: Some("org-native".into()),
        statuses: vec![CanvasMirrorDeliveryStatus::Pending],
        limit: Some(10),
        status_sync_failures_only: false,
    };
    let (first_claim, second_claim) = tokio::join!(
        repository.claim_canvas_deliveries(
            pending_query.clone(),
            "mirror-claim-owner-a",
            lease_expires_at
        ),
        repository.claim_canvas_deliveries(pending_query, "mirror-claim-owner-b", lease_expires_at)
    );
    let first_claim = first_claim.unwrap();
    let second_claim = second_claim.unwrap();
    assert_eq!(first_claim.len() + second_claim.len(), 1);
    let (claim_id, mut claimed) = if first_claim.is_empty() {
        (
            "mirror-claim-owner-b",
            second_claim.into_iter().next().unwrap(),
        )
    } else {
        (
            "mirror-claim-owner-a",
            first_claim.into_iter().next().unwrap(),
        )
    };
    assert_eq!(claimed.id, ids[6]);
    assert!(!claimed.metadata.contains_key("_canvas_mirror_claim_id"));
    assert!(repository
        .mark_claim_effect_started(&claimed, "not-the-owner", Utc::now())
        .await
        .is_err());
    repository
        .mark_claim_effect_started(&claimed, claim_id, Utc::now())
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.credential_delivery_records SET metadata=jsonb_set(metadata,'{_canvas_mirror_claim_expires_at}',to_jsonb('2000-01-01T00:00:00Z'::text)) WHERE id=$1")
        .bind(ids[6])
        .execute(&pool)
        .await
        .unwrap();
    assert!(repository
        .claim_canvas_deliveries(
            CanvasMirrorDeliveryQuery {
                organization_id: Some("org-native".into()),
                statuses: vec![CanvasMirrorDeliveryStatus::Pending],
                limit: Some(10),
                status_sync_failures_only: false,
            },
            "mirror-claim-owner-after-ambiguous-effect",
            lease_expires_at,
        )
        .await
        .unwrap()
        .is_empty());
    assert!(repository
        .save_claimed_delivery(&claimed, "not-the-owner")
        .await
        .is_err());
    claimed.status = "delivered".into();
    claimed.updated_at = "2026-09-01T12:01:00+00:00".into();
    repository
        .save_claimed_delivery(&claimed, claim_id)
        .await
        .unwrap();
    let stored_claim_metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.credential_delivery_records WHERE id=$1",
    )
    .bind(ids[6])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored_claim_metadata
        .get("_canvas_mirror_claim_id")
        .is_none());

    let status_claim = repository
        .claim_canvas_deliveries(
            CanvasMirrorDeliveryQuery {
                organization_id: Some("org-native".into()),
                statuses: vec![CanvasMirrorDeliveryStatus::Delivered],
                limit: Some(10),
                status_sync_failures_only: true,
            },
            "mirror-status-owner",
            lease_expires_at,
        )
        .await
        .unwrap();
    assert_eq!(
        status_claim
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        [ids[7]]
    );

    let event_id = "mirror-native-alert-event";
    sqlx::query("DELETE FROM issuance_service.issuance_events WHERE id=$1")
        .bind(event_id)
        .execute(&pool)
        .await
        .unwrap();
    repository
        .save_alert_event(&CanvasMirrorAlertEvent {
            id: event_id.into(),
            transaction_id: "transaction-native-0".into(),
            application_id: None,
            event_type: "canvas_mirror_alert_emitted".into(),
            metadata: json!({"organization_id":"org-native","severity":"critical"}),
            created_at: "2026-09-01T12:00:00+00:00".into(),
        })
        .await
        .unwrap();
    let event: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM issuance_service.issuance_events e WHERE id=$1",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event["event_type"], "canvas_mirror_alert_emitted");
    assert_eq!(event["metadata"]["organization_id"], "org-native");

    sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
        .bind(&ids[..])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM issuance_service.issued_credentials WHERE id='mirror-native-foreign-credential'")
        .execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM issuance_service.issuance_transactions WHERE id='mirror-native-foreign-transaction'")
        .execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM issuance_service.issuance_events WHERE id=$1")
        .bind(event_id)
        .execute(&pool)
        .await
        .unwrap();
}
