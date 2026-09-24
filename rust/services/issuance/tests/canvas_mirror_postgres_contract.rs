use chrono::{TimeDelta, Utc};
use marty_issuance_service::{
    canvas_mirror_domain::{CanvasMirrorAlertEvent, CanvasMirrorAlertThresholds},
    canvas_mirror_postgres::PostgresCanvasMirrorRepository,
    canvas_mirror_repository::{
        CanvasMirrorDeliveryQuery, CanvasMirrorDeliveryStatus, CanvasMirrorRepository,
    },
    canvas_mirror_service::CanvasMirrorService,
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

static CONTRACT_SCHEMA: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

async fn contract_pool() -> Option<sqlx::PgPool> {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas mirror PostgreSQL contract without database URL");
        return None;
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
    CONTRACT_SCHEMA
        .get_or_init(|| async {
            for statement in [
                "CREATE SCHEMA IF NOT EXISTS issuance_service",
                "CREATE TABLE IF NOT EXISTS issuance_service.credential_delivery_records (
            id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, transaction_id TEXT NOT NULL,
            organization_id TEXT NOT NULL, delivery_target TEXT NOT NULL,
            delivery_mode TEXT NOT NULL, status TEXT NOT NULL, canvas_account_id TEXT,
            external_credential_id TEXT, external_issuer_id TEXT, last_error TEXT,
            metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL)",
                "CREATE TABLE IF NOT EXISTS issuance_service.issued_credentials (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, transaction_id TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS issuance_service.issuance_events (
            id TEXT PRIMARY KEY, transaction_id TEXT NOT NULL, application_id TEXT,
            event_type TEXT NOT NULL, metadata JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)",
            ] {
                sqlx::query(statement).execute(&pool).await.unwrap();
            }
        })
        .await;
    Some(pool)
}

#[tokio::test]
async fn selection_and_mutation_are_tenant_and_identity_qualified() {
    let Some(pool) = contract_pool().await else {
        return;
    };
    let scope = uuid::Uuid::new_v4().simple().to_string();
    let native_organization = format!("org-native-{scope}");
    let foreign_organization = format!("org-foreign-{scope}");
    let ids = [
        format!("mirror-native-owned-pending-{scope}"),
        format!("mirror-native-owned-failed-{scope}"),
        format!("mirror-native-foreign-{scope}"),
        format!("mirror-native-other-target-{scope}"),
        format!("mirror-native-tie-a-{scope}"),
        format!("mirror-native-tie-b-{scope}"),
        format!("mirror-native-claim-pending-{scope}"),
        format!("mirror-native-claim-status-{scope}"),
    ];
    sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
        .bind(&ids[..])
        .execute(&pool)
        .await
        .unwrap();
    for (index, (id, organization, target, status)) in [
        (
            &ids[0],
            native_organization.as_str(),
            "canvas_credentials",
            "pending",
        ),
        (
            &ids[1],
            native_organization.as_str(),
            "canvas_credentials",
            "failed",
        ),
        (
            &ids[2],
            foreign_organization.as_str(),
            "canvas_credentials",
            "pending",
        ),
        (&ids[3], native_organization.as_str(), "wallet", "pending"),
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
    for id in [&ids[5], &ids[4]] {
        sqlx::query("INSERT INTO issuance_service.credential_delivery_records (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,canvas_account_id,external_credential_id,metadata,created_at,updated_at) VALUES ($1,$2,$3,$4,'canvas_credentials','wallet_plus_canvas_mirror','delivered','account-native','external-native-tie','{}','2026-09-01T00:00:09Z','2026-09-01T00:00:09Z')")
            .bind(id)
            .bind(format!("credential-native-tie-{scope}"))
            .bind(format!("transaction-native-tie-{scope}"))
            .bind(&native_organization)
            .execute(&pool).await.unwrap();
    }

    let foreign_before: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d WHERE id=$1",
    )
    .bind(&ids[2])
    .fetch_one(&pool)
    .await
    .unwrap();

    let repository = PostgresCanvasMirrorRepository::new(pool.clone());
    let records = repository
        .canvas_deliveries(CanvasMirrorDeliveryQuery {
            organization_id: Some(native_organization.clone()),
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
        [ids[0].as_str()]
    );
    assert!(repository
        .delivery_by_external_credential(
            "external-native-0",
            Some("account-foreign"),
            &native_organization,
        )
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        repository
            .delivery_by_external_credential(
                "external-native-tie",
                Some("account-native"),
                &native_organization,
            )
            .await
            .unwrap()
            .unwrap()
            .id,
        ids[4]
    );
    let mut record = repository
        .delivery_by_external_credential(
            "external-native-0",
            Some("account-native"),
            &native_organization,
        )
        .await
        .unwrap()
        .unwrap();
    record.status = "delivered".into();
    record.metadata.insert("saved".into(), json!(true));
    record.updated_at = "2026-09-01T12:00:00+00:00".into();
    repository.save_delivery(&record).await.unwrap();
    let persisted = repository
        .delivery_record(&ids[0], &native_organization)
        .await
        .unwrap()
        .unwrap();
    assert!(repository
        .delivery_record(&ids[0], &foreign_organization)
        .await
        .unwrap()
        .is_none());
    assert_eq!(persisted.status, "delivered");
    assert_eq!(persisted.metadata["saved"], true);

    let mut foreign_identity = persisted.clone();
    foreign_identity.organization_id = foreign_organization.clone();
    assert!(repository.save_delivery(&foreign_identity).await.is_err());
    assert_eq!(
        repository
            .delivery_record(&ids[0], &native_organization)
            .await
            .unwrap()
            .unwrap()
            .organization_id,
        native_organization
    );
    let foreign_credential_id = format!("mirror-native-foreign-credential-{scope}");
    let foreign_transaction_id = format!("mirror-native-foreign-transaction-{scope}");
    sqlx::query("INSERT INTO issuance_service.issued_credentials (id,organization_id,transaction_id) VALUES ($1,$2,$3)")
        .bind(&foreign_credential_id)
        .bind(&foreign_organization)
        .bind(&foreign_transaction_id)
        .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO issuance_service.issuance_transactions (id,organization_id) VALUES ($1,$2)",
    )
    .bind(&foreign_transaction_id)
    .bind(&foreign_organization)
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .credential(&foreign_credential_id, &native_organization)
        .await
        .unwrap()
        .is_none());
    assert!(repository
        .transaction(&foreign_transaction_id, &native_organization)
        .await
        .unwrap()
        .is_none());

    sqlx::query("INSERT INTO issuance_service.credential_delivery_records (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,metadata,created_at,updated_at) VALUES ($1,$3,$4,$5,'canvas_credentials','wallet_plus_canvas_mirror','pending','{}','2026-09-01T00:01:00Z','2026-09-01T00:01:00Z'),($2,$6,$7,$5,'canvas_credentials','wallet_plus_canvas_mirror','delivered','{\"last_status_sync_error\":\"retry\"}','2026-09-01T00:01:01Z','2026-09-01T00:01:01Z')")
        .bind(&ids[6])
        .bind(&ids[7])
        .bind(format!("credential-native-claim-{scope}"))
        .bind(format!("transaction-native-claim-{scope}"))
        .bind(&native_organization)
        .bind(format!("credential-native-status-{scope}"))
        .bind(format!("transaction-native-status-{scope}"))
        .execute(&pool)
        .await
        .unwrap();
    let lease_expires_at = Utc::now() + TimeDelta::minutes(15);
    let pending_query = CanvasMirrorDeliveryQuery {
        organization_id: Some(native_organization.clone()),
        statuses: vec![CanvasMirrorDeliveryStatus::Pending],
        limit: Some(10),
        status_sync_failures_only: false,
    };
    let first_claim_id = format!("mirror-claim-owner-a-{scope}");
    let second_claim_id = format!("mirror-claim-owner-b-{scope}");
    let (first_claim, second_claim) = tokio::join!(
        repository.claim_canvas_deliveries(
            pending_query.clone(),
            &first_claim_id,
            lease_expires_at
        ),
        repository.claim_canvas_deliveries(pending_query, &second_claim_id, lease_expires_at)
    );
    let first_claim = first_claim.unwrap();
    let second_claim = second_claim.unwrap();
    assert_eq!(first_claim.len() + second_claim.len(), 1);
    let (claim_id, mut claimed) = if first_claim.is_empty() {
        (second_claim_id, second_claim.into_iter().next().unwrap())
    } else {
        (first_claim_id, first_claim.into_iter().next().unwrap())
    };
    assert_eq!(claimed.id, ids[6]);
    assert!(!claimed.metadata.contains_key("_canvas_mirror_claim_id"));
    assert!(repository
        .mark_claim_effect_started(&claimed, "not-the-owner", Utc::now())
        .await
        .is_err());
    repository
        .mark_claim_effect_started(&claimed, &claim_id, Utc::now())
        .await
        .unwrap();
    sqlx::query("UPDATE issuance_service.credential_delivery_records SET metadata=jsonb_set(metadata,'{_canvas_mirror_claim_expires_at}',to_jsonb('2000-01-01T00:00:00Z'::text)) WHERE id=$1")
        .bind(&ids[6])
        .execute(&pool)
        .await
        .unwrap();
    assert!(repository
        .claim_canvas_deliveries(
            CanvasMirrorDeliveryQuery {
                organization_id: Some(native_organization.clone()),
                statuses: vec![CanvasMirrorDeliveryStatus::Pending],
                limit: Some(10),
                status_sync_failures_only: false,
            },
            &format!("mirror-claim-owner-after-ambiguous-effect-{scope}"),
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
        .save_claimed_delivery(&claimed, &claim_id)
        .await
        .unwrap();
    let stored_claim_metadata: serde_json::Value = sqlx::query_scalar(
        "SELECT metadata FROM issuance_service.credential_delivery_records WHERE id=$1",
    )
    .bind(&ids[6])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stored_claim_metadata
        .get("_canvas_mirror_claim_id")
        .is_none());

    let status_claim = repository
        .claim_canvas_deliveries(
            CanvasMirrorDeliveryQuery {
                organization_id: Some(native_organization.clone()),
                statuses: vec![CanvasMirrorDeliveryStatus::Delivered],
                limit: Some(10),
                status_sync_failures_only: true,
            },
            &format!("mirror-status-owner-{scope}"),
            lease_expires_at,
        )
        .await
        .unwrap();
    assert_eq!(
        status_claim
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        [ids[7].as_str()]
    );

    let event_id = format!("mirror-native-alert-event-{scope}");
    sqlx::query("DELETE FROM issuance_service.issuance_events WHERE id=$1")
        .bind(&event_id)
        .execute(&pool)
        .await
        .unwrap();
    repository
        .save_alert_event(&CanvasMirrorAlertEvent {
            id: event_id.clone(),
            transaction_id: format!("transaction-native-0-{scope}"),
            application_id: None,
            event_type: "canvas_mirror_alert_emitted".into(),
            metadata: json!({"organization_id":native_organization,"severity":"critical"}),
            created_at: "2026-09-01T12:00:00+00:00".into(),
        })
        .await
        .unwrap();
    let event: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM issuance_service.issuance_events e WHERE id=$1",
    )
    .bind(&event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(event["event_type"], "canvas_mirror_alert_emitted");
    assert_eq!(event["metadata"]["organization_id"], native_organization);

    let foreign_after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d WHERE id=$1",
    )
    .bind(&ids[2])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        foreign_after, foreign_before,
        "tenant-qualified repository operations must not mutate the second tenant"
    );

    sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
        .bind(&ids[..])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM issuance_service.issued_credentials WHERE id=$1")
        .bind(&foreign_credential_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM issuance_service.issuance_transactions WHERE id=$1")
        .bind(&foreign_transaction_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM issuance_service.issuance_events WHERE id=$1")
        .bind(&event_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn tenant_scoped_service_batches_leave_foreign_postgres_effects_unchanged() {
    let Some(pool) = contract_pool().await else {
        return;
    };
    let scope = uuid::Uuid::new_v4().simple().to_string();
    let native_organization = format!("org-native-{scope}");
    let foreign_organization = format!("org-foreign-{scope}");

    for operation in ["pending", "status", "automation"] {
        let mut rows = Vec::new();
        if operation != "status" {
            rows.extend([
                (
                    format!("mirror-service-{operation}-native-pending-{scope}"),
                    native_organization.clone(),
                    "pending",
                    json!({}),
                ),
                (
                    format!("mirror-service-{operation}-foreign-pending-{scope}"),
                    foreign_organization.clone(),
                    "pending",
                    json!({}),
                ),
            ]);
        }
        if operation != "pending" {
            rows.extend([
                (
                    format!("mirror-service-{operation}-native-status-{scope}"),
                    native_organization.clone(),
                    "delivered",
                    json!({"last_status_sync_error":"retry"}),
                ),
                (
                    format!("mirror-service-{operation}-foreign-status-{scope}"),
                    foreign_organization.clone(),
                    "delivered",
                    json!({"last_status_sync_error":"retry"}),
                ),
            ]);
        }
        let ids = rows
            .iter()
            .map(|(id, _, _, _)| id.clone())
            .collect::<Vec<_>>();
        let transaction_ids = rows
            .iter()
            .map(|(id, _, _, _)| format!("{id}-transaction"))
            .collect::<Vec<_>>();
        sqlx::query("DELETE FROM issuance_service.issuance_events WHERE transaction_id=ANY($1)")
            .bind(&transaction_ids)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
            .bind(&ids)
            .execute(&pool)
            .await
            .unwrap();
        for (id, organization, status, metadata) in &rows {
            sqlx::query(
                "INSERT INTO issuance_service.credential_delivery_records
                (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,
                 status,metadata,created_at,updated_at)
                VALUES ($1,$2,$3,$4,'canvas_credentials','wallet_plus_canvas_mirror',$5,$6,
                        '2026-09-01T00:10:00Z','2026-09-01T00:10:00Z')",
            )
            .bind(id)
            .bind(format!("{id}-credential"))
            .bind(format!("{id}-transaction"))
            .bind(organization)
            .bind(status)
            .bind(metadata)
            .execute(&pool)
            .await
            .unwrap();
        }

        let foreign_ids = rows
            .iter()
            .filter(|(_, organization, _, _)| organization == &foreign_organization)
            .map(|(id, _, _, _)| id.clone())
            .collect::<Vec<_>>();
        let native_ids = rows
            .iter()
            .filter(|(_, organization, _, _)| organization == &native_organization)
            .map(|(id, _, _, _)| id.clone())
            .collect::<Vec<_>>();
        let foreign_transactions = foreign_ids
            .iter()
            .map(|id| format!("{id}-transaction"))
            .collect::<Vec<_>>();
        let native_transactions = native_ids
            .iter()
            .map(|id| format!("{id}-transaction"))
            .collect::<Vec<_>>();
        let snapshot = |ids: Vec<String>| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, serde_json::Value>(
                    "SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb)
                     FROM issuance_service.credential_delivery_records d WHERE id=ANY($1)",
                )
                .bind(ids)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        let foreign_before = snapshot(foreign_ids.clone()).await;
        let native_before = snapshot(native_ids.clone()).await;

        let service = CanvasMirrorService::new(
            std::sync::Arc::new(PostgresCanvasMirrorRepository::new(pool.clone())),
            "https://issuer.example".into(),
            CanvasMirrorAlertThresholds {
                warning_attempts: 1,
                critical_attempts: 1,
            },
        );
        let now = "2026-09-01T12:00:00Z".parse().unwrap();
        let response = match operation {
            "pending" => service
                .process_pending(Some(&native_organization), 25, false, now)
                .await
                .unwrap(),
            "status" => service
                .process_status_sync_failures(Some(&native_organization), 25, now)
                .await
                .unwrap(),
            "automation" => service
                .run_automation_cycle(Some(&native_organization), 25, false, now, now)
                .await
                .unwrap(),
            _ => unreachable!(),
        };

        assert_eq!(
            response["processed_count"].as_u64().unwrap(),
            native_ids.len() as u64,
            "{operation} must process only the trusted tenant"
        );
        assert_eq!(
            snapshot(foreign_ids.clone()).await,
            foreign_before,
            "{operation}"
        );
        assert_ne!(
            snapshot(native_ids.clone()).await,
            native_before,
            "{operation}"
        );
        let foreign_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM issuance_service.issuance_events WHERE transaction_id=ANY($1)",
        )
        .bind(&foreign_transactions)
        .fetch_one(&pool)
        .await
        .unwrap();
        let native_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM issuance_service.issuance_events WHERE transaction_id=ANY($1)",
        )
        .bind(&native_transactions)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(foreign_events, 0, "{operation}");
        assert_eq!(native_events, native_ids.len() as i64, "{operation}");

        sqlx::query("DELETE FROM issuance_service.issuance_events WHERE transaction_id=ANY($1)")
            .bind(&transaction_ids)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM issuance_service.credential_delivery_records WHERE id=ANY($1)")
            .bind(&ids)
            .execute(&pool)
            .await
            .unwrap();
    }
}
