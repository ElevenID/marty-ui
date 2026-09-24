use chrono::{TimeZone, Utc};
use marty_issuance_service::retention::{PostgresRetentionRepository, RetentionRepository};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn retention_purge_preserves_tenant_and_recent_event_ownership() {
    let Ok(database_url) = std::env::var("MARTY_RETENTION_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("retention contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert_eq!(
        database_name, "marty_retention_contract_test",
        "retention contract requires its dedicated disposable database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("retention contract database must connect");
    // This test owns the entire disposable database; make failed reruns repeatable.
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    for statement in [
        "CREATE SCHEMA issuance_service",
        "CREATE TABLE issuance_service.applications (id text PRIMARY KEY, organization_id text NOT NULL, created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.issuance_transactions (id text PRIMARY KEY, organization_id text NOT NULL, created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.authorization_sessions (id text PRIMARY KEY, organization_id text NOT NULL, created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.issued_credentials (id text PRIMARY KEY, organization_id text NOT NULL, transaction_id text NOT NULL REFERENCES issuance_service.issuance_transactions(id))",
        "CREATE TABLE issuance_service.credential_delivery_records (id text PRIMARY KEY, organization_id text NOT NULL, credential_id text NOT NULL REFERENCES issuance_service.issued_credentials(id) ON DELETE CASCADE, transaction_id text NOT NULL REFERENCES issuance_service.issuance_transactions(id) ON DELETE CASCADE)",
        "CREATE TABLE issuance_service.evidence_facts (id text PRIMARY KEY, organization_id text NOT NULL, application_id text NOT NULL REFERENCES issuance_service.applications(id) ON DELETE CASCADE)",
        "CREATE TABLE issuance_service.issuance_events (id text PRIMARY KEY, organization_id text, transaction_id text REFERENCES issuance_service.issuance_transactions(id) ON DELETE SET NULL, application_id text REFERENCES issuance_service.applications(id) ON DELETE SET NULL, created_at timestamptz NOT NULL)",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    for (query, rows) in [
        (
            "INSERT INTO issuance_service.applications (id, organization_id, created_at) VALUES ($1,$2,$3::timestamptz)",
            vec![
                ("old-app", "owned", "2026-01-01"),
                ("new-app", "owned", "2026-02-01"),
                ("other-app", "other", "2026-01-01"),
            ],
        ),
        (
            "INSERT INTO issuance_service.issuance_transactions (id, organization_id, created_at) VALUES ($1,$2,$3::timestamptz)",
            vec![
                ("old-tx", "owned", "2026-01-01"),
                ("new-tx", "owned", "2026-02-01"),
                ("other-tx", "other", "2026-01-01"),
            ],
        ),
        (
            "INSERT INTO issuance_service.authorization_sessions (id, organization_id, created_at) VALUES ($1,$2,$3::timestamptz)",
            vec![
                ("old-session", "owned", "2026-01-01"),
                ("new-session", "owned", "2026-02-01"),
                ("other-session", "other", "2026-01-01"),
            ],
        ),
    ] {
        for (id, organization, created_at) in rows {
            sqlx::query(query)
                .bind(id)
                .bind(organization)
                .bind(created_at)
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    for (id, organization, transaction) in [
        ("old-credential", "owned", "old-tx"),
        ("new-credential", "owned", "new-tx"),
        ("other-credential", "other", "other-tx"),
    ] {
        sqlx::query("INSERT INTO issuance_service.issued_credentials VALUES ($1,$2,$3)")
            .bind(id)
            .bind(organization)
            .bind(transaction)
            .execute(&pool)
            .await
            .unwrap();
    }
    for (id, organization, credential, transaction) in [
        ("old-delivery", "owned", "old-credential", "old-tx"),
        ("new-delivery", "owned", "new-credential", "new-tx"),
        ("other-delivery", "other", "other-credential", "other-tx"),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.credential_delivery_records VALUES ($1,$2,$3,$4)",
        )
        .bind(id)
        .bind(organization)
        .bind(credential)
        .bind(transaction)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (id, organization, application) in [
        ("old-fact", "owned", "old-app"),
        ("new-fact", "owned", "new-app"),
        ("other-fact", "other", "other-app"),
    ] {
        sqlx::query("INSERT INTO issuance_service.evidence_facts VALUES ($1,$2,$3)")
            .bind(id)
            .bind(organization)
            .bind(application)
            .execute(&pool)
            .await
            .unwrap();
    }
    for (id, organization, transaction, application, created_at) in [
        (
            "old-owned-event",
            None::<&str>,
            Some("old-tx"),
            None,
            "2026-01-01",
        ),
        (
            "recent-owned-event",
            None,
            Some("old-tx"),
            None,
            "2026-02-01",
        ),
        (
            "old-application-event",
            None,
            None,
            Some("old-app"),
            "2026-01-01",
        ),
        (
            "recent-application-event",
            None,
            None,
            Some("old-app"),
            "2026-02-01",
        ),
        (
            "old-other-event",
            None,
            Some("other-tx"),
            None,
            "2026-01-01",
        ),
        (
            "recent-other-event",
            None,
            Some("other-tx"),
            None,
            "2026-02-01",
        ),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_events VALUES ($1,$2,$3,$4,$5::timestamptz)",
        )
        .bind(id)
        .bind(organization)
        .bind(transaction)
        .bind(application)
        .bind(created_at)
        .execute(&pool)
        .await
        .unwrap();
    }

    let cutoff = Utc.with_ymd_and_hms(2026, 1, 15, 0, 0, 0).unwrap();
    let repository = PostgresRetentionRepository::new(pool.clone());
    let before = repository.summary("owned", cutoff).await.unwrap();
    assert_eq!(before.eligible_for_purge.total, 6);
    assert_eq!(before.eligible_for_purge.issuance_events, 2);
    assert_eq!(
        before.oldest_retained_record_at,
        Some(Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap())
    );
    let purged = repository.purge("owned", cutoff).await.unwrap();
    assert_eq!(purged, before.eligible_for_purge);
    assert_eq!(repository.purge("owned", cutoff).await.unwrap().total, 0);
    assert_eq!(
        repository
            .summary("owned", cutoff)
            .await
            .unwrap()
            .eligible_for_purge
            .total,
        0
    );
    let retained_owner: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, organization_id FROM issuance_service.issuance_events ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained_owner,
        vec![
            ("old-other-event".into(), None),
            ("recent-application-event".into(), Some("owned".into())),
            ("recent-other-event".into(), None),
            ("recent-owned-event".into(), Some("owned".into())),
        ]
    );
    let delivery_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM issuance_service.credential_delivery_records ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(delivery_ids, ["new-delivery", "other-delivery"]);
    let evidence_ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM issuance_service.evidence_facts ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(evidence_ids, ["new-fact", "other-fact"]);
    for (table, query) in [
        ("applications", "SELECT count(*) FROM issuance_service.applications WHERE organization_id = 'other'"),
        ("issuance_transactions", "SELECT count(*) FROM issuance_service.issuance_transactions WHERE organization_id = 'other'"),
        ("authorization_sessions", "SELECT count(*) FROM issuance_service.authorization_sessions WHERE organization_id = 'other'"),
        ("issued_credentials", "SELECT count(*) FROM issuance_service.issued_credentials WHERE organization_id = 'other'"),
    ] {
        let remaining: i64 = sqlx::query_scalar(query).fetch_one(&pool).await.unwrap();
        assert_eq!(remaining, 1, "foreign {table} must survive");
    }
}
