use chrono::{DateTime, Utc};
use marty_issuance_service::{
    transaction_postgres::PostgresTransactionReadRepository,
    transaction_reads::{TransactionReadError, TransactionReadRepository, TransactionStatus},
};
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn transaction_projection_round_trips_and_enforces_tenant_lists_when_configured() {
    let Ok(database_url) = std::env::var("ISSUANCE_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("issuance PostgreSQL contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert!(
        database_name.ends_with("_test"),
        "ISSUANCE_POSTGRES_TEST_URL must name a dedicated *_test database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");

    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .expect("issuance schema must be available");
    sqlx::query("DROP TABLE IF EXISTS issuance_service.issuance_transactions")
        .execute(&pool)
        .await
        .expect("stale issuance contract table must be removable");
    sqlx::query(
        "CREATE TABLE issuance_service.issuance_transactions (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            credential_template_id TEXT NOT NULL,
            applicant_id TEXT,
            application_id TEXT,
            subject_did TEXT,
            status TEXT NOT NULL,
            pre_auth_code TEXT NOT NULL UNIQUE,
            credential_type TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            issued_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            revocation_reason TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("issuance contract table must be created");

    let created_at = timestamp("2026-08-20T12:34:56.123000+00:00");
    let expires_at = timestamp("2099-08-20T12:49:56+00:00");
    for (id, organization_id, status, revoked_at) in [
        ("tx-a", "org-a", "pending", None),
        (
            "tx-revoked",
            "org-a",
            "revoked",
            Some(timestamp("2026-08-21T09:30:00+00:00")),
        ),
        ("tx-foreign", "org-b", "authorized", None),
    ] {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_transactions (
                id, organization_id, credential_template_id, applicant_id, application_id,
                subject_did, status, pre_auth_code, credential_type, created_at, expires_at,
                issued_at, revoked_at, revocation_reason
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(id)
        .bind(organization_id)
        .bind(format!("template-{id}"))
        .bind(Some(format!("applicant-{id}")))
        .bind(Some(format!("application-{id}")))
        .bind(Some(format!("did:key:{id}")))
        .bind(status)
        .bind(format!("pre-auth-{id}"))
        .bind(Some(format!("Credential{id}")))
        .bind(created_at)
        .bind(expires_at)
        .bind(None::<DateTime<Utc>>)
        .bind(revoked_at)
        .bind(revoked_at.map(|_| "superseded"))
        .execute(&pool)
        .await
        .expect("issuance transaction fixture must insert");
    }

    let repository = PostgresTransactionReadRepository::new(pool.clone());
    let transaction = repository
        .get("tx-revoked")
        .await
        .expect("transaction lookup must succeed")
        .expect("transaction must exist");
    assert_eq!(transaction.organization_id, "org-a");
    assert_eq!(transaction.status, TransactionStatus::Revoked);
    assert_eq!(transaction.created_at, created_at);
    assert_eq!(
        transaction.revoked_at,
        Some(timestamp("2026-08-21T09:30:00+00:00"))
    );
    assert_eq!(transaction.revocation_reason.as_deref(), Some("superseded"));
    assert!(repository
        .get("missing")
        .await
        .expect("missing lookup must succeed")
        .is_none());

    let tenant_transactions = repository
        .list("org-a")
        .await
        .expect("tenant list must succeed");
    assert_eq!(tenant_transactions.len(), 2);
    assert!(tenant_transactions
        .iter()
        .all(|transaction| transaction.organization_id == "org-a"));

    sqlx::query(
        "UPDATE issuance_service.issuance_transactions SET status = 'unknown' WHERE id = 'tx-a'",
    )
    .execute(&pool)
    .await
    .expect("invalid status fixture must update");
    assert_eq!(
        repository.get("tx-a").await,
        Err(TransactionReadError::RepositoryUnavailable)
    );

    sqlx::query("DROP TABLE issuance_service.issuance_transactions")
        .execute(&pool)
        .await
        .expect("issuance contract table must be removed");
}

fn timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("contract timestamp")
        .to_utc()
}
