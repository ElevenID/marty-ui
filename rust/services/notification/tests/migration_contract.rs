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
    let forward = include_str!("../migrations/0003_webhook_aws_envelope.sql");
    assert_eq!(forward.matches("20261031_0003").count(), 1);
    assert!(include_str!("../src/migration.rs").contains("const HEAD: &str = \"20261031_0003\""));
}

#[test]
fn correlation_migration_is_applied_and_validated() {
    let source = include_str!("../src/migration.rs");
    let sql = include_str!("../migrations/0002_webhook_delivery_correlation.sql");
    let compact_source: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    // Keep a source assertion from looking like another compiler include input.
    let expected_include = format!(
        "{}({})",
        "include_str!", r#""../migrations/0002_webhook_delivery_correlation.sql""#
    );
    assert!(compact_source.contains(&expected_include));
    assert!(source.contains("webhook delivery correlation column is missing"));
    assert!(sql.contains("ADD COLUMN IF NOT EXISTS correlation_id varchar(64)"));
}

fn owned_postgres_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "postgres" | "postgresql")
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && url.path() == "/marty_db_contracts_test"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

#[test]
fn native_postgres_contract_refuses_unrelated_database_targets() {
    assert!(owned_postgres_url(
        "postgresql://postgres:fixture-only@127.0.0.1:5432/marty_db_contracts_test"
    ));
    for value in [
        "postgresql://postgres@127.0.0.1:5432/marty",
        "postgresql://postgres@remote.example:5432/marty_db_contracts_test",
        "postgresql://postgres@127.0.0.1:5432/marty_db_contracts_test?options=unknown",
        "https://127.0.0.1/marty_db_contracts_test",
    ] {
        assert!(!owned_postgres_url(value));
    }
}

#[tokio::test]
#[ignore = "requires the owned Notification PostgreSQL fixture"]
async fn native_postgres_preserves_both_envelope_formats_across_migration_reruns() {
    use marty_notification::{
        migration, postgres::PgNotificationRepository, repository::NotificationRepository,
        webhook::WebhookSecretEnvelope,
    };

    const CHILD: &str = "MARTY_NOTIFICATION_MIGRATION_CONTRACT_CHILD";
    const CASE: &str = "native_postgres_preserves_both_envelope_formats_across_migration_reruns";
    let database_url = std::env::var("NOTIFICATION_MIGRATION_TEST_DATABASE_URL")
        .expect("owned Notification PostgreSQL URL is required");
    assert!(
        owned_postgres_url(&database_url),
        "only the owned loopback database contract fixture is permitted"
    );
    if std::env::var_os(CHILD).is_none() {
        // Isolate provider configuration from concurrent tests. Construction is
        // pure; the schema test never invokes KMS or probes a workload identity.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", CASE, "--ignored", "--nocapture"])
            .env(CHILD, "1")
            .env("NOTIFICATION_SECRET_KMS_PROVIDER", "aws-kms")
            .env("NOTIFICATION_SECRET_AWS_REGION", "us-east-2")
            .env(
                "NOTIFICATION_SECRET_AWS_KEY_ARN",
                "arn:aws:kms:us-east-2:111122223333:key/schema-only-fixture",
            )
            .env("AWS_EC2_METADATA_DISABLED", "true");
        for name in [
            "NOTIFICATION_OPENBAO_TOKEN",
            "NOTIFICATION_OPENBAO_TOKEN_FILE",
            "NOTIFICATION_OPENBAO_CA_CERT_FILE",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        ] {
            child.env_remove(name);
        }
        let output = child.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "native Notification migration contract failed: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("owned Notification PostgreSQL must connect");
    let legacy_columns: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='notification_service' AND table_name='webhook_endpoints' AND column_name='secret'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(
        legacy_columns, 0,
        "schema-only fixture must not trigger legacy secret encryption"
    );
    let envelope = WebhookSecretEnvelope::from_environment().unwrap();
    migration::migrate(&pool, &envelope).await.unwrap();
    migration::validate(&pool).await.unwrap();
    let repository = PgNotificationRepository::new(pool.clone());
    let vault_id = uuid::Uuid::new_v4().to_string();
    let aws_id = uuid::Uuid::new_v4().to_string();
    let aws_ciphertext = mmf_aws_kms::encode_ciphertext(b"opaque-storage-contract").unwrap();
    for id in [&vault_id, &aws_id] {
        sqlx::query("INSERT INTO notification_service.webhook_endpoints (id, organization_id, name, url, secret_envelope, secret_hint, created_at, updated_at) VALUES ($1, 'notification-schema-contract', 'Envelope contract', 'https://example.com/webhook', 'vault:v1:retained-contract', 'test', now(), now())")
            .bind(id).execute(&pool).await.unwrap();
    }
    let mut aws_record = repository.get_webhook(&aws_id).await.unwrap().unwrap();
    aws_record.secret_envelope = Some(aws_ciphertext.clone());
    repository.save_webhook(aws_record.clone()).await.unwrap();
    let mut malformed = aws_record;
    malformed.secret_envelope = Some("aws-kms:v1:AQ".into());
    assert!(repository.save_webhook(malformed).await.is_err());
    for ciphertext in [
        "plaintext".to_owned(),
        "aws-kms:v2:b3BhcXVl".into(),
        "aws-kms:v1:".into(),
        format!("aws-kms:v1:{}", "A".repeat(8196)),
    ] {
        let failure = sqlx::query(
            "UPDATE notification_service.webhook_endpoints SET secret_envelope=$1 WHERE id=$2",
        )
        .bind(ciphertext)
        .bind(&aws_id)
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(matches!(failure, sqlx::Error::Database(error)
            if error.code().as_deref() == Some("23514")));
    }
    migration::migrate(&pool, &envelope).await.unwrap();
    migration::validate(&pool).await.unwrap();
    assert_eq!(
        repository
            .get_webhook(&vault_id)
            .await
            .unwrap()
            .unwrap()
            .secret_envelope
            .as_deref(),
        Some("vault:v1:retained-contract")
    );
    assert_eq!(
        repository
            .get_webhook(&aws_id)
            .await
            .unwrap()
            .unwrap()
            .secret_envelope
            .as_deref(),
        Some(aws_ciphertext.as_str())
    );
    sqlx::query("DELETE FROM notification_service.webhook_endpoints WHERE id=$1 OR id=$2")
        .bind(vault_id)
        .bind(aws_id)
        .execute(&pool)
        .await
        .unwrap();
}
