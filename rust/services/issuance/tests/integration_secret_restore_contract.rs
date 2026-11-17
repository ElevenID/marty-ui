//! Provider-neutral integration-secret custody and coordinated restore contracts.
//! No provider repository, OAuth state, or connector authority is loaded.
use marty_issuance_service::integration_secret_kms::KmsIntegrationSecretCipher;
use sqlx::{postgres::PgPoolOptions, Row};

#[path = "support/remote_integration_secret.rs"]
mod remote_integration_secret;

const ORGANIZATION: &str = "kms-restore-org";
const SECRET: &str = "kms-restore-secret-1";
const PROVIDER: &str = "external-provider";
const PURPOSE: &str = "api_token";
const PLAINTEXT: &str = "synthetic-remote-recovery-value";

fn current_secret_table_ddl() -> &'static str {
    let baseline = include_str!("../migrations/0000_issuance_service_baseline.sql");
    let declaration = "CREATE TABLE issuance_service.organization_integration_secrets (";
    let body = baseline
        .split_once(declaration)
        .expect("current secret table owner")
        .1;
    let end = body
        .find("\n);")
        .expect("complete current table declaration");
    let start = baseline.len() - body.len() - declaration.len();
    &baseline[start..start + declaration.len() + end + 3]
}

async fn require_bound_envelope(cipher: &KmsIntegrationSecretCipher, stored: &str) {
    assert!(stored.contains("marty.integration-secret-envelope/v1"));
    assert!(!stored.contains(PLAINTEXT));
    assert_eq!(
        cipher
            .decrypt(ORGANIZATION, SECRET, PROVIDER, PURPOSE, stored)
            .await
            .expect("bound remote decrypt"),
        PLAINTEXT
    );
    for (org, secret, provider, purpose) in [
        ("foreign-org", SECRET, PROVIDER, PURPOSE),
        (ORGANIZATION, "foreign-secret", PROVIDER, PURPOSE),
        (ORGANIZATION, SECRET, "foreign-provider", PURPOSE),
        (ORGANIZATION, SECRET, PROVIDER, "foreign-purpose"),
    ] {
        assert!(
            cipher
                .decrypt(org, secret, provider, purpose, stored)
                .await
                .is_err(),
            "a different database-bound identity must never decrypt the envelope"
        );
    }
}

#[tokio::test]
async fn generic_remote_envelope_binds_all_database_identity_fields() {
    let cipher = remote_integration_secret::cipher();
    let stored = cipher
        .encrypt(ORGANIZATION, SECRET, PROVIDER, PURPOSE, PLAINTEXT)
        .await
        .expect("remote synthetic encrypt");
    require_bound_envelope(&cipher, &stored).await;
}

#[test]
fn restore_uses_only_the_current_secret_table_definition() {
    let ddl = current_secret_table_ddl();
    assert!(ddl.starts_with("CREATE TABLE issuance_service.organization_integration_secrets ("));
    assert!(ddl.ends_with("\n);"));
    assert_eq!(ddl.matches("CREATE TABLE").count(), 1);
    assert!(!ddl.contains("canvas"));
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL *_test database and live Signing Keys/OpenBao route"]
async fn integration_secret_coordinated_restore_phase() {
    let phase = std::env::var("MARTY_KMS_RESTORE_PHASE").expect("write or read phase required");
    assert!(matches!(phase.as_str(), "write" | "read"));
    let database_url = std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .expect("disposable PostgreSQL contract database");
    let database = url::Url::parse(&database_url).expect("PostgreSQL URL");
    assert!(matches!(database.scheme(), "postgres" | "postgresql"));
    assert!(
        database.path().trim_start_matches('/').ends_with("_test"),
        "the recovery contract requires a dedicated *_test database"
    );
    // Both are mandatory: the shared fixture must never silently supply a mock.
    std::env::var("MARTY_TEST_SIGNING_KEYS_INTERNAL_URL").expect("live Signing Keys URL required");
    std::env::var("MARTY_TEST_SIGNING_KEYS_INTEGRATION_SECRET_KEY")
        .expect("live dedicated integration-secret key required");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("disposable database must connect");
    let cipher = remote_integration_secret::cipher();
    if phase == "write" {
        sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS issuance_service")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(current_secret_table_ddl())
            .execute(&pool)
            .await
            .unwrap();
        let stored = cipher
            .encrypt(ORGANIZATION, SECRET, PROVIDER, PURPOSE, PLAINTEXT)
            .await
            .expect("live remote secret encrypt");
        sqlx::query(
            "INSERT INTO issuance_service.organization_integration_secrets
            (id, organization_id, name, provider, purpose, encrypted_secret_value)
            VALUES ($1, $2, 'Recovery proof', $3, $4, $5)",
        )
        .bind(SECRET)
        .bind(ORGANIZATION)
        .bind(PROVIDER)
        .bind(PURPOSE)
        .bind(stored)
        .execute(&pool)
        .await
        .expect("opaque envelope write");
    }
    let mut connection = pool.acquire().await.expect("database connection");
    assert_eq!(
        cipher
            .verify_storage(&mut connection)
            .await
            .expect("KMS-only startup verification"),
        1
    );
    drop(connection);
    let row = sqlx::query("SELECT organization_id, id, provider, purpose, encrypted_secret_value
        FROM issuance_service.organization_integration_secrets WHERE organization_id = $1 AND id = $2")
        .bind(ORGANIZATION).bind(SECRET).fetch_one(&pool).await.expect("restored database-bound identity");
    assert_eq!(row.get::<String, _>("organization_id"), ORGANIZATION);
    assert_eq!(row.get::<String, _>("id"), SECRET);
    assert_eq!(row.get::<String, _>("provider"), PROVIDER);
    assert_eq!(row.get::<String, _>("purpose"), PURPOSE);
    require_bound_envelope(&cipher, &row.get::<String, _>("encrypted_secret_value")).await;
    let foreign: Option<String> = sqlx::query_scalar("SELECT encrypted_secret_value
        FROM issuance_service.organization_integration_secrets WHERE organization_id = $1 AND id = $2")
        .bind("foreign-org").bind(SECRET).fetch_optional(&pool).await.expect("tenant-scoped read");
    assert!(foreign.is_none());
}
