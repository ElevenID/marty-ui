use marty_issuance_service::{
    ephemeral_postgres::PostgresProofNonceRepository,
    proof_nonce::{ProofNonceError, ProofNonceRepository},
};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Row};
use uuid::Uuid;

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn random_nonce() -> String {
    Uuid::new_v4().to_string()
}

#[tokio::test]
async fn proof_nonces_are_digest_only_database_clocked_and_single_use() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping proof nonce PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(12)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS issuance_service")
        .execute(&pool)
        .await
        .expect("issuance schema must be available");
    sqlx::query("DROP TABLE IF EXISTS issuance_service.oid4vci_ephemeral_capabilities")
        .execute(&pool)
        .await
        .expect("stale proof nonce contract table must be removable");
    sqlx::query(
        "CREATE TABLE issuance_service.oid4vci_ephemeral_capabilities (
             purpose varchar(32) NOT NULL,
             key_digest varchar(64) NOT NULL,
             payload jsonb NULL,
             created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
             expires_at timestamptz NOT NULL,
             PRIMARY KEY (purpose, key_digest),
             CONSTRAINT ck_oid4vci_ephemeral_capabilities_purpose
                 CHECK (purpose IN ('par', 'proof_nonce')),
             CONSTRAINT ck_oid4vci_ephemeral_capabilities_payload
                 CHECK ((purpose = 'par' AND payload IS NOT NULL)
                     OR (purpose = 'proof_nonce' AND payload IS NULL))
         )",
    )
    .execute(&pool)
    .await
    .expect("proof nonce contract table must be created");

    let repository = PostgresProofNonceRepository::new(pool.clone());
    let nonce = random_nonce();
    assert!(repository.save_proof_nonce(&nonce, 300).await.unwrap());
    assert!(!repository.save_proof_nonce(&nonce, 300).await.unwrap());
    let row = sqlx::query(
        "SELECT key_digest, payload,
                extract(epoch FROM expires_at - clock_timestamp())::double precision
                    AS remaining_seconds
         FROM issuance_service.oid4vci_ephemeral_capabilities
         WHERE purpose = 'proof_nonce'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let stored_digest: String = row.try_get("key_digest").unwrap();
    let remaining_seconds: f64 = row.try_get("remaining_seconds").unwrap();
    assert_eq!(stored_digest, digest(&nonce));
    assert_ne!(stored_digest, nonce);
    assert!(row
        .try_get::<Option<serde_json::Value>, _>("payload")
        .unwrap()
        .is_none());
    assert!((295.0..=300.0).contains(&remaining_seconds));

    let race_nonce = random_nonce();
    assert!(repository.save_proof_nonce(&race_nonce, 300).await.unwrap());
    let mut contenders = Vec::new();
    for _ in 0..8 {
        let repository = repository.clone();
        let race_nonce = race_nonce.clone();
        contenders.push(tokio::spawn(async move {
            repository.consume_proof_nonce(&race_nonce).await.unwrap()
        }));
    }
    let mut winners = 0;
    for contender in contenders {
        winners += usize::from(contender.await.unwrap());
    }
    assert_eq!(winners, 1);

    let expired_nonce = random_nonce();
    sqlx::query(
        "INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
             (purpose, key_digest, payload, created_at, expires_at)
         VALUES ('proof_nonce', $1, NULL, clock_timestamp() - interval '2 seconds',
                 clock_timestamp() - interval '1 second')",
    )
    .bind(digest(&expired_nonce))
    .execute(&pool)
    .await
    .unwrap();
    assert!(!repository
        .consume_proof_nonce(&expired_nonce)
        .await
        .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities
             WHERE purpose = 'proof_nonce' AND key_digest = $1",
        )
        .bind(digest(&expired_nonce))
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );

    let reusable_nonce = random_nonce();
    sqlx::query(
        "INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
             (purpose, key_digest, payload, created_at, expires_at)
         VALUES ('proof_nonce', $1, NULL, clock_timestamp() - interval '2 seconds',
                 clock_timestamp() - interval '1 second')",
    )
    .bind(digest(&reusable_nonce))
    .execute(&pool)
    .await
    .unwrap();
    assert!(repository
        .save_proof_nonce(&reusable_nonce, 300)
        .await
        .unwrap());
    assert!(repository
        .consume_proof_nonce(&reusable_nonce)
        .await
        .unwrap());

    sqlx::query(
        "INSERT INTO issuance_service.oid4vci_ephemeral_capabilities
             (purpose, key_digest, payload, created_at, expires_at)
         SELECT 'par', lpad(series::text, 64, '0'), '{}'::jsonb,
                clock_timestamp() - interval '2 seconds',
                clock_timestamp() - interval '1 second'
         FROM generate_series(1, 1002) AS series",
    )
    .execute(&pool)
    .await
    .unwrap();
    let cleanup_probe = random_nonce();
    assert!(repository
        .save_proof_nonce(&cleanup_probe, 300)
        .await
        .unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM issuance_service.oid4vci_ephemeral_capabilities
             WHERE expires_at <= clock_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );
    assert!(repository
        .consume_proof_nonce(&cleanup_probe)
        .await
        .unwrap());

    let empty_nonce = String::new();
    assert_eq!(
        repository.save_proof_nonce(&empty_nonce, 300).await,
        Err(ProofNonceError::RepositoryUnavailable)
    );
    let invalid_ttl_nonce = random_nonce();
    assert_eq!(
        repository.save_proof_nonce(&invalid_ttl_nonce, 0).await,
        Err(ProofNonceError::RepositoryUnavailable)
    );
    assert_eq!(
        repository.save_proof_nonce(&invalid_ttl_nonce, 3_601).await,
        Err(ProofNonceError::RepositoryUnavailable)
    );

    sqlx::query("DROP TABLE issuance_service.oid4vci_ephemeral_capabilities")
        .execute(&pool)
        .await
        .expect("proof nonce contract table must be removed");
}
