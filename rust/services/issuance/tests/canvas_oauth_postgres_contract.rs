use chrono::{Duration, Utc};
use marty_issuance_service::{
    canvas_oauth::{
        CanvasOAuthAuthorization, CanvasOAuthConnection, CanvasOAuthPlatformPatch,
        CanvasOAuthRepository, CanvasOAuthSecretVault,
    },
    canvas_oauth_postgres::{PostgresCanvasOAuthRepository, PostgresIntegrationSecretVault},
    integration_secret::{IntegrationSecretCipher, NewIntegrationSecret},
};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

const MASTER_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn database_url() -> Option<String> {
    std::env::var("MARTY_ISSUANCE_POSTGRES_CONTRACT_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[tokio::test]
async fn oauth_state_secrets_publication_and_revocation_are_atomic_and_tenant_bound() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping Canvas OAuth PostgreSQL contract without database URL");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("issuance PostgreSQL contract database must connect");
    setup_schema(&pool).await;
    seed_platform(&pool).await;
    let repository = PostgresCanvasOAuthRepository::new(pool.clone());
    let vault = PostgresIntegrationSecretVault::new(
        pool.clone(),
        IntegrationSecretCipher::from_base64(MASTER_KEY).expect("cipher"),
    );

    vault
        .save(NewIntegrationSecret {
            id: "client-secret-1".to_owned(),
            organization_id: "org-1".to_owned(),
            name: "Canvas client secret".to_owned(),
            provider: "canvas".to_owned(),
            purpose: "oauth_client_secret".to_owned(),
            value: "plaintext-client-secret".to_owned(),
            metadata: json!({"owner": "admin"}),
        })
        .await
        .expect("save client secret");
    let encrypted: String = sqlx::query_scalar(
        "SELECT encrypted_secret_value
         FROM issuance_service.organization_integration_secrets
         WHERE id = 'client-secret-1'",
    )
    .fetch_one(&pool)
    .await
    .expect("encrypted value");
    assert!(!encrypted.contains("plaintext-client-secret"));
    assert_eq!(
        vault.value("org-1", "client-secret-1").await.unwrap(),
        Some("plaintext-client-secret".to_owned())
    );
    assert_eq!(
        vault.value("org-other", "client-secret-1").await.unwrap(),
        None
    );
    assert!(vault
        .metadata("org-other", "client-secret-1")
        .await
        .unwrap()
        .is_none());
    vault
        .delete("org-other", "client-secret-1")
        .await
        .expect("foreign delete is a tenant-bound no-op");
    assert_eq!(
        vault.value("org-1", "client-secret-1").await.unwrap(),
        Some("plaintext-client-secret".to_owned())
    );

    let now = Utc::now();
    let authorization = CanvasOAuthAuthorization {
        id: "authorization-1".to_owned(),
        organization_id: "org-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        canvas_base_url: "https://canvas.example.edu".to_owned(),
        platform_config_version: 3,
        client_id: "canvas-client".to_owned(),
        client_secret_ref: "org_secret://org-1/client-secret-1".to_owned(),
        state_hash: "a".repeat(64),
        capabilities: vec!["catalog".to_owned()],
        scopes: vec!["url:GET|/api/v1/courses".to_owned()],
        redirect_uri: "https://issuer.example.edu/v1/integrations/canvas/oauth/callback".to_owned(),
        expires_at: now + Duration::minutes(10),
        created_at: now,
    };
    repository
        .save_authorization(&authorization)
        .await
        .expect("save authorization");
    assert_eq!(
        repository
            .consume_authorization(&authorization.state_hash, now)
            .await
            .unwrap(),
        Some(authorization.clone())
    );
    assert_eq!(
        repository
            .consume_authorization(&authorization.state_hash, now)
            .await
            .unwrap(),
        None
    );

    assert!(repository
        .patch_platform(
            "org-1",
            "platform-1",
            3,
            CanvasOAuthPlatformPatch::AuthorizationPending {
                client_id: "canvas-client".to_owned(),
                authorization_id: "authorization-1".to_owned(),
            },
        )
        .await
        .unwrap());
    let config: Value = sqlx::query_scalar(
        "SELECT connection_config FROM issuance_service.canvas_platforms
         WHERE id = 'platform-1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(config["unrelated"], "preserved");
    assert_eq!(config["oauth_status"], "authorization_pending");

    vault
        .save(NewIntegrationSecret {
            id: "access-1".to_owned(),
            organization_id: "org-1".to_owned(),
            name: "Canvas OAuth access token - platform-1".to_owned(),
            provider: "canvas".to_owned(),
            purpose: "oauth_access_token".to_owned(),
            value: "access-token".to_owned(),
            metadata: json!({"platform_id": "platform-1"}),
        })
        .await
        .unwrap();
    let connection = CanvasOAuthConnection {
        id: "connection-1".to_owned(),
        organization_id: "org-1".to_owned(),
        platform_id: "platform-1".to_owned(),
        canvas_base_url: "https://canvas.example.edu".to_owned(),
        platform_config_version: 3,
        client_id: "canvas-client".to_owned(),
        client_secret_ref: "org_secret://org-1/client-secret-1".to_owned(),
        capabilities: vec!["catalog".to_owned()],
        scopes: vec!["url:GET|/api/v1/courses".to_owned()],
        access_token_secret_ref: Some("org_secret://org-1/access-1".to_owned()),
        refresh_token_secret_ref: None,
        token_expires_at: Some(now + Duration::hours(1)),
        status: "connected".to_owned(),
        revoke_retry_count: 0,
        updated_at: now,
    };
    let published_at = repository
        .publish_connection(&connection)
        .await
        .unwrap()
        .expect("connection published");
    assert_eq!(
        repository.publish_connection(&connection).await.unwrap(),
        None
    );
    sqlx::query(
        "UPDATE issuance_service.canvas_platforms SET config_version = 4
         WHERE id = 'platform-1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let stale = CanvasOAuthConnection {
        id: "connection-stale".to_owned(),
        platform_id: "platform-2".to_owned(),
        ..connection.clone()
    };
    assert_eq!(repository.publish_connection(&stale).await.unwrap(), None);
    sqlx::query(
        "UPDATE issuance_service.canvas_platforms SET config_version = 3
         WHERE id = 'platform-1'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let leased = repository
        .begin_revocation("org-1", "platform-1", published_at, "lease-1", 60)
        .await
        .unwrap()
        .expect("revocation lease");
    assert_eq!(leased.status, "revocation_pending");
    assert!(repository
        .reschedule_revocation(
            "org-1",
            "platform-1",
            "lease-1",
            now + Duration::minutes(1),
            "canvas_oauth_revoke_failed",
        )
        .await
        .unwrap());
    let retried = repository
        .connection("org-1", "platform-1")
        .await
        .unwrap()
        .expect("retry connection");
    assert_eq!(retried.revoke_retry_count, 1);
    let leased_again = repository
        .begin_revocation("org-1", "platform-1", retried.updated_at, "lease-2", 60)
        .await
        .unwrap()
        .expect("second lease");
    assert_eq!(leased_again.status, "revocation_pending");
    assert!(repository
        .complete_revocation("org-1", "platform-1", "lease-2", &["access-1".to_owned()],)
        .await
        .unwrap());
    assert_eq!(
        repository.connection("org-1", "platform-1").await.unwrap(),
        None
    );
    assert_eq!(vault.value("org-1", "access-1").await.unwrap(), None);
    assert_eq!(
        vault.value("org-1", "client-secret-1").await.unwrap(),
        Some("plaintext-client-secret".to_owned())
    );
}

async fn setup_schema(pool: &sqlx::PgPool) {
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA issuance_service")
        .execute(pool)
        .await
        .unwrap();
    for statement in [
        "CREATE TABLE issuance_service.canvas_platforms (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            canvas_base_url text,
            config_version integer NOT NULL,
            connection_config jsonb NOT NULL DEFAULT '{}'::jsonb,
            last_validated_at timestamptz,
            last_connection_error text,
            archived_at timestamptz,
            updated_at timestamptz NOT NULL DEFAULT clock_timestamp())",
        "CREATE TABLE issuance_service.organization_integration_secrets (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            name varchar(255) NOT NULL,
            provider varchar(80) NOT NULL,
            purpose varchar(80) NOT NULL,
            encrypted_secret_value text NOT NULL,
            secret_hint varchar(80),
            metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
            enabled boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL,
            last_used_at timestamptz,
            UNIQUE (organization_id, provider, name))",
        "CREATE TABLE issuance_service.canvas_oauth_authorizations (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            canvas_base_url text NOT NULL,
            platform_config_version integer NOT NULL,
            client_id text NOT NULL,
            client_secret_ref text NOT NULL,
            state_hash varchar(64) NOT NULL UNIQUE,
            capabilities jsonb NOT NULL,
            scopes jsonb NOT NULL,
            redirect_uri text NOT NULL,
            expires_at timestamptz NOT NULL,
            consumed_at timestamptz,
            created_at timestamptz NOT NULL)",
        "CREATE TABLE issuance_service.canvas_oauth_connections (
            id text PRIMARY KEY,
            organization_id text NOT NULL,
            platform_id text NOT NULL REFERENCES issuance_service.canvas_platforms(id),
            canvas_base_url text NOT NULL,
            platform_config_version integer NOT NULL,
            client_id text NOT NULL,
            client_secret_ref text NOT NULL,
            capabilities jsonb NOT NULL,
            scopes jsonb NOT NULL,
            access_token_secret_ref text,
            refresh_token_secret_ref text,
            token_expires_at timestamptz,
            status varchar(40) NOT NULL,
            reauthorization_required boolean NOT NULL DEFAULT false,
            refresh_lease_owner text,
            refresh_lease_expires_at timestamptz,
            revoke_retry_count integer NOT NULL DEFAULT 0,
            revoke_retry_at timestamptz,
            revoke_last_error_code varchar(120),
            connected_at timestamptz NOT NULL,
            last_refreshed_at timestamptz,
            created_at timestamptz NOT NULL,
            updated_at timestamptz NOT NULL,
            UNIQUE (organization_id, platform_id))",
    ] {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

async fn seed_platform(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO issuance_service.canvas_platforms
         (id, organization_id, canvas_base_url, config_version, connection_config)
         VALUES ('platform-1', 'org-1', 'https://canvas.example.edu', 3,
                 '{\"unrelated\":\"preserved\"}'::jsonb),
                ('platform-2', 'org-1', 'https://canvas.example.edu', 4, '{}'::jsonb)",
    )
    .execute(pool)
    .await
    .unwrap();
}
