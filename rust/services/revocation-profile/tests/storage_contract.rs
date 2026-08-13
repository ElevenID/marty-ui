use marty_revocation_profile::{
    CredentialFormat, NewProfile, PgProfileRepository, ProfileRepository, RedisStatusRepository,
    RevocationProfile, RevocationProfileService, StatusListFormat, StatusRepository,
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires MARTY_TEST_POSTGRES_URL"]
async fn postgres_preserves_the_released_profile_schema() {
    let database_url = std::env::var("MARTY_TEST_POSTGRES_URL").expect("test PostgreSQL URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    install_released_schema(&pool).await;
    let repository = PgProfileRepository::from_pool(pool.clone());
    let id = Uuid::new_v4().to_string();
    let mut profile = RevocationProfile::new("org-storage-a".into(), "profile".into(), None);
    profile.id = id.clone();
    profile.supported_formats = vec![CredentialFormat::SdJwtVc, CredentialFormat::Mdoc];

    repository.save(profile.clone()).await.unwrap();
    let restored = repository.get(&id).await.unwrap().unwrap();
    assert_eq!(restored, profile);
    assert_eq!(
        repository.list("org-storage-a").await.unwrap(),
        [profile.clone()]
    );

    let service = RevocationProfileService::new(
        Arc::new(repository.clone()),
        Arc::new(marty_revocation_profile::InMemoryStatusRepository::default()),
        "https://status.example.test",
    )
    .unwrap();
    let created = service
        .create(NewProfile {
            organization_id: "org-storage-a".into(),
            name: "second".into(),
            description: None,
            issuer_config: None,
            verifier_config: None,
            automation_config: None,
            supported_formats: None,
        })
        .await
        .unwrap();
    assert_eq!(repository.get(&created.id).await.unwrap().unwrap(), created);
    assert!(repository.delete(&id).await.unwrap());
    assert!(repository.get(&id).await.unwrap().is_none());

    sqlx::query(
        "DELETE FROM revocation_profile_service.revocation_profiles WHERE organization_id = $1",
    )
    .bind("org-storage-a")
    .execute(&pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires MARTY_TEST_REDIS_URL"]
async fn redis_allocations_and_mutations_are_atomic_and_python_compatible() {
    let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("test Redis URL");
    let prefix = format!("marty:test:revocation:{}", Uuid::new_v4());
    let repository = RedisStatusRepository::connect(&redis_url)
        .await
        .unwrap()
        .with_key_prefix(prefix);
    let scope = "org-a:profile-a";
    let size = 131_072;

    let mut allocations = Vec::new();
    for _ in 0..64 {
        let repository = repository.clone();
        allocations.push(tokio::spawn(async move {
            repository
                .allocate_index(scope, StatusListFormat::Bitstring, size)
                .await
                .unwrap()
        }));
    }
    let mut indices = Vec::new();
    for allocation in allocations {
        indices.push(allocation.await.unwrap());
    }
    indices.sort_unstable();
    assert_eq!(indices, (0..64).collect::<Vec<_>>());

    for index in 0..16 {
        repository
            .set_status(scope, StatusListFormat::Bitstring, size, index, 1)
            .await
            .unwrap();
    }
    let restored = repository
        .get_or_create(scope, StatusListFormat::Bitstring, size)
        .await
        .unwrap();
    for index in 0..16 {
        assert_eq!(restored.get(index).unwrap(), 1);
    }
    assert_eq!(restored.version, 16);
    assert!(restored.encoded_list().unwrap().starts_with('u'));

    assert!(repository
        .get_or_create(scope, StatusListFormat::Bitstring, size + 1)
        .await
        .is_err());
}

async fn install_released_schema(pool: &PgPool) {
    let mut transaction = pool.begin().await.unwrap();
    // PostgreSQL's CREATE SCHEMA IF NOT EXISTS can still race when separate
    // integration tests initialize the same schema concurrently. Serialize
    // only this test DDL; the storage contracts themselves remain parallel.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('revocation_profile_service')::bigint)")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("CREATE SCHEMA IF NOT EXISTS revocation_profile_service")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS revocation_profile_service.revocation_profiles (
            id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            issuer_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            verifier_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            automation_config JSONB NOT NULL DEFAULT '{}'::jsonb,
            supported_formats JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}
