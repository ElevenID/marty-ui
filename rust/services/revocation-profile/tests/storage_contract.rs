use marty_revocation_profile::{
    migrate_and_seed, CascadeOperationType, CascadeRevocationOperation, CascadeStatus,
    CredentialFormat, InMemoryStatusRepository, NewProfile, PgProfileRepository,
    PgRevocationOperationRepository, ProfileRepository, RedisStatusRepository, RevocationBatch,
    RevocationOperationRepository, RevocationProfile, RevocationProfileService, ServiceError,
    StatusListFormat, StatusRepository, TriggerEntityType,
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
#[ignore = "requires MARTY_TEST_POSTGRES_URL"]
async fn postgres_status_allocations_are_idempotent_race_safe_and_restart_safe() {
    let database_url = std::env::var("MARTY_TEST_POSTGRES_URL").expect("test PostgreSQL URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let organization_id = format!("org-allocation-{}", Uuid::new_v4());
    migrate_and_seed(&pool, &organization_id, "https://status.example.test")
        .await
        .unwrap();
    let repository = PgProfileRepository::from_pool(pool.clone());
    let profile = RevocationProfile::new(
        organization_id.clone(),
        "idempotent allocation".into(),
        None,
    );
    repository.save(profile.clone()).await.unwrap();
    let service = Arc::new(
        RevocationProfileService::new(
            Arc::new(repository.clone()),
            Arc::new(InMemoryStatusRepository::default()),
            "https://status.example.test",
        )
        .unwrap(),
    );

    let mut retries = Vec::new();
    for _ in 0..64 {
        let service = service.clone();
        let profile_id = profile.id.clone();
        let organization_id = organization_id.clone();
        retries.push(tokio::spawn(async move {
            service
                .reserve_index(
                    &profile_id,
                    &organization_id,
                    "sd_jwt_vc",
                    "credential-postgres-retry",
                )
                .await
                .unwrap()
                .index
        }));
    }
    for retry in retries {
        assert_eq!(retry.await.unwrap(), 0);
    }

    let mut distinct = Vec::new();
    for ordinal in 0..32 {
        let service = service.clone();
        let profile_id = profile.id.clone();
        let organization_id = organization_id.clone();
        distinct.push(tokio::spawn(async move {
            service
                .reserve_index(
                    &profile_id,
                    &organization_id,
                    "sd_jwt_vc",
                    &format!("credential-postgres-{ordinal}"),
                )
                .await
                .unwrap()
                .index
        }));
    }
    let mut indices = Vec::new();
    for allocation in distinct {
        indices.push(allocation.await.unwrap());
    }
    indices.sort_unstable();
    assert_eq!(indices, (1..=32).collect::<Vec<_>>());

    // A fresh service process has no in-memory allocation knowledge. The
    // PostgreSQL reservation must still recover the exact original index.
    let restarted = RevocationProfileService::new(
        Arc::new(repository.clone()),
        Arc::new(InMemoryStatusRepository::default()),
        "https://status.example.test",
    )
    .unwrap();
    assert_eq!(
        restarted
            .reserve_index(
                &profile.id,
                &organization_id,
                "sd_jwt_vc",
                "credential-postgres-retry",
            )
            .await
            .unwrap()
            .index,
        0
    );

    let other_organization_id = format!("org-allocation-other-{}", Uuid::new_v4());
    let other_profile = RevocationProfile::new(
        other_organization_id.clone(),
        "other allocation scope".into(),
        None,
    );
    repository.save(other_profile.clone()).await.unwrap();
    let error = restarted
        .reserve_index(
            &other_profile.id,
            &other_organization_id,
            "sd_jwt_vc",
            "credential-postgres-retry",
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ServiceError::FailedPrecondition(_)));

    repository.delete(&profile.id).await.unwrap();
    let error_after_profile_deletion = restarted
        .reserve_index(
            &other_profile.id,
            &other_organization_id,
            "sd_jwt_vc",
            "credential-postgres-retry",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error_after_profile_deletion,
        ServiceError::FailedPrecondition(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM revocation_profile_service.status_list_allocations
            WHERE credential_id = 'credential-postgres-retry'
            "#,
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    repository.save(profile.clone()).await.unwrap();
    assert_eq!(
        restarted
            .reserve_index(
                &profile.id,
                &organization_id,
                "sd_jwt_vc",
                "credential-after-profile-restore",
            )
            .await
            .unwrap()
            .index,
        33
    );
    repository.delete(&profile.id).await.unwrap();
    repository.delete(&other_profile.id).await.unwrap();
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
    assert_eq!(
        repository
            .allocation_floor(scope, StatusListFormat::Bitstring)
            .await
            .unwrap(),
        64
    );
    repository
        .advance_allocation_floor(scope, StatusListFormat::Bitstring, 80)
        .await
        .unwrap();
    assert_eq!(
        repository
            .allocate_index(scope, StatusListFormat::Bitstring, size)
            .await
            .unwrap(),
        80
    );

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

#[tokio::test]
#[ignore = "requires MARTY_TEST_POSTGRES_URL"]
async fn postgres_preserves_cascade_and_batch_operations() {
    let database_url = std::env::var("MARTY_TEST_POSTGRES_URL").expect("test PostgreSQL URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    install_released_schema(&pool).await;
    install_operation_schema(&pool).await;
    let profiles = PgProfileRepository::from_pool(pool.clone());
    let operations = PgRevocationOperationRepository::from_pool(pool.clone());
    let profile =
        RevocationProfile::new("org-storage-operations".into(), "operations".into(), None);
    profiles.save(profile.clone()).await.unwrap();
    let now =
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let cascade = CascadeRevocationOperation {
        id: Uuid::new_v4().to_string(),
        organization_id: "org-storage-operations".into(),
        operation_type: CascadeOperationType::IssuerRevocation,
        trigger_entity_type: TriggerEntityType::Issuer,
        trigger_entity_id: "issuer-1".into(),
        status: CascadeStatus::PendingConfirmation,
        affected_credential_count: 1,
        affected_credential_ids: vec!["credential-1".into()],
        requires_confirmation: true,
        confirmed_at: None,
        confirmed_by: None,
        max_cascade_depth: 3,
        current_depth: 0,
        circuit_breaker_threshold: 1_000,
        circuit_breaker_triggered: false,
        can_rollback: true,
        rollback_snapshot: Some(serde_json::json!({"credential": "credential-1"})),
        rolled_back_at: None,
        rolled_back_by: None,
        error_message: None,
        metadata: Some(serde_json::json!({"source": "contract"})),
        created_at: now,
        updated_at: now,
        completed_at: None,
    };
    operations.save_cascade(cascade.clone()).await.unwrap();
    assert_eq!(
        operations.get_cascade(&cascade.id).await.unwrap(),
        Some(cascade.clone())
    );
    let batch = RevocationBatch::new(
        "org-storage-operations".into(),
        profile.id.clone(),
        "1h".into(),
        "SD_JWT_VC".into(),
        vec!["credential-1".into()],
    )
    .unwrap();
    operations.save_batch(batch.clone()).await.unwrap();
    assert_eq!(
        operations.get_batch(&batch.id).await.unwrap(),
        Some(batch.clone())
    );
    sqlx::query("DELETE FROM revocation_profile_service.revocation_profiles WHERE id = $1")
        .bind(&profile.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(operations.get_batch(&batch.id).await.unwrap().is_none());
    operations.delete_cascade(&cascade.id).await.unwrap();
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

async fn install_operation_schema(pool: &PgPool) {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS revocation_profile_service.cascade_revocation_operations (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, operation_type TEXT NOT NULL,
            trigger_entity_type TEXT NOT NULL, trigger_entity_id TEXT NOT NULL, status TEXT NOT NULL,
            affected_credential_count BIGINT NOT NULL, affected_credential_ids JSONB NOT NULL,
            requires_confirmation BOOLEAN NOT NULL, confirmed_at TIMESTAMPTZ, confirmed_by TEXT,
            max_cascade_depth SMALLINT NOT NULL, current_depth SMALLINT NOT NULL,
            circuit_breaker_threshold BIGINT NOT NULL, circuit_breaker_triggered BOOLEAN NOT NULL,
            can_rollback BOOLEAN NOT NULL, rollback_snapshot JSONB, rolled_back_at TIMESTAMPTZ,
            rolled_back_by TEXT, error_message TEXT, metadata JSONB, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL, completed_at TIMESTAMPTZ)
    "#).execute(pool).await.unwrap();
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS revocation_profile_service.revocation_batches (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL,
            revocation_profile_id TEXT NOT NULL REFERENCES revocation_profile_service.revocation_profiles(id) ON DELETE CASCADE,
            batch_interval TEXT NOT NULL, credential_format TEXT NOT NULL, credential_ids JSONB NOT NULL,
            status TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, published_at TIMESTAMPTZ)
    "#).execute(pool).await.unwrap();
}
