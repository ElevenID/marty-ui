#[path = "support/managed_http_provider_tls.rs"]
mod managed_http_provider_tls;

#[path = "support/base_runtime_redis.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod base_runtime_redis;
#[path = "support/didcomm_gateway_replay.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod didcomm_gateway_replay;
#[path = "../../../acceptance/support/didcomm_native_grpc_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod didcomm_native_grpc_fixture;
#[path = "../../../acceptance/support/issuance_named_peers.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod issuance_named_peers;
#[path = "../../../services/issuance/tests/support/issuance_process.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod issuance_process;
#[allow(
    dead_code,
    reason = "shared fixture also serves other acceptance cases"
)]
mod bounded_fixture_command {
    include!("../../../services/issuance/tests/support/bounded_fixture_command.rs");
}
#[expect(
    dead_code,
    reason = "shared database fixture also serves other platform acceptance"
)]
mod platform_test_database {
    include!("../../../services/issuance/tests/support/platform_test_database.rs");
}
#[path = "support/flow_admission.rs"]
mod didcomm_admission_recovery;

#[tokio::test]
async fn didcomm_http_admission_recovers_real_keyed_reservation() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Admission recovery requires the exact-owned published schema gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    didcomm_admission_recovery::run(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_flow_grpc_provider_preserves_keyed_admission() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Flow gRPC admission requires the exact-owned published schema gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    didcomm_admission_recovery::run_flow_grpc(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Flow consumer composition requires the exact-owned published schema gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    didcomm_admission_recovery::run_flow_consumer(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn flow_rendered_provider_child() {
    if std::env::var("MARTY_FLOW_RENDERED_CHILD").as_deref() != Ok("1") {
        return;
    }
    didcomm_admission_recovery::flow_rendered_child().await;
}

#[tokio::test]
async fn flow_actual_main_boots_rendered_base_and_preserves_public_admission() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Actual Flow startup requires the exact-owned published schema gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start().await.unwrap();
    didcomm_admission_recovery::run_flow_public_startup(&owned.url, redis.url()).await;
    redis.close_verified().unwrap();
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn flow_rendered_settings_select_native_rpc_and_preserve_legacy_http() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Rendered Flow selection requires the exact-owned published schema gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    didcomm_admission_recovery::run_flow_rendered(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn platform_fixture_uses_current_owned_schema_without_provider_objects() {
    if std::env::var("MARTY_PLATFORM_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Current platform schema fixture requires its exact-owned Docker gate");
        return;
    }
    let owned = platform_test_database::PublishedDatabase::start_for_current_issuance()
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&owned.url)
        .await
        .unwrap();
    marty_issuance_service::migration::verify_owned_schema(&pool)
        .await
        .unwrap();
    let retired: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'issuance_service' AND table_name LIKE 'canvas%'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(retired, 0);
    let versions: Vec<String> =
        sqlx::query_scalar("SELECT version FROM issuance_service.rust_schema_migrations")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(versions
        .iter()
        .any(|version| version == "issuance_service_baseline_v2"));
    assert!(!versions
        .iter()
        .any(|version| version == "issuance_service_baseline_v1"));
    pool.close().await;
    owned.close_verified().unwrap();
}

#[test]
fn platform_fixture_recovery_rejects_foreign_topology_before_removal() {
    platform_test_database::assert_recovery_mutations_never_remove_a_foreign_database();
}
