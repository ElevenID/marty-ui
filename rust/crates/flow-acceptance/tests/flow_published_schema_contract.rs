#[path = "../../../services/issuance/tests/support/base_runtime_redis.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves Canvas acceptance cases"
)]
mod base_runtime_redis;
#[path = "../../../services/issuance/tests/support/didcomm_gateway_replay.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves Canvas acceptance cases"
)]
mod didcomm_gateway_replay;
#[path = "../../../services/issuance/tests/support/didcomm_native_grpc_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared fixture also serves Canvas acceptance cases"
)]
mod didcomm_native_grpc_fixture;
#[path = "../../../services/issuance/tests/support/issuance_named_peers.rs"]
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
    reason = "shared database fixture also serves Canvas and worker acceptance"
)]
mod canvas_published_database {
    include!("../../../services/issuance/tests/support/canvas_published_database.rs");
}
#[path = "support/flow_admission.rs"]
mod didcomm_admission_recovery;

#[tokio::test]
async fn didcomm_http_admission_recovers_real_keyed_reservation() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Admission recovery requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_admission_recovery::run(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_flow_grpc_provider_preserves_keyed_admission() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Flow gRPC admission requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_admission_recovery::run_flow_grpc(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn flow_native_consumer_preserves_artifacts_retries_and_legacy_physical_http() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Flow consumer composition requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
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
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Actual Flow startup requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start().await.unwrap();
    didcomm_admission_recovery::run_flow_public_startup(&owned.url, redis.url()).await;
    redis.close_verified().unwrap();
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn flow_rendered_settings_select_native_rpc_and_preserve_legacy_http() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Rendered Flow selection requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_admission_recovery::run_flow_rendered(&owned.url).await;
    owned.close_verified().unwrap();
}
