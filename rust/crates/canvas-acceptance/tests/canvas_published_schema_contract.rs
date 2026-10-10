use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use tracing::instrument::WithSubscriber;

#[path = "../../../services/issuance/tests/support/renewal_reference_fixture.rs"]
mod renewal_reference_fixture;

#[path = "support/owned_cleanup.rs"]
mod owned_cleanup;

#[path = "support/base_runtime_canvas.rs"]
mod base_runtime_canvas;
#[path = "support/base_runtime_container.rs"]
mod base_runtime_container;
#[path = "support/base_runtime_didcomm.rs"]
mod base_runtime_didcomm;
#[path = "support/base_runtime_gateway.rs"]
mod base_runtime_gateway;
#[path = "support/base_runtime_ordinary.rs"]
mod base_runtime_ordinary;
#[path = "support/base_runtime_redis.rs"]
mod base_runtime_redis;
mod bounded_fixture_command {
    include!("../../../services/issuance/tests/support/bounded_fixture_command.rs");
    include!("../../../services/issuance/tests/support/bounded_fixture_command_tests.rs");
}
#[path = "../../../services/issuance/tests/support/envoy_runtime.rs"]
mod envoy_runtime;
#[path = "../../../services/issuance/tests/support/envoy_runtime_sidecar.rs"]
mod envoy_runtime_sidecar;
#[path = "../../../services/issuance/tests/support/issuance_named_peers.rs"]
mod issuance_named_peers;
#[path = "support/rendered_base_process.rs"]
mod rendered_base_process;
#[path = "support/renewal_binding_postgres.rs"]
mod renewal_binding_postgres;
#[path = "support/renewal_fresh_main.rs"]
mod renewal_fresh_main;
#[path = "support/renewal_gateway_replay.rs"]
mod renewal_gateway_replay;
#[path = "support/renewal_main_replay.rs"]
mod renewal_main_replay;
#[path = "support/resolved_kubernetes_runtime.rs"]
mod resolved_kubernetes_runtime;
#[path = "support/resolved_runtime.rs"]
mod resolved_runtime;
#[path = "support/runtime_failure_diagnostics.rs"]
mod runtime_failure_diagnostics;

#[test]
fn composition_source_root_matches_acceptance_package_root() {
    let root = canvas_published_database::repository_root();
    assert_eq!(base_runtime_container::lexical_source_root().unwrap(), root);
    for package in [
        "rust/services/issuance",
        "rust/crates/canvas-acceptance",
        "rust/crates/flow-acceptance",
    ] {
        assert_eq!(
            canvas_published_database::repository_root_from(&root.join(package)),
            Some(root.as_path()),
        );
        let packaged_root = root.join("unmounted-checkout");
        let packaged_manifest = packaged_root.join(package);
        assert_eq!(
            canvas_published_database::repository_root_from(&packaged_manifest),
            Some(packaged_root.as_path()),
        );
    }
    assert!(
        canvas_published_database::repository_root_from(&root.join("rust/crates/other")).is_none()
    );
}

#[tokio::test]
async fn kubernetes_profile_gateway_composition_isolated() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Kubernetes resolved executable composition requires the owned Linux gate");
        return;
    }
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "Kubernetes gateway acceptance requires Linux artifacts"
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start_in_published_namespace(&owned)
        .await
        .unwrap();
    let result = base_runtime_container::run_kubernetes(&owned, &redis).await;
    let result = base_runtime_container::retain_failure(result, redis.close_verified());
    base_runtime_container::retain_failure(result, owned.close_verified()).unwrap();
}

#[tokio::test]
async fn kubernetes_profile_gateway_composition_child() {
    if std::env::var("MARTY_KUBERNETES_RUNTIME_CHILD").as_deref() != Ok("1") {
        eprintln!("Kubernetes inner test requires the owned prepared-model namespace");
        return;
    }
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    renewal_fresh_main::run_kubernetes(
        "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        "redis://127.0.0.1:6379",
        true,
    )
    .await;
    println!("\nMARTY_BASE_COMPOSITION_COMPLETE_V1");
}

#[tokio::test]
async fn kubernetes_resolved_native_profile_delivers_both_encryption_modes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Kubernetes native-only profile requires configured owned fixtures");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start().await.unwrap();
    renewal_fresh_main::run_kubernetes(&owned.url, redis.url(), false).await;
    let result = redis.close_verified();
    base_runtime_container::retain_failure(result, owned.close_verified()).unwrap();
}

#[tokio::test]
async fn base_profile_envoy_composition_isolated() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Envoy composition requires the configured owned Linux gate");
        return;
    }
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "Actual Envoy composition cannot be qualified with Windows executables"
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start_in_published_namespace(&owned)
        .await
        .unwrap();
    let result = base_runtime_container::run_envoy(
        &owned,
        &redis,
        &base_runtime_container::source_assets().unwrap(),
    )
    .await;
    redis.close_verified().unwrap();
    owned.close_verified().unwrap();
    result.unwrap();
}

#[tokio::test]
async fn envoy_actual_image_validates_candidate() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Actual Envoy configuration requires the configured owned Docker gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let result = async {
        let mut baseline = envoy_runtime_sidecar::OwnedEnvoy::start_baseline(&owned).await?;
        match envoy_runtime_sidecar::OwnedEnvoy::start(&owned).await {
            Ok(mut candidate) => base_runtime_container::retain_failure(
                candidate.close_verified(),
                baseline.close_verified(),
            ),
            Err(error) => {
                base_runtime_container::retain_failure(Err(error), baseline.close_verified())
            }
        }
    }
    .await;
    base_runtime_container::retain_failure(result, owned.close_verified())
        .expect("Actual baseline/candidate Envoy image validation and cleanup");
}

#[tokio::test]
async fn base_profile_envoy_composition_child() {
    if std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref() != Ok("1") {
        eprintln!("Inner Envoy composition is invoked only by the exact-owned namespace container");
        return;
    }
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    renewal_fresh_main::run_envoy(
        "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        "redis://127.0.0.1:6379",
    )
    .await;
    println!("\nMARTY_BASE_COMPOSITION_COMPLETE_V1");
}

#[tokio::test]
async fn base_profile_gateway_composition_isolated() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Base executable composition requires the configured owned Linux gate");
        return;
    }
    assert_eq!(
        std::env::consts::OS,
        "linux",
        "required isolated composition cannot be qualified with Windows artifacts"
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    base_runtime_redis::OwnedRedis::assert_constructor_timeout_cleanup(&owned)
        .await
        .unwrap();
    let redis = base_runtime_redis::OwnedRedis::start_in_published_namespace(&owned)
        .await
        .unwrap();
    let result = base_runtime_container::run(
        &owned,
        &redis,
        &base_runtime_container::source_assets().unwrap(),
    )
    .await;
    redis.close_verified().unwrap();
    owned.close_verified().unwrap();
    result.unwrap();
}

#[tokio::test]
async fn base_profile_gateway_composition_child() {
    if std::env::var("MARTY_BASE_RUNTIME_CHILD").as_deref() != Ok("1") {
        eprintln!("Inner composition is invoked only by the exact-owned namespace container");
        return;
    }
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let _ = rendered_base_process::require_explicit_python();
    renewal_fresh_main::run_gateway(
        "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        "redis://127.0.0.1:6379",
    )
    .await;
    println!("\nMARTY_BASE_COMPOSITION_COMPLETE_V1");
}

#[tokio::test]
async fn base_profile_native_renewal_uses_actual_rendered_configuration() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Rendered base native process requires the exact-owned published schema gate");
        return;
    }
    let _ = rendered_base_process::require_explicit_python();
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    base_runtime_redis::OwnedRedis::assert_constructor_timeout_cleanup(&owned)
        .await
        .unwrap();
    let namespace_redis = base_runtime_redis::OwnedRedis::start_in_published_namespace(&owned)
        .await
        .unwrap();
    namespace_redis.verify_published_namespace(&owned).unwrap();
    namespace_redis.close_verified().unwrap();
    let redis = base_runtime_redis::OwnedRedis::start().await.unwrap();
    renewal_fresh_main::run_rendered(&owned.url, redis.url()).await;
    redis.close_verified().unwrap();
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_renewal_canvas_preserves_real_association_and_delivery_phases() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Canvas renewal requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_renewal_canvas(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn renewal_fresh_packaged_main_delivers_both_encryption_modes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Fresh renewal packaged main requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    renewal_fresh_main::run(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn renewal_packaged_main_recovers_historical_keyed_offer() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Renewal packaged main requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    renewal_main_replay::run(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_renewal_gateway_selects_native_with_required_owner_read() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Renewal gateway requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_renewal_gateway(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn renewal_postgres_binding_and_same_successor_recovery_are_fenced() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Renewal binding/recovery requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    renewal_binding_postgres::run(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_renewal_http_composes_real_delivery_and_renewal_links() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Renewal delivery requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_renewal_http(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_renewal_private_ip_refusal_preserves_published_rows() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Renewal private-IP refusal requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_renewal_private_ip_refusal(&owned.url).await;
    owned.close_verified().unwrap();
    println!("\nDIDCOMM_RENEWAL_PRIVATE_IP_PG_REFUSAL_COMPLETE_V1");
}

#[path = "../../../services/issuance/tests/support/didcomm_native_grpc_fixture.rs"]
#[allow(dead_code, reason = "shared fixture also serves Flow acceptance cases")]
mod didcomm_native_grpc_fixture;

#[tokio::test]
async fn didcomm_unkeyed_grpc_initiation_composes_real_delivery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Unkeyed native RPC delivery requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_fresh_grpc(&owned.url).await;
    owned.close_verified().unwrap();
}

#[path = "../../../services/issuance/tests/support/didcomm_wallet_fixture.rs"]
mod didcomm_wallet_fixture;

#[path = "../../../services/issuance/tests/support/didcomm_test_fixtures.rs"]
mod didcomm_test_fixtures;

#[path = "support/didcomm_composed_delivery.rs"]
mod didcomm_composed_delivery;

#[tokio::test]
async fn didcomm_historical_keyed_http_recovers_before_fresh_admission_guard() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Historical DIDComm recovery requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_historical_http(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_fresh_gateway_admission_preserves_public_projection_without_legacy_fallback() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Gateway admission requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_fresh_gateway(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_fresh_http_admission_composes_reservation_and_delivery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Fresh DIDComm HTTP admission requires the exact-owned published schema gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_fresh_http(&owned.url).await;
    owned.close_verified().unwrap();
}

#[path = "support/didcomm_gateway_replay.rs"]
mod didcomm_gateway_replay;

#[path = "../../../services/issuance/tests/support/didcomm_tls_transport_contract.rs"]
mod didcomm_tls_transport_contract;

#[tokio::test]
async fn didcomm_transport_reloads_valid_ca_bundles_without_disabling_tls() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("DIDComm trust rotation requires the explicit owned fixture gate");
        return;
    }
    didcomm_tls_transport_contract::run().await;
}

#[tokio::test]
async fn didcomm_gateway_candidate_preserves_real_delivery_without_legacy_fallback() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("DIDComm gateway test requires the explicit owned Docker gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    didcomm_composed_delivery::run_gateway(&owned.url).await;
    owned.close_verified().unwrap();
}

#[tokio::test]
async fn didcomm_native_composes_crypto_https_and_published_durability() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("DIDComm composed test requires the explicit owned Docker gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .expect("start exact-owned published-schema DIDComm database");
    didcomm_composed_delivery::run(&owned.url).await;
    owned
        .close_verified()
        .expect("verify exact-owned database cleanup");
}

#[path = "../../../services/issuance/tests/support/canvas_json_depth_replay.rs"]
mod canvas_json_depth_replay;
#[path = "../../../services/issuance/tests/support/canvas_observation_values.rs"]
mod canvas_observation_values;

#[tokio::test]
async fn status_provider_matches_json_depth_reference() {
    canvas_status_provider_replay::replay_depth().await;
}

#[path = "../../../services/issuance/tests/support/canvas_operations_read_replay.rs"]
mod canvas_operations_read_replay;

#[path = "../../../services/issuance/tests/support/canvas_operations_gateway_replay.rs"]
mod canvas_operations_gateway_replay;

#[tokio::test]
async fn operations_gateway_candidate_preserves_trusted_actor_and_frozen_routes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_review_recovery()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(300),
        canvas_operations_gateway_replay::run(&pool, &owned.url),
    )
    .await
    .expect("gateway operations replay must not deadlock");
    pool.close().await;
    owned.close().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_gateway_lifecycle_replay.rs"]
mod canvas_gateway_lifecycle_replay;

#[tokio::test]
async fn operations_gateway_candidate_preserves_review_lifecycle() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(300),
        canvas_gateway_lifecycle_replay::run(&pool, &owned.url),
    )
    .await
    .expect("gateway lifecycle replay must not deadlock");
    pool.close().await;
    owned.close().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_status_provider_replay.rs"]
mod canvas_status_provider_replay;

#[path = "../../../services/issuance/tests/support/canvas_status_runtime_contract.rs"]
mod canvas_status_runtime_contract;
#[path = "../../../services/issuance/tests/support/issuance_process.rs"]
mod issuance_process;

#[tokio::test]
async fn validation_boundary_matches_published_http() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_validation_boundary()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-validation-boundary-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[tokio::test]
async fn utf7_consumer_diagnostic_matches_published_boundaries() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    // Freeze actual application, full credential-route and delivery persistence
    // behavior. This is not native UTF-7 body adoption qualification.
    let owned = canvas_published_database::PublishedDatabase::start_with_utf7_consumer()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-utf7-consumer-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[tokio::test]
async fn json_consumer_diagnostic_matches_published_boundaries() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    // Frozen published app/provider/database evidence, not native JSON adoption.
    let owned = canvas_published_database::PublishedDatabase::start_with_json_consumer()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-json-consumer-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[tokio::test]
async fn json_depth_diagnostic_matches_published_boundaries() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    // Independent published consumer-depth evidence, not native depth parity.
    let owned = canvas_published_database::PublishedDatabase::start_with_json_depth()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-json-depth-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[tokio::test]
async fn timeout_consumer_matches_published_socket_behavior() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_timeout_consumer()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-timeout-consumer-oracle.json"
    ))
    .unwrap();
    // Capture installed published versions; local versions are provenance, not
    // an invented constraint on the immutable published image's dependencies.
    eprintln!("Published timeout consumer runtime: {}", oracle["runtime"]);
    for key in [
        "source_sha256",
        "response_source_sha256",
        "boundary",
        "cases",
    ] {
        assert_eq!(oracle[key], expected[key], "published timeout {key}");
    }
    let codecs: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-single-byte-codecs.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["single_byte_codecs"], codecs,
        "published single-byte codec mappings and aliases"
    );
    let unicode: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-unicode-text-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["unicode_text_codecs"], unicode,
        "published Unicode text and excerpt behavior"
    );
    let headers: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-charset-headers-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["charset_headers"], headers,
        "published charset header behavior and registry aliases"
    );
    let multibyte_sources = [
        (
            "big5",
            include_str!("../../../../contracts/canvas-multibyte-codecs/big5.json"),
        ),
        (
            "big5hkscs",
            include_str!("../../../../contracts/canvas-multibyte-codecs/big5hkscs.json"),
        ),
        (
            "cp932",
            include_str!("../../../../contracts/canvas-multibyte-codecs/cp932.json"),
        ),
        (
            "cp949",
            include_str!("../../../../contracts/canvas-multibyte-codecs/cp949.json"),
        ),
        (
            "cp950",
            include_str!("../../../../contracts/canvas-multibyte-codecs/cp950.json"),
        ),
        (
            "gb2312",
            include_str!("../../../../contracts/canvas-multibyte-codecs/gb2312.json"),
        ),
        (
            "gbk",
            include_str!("../../../../contracts/canvas-multibyte-codecs/gbk.json"),
        ),
        (
            "johab",
            include_str!("../../../../contracts/canvas-multibyte-codecs/johab.json"),
        ),
        (
            "shift_jis",
            include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jis.json"),
        ),
        (
            "shift_jis_2004",
            include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jis_2004.json"),
        ),
        (
            "shift_jisx0213",
            include_str!("../../../../contracts/canvas-multibyte-codecs/shift_jisx0213.json"),
        ),
        (
            "euc_jp",
            include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jp.json"),
        ),
        (
            "euc_jis_2004",
            include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jis_2004.json"),
        ),
        (
            "euc_jisx0213",
            include_str!("../../../../contracts/canvas-multibyte-codecs/euc_jisx0213.json"),
        ),
        (
            "hz",
            include_str!("../../../../contracts/canvas-multibyte-codecs/hz.json"),
        ),
    ];
    let multibyte: serde_json::Map<String, serde_json::Value> = multibyte_sources
        .into_iter()
        .map(|(name, source)| (name.to_owned(), serde_json::from_str(source).unwrap()))
        .collect();
    assert_eq!(
        oracle["multibyte_codecs"],
        serde_json::Value::Object(multibyte),
        "published multibyte machines and independent decoder observations"
    );
    let gb18030: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-gb18030-codec.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["gb18030_codec"], gb18030,
        "published GB18030 mappings and independent observations"
    );
    let euc_kr: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-euc-kr-codec.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["euc_kr_codec"], euc_kr,
        "published EUC-KR mappings and independent observations"
    );
    let ordinals: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-charset-ordinal-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        oracle["charset_ordinals"], ordinals,
        "published continuation ordinal limits and consumer bypasses"
    );
    let utf7: serde_json::Value =
        serde_json::from_str(include_str!("../../../../contracts/canvas-utf7-codec.json")).unwrap();
    assert_eq!(
        oracle["utf7_codec"], utf7,
        "published UTF-7 codepoints, strict errors and labels"
    );
    let iso2022: serde_json::Map<String, serde_json::Value> = [
        (
            "iso2022_kr",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_kr.json"),
        ),
        (
            "iso2022_jp",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp.json"),
        ),
        (
            "iso2022_jp_1",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_1.json"),
        ),
        (
            "iso2022_jp_2",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_2.json"),
        ),
        (
            "iso2022_jp_2004",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_2004.json"),
        ),
        (
            "iso2022_jp_3",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_3.json"),
        ),
        (
            "iso2022_jp_ext",
            include_str!("../../../../contracts/canvas-iso2022-codecs/iso2022_jp_ext.json"),
        ),
    ]
    .into_iter()
    .map(|(name, source)| (name.to_owned(), serde_json::from_str(source).unwrap()))
    .collect();
    assert_eq!(
        oracle["iso2022_codecs"],
        serde_json::Value::Object(iso2022),
        "published ISO-2022 mappings and state/escape outcomes"
    );
    eprintln!("PUBLISHED_TIMEOUT_CONSUMER_COMPLETE_V1");
}

#[tokio::test]
async fn provider_configuration_matches_published_helpers() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let oracle = canvas_published_database::provider_configuration_image_oracle()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-provider-configuration-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[test]
fn provider_configuration_image_owner_rejects_isolation_and_mount_drift() {
    let id = "a".repeat(64);
    let scope = "12345678-1234-4234-8234-123456789abc";
    let image = "synthetic.invalid/issuance@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let owner = canvas_published_database::PublishedImageOracle::synthetic(scope, image);
    let mut info = serde_json::json!({
        "Id": id,
        "Config": {
            "Labels": {"com.elevenid.test.canvas-published-schema": scope},
            "Image": image,
            "Entrypoint": ["python"],
            "Cmd": ["-c", canvas_published_database::PROVIDER_ORACLE_COMMAND],
            "Env": ["PYTHONDONTWRITEBYTECODE=1", "TOKEN_HMAC_KEY=synthetic-schema-only-hmac-key"]
        },
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": true,
            "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"],
            "PortBindings": {}
        },
        "NetworkSettings": {"Ports": {}},
        "Mounts": [
            {"Type": "bind", "RW": false, "Source": "/expected/script.py", "Destination": "/verification/scripts/run_canvas_provider_configuration_oracle.py"},
            {"Type": "bind", "RW": false, "Source": "/expected/scenarios.json", "Destination": "/verification/contracts/canvas-provider-configuration-scenarios.json"}
        ]
    });
    owner.checked(&info, &id).unwrap();
    for (pointer, replacement) in [
        ("/Id", serde_json::json!("c".repeat(64))),
        (
            "/Config/Labels/com.elevenid.test.canvas-published-schema",
            serde_json::json!("foreign"),
        ),
        ("/Config/Image", serde_json::json!("other-image")),
        (
            "/Config/Cmd",
            serde_json::json!(["-c", "print('not the oracle')"]),
        ),
        (
            "/Config/Env/0",
            serde_json::json!("PYTHONDONTWRITEBYTECODE=0"),
        ),
        (
            "/HostConfig/NetworkMode",
            serde_json::json!("container:database"),
        ),
        ("/HostConfig/ReadonlyRootfs", serde_json::json!(false)),
        ("/HostConfig/CapDrop", serde_json::json!([])),
        (
            "/HostConfig/PortBindings",
            serde_json::json!({"5432/tcp": []}),
        ),
        (
            "/NetworkSettings/Ports",
            serde_json::json!({"5432/tcp": []}),
        ),
        ("/Mounts/0/RW", serde_json::json!(true)),
        ("/Mounts/0/Source", serde_json::json!("/foreign/script.py")),
        (
            "/Mounts/1/Source",
            serde_json::json!("/foreign/scenarios.json"),
        ),
        (
            "/Mounts/1/Destination",
            serde_json::json!("/verification/foreign"),
        ),
    ] {
        let previous = info.pointer(pointer).unwrap().clone();
        *info.pointer_mut(pointer).unwrap() = replacement;
        assert!(owner.checked(&info, &id).is_err(), "{pointer}");
        *info.pointer_mut(pointer).unwrap() = previous;
    }
}

#[test]
fn provider_configuration_image_reference_rejects_tags_options_and_malformed_digests() {
    let valid = format!(
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:{}",
        "a".repeat(64)
    );
    assert_eq!(
        canvas_published_database::pinned_published_image(&valid).unwrap(),
        valid
    );
    for invalid in [
        "ghcr.io/elevenid/marty-credentials-issuance:latest".to_owned(),
        format!("--privileged@sha256:{}", "a".repeat(64)),
        format!("GHCR.io/elevenid/marty@sha256:{}", "a".repeat(64)),
        format!("ghcr.io/elevenid/marty@sha256:{}", "a".repeat(63)),
        format!("ghcr.io/elevenid/marty@sha256:{}", "A".repeat(64)),
        format!("ghcr.io/elevenid/marty@sha256:{};rm", "a".repeat(64)),
    ] {
        assert!(
            canvas_published_database::pinned_published_image(&invalid).is_err(),
            "invalid image reference was accepted: {invalid}"
        );
    }
}

#[tokio::test]
async fn status_runtime_preserves_credential_and_delivery_effects() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

async fn assert_status_native_seed_matches_published(
    published: &canvas_published_database::PublishedDatabase,
) {
    // The independent oracle remains the only published-behavior capture.
    // Check that its resulting native-test rows can be initialized without
    // replaying the whole provider matrix in every separate database.
    let seeded = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let first = PgPoolOptions::new().connect(&published.url).await.unwrap();
    let second = PgPoolOptions::new().connect(&seeded.url).await.unwrap();
    for (table, query) in [
        (
            "organizations",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM organization_service.organizations t",
        ),
        (
            "application_templates",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.application_templates t",
        ),
        (
            "issued_credentials",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.issued_credentials t",
        ),
        (
            "credential_delivery_records",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.credential_delivery_records t",
        ),
        (
            "canvas_program_bindings",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.canvas_program_bindings t",
        ),
        (
            "canvas_platforms",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.canvas_platforms t",
        ),
        (
            "issuance_transactions",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.issuance_transactions t",
        ),
        (
            "applications",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.applications t",
        ),
        (
            "canvas_learner_identities",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.canvas_learner_identities t",
        ),
        (
            "canvas_evidence_sync_targets",
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id), '[]'::jsonb) FROM issuance_service.canvas_evidence_sync_targets t",
        ),
    ] {
        let mut left: serde_json::Value = sqlx::query_scalar(query)
            .fetch_one(&first)
            .await
            .unwrap();
        let mut right: serde_json::Value = sqlx::query_scalar(query)
            .fetch_one(&second)
            .await
            .unwrap();
        for rows in [&mut left, &mut right] {
            for row in rows.as_array_mut().unwrap() {
                for timestamp in [
                    "created_at", "updated_at", "issued_at", "status_updated_at",
                    "activated_at", "expires_at", "submitted_at", "verified_at",
                    "next_run_at",
                ] {
                    row.as_object_mut().unwrap().remove(timestamp);
                }
            }
        }
        assert_eq!(
            left, right,
            "native status seed differs from published {table}"
        );
    }
    first.close().await;
    second.close().await;
    seeded.close().unwrap();
}

#[tokio::test]
async fn status_provider_matches_frozen_protocol() {
    canvas_status_provider_replay::replay(&canvas_status_provider_replay::frozen()).await;
}

#[tokio::test]
async fn status_runtime_composes_review_resolution_with_configured_http() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_review_operations(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_main_process_resolves_reviews_with_real_http_publication_and_mirror() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_review_operations_main(&pool, &owned.url).await;
    pool.close().await;
    owned.close().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn canvas_mirror_worker_enabled_packaged_main_runs_and_shuts_down_cleanly() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_canvas_mirror_automation_main_lifecycle(&pool, &owned.url)
        .await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_preserves_unicode_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_unicode(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_preserves_charset_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_charset(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_provider_matches_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    assert_status_native_seed_matches_published(&owned).await;
    owned.close().unwrap();
    assert_eq!(oracle, canvas_status_provider_replay::frozen());
    canvas_status_provider_replay::replay(&oracle).await;
}

#[tokio::test]
async fn status_runtime_preserves_iso2022_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_iso2022(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_preserves_ordinal_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_ordinal(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_preserves_utf7_label_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_utf7_label(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_matches_utf7_full_credential_routes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    canvas_status_provider_replay::replay_utf7().await;
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_utf7_body(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_provider_matches_json_consumer_reference() {
    canvas_status_provider_replay::replay_json().await;
}

#[tokio::test]
async fn status_runtime_matches_json_full_credential_routes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_json_body(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_matches_json_depth_full_credential_routes() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_native_seed()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_status_runtime_contract::run_json_depth_body(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn cancelled_pool_release_does_not_wait_for_blocked_query() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect(&owned.url)
        .await
        .unwrap();
    for bounded in [false, true] {
        let release_entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let options = if bounded {
            marty_issuance_service::canvas_sync_worker_lifecycle::worker_pool_options()
        } else {
            let entered = release_entered.clone();
            PgPoolOptions::new().after_release(move |_, _| {
                entered.notify_one();
                Box::pin(async { Ok(true) })
            })
        };
        let pool = options
            .max_connections(1)
            .connect(&owned.url)
            .await
            .unwrap();
        let mut lock = admin.begin().await.unwrap();
        sqlx::query(
            "LOCK TABLE issuance_service.canvas_worker_heartbeats IN ACCESS EXCLUSIVE MODE",
        )
        .execute(&mut *lock)
        .await
        .unwrap();
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            sqlx::query("SELECT * FROM issuance_service.canvas_worker_heartbeats")
                .execute(&task_pool)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query='SELECT * FROM issuance_service.canvas_worker_heartbeats')").fetch_one(&admin).await.unwrap();
                if blocked { break; }
                tokio::task::yield_now().await;
            }
        }).await.expect("owned query must reach actual lock wait");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // Observe the actual release boundary; do not assume a scheduling sleep
        // makes the cancelled connection enter driver validation.
        let settled = if bounded {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while pool.size() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok()
        } else {
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                release_entered.notified(),
            )
            .await
            .is_ok()
        };
        let deadline = if bounded {
            std::time::Duration::from_secs(3)
        } else {
            std::time::Duration::from_millis(200)
        };
        let closed = tokio::time::timeout(deadline, pool.close()).await.is_ok();
        // Always release only this test's lock and settle its pool before asserting.
        lock.rollback().await.unwrap();
        pool.close().await;
        assert!(
            settled,
            "connection release boundary must be observed while the lock is held"
        );
        assert_eq!(
            closed, bounded,
            "default pool negative control versus bounded worker release"
        );
    }
    admin.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn review_lifecycle_matches_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let first = canvas_published_database::PublishedDatabase::start_with_review_lifecycle()
        .await
        .unwrap();
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-review-lifecycle-oracle.json"
    ))
    .unwrap();
    assert_eq!(first.oracle.as_ref().unwrap(), &oracle);
    first.close().unwrap();
    for use_candidate in [false, true] {
        let native = canvas_published_database::PublishedDatabase::start_with_review_recovery()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&native.url)
            .await
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            canvas_review_lifecycle_replay::replay(&pool, &oracle, use_candidate),
        )
        .await
        .expect("lifecycle replay deadline");
        pool.close().await;
        native.close().unwrap();
    }
}

#[path = "../../../services/issuance/tests/support/canvas_review_lifecycle_replay.rs"]
mod canvas_review_lifecycle_replay;

#[tokio::test]
async fn review_inputs_match_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let first = canvas_published_database::PublishedDatabase::start_with_review_inputs()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-review-input-oracle.json"
    ))
    .unwrap();
    assert_eq!(first.oracle.as_ref().unwrap(), &expected);
    first.close().unwrap();
    let second = canvas_published_database::PublishedDatabase::start_with_review_recovery()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&second.url)
        .await
        .unwrap();
    canvas_review_resolution_replay::replay_inputs(&pool, &expected).await;
    pool.close().await;
    second.close().unwrap();
}

#[tokio::test]
async fn operations_resolution_matches_corrected_published_schema() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_operations_recovery()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-operations-recovery-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "corrected published recovery baseline drifted"
    );
    owned.close().unwrap();
    let native = canvas_published_database::PublishedDatabase::start_with_review_recovery()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    let revision: String =
        sqlx::query_scalar("SELECT version_num FROM issuance_service.alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(revision, "canvas_review_recovery_claim");
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        canvas_review_resolution_replay::replay(&pool, &expected),
    )
    .await
    .expect("manual review replay must not deadlock");
    pool.close().await;
    native.close().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_review_resolution_replay.rs"]
mod canvas_review_resolution_replay;

#[path = "../../../services/issuance/tests/support/canvas_base_gateway_recovery.rs"]
mod canvas_base_gateway_recovery;

#[tokio::test]
async fn canvas_base_review_gateway_matches_corrected_published_schema() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let expected = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-operations-recovery-oracle.json"
    ))
    .unwrap();
    let native = canvas_published_database::PublishedDatabase::start_with_review_recovery()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    let revision: String =
        sqlx::query_scalar("SELECT version_num FROM issuance_service.alembic_version")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(revision, "canvas_review_recovery_claim");
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        canvas_review_resolution_replay::replay_gateway(&pool, &expected),
    )
    .await
    .expect("base gateway review replay must not deadlock");
    pool.close().await;
    native.close_verified().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_review_resolution_checks.rs"]
mod canvas_review_resolution_checks;

#[tokio::test]
async fn operations_resolution_fences_and_lifecycle_delegate() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_review_recovery()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        canvas_review_resolution_checks::exercise(&pool),
    )
    .await
    .expect("review invariant checks must not deadlock");
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn enqueue_inputs_match_frozen_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_enqueue_inputs()
        .await
        .unwrap();
    let frozen: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-enqueue-input-oracle.json"
    ))
    .unwrap();
    let mut report = owned.oracle.clone().unwrap();
    let unicode = report.as_object_mut().unwrap().remove("unicode").unwrap();
    let expected_unicode: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/python-text-semantics.json"
    ))
    .unwrap();
    assert_eq!(
        unicode, expected_unicode,
        "published Unicode text rules drifted"
    );
    assert_eq!(report, frozen);
    owned.close().unwrap();
    let native = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    canvas_enqueue_input_replay::replay(&pool, &frozen).await;
    pool.close().await;
    native.close().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_enqueue_input_replay.rs"]
mod canvas_enqueue_input_replay;

#[path = "../../../services/issuance/tests/support/canvas_job_operations_checks.rs"]
mod canvas_job_operations_checks;

#[tokio::test]
async fn operations_jobs_match_frozen_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_operations_read_replay::replay_jobs(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn operations_jobs_are_atomic_and_concurrent() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        canvas_job_operations_checks::exercise(&pool),
    )
    .await
    .expect("job operation checks must not deadlock");
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn operations_reads_match_frozen_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_operations_read_replay::replay(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn operations_inputs_match_frozen_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_operations_inputs()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-operations-input-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "published operations inputs drifted"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_operations_read_replay::replay_inputs(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn operations_match_frozen_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_operations()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-operations-oracle.json"
    ))
    .unwrap();
    assert_eq!(expected["observations"].as_array().unwrap().len(), 46);
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "published operations baseline drifted"
    );
    owned.close().unwrap();
}

#[tokio::test]
async fn heartbeat_readiness_matches_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_heartbeat_readiness()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-heartbeat-readiness-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "published heartbeat oracle drifted"
    );
    owned.close().unwrap();
    let native = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    canvas_heartbeat_readiness_replay::replay(&pool, &expected).await;
    pool.close().await;
    native.close().unwrap();
}

#[path = "../../../services/issuance/tests/support/canvas_heartbeat_readiness_replay.rs"]
mod canvas_heartbeat_readiness_replay;

#[path = "../../../services/issuance/tests/support/canvas_issued_review_replay.rs"]
mod canvas_issued_review_replay;
#[path = "../../../services/issuance/tests/support/canvas_mixed_roster_replay.rs"]
mod canvas_mixed_roster_replay;
#[expect(
    dead_code,
    reason = "shared database fixture has worker-only constructors"
)]
mod canvas_published_database {
    include!("../../../services/issuance/tests/support/canvas_published_database.rs");
    include!(
        "../../../services/issuance/tests/support/canvas_published_database_diagnostic_tests.rs"
    );
}
#[path = "../../../services/issuance/tests/support/canvas_published_processor.rs"]
mod canvas_published_processor;

#[tokio::test]
async fn issued_reviews_match_published_python_without_mutating_credentials() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_issued_reviews()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-issued-review-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "published Python drifted from its frozen observations"
    );
    owned.close().unwrap();
    let native = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    canvas_issued_review_replay::replay(&pool, &expected)
        .with_subscriber(tracing_subscriber::fmt().with_test_writer().finish())
        .await;
    pool.close().await;
    native.close().unwrap();
}

#[tokio::test]
async fn mixed_roster_matches_published_python() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_mixed_roster()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-mixed-roster-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        owned.oracle.as_ref().unwrap(),
        &expected,
        "published Python mixed-roster observations drifted"
    );
    owned.close().unwrap();
    let native = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&native.url)
        .await
        .unwrap();
    canvas_mixed_roster_replay::replay(&pool, &expected)
        .with_subscriber(tracing_subscriber::fmt().with_test_writer().finish())
        .await;
    pool.close().await;
    native.close().unwrap();
}

#[tokio::test]
async fn native_canvas_uses_published_migrations_and_constraints() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        eprintln!("Published-schema test requires its explicit Docker gate");
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    let revisions: Vec<String> =
        sqlx::query_scalar("SELECT version_num FROM issuance_service.alembic_version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(revisions, ["merge_issuance_heads"]);
    let constraints: BTreeSet<String> = sqlx::query_scalar(
        "SELECT c.conname FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace WHERE n.nspname = 'issuance_service'"
    ).fetch_all(&pool).await.unwrap().into_iter().collect();
    for expected in [
        "fk_canvas_sync_jobs_tenant_target",
        "ck_canvas_award_candidates_state",
        "ck_canvas_candidate_observations_revision",
    ] {
        assert!(
            constraints.contains(expected),
            "published constraint missing: {expected}"
        );
    }
    let metadata_type: String = sqlx::query_scalar("SELECT data_type FROM information_schema.columns WHERE table_schema = 'issuance_service' AND table_name = 'canvas_evidence_sync_targets' AND column_name = 'metadata'").fetch_one(&pool).await.unwrap();
    assert_eq!(metadata_type, "json");
    // This subscriber is scoped to synthetic test data, never deployment logs.
    canvas_published_processor::exercise(&pool)
        .with_subscriber(tracing_subscriber::fmt().with_test_writer().finish())
        .await;
    pool.close().await;
    owned.close().unwrap();
}
