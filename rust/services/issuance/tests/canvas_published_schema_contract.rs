use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use tracing::instrument::WithSubscriber;

#[path = "support/canvas_operations_read_replay.rs"]
mod canvas_operations_read_replay;

#[path = "support/canvas_status_provider_replay.rs"]
mod canvas_status_provider_replay;

#[path = "support/canvas_status_runtime_contract.rs"]
mod canvas_status_runtime_contract;

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
}

#[tokio::test]
async fn provider_configuration_matches_published_helpers() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_provider_configuration()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    owned.close().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-provider-configuration-oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle, expected);
}

#[tokio::test]
async fn status_runtime_preserves_credential_and_delivery_effects() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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

#[tokio::test]
async fn status_provider_matches_frozen_protocol() {
    canvas_status_provider_replay::replay(&canvas_status_provider_replay::frozen()).await;
}

#[tokio::test]
async fn status_runtime_preserves_unicode_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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
    owned.close().unwrap();
    assert_eq!(oracle, canvas_status_provider_replay::frozen());
    canvas_status_provider_replay::replay(&oracle).await;
}

#[tokio::test]
async fn status_runtime_preserves_iso2022_failures_and_recovery() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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
    let owned = canvas_published_database::PublishedDatabase::start_with_status_provider()
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

#[path = "support/canvas_review_lifecycle_replay.rs"]
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

#[path = "support/canvas_review_resolution_replay.rs"]
mod canvas_review_resolution_replay;

#[path = "support/canvas_review_resolution_checks.rs"]
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

#[path = "support/canvas_enqueue_input_replay.rs"]
mod canvas_enqueue_input_replay;

#[path = "support/canvas_job_operations_checks.rs"]
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

#[path = "support/canvas_heartbeat_readiness_replay.rs"]
mod canvas_heartbeat_readiness_replay;

#[path = "support/canvas_issued_review_replay.rs"]
mod canvas_issued_review_replay;
#[path = "support/canvas_mixed_roster_replay.rs"]
mod canvas_mixed_roster_replay;
#[path = "support/canvas_published_database.rs"]
mod canvas_published_database;
#[path = "support/canvas_published_processor.rs"]
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
