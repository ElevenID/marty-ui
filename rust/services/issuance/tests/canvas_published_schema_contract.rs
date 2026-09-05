use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use tracing::instrument::WithSubscriber;

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
