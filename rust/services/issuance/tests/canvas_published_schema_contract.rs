use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeSet;
use tracing::instrument::WithSubscriber;

#[path = "support/canvas_worker_deadline_replay.rs"]
mod canvas_worker_deadline_replay;

#[path = "support/canvas_worker_output.rs"]
mod canvas_worker_output;

#[path = "support/canvas_worker_timeout_replay.rs"]
mod canvas_worker_timeout_replay;

#[path = "support/canvas_published_borrowed_database.rs"]
mod canvas_published_borrowed_database;

#[tokio::test]
async fn worker_deadline_matches_frozen_published_process() {
    assert_borrowed_worker_cases(
        "test_canvas_worker_deadline_https.py",
        &["early_release", "deadline_cancel"],
        "MARTY_CANVAS_WORKER_DEADLINE_DATABASE",
    )
    .await;
}

#[tokio::test]
async fn worker_timeout_matches_frozen_published_process() {
    assert_borrowed_worker_cases(
        "test_canvas_worker_timeout_https.py",
        &[
            "application_prompt",
            "application_delayed_headers",
            "roster_prompt",
            "roster_delayed_headers",
        ],
        "MARTY_CANVAS_WORKER_TIMEOUT_DATABASE",
    )
    .await;
}

async fn assert_borrowed_worker_cases(script: &str, cases: &[&str], descriptor_environment: &str) {
    assert!(matches!(
        (script, descriptor_environment),
        (
            "test_canvas_worker_deadline_https.py",
            "MARTY_CANVAS_WORKER_DEADLINE_DATABASE"
        ) | (
            "test_canvas_worker_timeout_https.py",
            "MARTY_CANVAS_WORKER_TIMEOUT_DATABASE"
        )
    ));
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("Actual worker process containment requires the mandatory Linux gate");
        return;
    }
    for case in cases {
        // Keep Docker ownership outside the killable inner coordinator. Each
        // case receives a fresh database and only a checked ownership descriptor.
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let descriptor = owned.borrow_descriptor().unwrap();
        assert_worker_https_script_with_environment(
            script,
            &[case],
            &[(descriptor_environment, descriptor.as_str())],
        );
        owned.close_verified().unwrap();
    }
}

#[tokio::test]
async fn worker_deadline_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_DEADLINE_NATIVE_ORIGIN") else {
        return;
    };
    let case = std::env::var("MARTY_CANVAS_WORKER_DEADLINE_CASE").unwrap();
    let (pool, database_url) = borrowed_worker_pool("MARTY_CANVAS_WORKER_DEADLINE_DATABASE").await;
    canvas_worker_deadline_replay::replay(&pool, &database_url, &origin, &case).await;
    pool.close().await;
}

#[tokio::test]
async fn worker_timeout_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_TIMEOUT_NATIVE_ORIGIN") else {
        return;
    };
    let case = std::env::var("MARTY_CANVAS_WORKER_TIMEOUT_CASE").unwrap();
    let (pool, database_url) = borrowed_worker_pool("MARTY_CANVAS_WORKER_TIMEOUT_DATABASE").await;
    canvas_worker_timeout_replay::replay(&pool, &database_url, &origin, &case).await;
    pool.close().await;
}

async fn borrowed_worker_pool(descriptor_environment: &str) -> (sqlx::PgPool, String) {
    assert!(matches!(
        descriptor_environment,
        "MARTY_CANVAS_WORKER_DEADLINE_DATABASE" | "MARTY_CANVAS_WORKER_TIMEOUT_DATABASE"
    ));
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let descriptor = std::env::var(descriptor_environment).unwrap();
    let database_url =
        canvas_published_database::PublishedDatabase::borrowed_url(&descriptor).unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    (pool, database_url)
}

#[tokio::test]
async fn worker_timeout_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let mut observations = Vec::new();
    for case in [
        "application_prompt",
        "application_delayed_headers",
        "roster_prompt",
        "roster_delayed_headers",
    ] {
        let owned = canvas_published_database::PublishedDatabase::start_with_worker_timeout(case)
            .await
            .unwrap();
        observations.push(owned.oracle.as_ref().unwrap().clone());
        owned.close().unwrap();
    }
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-timeout-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::json!({
            "schema": "marty.canvas-worker-timeout-oracle/v1",
            "observations": observations,
        }),
        reference,
    );
}

#[tokio::test]
async fn worker_deadline_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let mut observations = Vec::new();
    for case in ["early_release", "deadline_cancel"] {
        let owned = canvas_published_database::PublishedDatabase::start_with_worker_deadline(case)
            .await
            .unwrap();
        observations.push(owned.oracle.as_ref().unwrap().clone());
        owned.close().unwrap();
    }
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-deadline-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::json!({
            "schema": "marty.canvas-worker-deadline-oracle/v1",
            "observations": observations,
        }),
        reference,
    );
}

#[tokio::test]
async fn worker_dispatch_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let matrix: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-dispatch-scenarios.json"
    ))
    .unwrap();
    let mut observations = Vec::new();
    for case in matrix["cases"].as_array().unwrap() {
        let owned = canvas_published_database::PublishedDatabase::start_with_worker_dispatch(
            case["name"].as_str().unwrap(),
        )
        .await
        .unwrap();
        observations.push(owned.oracle.as_ref().unwrap().clone());
        owned.close().unwrap();
    }
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-dispatch-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        serde_json::json!({
            "schema": "marty.canvas-worker-dispatch-corpus/v1",
            "observations": observations,
        }),
        reference
    );
}

#[path = "support/canvas_worker_effect_expiry.rs"]
mod canvas_worker_effect_expiry;

#[path = "support/canvas_worker_roster_metadata.rs"]
mod canvas_worker_roster_metadata;

#[tokio::test]
async fn worker_roster_metadata_reconciliation_preserves_current_fields_and_fences() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    for case in [
        "absent",
        "preexisting",
        "explicit_null",
        "worker_only",
        "heartbeat_only",
        "stale_target_generation",
        "wrong_owner",
        "wrong_attempt",
        "expired_before_write",
        "expired_during_lock",
    ] {
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&owned.url)
            .await
            .unwrap();
        canvas_worker_roster_metadata::assert_reconciliation(&pool, case).await;
        pool.close().await;
        owned.close().unwrap();
    }
}

#[path = "support/canvas_worker_mixed_roster_replay.rs"]
mod canvas_worker_mixed_roster_replay;

#[test]
fn worker_mixed_roster_matches_frozen_published_process() {
    assert_worker_https_script("test_canvas_worker_mixed_roster_https.py", &[]);
}

#[tokio::test]
async fn worker_mixed_roster_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_MIXED_ROSTER_NATIVE_ORIGIN") else {
        return;
    };
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let signer_origin = std::env::var("MARTY_CANVAS_WORKER_MIXED_ROSTER_SIGNER_ORIGIN").unwrap();
    let case = std::env::var("MARTY_CANVAS_WORKER_MIXED_ROSTER_CASE").unwrap();
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_mixed_roster_replay::replay(&pool, &owned.url, &origin, &signer_origin, &case)
        .await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_mixed_roster_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_mixed_roster(
        "mixed_candidates_resume_wrap",
    )
    .await
    .unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-mixed-roster-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &reference);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_effect_transaction_obeys_real_database_lease_expiry() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    for expire_before_commit in [false, true] {
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&owned.url)
            .await
            .unwrap();
        canvas_worker_effect_expiry::run(&pool, &owned.url, expire_before_commit).await;
        pool.close().await;
        owned.close().unwrap();
    }
}

#[test]
fn worker_provider_recovery_first_preserves_terminal_winner() {
    assert_worker_provider_https("recovery_first");
}

#[tokio::test]
async fn worker_provider_recovery_first_native_child() {
    worker_provider_child("recovery_first").await;
}

#[tokio::test]
async fn worker_provider_recovery_first_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned =
        canvas_published_database::PublishedDatabase::start_with_worker_provider_recovery_first()
            .await
            .unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-recovery-first-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &reference);
    owned.close().unwrap();
}

#[path = "support/canvas_worker_provider_completion_replay.rs"]
mod canvas_worker_provider_completion_replay;

#[test]
fn worker_provider_completion_preserves_atomic_terminal_winner() {
    assert_worker_provider_https("completion");
}

#[tokio::test]
async fn worker_provider_completion_native_child() {
    worker_provider_child("completion").await;
}

#[tokio::test]
async fn worker_provider_completion_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned =
        canvas_published_database::PublishedDatabase::start_with_worker_provider_completion()
            .await
            .unwrap();
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-completion-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &reference);
    owned.close().unwrap();
}

#[path = "support/canvas_worker_final_completion_race.rs"]
mod canvas_worker_final_completion_race;

#[tokio::test]
async fn worker_final_completion_race_has_one_repository_winner() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let scenarios: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-final-completion-race-scenarios.json"
    ))
    .unwrap();
    assert_eq!(scenarios["lease_seconds"], 30);
    assert_eq!(scenarios["cases"].as_array().unwrap().len(), 2);
    for case in scenarios["cases"].as_array().unwrap() {
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&owned.url)
            .await
            .unwrap();
        canvas_worker_final_completion_race::run(&pool, &owned.url, case).await;
        pool.close().await;
        owned.close().unwrap();
    }
}

#[tokio::test]
async fn worker_provider_generation_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned =
        canvas_published_database::PublishedDatabase::start_with_worker_provider_generation()
            .await
            .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-generation-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[test]
fn worker_provider_generation_preserves_stronger_recovery_fence() {
    assert_worker_provider_https("generation");
}

#[tokio::test]
async fn worker_provider_generation_native_child() {
    worker_provider_child("generation").await;
}

#[tokio::test]
async fn worker_oauth_revocation_secrets_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-secrets").await;
}

#[test]
fn worker_oauth_revocation_secrets_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-secrets");
}

#[tokio::test]
async fn worker_oauth_revocation_counters_reference_matches_published_cycle() {
    assert_worker_matrix_reference("oauth-revocation-counters").await;
}

#[test]
fn worker_oauth_revocation_counters_matches_frozen_published_cycle() {
    assert_native_oauth_revocation_matrix("oauth-revocation-counters");
}

#[path = "support/canvas_worker_oauth_revocation_replay.rs"]
mod canvas_worker_oauth_revocation_replay;

#[tokio::test]
async fn worker_oauth_revocation_selection_repository_matches_published() {
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
    canvas_worker_oauth_revocation_replay::assert_capped_repository_selection(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_oauth_revocation_secret_reference_constraints_match_published_schema() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_oauth_revocation_replay::assert_secret_reference_constraints(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_oauth_revocation_empty_token_is_not_dispatched() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_oauth_revocation_replay::assert_empty_token_not_dispatched(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_oauth_revocation_repository_selection_matches_published_order() {
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
    canvas_worker_oauth_revocation_replay::assert_queue_repository_selection(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[test]
fn worker_oauth_revocation_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation");
}

#[test]
fn worker_oauth_revocation_fence_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-fence");
}

#[test]
fn worker_oauth_revocation_patch_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-patch");
}

#[test]
fn worker_oauth_revocation_retry_after_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-retry-after");
}

#[test]
fn worker_oauth_revocation_backoff_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-backoff");
}

#[test]
fn worker_oauth_revocation_queue_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-queue");
}

#[test]
fn worker_oauth_revocation_lease_matches_frozen_published_process() {
    assert_native_oauth_revocation_matrix("oauth-revocation-lease");
}

fn assert_native_oauth_revocation_matrix(kind: &str) {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("Mandatory hosted Linux gate runs native OAuth revocation replay");
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/test_canvas_worker_oauth_revocation_https.py"))
        .arg(std::env::current_exe().unwrap())
        .arg(kind)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Native OAuth revocation replay failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
async fn worker_oauth_revocation_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_REVOCATION_NATIVE_ORIGIN") else {
        return;
    };
    if !cfg!(target_os = "linux") {
        panic!("native HTTPS child requires the Linux platform-trust gate");
    }
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let name = std::env::var("MARTY_CANVAS_WORKER_OAUTH_REVOCATION_CASE").unwrap();
    let kind = std::env::var("MARTY_CANVAS_WORKER_OAUTH_REVOCATION_KIND").unwrap();
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_oauth_revocation_replay::replay(&pool, &owned.url, &origin, &name, &kind).await;
    pool.close().await;
    owned.close().unwrap();
}

#[path = "support/canvas_worker_concurrent_replay.rs"]
mod canvas_worker_concurrent_replay;
#[path = "support/canvas_worker_provider_recovery_replay.rs"]
mod canvas_worker_provider_recovery_replay;
#[path = "support/canvas_worker_provider_signals_replay.rs"]
mod canvas_worker_provider_signals_replay;
#[path = "support/canvas_worker_rest_replay.rs"]
mod canvas_worker_rest_replay;

#[test]
fn worker_provider_signals_match_frozen_published_process() {
    assert_worker_provider_https("signals");
}

#[test]
fn worker_provider_reclaimers_retry_matches_frozen_published_process() {
    assert_worker_provider_https("reclaimers_retry");
}

#[test]
fn worker_provider_reclaimers_matches_frozen_published_process() {
    assert_worker_provider_https("reclaimers");
}

#[test]
fn worker_provider_concurrent_matches_frozen_published_process() {
    assert_worker_provider_https("concurrent");
}

#[test]
fn worker_provider_final_matches_frozen_published_process() {
    assert_worker_provider_https("final");
}

#[test]
fn worker_provider_recovery_matches_frozen_published_process() {
    assert_worker_provider_https("recovery");
}

#[test]
fn worker_provider_resource_race_matches_frozen_published_process() {
    assert_worker_provider_https("resource_race");
}

#[path = "support/canvas_worker_resource_race_replay.rs"]
mod canvas_worker_resource_race_replay;

#[tokio::test]
async fn worker_provider_resource_race_native_child() {
    worker_provider_child("resource_race").await;
}

#[tokio::test]
async fn worker_resource_race_repository_preserves_stale_write_fences() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    for name in [
        "platform_reconfigured",
        "application_removed",
        "application_status_changed",
        "application_context_changed",
        "target_reconfigured",
        "binding_reconfigured",
        "platform_reconfigured_wrong_owner",
        "platform_reconfigured_wrong_attempt",
        "application_removed_wrong_owner",
        "application_removed_wrong_attempt",
        "application_context_changed_wrong_owner",
        "application_context_changed_wrong_attempt",
    ] {
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&owned.url)
            .await
            .unwrap();
        canvas_worker_resource_race_replay::assert_repository_errors(&pool, name).await;
        pool.close().await;
        owned.close().unwrap();
    }
}

fn assert_worker_provider_https(scenario: &str) {
    assert_worker_https_script("test_canvas_worker_provider_signals_https.py", &[scenario]);
}

fn assert_worker_https_script(script: &str, arguments: &[&str]) {
    assert_worker_https_script_with_environment(script, arguments, &[]);
}

fn assert_worker_https_script_with_environment(
    script: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
) {
    assert!(matches!(
        script,
        "test_canvas_worker_provider_signals_https.py"
            | "test_canvas_worker_mixed_roster_https.py"
            | "test_canvas_worker_deadline_https.py"
            | "test_canvas_worker_timeout_https.py"
    ));
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("Actual active-provider signal qualification requires the mandatory Linux gate");
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts").join(script))
        .arg(std::env::current_exe().unwrap())
        .args(arguments)
        .envs(environment.iter().copied())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Native provider signal gate failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
async fn worker_provider_signals_native_child() {
    worker_provider_child("signals").await;
}

#[tokio::test]
async fn worker_provider_reclaimers_retry_native_child() {
    worker_provider_child("reclaimers_retry").await;
}

#[tokio::test]
async fn worker_provider_reclaimers_native_child() {
    worker_provider_child("reclaimers").await;
}

#[tokio::test]
async fn worker_provider_concurrent_native_child() {
    worker_provider_child("concurrent").await;
}

#[tokio::test]
async fn worker_provider_final_native_child() {
    worker_provider_child("final").await;
}

#[tokio::test]
async fn worker_provider_recovery_native_child() {
    worker_provider_child("recovery").await;
}

async fn worker_provider_child(scenario: &str) {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_SIGNAL_NATIVE_ORIGIN") else {
        return;
    };
    assert_eq!(std::env::consts::OS, "linux");
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    let signal = std::env::var("MARTY_CANVAS_WORKER_SIGNAL_NAME").unwrap();
    match scenario {
        "resource_race" => {
            canvas_worker_resource_race_replay::replay(&pool, &owned.url, &origin, &signal).await;
        }
        "completion" | "recovery_first" => {
            assert_eq!(signal, scenario);
            canvas_worker_provider_completion_replay::replay(&pool, &owned.url, &origin, &signal)
                .await;
        }
        "concurrent" => {
            assert_eq!(signal, "concurrent");
            canvas_worker_concurrent_replay::replay(&pool, &owned.url, &origin).await;
        }
        "signals" => {
            canvas_worker_provider_signals_replay::replay(&pool, &owned.url, &origin, &signal).await
        }
        "recovery" | "final" | "generation" | "reclaimers" | "reclaimers_retry" => {
            canvas_worker_provider_recovery_replay::replay(&pool, &owned.url, &origin, &signal)
                .await
        }
        _ => panic!("unknown static provider scenario"),
    }
    pool.close().await;
    owned.close().unwrap();
}

#[test]
fn worker_rest_matches_frozen_published_process() {
    assert_worker_https("rest");
}

#[test]
fn worker_facts_match_frozen_published_process() {
    assert_worker_https("facts");
}

#[test]
fn worker_validation_matches_frozen_published_process() {
    assert_worker_https("validation");
}

#[test]
fn worker_roster_failure_matches_frozen_published_process() {
    assert_worker_https("roster-failure");
}

#[path = "support/canvas_worker_resources_unavailable_replay.rs"]
mod canvas_worker_resources_unavailable_replay;

#[test]
fn worker_resources_unavailable_matches_frozen_published_process() {
    assert_worker_https("resources-unavailable");
}

#[test]
fn worker_retry_after_matches_frozen_published_process() {
    assert_worker_https("retry-after");
}

#[test]
fn worker_retry_matches_frozen_published_process() {
    assert_worker_https("retry");
}

fn assert_worker_https(scenario: &str) {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("Actual native HTTPS worker qualification requires the mandatory Linux gate");
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/test_canvas_worker_rest_https.py"))
        .arg(std::env::current_exe().unwrap())
        .arg(scenario)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Native worker HTTPS gate failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
async fn worker_rest_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_REST_NATIVE_ORIGIN") else {
        return;
    };
    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&owned.url)
        .await
        .unwrap();
    let scenario = std::env::var("MARTY_CANVAS_WORKER_REST_SCENARIO").unwrap();
    assert!(matches!(
        scenario.as_str(),
        "rest"
            | "facts"
            | "retry"
            | "retry-after"
            | "validation"
            | "roster-failure"
            | "resources-unavailable"
    ));
    if scenario == "resources-unavailable" {
        let name = std::env::var("MARTY_CANVAS_WORKER_RESOURCES_UNAVAILABLE_CASE").unwrap();
        canvas_worker_resources_unavailable_replay::replay(&pool, &owned.url, &origin, &name).await;
    } else {
        canvas_worker_rest_replay::replay(&pool, &owned.url, &origin, &scenario).await;
    }
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_rest_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_rest()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-rest-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_facts_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_facts()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-facts-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_reclaimers_retry_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_reclaimers_retry()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-reclaimers-retry-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_reclaimers_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_reclaimers()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-reclaimers-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_concurrent_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_concurrent()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-concurrent-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_provider_final_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_provider_final()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-final-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[tokio::test]
async fn worker_provider_recovery_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-recovery-oracle.json"
    ))
    .unwrap();
    assert_eq!(expected.as_object().unwrap().len(), 2);
    for case in ["renewal", "recovery"] {
        let owned =
            canvas_published_database::PublishedDatabase::start_with_worker_provider_recovery(case)
                .await
                .unwrap();
        assert_eq!(owned.oracle.as_ref().unwrap(), &expected[case], "{case}");
        owned.close().unwrap();
    }
}

#[tokio::test]
async fn worker_provider_signals_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-provider-signals-oracle.json"
    ))
    .unwrap();
    assert_eq!(expected.as_object().unwrap().len(), 3);
    for signal in ["SIGINT", "SIGTERM", "SIGKILL"] {
        let owned =
            canvas_published_database::PublishedDatabase::start_with_worker_provider_signal(signal)
                .await
                .unwrap();
        assert_eq!(
            owned.oracle.as_ref().unwrap(),
            &expected[signal],
            "{signal}"
        );
        owned.close().unwrap();
    }
}

#[tokio::test]
async fn worker_retry_after_reference_matches_published_process() {
    assert_worker_matrix_reference("retry-after").await;
}

#[tokio::test]
async fn worker_oauth_revocation_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation").await;
}

#[tokio::test]
async fn worker_oauth_revocation_fence_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-fence").await;
}

#[tokio::test]
async fn worker_oauth_revocation_patch_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-patch").await;
}

#[tokio::test]
async fn worker_oauth_revocation_retry_after_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-retry-after").await;
}

#[tokio::test]
async fn worker_oauth_revocation_backoff_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-backoff").await;
}

#[tokio::test]
async fn worker_oauth_revocation_queue_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-queue").await;
}

#[tokio::test]
async fn worker_oauth_revocation_lease_reference_matches_published_process() {
    assert_worker_matrix_reference("oauth-revocation-lease").await;
}

#[tokio::test]
async fn worker_oauth_revocation_selection_reference_matches_published_repository() {
    assert_worker_matrix_reference("oauth-revocation-selection").await;
}

#[tokio::test]
async fn worker_validation_repository_matches_frozen_errors() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    use marty_issuance_service::{
        canvas_sync_worker::CanvasSyncWorkerRepository,
        canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    };
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-oracle.json"
    ))
    .unwrap();
    for case in canvas_worker_rest_replay::validation_scenarios()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["boundary"] != "processor_dispatch")
    {
        let name = case["name"].as_str().unwrap();
        let owned = canvas_published_database::PublishedDatabase::start()
            .await
            .unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&owned.url)
            .await
            .unwrap();
        let fixture =
            canvas_worker_rest_replay::prepare(&pool, "https://127.0.0.1:1", "rest").await;
        let case = canvas_worker_rest_replay::seed_validation_case(&pool, name).await;
        let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
        let target = repository
            .target("org-review", "target-review")
            .await
            .unwrap()
            .unwrap();
        if let Some(race) = case.get("reference_race") {
            // The repository receives the target already read before removal.
            // This focused check is not the actual-process barrier replay.
            let mut transaction = pool.begin().await.unwrap();
            for statement in canvas_worker_rest_replay::validation_release_statements(race) {
                sqlx::raw_sql(statement)
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
            }
            transaction.commit().await.unwrap();
        }
        let error = repository.validate_target(&target).await.unwrap_err();
        let expected = &reference[name]["observations"][0]["jobs"][0];
        assert_eq!(
            error.code,
            expected["last_error_code"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            error.summary,
            expected["last_error_summary"].as_str().unwrap(),
            "{name}"
        );
        assert!(!error.retryable);
        assert_eq!(error.retry_after_seconds, None);
        fixture.assert_preserved(&pool).await;
        pool.close().await;
        owned.close().unwrap();
    }
}

#[tokio::test]
async fn worker_validation_reference_matches_published_process() {
    assert_worker_matrix_reference("validation").await;
}

#[tokio::test]
async fn worker_roster_failure_reference_matches_published_process() {
    assert_worker_matrix_reference("roster-failure").await;
}

#[tokio::test]
async fn worker_resource_race_reference_matches_published_process() {
    assert_worker_matrix_reference("resource-race").await;
}

#[tokio::test]
async fn worker_resources_unavailable_reference_matches_published_process() {
    assert_worker_matrix_reference("resources-unavailable").await;
}

async fn assert_worker_matrix_reference(kind: &str) {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let (scenario_source, oracle_source) = match kind {
        "oauth-revocation-secrets" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-secrets-scenarios.json"
            ),
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-secrets-oracle.json"
            ),
        ),
        "oauth-revocation-counters" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-counters-scenarios.json"
            ),
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-counters-oracle.json"
            ),
        ),
        "oauth-revocation-selection" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-selection-scenarios.json"
            ),
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-selection-oracle.json"
            ),
        ),
        "oauth-revocation-lease" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-lease-scenarios.json"
            ),
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-lease-oracle.json"),
        ),
        "oauth-revocation-queue" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-queue-scenarios.json"
            ),
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-queue-oracle.json"),
        ),
        "oauth-revocation-backoff" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-backoff-scenarios.json"
            ),
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-backoff-oracle.json"
            ),
        ),
        "oauth-revocation-retry-after" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-retry-after-scenarios.json"
            ),
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-retry-after-oracle.json"
            ),
        ),
        "oauth-revocation-patch" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-patch-scenarios.json"
            ),
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-patch-oracle.json"),
        ),
        "oauth-revocation-fence" => (
            include_str!(
                "../../../../contracts/canvas-worker-oauth-revocation-fence-scenarios.json"
            ),
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-fence-oracle.json"),
        ),
        "oauth-revocation" => (
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-scenarios.json"),
            include_str!("../../../../contracts/canvas-worker-oauth-revocation-oracle.json"),
        ),
        "retry-after" => (
            include_str!("../../../../contracts/canvas-worker-retry-after-scenarios.json"),
            include_str!("../../../../contracts/canvas-worker-retry-after-oracle.json"),
        ),
        "validation" => (
            include_str!("../../../../contracts/canvas-worker-validation-scenarios.json"),
            include_str!("../../../../contracts/canvas-worker-validation-oracle.json"),
        ),
        "roster-failure" => (
            include_str!("../../../../contracts/canvas-worker-roster-failure-scenarios.json"),
            include_str!("../../../../contracts/canvas-worker-roster-failure-oracle.json"),
        ),
        "resources-unavailable" => (
            include_str!(
                "../../../../contracts/canvas-worker-resources-unavailable-scenarios.json"
            ),
            include_str!("../../../../contracts/canvas-worker-resources-unavailable-oracle.json"),
        ),
        "resource-race" => (
            include_str!("../../../../contracts/canvas-worker-resource-race-scenarios.json"),
            include_str!("../../../../contracts/canvas-worker-resource-race-oracle.json"),
        ),
        _ => panic!("unknown static worker matrix"),
    };
    let scenarios: serde_json::Value = serde_json::from_str(scenario_source).unwrap();
    let expected: serde_json::Value = serde_json::from_str(oracle_source).unwrap();
    let cases = scenarios["cases"].as_array().unwrap();
    assert!(
        !cases.is_empty(),
        "worker matrix must execute at least one case"
    );
    let names = cases
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(cases.len(), names.len(), "duplicate worker matrix case");
    assert_eq!(
        names,
        expected
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
    for name in names {
        let owned = match kind {
            "oauth-revocation-secrets" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_secrets(name).await
            }
            "oauth-revocation-counters" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_counters(name).await
            }
            "oauth-revocation-selection" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_selection(name).await
            }
            "oauth-revocation-lease" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_lease(name).await
            }
            "oauth-revocation-queue" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_queue(name).await
            }
            "oauth-revocation-backoff" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_backoff(name).await
            }
            "oauth-revocation-retry-after" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_retry_after(name).await
            }
            "oauth-revocation-patch" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_patch(name).await
            }
            "oauth-revocation-fence" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation_fence(name).await
            }
            "oauth-revocation" => {
                canvas_published_database::PublishedDatabase::start_with_worker_oauth_revocation(
                    name,
                )
                .await
            }
            "retry-after" => {
                canvas_published_database::PublishedDatabase::start_with_worker_retry_after(name)
                    .await
            }
            "validation" => {
                canvas_published_database::PublishedDatabase::start_with_worker_validation(name)
                    .await
            }
            "roster-failure" => {
                canvas_published_database::PublishedDatabase::start_with_worker_roster_failure(name)
                    .await
            }
            "resources-unavailable" => {
                canvas_published_database::PublishedDatabase::start_with_worker_resources_unavailable(name).await
            }
            "resource-race" => {
                canvas_published_database::PublishedDatabase::start_with_worker_resource_race(name)
                    .await
            }
            _ => unreachable!(),
        }
        .unwrap();
        assert_eq!(owned.oracle.as_ref().unwrap(), &expected[name], "{name}");
        owned.close().unwrap();
    }
}

#[tokio::test]
async fn worker_retry_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_retry()
        .await
        .unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-retry-oracle.json"
    ))
    .unwrap();
    assert_eq!(owned.oracle.as_ref().unwrap(), &expected);
    owned.close().unwrap();
}

#[allow(dead_code)]
#[path = "support/canvas_worker_process_signals.rs"]
mod canvas_worker_process_signals;
#[path = "support/canvas_worker_startup_replay.rs"]
mod canvas_worker_startup_replay;

#[tokio::test]
async fn worker_startup_matches_published_process_and_idle_heartbeat() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start_with_worker_startup()
        .await
        .unwrap();
    let oracle = owned.oracle.clone().unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-startup-oracle.json"
    ))
    .unwrap();
    assert_eq!(
        oracle, expected,
        "published startup reference must regenerate unchanged"
    );
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_startup_replay::replay(&pool, &owned.url, &oracle).await;
    pool.close().await;
    owned.close().unwrap();
}

#[path = "support/canvas_json_depth_replay.rs"]
mod canvas_json_depth_replay;
#[path = "support/canvas_observation_values.rs"]
mod canvas_observation_values;

#[tokio::test]
async fn status_provider_matches_json_depth_reference() {
    canvas_status_provider_replay::replay_depth().await;
}

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
async fn status_provider_matches_json_consumer_reference() {
    canvas_status_provider_replay::replay_json().await;
}

#[tokio::test]
async fn status_runtime_matches_json_full_credential_routes() {
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
    canvas_status_runtime_contract::run_json_body(&pool).await;
    pool.close().await;
    owned.close().unwrap();
}

#[tokio::test]
async fn status_runtime_matches_json_depth_full_credential_routes() {
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
