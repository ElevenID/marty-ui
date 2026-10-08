//! Published Canvas worker acceptance cases. The CI runner resolves the real
//! `marty-canvas-sync-worker` Cargo binary artifact and passes its absolute
//! path in `MARTY_CANVAS_WORKER_TEST_BINARY`. For a direct guarded Cargo run,
//! build that issuance binary first and set the same variable to its absolute
//! path; dependency packages do not receive `CARGO_BIN_EXE_*` from Cargo.

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::BTreeSet;

// The pinned migration probe leaves its template database disconnected.
// Repository-only cases can clone that pristine schema while each case keeps
// independent mutable state. The surviving container owner removes every
// clone even if a case panics before its explicit DROP DATABASE.
async fn published_template_admin(owned: &canvas_published_database::PublishedDatabase) -> PgPool {
    let mut admin_url = url::Url::parse(&owned.url).unwrap();
    assert_eq!(admin_url.path(), "/canvas_published_schema_test");
    admin_url.set_path("/postgres");
    PgPoolOptions::new()
        .max_connections(1)
        .connect(admin_url.as_str())
        .await
        .unwrap()
}

async fn clone_published_case(
    owned: &canvas_published_database::PublishedDatabase,
    admin: &PgPool,
    case_name: &str,
) -> (String, PgPool) {
    // SQL identifiers cannot be bound; generate and validate the name here,
    // never from a scenario or its payload. The admin pool is on `postgres`,
    // because a connected template cannot be cloned.
    let database_name = format!("canvas_validation_{}", uuid::Uuid::new_v4().simple());
    assert!(
        database_name.len() < 63
            && database_name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE DATABASE \"{database_name}\" TEMPLATE \"canvas_published_schema_test\""
    )))
    .execute(admin)
    .await
    .unwrap();
    let mut case_url = url::Url::parse(&owned.url).unwrap();
    case_url.set_path(&format!("/{database_name}"));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(case_url.as_str())
        .await
        .unwrap();
    let unseeded_jobs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unseeded_jobs, 0, "{case_name}: clone was not pristine");
    (database_name, pool)
}

async fn close_published_case(admin: &PgPool, database_name: String, pool: PgPool) {
    pool.close().await;
    // No FORCE: a leaked connection fails the test instead of being hidden.
    // The owned tmpfs container remains the final cleanup boundary.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE \"{database_name}\""
    )))
    .execute(admin)
    .await
    .unwrap();
}

#[expect(
    dead_code,
    reason = "shared command fixture has composition-only diagnostics"
)]
#[path = "../../../services/issuance/tests/support/bounded_fixture_command.rs"]
mod bounded_fixture_command;
#[expect(
    dead_code,
    reason = "shared database fixture has composition-only constructors"
)]
#[path = "../../../services/issuance/tests/support/canvas_published_database.rs"]
mod canvas_published_database;

#[path = "../../../services/issuance/tests/support/canvas_worker_deadline_replay.rs"]
mod canvas_worker_deadline_replay;

#[path = "../../../services/issuance/tests/support/canvas_worker_output.rs"]
mod canvas_worker_output;

#[path = "../../../services/issuance/tests/support/canvas_worker_timeout_replay.rs"]
mod canvas_worker_timeout_replay;

#[path = "../../../services/issuance/tests/support/canvas_worker_lease_expiry_replay.rs"]
mod canvas_worker_lease_expiry_replay;

#[path = "../../../services/issuance/tests/support/canvas_published_borrowed_database.rs"]
mod canvas_published_borrowed_database;

#[test]
fn worker_repository_root_is_independent_of_cargo_package_depth() {
    let root = canvas_published_database::repository_root();
    for package in ["rust/services/issuance", "rust/crates/canvas-acceptance"] {
        assert_eq!(
            canvas_published_database::repository_root_from(&root.join(package)),
            Some(root.as_path()),
        );
    }
}

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

#[tokio::test]
async fn worker_body_timeout_matches_frozen_published_process() {
    assert_borrowed_worker_cases(
        "test_canvas_worker_body_timeout_https.py",
        canvas_worker_timeout_replay::BODY_CASES,
        "MARTY_CANVAS_WORKER_BODY_TIMEOUT_DATABASE",
    )
    .await;
}

#[tokio::test]
async fn worker_lease_expiry_matches_frozen_published_process() {
    assert_borrowed_worker_cases(
        "test_canvas_worker_lease_expiry_https.py",
        &["renewal_lock_early_release", "renewal_lock_crosses_expiry"],
        "MARTY_CANVAS_WORKER_LEASE_EXPIRY_DATABASE",
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
        ) | (
            "test_canvas_worker_body_timeout_https.py",
            "MARTY_CANVAS_WORKER_BODY_TIMEOUT_DATABASE"
        ) | (
            "test_canvas_worker_lease_expiry_https.py",
            "MARTY_CANVAS_WORKER_LEASE_EXPIRY_DATABASE"
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

#[tokio::test]
async fn worker_body_timeout_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_BODY_TIMEOUT_NATIVE_ORIGIN") else {
        return;
    };
    let case = std::env::var("MARTY_CANVAS_WORKER_BODY_TIMEOUT_CASE").unwrap();
    let (pool, database_url) =
        borrowed_worker_pool("MARTY_CANVAS_WORKER_BODY_TIMEOUT_DATABASE").await;
    canvas_worker_timeout_replay::replay_body(&pool, &database_url, &origin, &case).await;
    pool.close().await;
}

#[tokio::test]
async fn worker_lease_expiry_native_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_WORKER_LEASE_EXPIRY_NATIVE_ORIGIN") else {
        return;
    };
    let case = std::env::var("MARTY_CANVAS_WORKER_LEASE_EXPIRY_CASE").unwrap();
    let (pool, database_url) =
        borrowed_worker_pool("MARTY_CANVAS_WORKER_LEASE_EXPIRY_DATABASE").await;
    canvas_worker_lease_expiry_replay::replay(&pool, &database_url, &origin, &case).await;
    pool.close().await;
}

async fn borrowed_worker_pool(descriptor_environment: &str) -> (sqlx::PgPool, String) {
    assert!(matches!(
        descriptor_environment,
        "MARTY_CANVAS_WORKER_DEADLINE_DATABASE"
            | "MARTY_CANVAS_WORKER_TIMEOUT_DATABASE"
            | "MARTY_CANVAS_WORKER_BODY_TIMEOUT_DATABASE"
            | "MARTY_CANVAS_WORKER_LEASE_EXPIRY_DATABASE"
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
async fn body_capture_rejects_non_matrix_cases_before_resource_creation() {
    for invalid in [
        "",
        "application_prompt",
        "roster_delayed_headers",
        "../escape",
        "application_body_prompt\n",
    ] {
        let result =
            canvas_published_database::PublishedDatabase::start_with_worker_body_timeout(invalid)
                .await;
        assert!(
            matches!(result, Err(message) if message == "unsupported owned worker matrix case")
        );
    }
}

fn body_timeout_reference_cases(scenarios: &serde_json::Value) -> Result<Vec<&str>, &'static str> {
    if scenarios["schema"] != "marty.canvas-worker-body-timeout-scenarios/v1" {
        return Err("unexpected published body scenario schema");
    }
    let cases = scenarios["cases"]
        .as_array()
        .ok_or("missing published body cases")?;
    if cases.len() != 6 {
        return Err("published body reference requires six cases");
    }
    let names = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .ok_or("invalid published body case name")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != 6
    {
        return Err("duplicate published body case");
    }
    let frozen: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../../contracts/canvas-worker-body-timeout-oracle.json"
    ))
    .map_err(|_| "invalid frozen body reference")?;
    let frozen_names = frozen
        .iter()
        .map(|report| {
            report["worker_body_timeout"]["case"]
                .as_str()
                .ok_or("invalid frozen body case")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names != frozen_names {
        return Err("published body cases differ from frozen order");
    }
    Ok(names)
}

#[test]
fn body_timeout_reference_rejects_invalid_scenario_closure() {
    let original: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-body-timeout-scenarios.json"
    ))
    .unwrap();
    assert_eq!(body_timeout_reference_cases(&original).unwrap().len(), 6);
    for mutation in [
        "schema",
        "missing",
        "count",
        "duplicate",
        "name_type",
        "unknown",
        "reordered",
    ] {
        let mut invalid = original.clone();
        match mutation {
            "schema" => invalid["schema"] = serde_json::json!("other-schema"),
            "missing" => invalid["cases"] = serde_json::Value::Null,
            "count" => {
                invalid["cases"].as_array_mut().unwrap().pop();
            }
            "duplicate" => invalid["cases"][1]["name"] = invalid["cases"][0]["name"].clone(),
            "name_type" => invalid["cases"][0]["name"] = serde_json::json!(1),
            "unknown" => invalid["cases"][5]["name"] = serde_json::json!("unknown-body-case"),
            "reordered" => invalid["cases"].as_array_mut().unwrap().swap(0, 1),
            _ => unreachable!(),
        }
        assert!(body_timeout_reference_cases(&invalid).is_err());
    }
}

async fn body_timeout_raw_published_reports() -> String {
    let scenarios: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-body-timeout-scenarios.json"
    ))
    .unwrap();
    // Reject malformed/duplicate selectors before creating any owned resource.
    let cases = body_timeout_reference_cases(&scenarios).unwrap();
    let mut raw_reports = Vec::new();
    for name in cases {
        let owned =
            canvas_published_database::PublishedDatabase::start_with_worker_body_timeout(name)
                .await
                .unwrap();
        let raw = owned.raw_probe_report().unwrap();
        assert!(raw.len() <= 1_048_576, "body capture report exceeds limit");
        let report: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(report["worker_body_timeout"]["case"], name);
        assert_eq!(
            report["worker_body_timeout"]["schema"],
            "marty.canvas-worker-body-timeout-observation/v1"
        );
        owned.close_verified().unwrap();
        raw_reports.push(raw);
        eprintln!("Published body capture and exact-owned cleanup passed: {name}");
    }
    // Preserve every original numeric token and complete probe report. This is
    // only the same array framing used by the independently equal A/B captures.
    format!("[{}]\n", raw_reports.join(",\n"))
}

#[tokio::test]
async fn worker_body_timeout_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let actual = body_timeout_raw_published_reports().await;
    let expected = include_bytes!("../../../../contracts/canvas-worker-body-timeout-oracle.json");
    assert!(
        actual.as_bytes() == expected,
        "published body reference differs from independently frozen raw reports"
    );
}

#[tokio::test]
#[ignore = "explicit reviewed reference capture only; not a native parity gate"]
async fn capture_worker_body_timeout_published_process() {
    use std::io::Write;

    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let destination = std::path::PathBuf::from(
        std::env::var_os("MARTY_CANVAS_BODY_CAPTURE_FILE")
            .expect("explicit new capture file required"),
    );
    assert!(destination.is_absolute(), "capture file must be absolute");
    assert!(!destination.exists(), "capture file must not already exist");
    let raw = body_timeout_raw_published_reports().await;
    // Emit only after all six observations and cleanups pass. create_new also
    // rejects a destination created concurrently; no existing evidence is lost.
    let mut output = std::fs::File::create_new(destination).unwrap();
    output.write_all(raw.as_bytes()).unwrap();
    output.sync_all().unwrap();
}

async fn lease_expiry_raw_published_reports() -> String {
    let mut reports = Vec::new();
    for name in ["renewal_lock_early_release", "renewal_lock_crosses_expiry"] {
        let owned =
            canvas_published_database::PublishedDatabase::start_with_worker_lease_expiry(name)
                .await
                .unwrap();
        let raw = owned.raw_probe_report().unwrap();
        assert!(raw.len() <= 1_048_576, "lease-expiry report exceeds limit");
        let report: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(report["worker_lease_expiry"]["case"], name);
        assert_eq!(
            report["worker_lease_expiry"]["schema"],
            "marty.canvas-worker-lease-expiry-observation/v1"
        );
        owned.close_verified().unwrap();
        reports.push(raw);
        eprintln!("Published lease-expiry observation and owned cleanup passed: {name}");
    }
    format!("[{}]\n", reports.join(",\n"))
}

#[tokio::test]
async fn worker_lease_expiry_reference_matches_published_process() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let raw = lease_expiry_raw_published_reports().await;
    assert!(
        raw.as_bytes()
            == include_bytes!("../../../../contracts/canvas-worker-lease-expiry-oracle.json"),
        "published lease-expiry reference differs from independent frozen reports"
    );
}

#[tokio::test]
#[ignore = "explicit reviewed lease-expiry reference capture only; not native qualification"]
async fn capture_worker_lease_expiry_published_process() {
    use std::io::Write;

    assert_eq!(
        std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref(),
        Ok("1")
    );
    let destination = std::path::PathBuf::from(
        std::env::var_os("MARTY_CANVAS_LEASE_EXPIRY_CAPTURE_FILE")
            .expect("explicit new lease-expiry capture file required"),
    );
    assert!(destination.is_absolute(), "capture file must be absolute");
    assert!(!destination.exists(), "capture file must not already exist");
    let raw = lease_expiry_raw_published_reports().await;
    // Preserve raw numeric lexemes; publish only after both owned cleanups.
    // create_new never replaces evidence; a write/sync error may leave a new
    // partial failed capture, which is not a frozen or qualifying artifact.
    let mut output = std::fs::File::create_new(destination).unwrap();
    output.write_all(raw.as_bytes()).unwrap();
    output.sync_all().unwrap();
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

#[path = "../../../services/issuance/tests/support/canvas_worker_effect_expiry.rs"]
mod canvas_worker_effect_expiry;

#[path = "../../../services/issuance/tests/support/canvas_worker_roster_metadata.rs"]
mod canvas_worker_roster_metadata;

const ROSTER_DATABASE_CASES: &[&str] = &[
    "absent",
    "preexisting",
    "explicit_null",
    "stale_target_generation",
    "wrong_owner",
    "wrong_attempt",
    "expired_before_write",
    "expired_during_lock",
];

#[test]
fn roster_case_ownership_matches_frozen_obligations() {
    let obligations: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-roster-metadata-obligations.json"
    ))
    .unwrap();
    assert_eq!(
        obligations["schema"],
        "marty.canvas-roster-metadata-obligations/v1"
    );
    let fast: Vec<&str> = obligations["fast_shape_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect();
    assert_eq!(
        fast,
        [
            "absent",
            "preexisting",
            "explicit_null",
            "worker_only",
            "heartbeat_only"
        ]
    );
    let database: Vec<&str> = obligations["database_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case.as_str().unwrap())
        .collect();
    assert_eq!(database, ROSTER_DATABASE_CASES);
    assert_eq!(database.len(), 8);
    assert_eq!(fast.len(), 5);
}

#[tokio::test]
async fn worker_roster_metadata_reconciliation_preserves_current_fields_and_fences() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let timing = canvas_published_database::repository_matrix_timer(
        canvas_published_database::RepositoryMatrix::RosterMetadata,
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let admin = published_template_admin(&owned).await;
    for case in ROSTER_DATABASE_CASES {
        let (database_name, pool) = clone_published_case(&owned, &admin, case).await;
        canvas_worker_roster_metadata::assert_reconciliation(&pool, case).await;
        close_published_case(&admin, database_name, pool).await;
    }
    admin.close().await;
    owned.close_verified().unwrap();
    timing.success();
}

#[path = "../../../services/issuance/tests/support/canvas_worker_mixed_roster_replay.rs"]
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

#[path = "../../../services/issuance/tests/support/canvas_worker_provider_completion_replay.rs"]
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

#[path = "../../../services/issuance/tests/support/canvas_worker_final_completion_race.rs"]
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

#[path = "../../../services/issuance/tests/support/canvas_worker_oauth_revocation_replay.rs"]
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
    let root = canvas_published_database::repository_root();
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

#[path = "../../../services/issuance/tests/support/canvas_worker_concurrent_replay.rs"]
mod canvas_worker_concurrent_replay;
#[path = "../../../services/issuance/tests/support/canvas_worker_provider_recovery_replay.rs"]
mod canvas_worker_provider_recovery_replay;
#[path = "../../../services/issuance/tests/support/canvas_worker_provider_signals_replay.rs"]
mod canvas_worker_provider_signals_replay;
#[path = "../../../services/issuance/tests/support/canvas_worker_rest_replay.rs"]
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

#[path = "../../../services/issuance/tests/support/canvas_worker_resource_race_replay.rs"]
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
    let timing = canvas_published_database::repository_matrix_timer(
        canvas_published_database::RepositoryMatrix::ResourceRace,
    );
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    let admin = published_template_admin(&owned).await;
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
        let (database_name, pool) = clone_published_case(&owned, &admin, name).await;
        canvas_worker_resource_race_replay::assert_repository_errors(&pool, name).await;
        close_published_case(&admin, database_name, pool).await;
    }
    admin.close().await;
    owned.close_verified().unwrap();
    timing.success();
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
            | "test_canvas_worker_body_timeout_https.py"
            | "test_canvas_worker_lease_expiry_https.py"
    ));
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("Actual active-provider signal qualification requires the mandatory Linux gate");
        return;
    }
    let root = canvas_published_database::repository_root();
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

#[path = "../../../services/issuance/tests/support/canvas_worker_resources_unavailable_replay.rs"]
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
    let root = canvas_published_database::repository_root();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/test_canvas_worker_rest_https.py"))
        .arg(std::env::current_exe().unwrap())
        .arg(scenario)
        // The Python matrix owns several serial cases. Inherit stdout so
        // its phase markers reach the CI relay as each case finishes. Its
        // ordinary output remains in the existing final raw contract log.
        .stdout(std::process::Stdio::inherit())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Native worker HTTPS gate failed (stdout retained in contract log): {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        canvas_sync_worker::{CanvasSyncJobStatus, CanvasSyncWorkerRepository, JobFailure},
        canvas_sync_worker_postgres::PostgresCanvasSyncWorkerRepository,
    };
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-worker-validation-oracle.json"
    ))
    .unwrap();
    let scenarios = canvas_worker_rest_replay::validation_scenarios()["cases"]
        .as_array()
        .unwrap();
    assert_eq!(scenarios.len(), 20);
    let names = scenarios
        .iter()
        .map(|case| case["name"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), scenarios.len());
    assert_eq!(
        names,
        reference
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
    let repository_cases = scenarios
        .iter()
        .filter(|case| case["boundary"] != "processor_dispatch")
        .collect::<Vec<_>>();
    assert_eq!(repository_cases.len(), 13);
    // The published migration probe leaves a pristine, disconnected database.
    // Clone it into a separate database for each case, so we keep independent
    // schemas and frozen observations without starting thirteen PostgreSQL
    // servers or re-running the same published migrations thirteen times.
    let timing = canvas_published_database::repository_matrix_timer(
        canvas_published_database::RepositoryMatrix::Validation,
    );
    let owned =
        canvas_published_database::PublishedDatabase::start_for_worker_validation_template()
            .await
            .unwrap();
    let admin = published_template_admin(&owned).await;
    for case in repository_cases {
        let name = case["name"].as_str().unwrap();
        let (database_name, pool) = clone_published_case(&owned, &admin, name).await;
        let fixture =
            canvas_worker_rest_replay::prepare(&pool, "https://127.0.0.1:1", "rest").await;
        let case = canvas_worker_rest_replay::seed_validation_case(&pool, name).await;
        let repository = PostgresCanvasSyncWorkerRepository::new(pool.clone());
        // Lease before validation: inactive/stale validation can disable the
        // target, but the actual worker already owns the queued job by then.
        let leased = repository
            .lease_ready("validation-worker", &1_u64.into(), &120_u64.into())
            .await
            .unwrap();
        assert_eq!(leased.len(), 1, "{name}");
        let job = &leased[0];
        assert_eq!(job.id, "worker-validation-job", "{name}");
        assert_eq!(job.status, CanvasSyncJobStatus::Leased, "{name}");
        assert_eq!(job.attempt_count, 1, "{name}");
        assert_eq!(job.max_attempts, 8, "{name}");
        assert_eq!(
            job.lease_owner.as_deref(),
            Some("validation-worker"),
            "{name}"
        );
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
        assert_eq!(
            repository
                .fail_job(
                    job,
                    "validation-worker",
                    &JobFailure {
                        error_code: error.code,
                        error_summary: Some(error.summary),
                        retry_after_seconds: error.retry_after_seconds,
                        force_dead_letter: !error.retryable,
                    },
                    job.target_config_version,
                )
                .await
                .unwrap(),
            Some(CanvasSyncJobStatus::DeadLetter),
            "{name}"
        );
        let jobs: serde_json::Value =
            sqlx::query_scalar(fixture.spec["jobs_sql"].as_str().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(jobs, reference[name]["observations"][0]["jobs"], "{name}");
        let target_state: serde_json::Value = sqlx::query_scalar(
            "SELECT jsonb_build_object('enabled',enabled,'config_version',config_version) \
             FROM issuance_service.canvas_evidence_sync_targets WHERE id='target-review'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(target_state, reference[name]["target"], "{name}");
        let oauth: serde_json::Value =
            sqlx::query_scalar(fixture.spec["oauth_sql"].as_str().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(oauth, reference[name]["observations"][0]["oauth"], "{name}");
        let facts: serde_json::Value =
            sqlx::query_scalar(fixture.spec["facts_sql"].as_str().unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(facts, reference[name]["observations"][0]["facts"], "{name}");
        fixture.assert_preserved(&pool).await;
        close_published_case(&admin, database_name, pool).await;
    }
    admin.close().await;
    owned.close_verified().unwrap();
    timing.success();
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
#[path = "../../../services/issuance/tests/support/canvas_worker_process_signals.rs"]
mod canvas_worker_process_signals;

#[test]
fn worker_binary_handoff_requires_an_absolute_path_and_keeps_cargo_default() {
    let explicit = std::env::temp_dir().join("canvas-worker-test-binary");
    let fallback = std::env::temp_dir().join("cargo-worker-binary");
    let fallback_text = fallback.to_str().unwrap();
    assert_eq!(
        canvas_worker_process_signals::worker_executable_from(
            Some(explicit.clone().into_os_string()),
            Some(fallback_text),
        ),
        explicit,
    );
    assert_eq!(
        canvas_worker_process_signals::worker_executable_from(None, Some(fallback_text)),
        fallback,
    );
    assert!(std::panic::catch_unwind(|| {
        canvas_worker_process_signals::worker_executable_from(
            Some("relative-worker".into()),
            Some(fallback_text),
        )
    })
    .is_err());
}
#[path = "support/canvas_startup_attestation.rs"]
mod canvas_startup_attestation;
#[path = "../../../services/issuance/tests/support/canvas_worker_startup_replay.rs"]
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
    let worker_binary = canvas_worker_process_signals::worker_executable();
    let worker_binary_before = canvas_startup_attestation::file_sha(&worker_binary);
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&owned.url)
        .await
        .unwrap();
    canvas_worker_startup_replay::replay(&pool, &owned.url, &oracle).await;
    pool.close().await;
    owned.close().unwrap();
    canvas_startup_attestation::emit_after_startup_pass(
        &canvas_published_database::repository_root(),
        &oracle,
        &worker_binary,
        &worker_binary_before,
    );
}

#[path = "../../../services/issuance/tests/support/canvas_worker_sql_logging.rs"]
mod canvas_worker_sql_logging;

#[tokio::test]
async fn worker_sql_logging_preserves_debug_diagnostics_and_operational_warnings() {
    if std::env::var("MARTY_CANVAS_PUBLISHED_SCHEMA_TEST").as_deref() != Ok("1") {
        return;
    }
    let owned = canvas_published_database::PublishedDatabase::start()
        .await
        .unwrap();
    canvas_worker_sql_logging::replay(&owned.url).await;
    owned.close().unwrap();
}
