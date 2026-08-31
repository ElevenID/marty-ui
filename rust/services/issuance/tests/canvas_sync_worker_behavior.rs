use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use marty_issuance_service::canvas_sync_worker::{
    job_retry_delay_seconds, retry_after_seconds, roster_cursor_window, safe_result,
    CanvasSyncWorkerConfig,
};
use serde_json::{Map, Value};

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-sync-worker.json"
    ))
    .expect("Canvas worker contract")
}

#[test]
fn configuration_matches_frozen_defaults_bounds_and_failures() {
    let defaults = CanvasSyncWorkerConfig::from_values(&BTreeMap::new()).expect("defaults");
    assert_eq!(defaults.batch_size, 10);
    assert_eq!(defaults.lease_seconds, 120);
    assert_eq!(defaults.job_timeout.as_secs_f64(), 600.0);
    assert_eq!(defaults.schedule_limit, 100);
    assert_eq!(defaults.oauth_revocation_limit, 25);
    assert_eq!(defaults.poll_interval.as_secs_f64(), 5.0);
    assert!(!defaults.worker_id.is_empty());

    let bounded = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([
        ("CANVAS_SYNC_WORKER_BATCH_SIZE".to_owned(), "0".to_owned()),
        (
            "CANVAS_SYNC_WORKER_LEASE_SECONDS".to_owned(),
            "1".to_owned(),
        ),
        (
            "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS".to_owned(),
            "99999".to_owned(),
        ),
        ("CANVAS_SYNC_WORKER_POLL_SECONDS".to_owned(), "0".to_owned()),
        (
            "CANVAS_SYNC_WORKER_ID".to_owned(),
            " explicit-worker ".to_owned(),
        ),
    ]))
    .expect("bounded configuration");
    assert_eq!(bounded.worker_id, "explicit-worker");
    assert_eq!(bounded.batch_size, 1);
    assert_eq!(bounded.lease_seconds, 30);
    assert_eq!(bounded.job_timeout.as_secs_f64(), 3_600.0);
    assert_eq!(bounded.poll_interval.as_secs_f64(), 0.1);

    for name in [
        "CANVAS_SYNC_WORKER_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_LEASE_SECONDS",
        "CANVAS_SYNC_WORKER_JOB_TIMEOUT_SECONDS",
        "CANVAS_SYNC_SCHEDULE_LIMIT",
        "CANVAS_OAUTH_REVOCATION_BATCH_SIZE",
        "CANVAS_SYNC_WORKER_POLL_SECONDS",
    ] {
        let error = CanvasSyncWorkerConfig::from_values(&BTreeMap::from([(
            name.to_owned(),
            "not-a-number".to_owned(),
        )]))
        .expect_err("malformed values fail startup");
        assert!(format!("{error}").contains(name));
    }
}

#[test]
fn language_neutral_result_retry_and_cursor_vectors_match() {
    let fixtures = &contract()["executable_fixtures"];
    let sanitization = &fixtures["result_sanitization"];
    let input: Map<String, Value> = sanitization["input"].as_object().expect("input").clone();
    assert_eq!(Value::Object(safe_result(&input)), sanitization["output"]);

    for vector in fixtures["retry_after"]
        .as_array()
        .expect("Retry-After vectors")
    {
        let now = vector["now"]
            .as_str()
            .expect("now")
            .parse::<DateTime<Utc>>()
            .expect("timestamp");
        let actual = retry_after_seconds(vector["value"].as_str().expect("value"), now);
        assert_eq!(actual, vector["seconds"].as_u64());
    }

    for vector in fixtures["job_backoff"].as_array().expect("backoff vectors") {
        let attempt = i32::try_from(vector["attempt_count"].as_i64().expect("attempt"))
            .expect("bounded attempt");
        let base = vector["base_seconds"].as_u64().expect("base");
        let maximum_jitter = vector["maximum_jitter_seconds"]
            .as_u64()
            .expect("maximum jitter");
        assert_eq!(job_retry_delay_seconds(attempt, None, 0), base);
        assert_eq!(
            job_retry_delay_seconds(attempt, None, u64::MAX),
            base + maximum_jitter
        );
    }

    for vector in fixtures["cursor"].as_array().expect("cursor vectors") {
        let cursor = vector["cursor"].as_i64().expect("cursor");
        let size = usize::try_from(vector["size"].as_u64().expect("size")).unwrap();
        let batch = usize::try_from(vector["batch_size"].as_u64().expect("batch size")).unwrap();
        assert_eq!(
            roster_cursor_window(cursor, size, batch),
            (
                usize::try_from(
                    vector["normalized_cursor"]
                        .as_u64()
                        .expect("normalized cursor")
                )
                .unwrap(),
                usize::try_from(vector["next_cursor"].as_u64().expect("next cursor")).unwrap()
            )
        );
    }
}

#[test]
fn contract_keeps_candidate_landing_separate_from_cutover_and_deletion() {
    let contract = contract();
    let gaps = contract["migration_gates"]["legacy_oracle_gaps"]
        .as_array()
        .expect("legacy oracle gaps");
    assert!(!gaps.is_empty());
    let deletion = contract["migration_gates"]["python_deletion_requires"]
        .as_array()
        .expect("deletion gates");
    assert!(deletion.iter().any(|gate| gate
        .as_str()
        .is_some_and(|gate| gate.contains("whole-worker differential"))));
    assert!(deletion.iter().any(|gate| {
        gate.as_str()
            .is_some_and(|gate| gate.contains("all Compose, self-host, and Kubernetes consumers"))
    }));
}
