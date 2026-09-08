//! Actual SQLx query events under the native worker's connection policy.
//! No worker parity gate accepts logs because of this diagnostic test.
use marty_issuance_service::canvas_sync_worker_lifecycle::worker_connect_options;
use serde_json::Value;
use sqlx::{postgres::PgConnectOptions, Connection, PgConnection};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut output = self.0.lock().unwrap();
        let remaining = 65_537_usize.saturating_sub(output.len());
        output.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn observe(database_url: &str, native: bool, level: &str) -> Vec<Value> {
    let options = if native {
        worker_connect_options(database_url).unwrap()
    } else {
        database_url.parse::<PgConnectOptions>().unwrap()
    };
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_env_filter(level)
        .with_writer(move || writer.clone())
        .finish();
    async {
        let mut connection = PgConnection::connect_with(&options).await.unwrap();
        capture.0.lock().unwrap().clear();
        sqlx::query("SELECT 17").execute(&mut connection).await.unwrap();
        // Real database execution exceeds the unchanged one-second SQLx
        // classification threshold; no injected logger or edited clock.
        sqlx::query("SELECT pg_sleep(1.05)").execute(&mut connection).await.unwrap();
        // A server NoticeResponse must remain WARN independently of statement
        // logging policy; this is not a synthetic tracing event.
        sqlx::query("DO $$ BEGIN RAISE WARNING 'synthetic PostgreSQL operational warning'; END $$")
            .execute(&mut connection).await.unwrap();
        tracing::warn!(target: "marty_canvas_sync_worker", operation="synthetic", "synthetic operational warning");
        tracing::error!(target: "marty_canvas_sync_worker", operation="synthetic", "synthetic operational error");
        connection.close().await.unwrap();
    }.with_subscriber(subscriber).await;
    let bytes = capture.0.lock().unwrap();
    assert!(
        bytes.len() <= 65_536,
        "bounded synthetic SQL capture exceeded"
    );
    assert!(bytes.ends_with(b"\n"), "complete JSON records required");
    bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .map(|line| serde_json::from_slice(line).expect("synthetic JSON logging record"))
        .collect()
}

pub async fn replay(database_url: &str) {
    let url = url::Url::parse(database_url).unwrap();
    assert!(url.path().ends_with("_test"));
    for (native, level) in [(false, "warn"), (true, "warn"), (true, "debug")] {
        let records = observe(database_url, native, level).await;
        let query: Vec<_> = records
            .iter()
            .filter(|record| record["target"] == "sqlx::query")
            .collect();
        let operations: Vec<_> = records
            .iter()
            .filter(|record| record["target"] == "marty_canvas_sync_worker")
            .collect();
        let notices: Vec<_> = records
            .iter()
            .filter(|record| record["target"] == "sqlx::postgres::notice")
            .collect();
        assert_eq!(notices.len(), 1, "actual PostgreSQL warning retained");
        assert_eq!(notices[0]["level"], "WARN");
        assert_eq!(
            notices[0]["fields"]["message"],
            "synthetic PostgreSQL operational warning"
        );
        assert_eq!(
            operations.len(),
            2,
            "operational warnings and errors retained"
        );
        assert_eq!(operations[0]["level"], "WARN");
        assert_eq!(operations[1]["level"], "ERROR");
        assert_eq!(
            operations[0]["fields"]["message"],
            "synthetic operational warning"
        );
        assert_eq!(
            operations[1]["fields"]["message"],
            "synthetic operational error"
        );
        if native && level == "warn" {
            assert!(
                query.is_empty(),
                "statement diagnostics must not become operational WARN output"
            );
        } else {
            let slow: Vec<_> = query
                .iter()
                .filter(|record| {
                    record["fields"]["message"]
                        == "slow statement: execution time exceeded alert threshold"
                })
                .collect();
            assert_eq!(slow.len(), 1, "actual slow-query positive control");
            assert_eq!(slow[0]["level"], if native { "DEBUG" } else { "WARN" });
            assert_eq!(slow[0]["fields"]["slow_threshold"], "1s");
            assert!(slow[0]["fields"]["elapsed_secs"]
                .as_f64()
                .is_some_and(|value| value.is_finite() && value >= 1.0));
            assert_eq!(
                query.len(),
                if native { 3 } else { 1 },
                "ordinary SELECT and DO statement DEBUG diagnostics retained"
            );
            if native {
                assert!(query.iter().all(|record| record["level"] == "DEBUG"));
            }
        }
    }
}
