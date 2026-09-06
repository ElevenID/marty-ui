//! Signal the actual packaged binary. Never signal the test runner or an
//! unowned PID. Uses only the parent contract's guarded synthetic database.

use std::{
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

use serde_json::Value;
use sqlx::PgPool;

struct OwnedWorker(Child);

impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

impl OwnedWorker {
    fn start(database_url: &str, worker_id: &str) -> Self {
        let mut database_url = url::Url::parse(database_url).unwrap();
        assert!(database_url.path().ends_with("_test"));
        database_url
            .query_pairs_mut()
            .append_pair("application_name", worker_id);
        Self(
            Command::new(env!("CARGO_BIN_EXE_marty-canvas-sync-worker"))
                .env_clear()
                .env("DATABASE_URL", database_url.as_str())
                .env("CANVAS_SYNC_WORKER_ID", worker_id)
                .env("CANVAS_SYNC_WORKER_POLL_SECONDS", "60")
                .env("CANVAS_PORTABLE_INTEGRATION_ENABLED", "false")
                .env(
                    "INTEGRATION_SECRET_MASTER_KEY",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .env("ISSUANCE_API_KEY", "synthetic-process-signal-key")
                .env("CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID", "signal-org")
                .env("CANVAS_LTI_TOOL_ISSUER_DID", "did:web:signal.invalid")
                .env("SIGNING_KEYS_INTERNAL_URL", "https://signing.invalid")
                .env("RUST_LOG", "error")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("actual Canvas worker binary must be packaged"),
        )
    }

    fn signal(&mut self, signal: &str) {
        assert!(matches!(signal, "SIGINT" | "SIGTERM"));
        assert!(
            self.0.try_wait().unwrap().is_none(),
            "worker exited before signal"
        );
        // An unreaped child retains its PID even if it exits between the
        // liveness check and kill. No process-group or broad name targeting.
        let status = Command::new("kill")
            .args(["-s", signal, "--"])
            .arg(self.0.id().to_string())
            .status()
            .expect("Unix signal sender must be available");
        assert!(status.success(), "signal delivery to owned child failed");
    }

    async fn wait(&mut self) -> ExitStatus {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("worker must finish after signal and required drain")
    }
}

async fn await_phase(pool: &PgPool, worker: &mut OwnedWorker, id: &str, blocked: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "worker failed before readiness"
            );
            let reached: bool = if blocked {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name = $1
                     AND state = 'active' AND wait_event_type = 'Lock')",
                )
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
            } else {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM issuance_service.canvas_worker_heartbeats
                     WHERE worker_id = $1 AND metadata->>'phase' = 'idle')",
                )
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap()
            };
            if reached {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actual worker must reach the observed database phase");
}

pub async fn assert_process_signals(pool: &PgPool, database_url: &str) {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-canvas-worker-process-signals.json"
    ))
    .unwrap();
    let cases = fixture["native_cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        4,
        "all frozen process signal cases are mandatory"
    );
    for phase in ["idle", "database_wait"] {
        for (signal, code, drains) in [("SIGINT", 130, false), ("SIGTERM", 0, true)] {
            let matching: Vec<_> = cases
                .iter()
                .filter(|case| case["phase"] == phase && case["signal"] == signal)
                .collect();
            assert_eq!(matching.len(), 1, "each phase/signal pair must occur once");
            assert_eq!(matching[0]["exit_code"], code);
            assert_eq!(matching[0]["drains_blocked_cycle"], drains);
        }
    }
    // The same module compiles on Windows. OS-level POSIX delivery is tested by
    // mandatory Linux CI; never manufacture a Windows POSIX passing result.
    if !cfg!(unix) {
        eprintln!("POSIX worker process signals require the mandatory Linux PostgreSQL gate");
        return;
    }
    for (index, case) in cases.iter().enumerate() {
        eprintln!(
            "worker process signal case {index}: {} {} starting",
            case["phase"], case["signal"]
        );
        sqlx::query("TRUNCATE issuance_service.canvas_evidence_sync_jobs, issuance_service.canvas_evidence_sync_targets, issuance_service.canvas_worker_heartbeats")
            .execute(pool).await.unwrap();
        let blocked = case["phase"] == "database_wait";
        let mut lock = if blocked {
            Some(pool.begin().await.unwrap())
        } else {
            None
        };
        if let Some(transaction) = &mut lock {
            sqlx::query(
                "LOCK TABLE issuance_service.canvas_worker_heartbeats IN ACCESS EXCLUSIVE MODE",
            )
            .execute(&mut **transaction)
            .await
            .unwrap();
        }
        let id = format!("process-signal-{}-{index}", std::process::id());
        let mut worker = OwnedWorker::start(database_url, &id);
        await_phase(pool, &mut worker, &id, blocked).await;
        worker.signal(case["signal"].as_str().unwrap());
        if blocked && case["drains_blocked_cycle"] == true {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), worker.wait())
                    .await
                    .is_err(),
                "graceful termination must not cancel the blocked cycle"
            );
            lock.take().unwrap().rollback().await.unwrap();
        }
        // In the cancellation case retain the lock until AFTER process exit:
        // waiting for a graceful SQL drain would hang and fail this assertion.
        let status = worker.wait().await;
        assert_eq!(status.code().map(i64::from), case["exit_code"].as_i64());
        if let Some(transaction) = lock {
            transaction.rollback().await.unwrap();
        }
        let jobs: i64 =
            sqlx::query_scalar("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            jobs, 0,
            "signal oracle must not create work or contact providers"
        );
        eprintln!("worker process signal case {index}: passed");
    }
    eprintln!("actual worker process signals: idle and blocked SQL SIGINT/SIGTERM passed");
}
