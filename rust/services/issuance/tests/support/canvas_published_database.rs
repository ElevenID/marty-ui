//! Exact-owned disposable Docker database; no deployment URL is accepted.

use serde_json::Value;
use std::{path::Path, process::Command, time::Duration};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.canvas-published-schema";

fn docker(arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(arguments)
        .output()
        .map_err(|_| "Docker execution unavailable".to_owned())?;
    if !output.status.success() {
        return Err(format!("Docker {} failed", arguments[0]));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "Docker returned invalid UTF-8".to_owned())
}

fn inspect(id: &str) -> Result<Value, String> {
    serde_json::from_str(&docker(&["inspect", "--format", "{{json .}}", id])?)
        .map_err(|_| "Invalid container inspection".into())
}

pub struct PublishedDatabase {
    scope: String,
    postgres: Option<String>,
    probe: Option<String>,
    pub url: String,
    pub issued_reviews: Option<Value>,
}

impl PublishedDatabase {
    fn accept_id(id: &str) -> Result<(), String> {
        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err("Docker did not return an exact container ID".into())
        }
    }

    pub async fn start() -> Result<Self, String> {
        Self::start_probe(false).await
    }

    pub async fn start_with_issued_reviews() -> Result<Self, String> {
        Self::start_probe(true).await
    }

    async fn start_probe(issued_reviews: bool) -> Result<Self, String> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let mut owned = Self {
            scope: Uuid::new_v4().to_string(),
            postgres: None,
            probe: None,
            url: String::new(),
            issued_reviews: None,
        };
        let label = format!("{LABEL}={}", owned.scope);
        let postgres = docker(&[
            "create",
            "--pull=never",
            "--label",
            &label,
            "--tmpfs",
            "/var/lib/postgresql/data:rw",
            "--tmpfs",
            "/var/run/postgresql:rw",
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_USER=oracle",
            "--env",
            "POSTGRES_PASSWORD=synthetic-local-only",
            "--env",
            "POSTGRES_DB=canvas_published_schema_test",
            fixture["observed_postgres_image"].as_str().unwrap(),
        ])?;
        Self::accept_id(&postgres)?;
        owned.postgres = Some(postgres.clone());
        eprintln!("Owned published-schema PostgreSQL: {postgres}");
        docker(&["start", &postgres])?;
        loop {
            if docker(&[
                "exec",
                &postgres,
                "pg_isready",
                "-U",
                "oracle",
                "-d",
                "canvas_published_schema_test",
            ])
            .is_ok()
            {
                break;
            }
            if inspect(&postgres)?["State"]["Running"] != true {
                return Err("Owned PostgreSQL exited before readiness".into());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let info = inspect(&postgres)?;
        let port = info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"]
            .as_str()
            .ok_or("Missing owned port")?;
        port.parse::<u16>().map_err(|_| "Invalid owned port")?;
        if info["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] != "127.0.0.1" {
            return Err("Non-loopback test port".into());
        }
        owned.url = format!("postgresql://oracle:synthetic-local-only@127.0.0.1:{port}/canvas_published_schema_test");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap();
        // Mount only the two public test inputs, not the checkout or its Git
        // configuration. The native client connects through an owned loopback
        // port; unlike the Python-only oracle this runner is not network-none.
        let mount = format!("type=bind,source={},target=/verification/scripts/prepare_canvas_published_schema.py,readonly",
            root.join("scripts/prepare_canvas_published_schema.py").display());
        let fixture_mount = format!("type=bind,source={},target=/verification/contracts/canvas-worker-consumer-range-oracle.json,readonly",
            root.join("contracts/canvas-worker-consumer-range-oracle.json").display());
        let network = format!("container:{postgres}");
        let mut arguments = vec![
            "create",
            "--pull=never",
            "--label",
            &label,
            "--network",
            &network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            "TOKEN_HMAC_KEY=synthetic-schema-only-hmac-key",
            "--mount",
            &mount,
            "--mount",
            &fixture_mount,
            "--entrypoint",
            "python",
            fixture["observed_image"].as_str().unwrap(),
            "/verification/scripts/prepare_canvas_published_schema.py",
        ];
        let oracle_script_mount = format!("type=bind,source={},target=/verification/scripts/run_canvas_issued_review_oracle.py,readonly",
            root.join("scripts/run_canvas_issued_review_oracle.py").display());
        let oracle_scenario_mount = format!("type=bind,source={},target=/verification/contracts/canvas-issued-review-scenarios.json,readonly",
            root.join("contracts/canvas-issued-review-scenarios.json").display());
        if issued_reviews {
            // Insert options before the image, never turn them into Python args.
            let index = arguments.len() - 2;
            arguments.splice(
                index..index,
                [
                    "--env",
                    "MARTY_CANVAS_ISSUED_REVIEW_ORACLE=1",
                    "--mount",
                    &oracle_script_mount,
                    "--mount",
                    &oracle_scenario_mount,
                ],
            );
        }
        let probe = docker(&arguments)?;
        Self::accept_id(&probe)?;
        owned.probe = Some(probe.clone());
        eprintln!("Owned published migration probe: {probe}");
        docker(&["start", &probe])?;
        loop {
            let state = inspect(&probe)?;
            if state["State"]["Running"] == false {
                if state["State"]["ExitCode"] != 0 {
                    let report: Value = serde_json::from_str(&docker(&["logs", &probe])?)
                        .map_err(|_| "Probe failed without a structured diagnostic")?;
                    return Err(format!("Published probe failed: class={}, frames={} (exception messages suppressed)",
                        report["error_class"], report["frames"]));
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let report: Value = serde_json::from_str(&docker(&["logs", &probe])?)
            .map_err(|_| "Invalid migration report")?;
        if report["status"] != "passed"
            || report["migration_revisions"] != fixture["migration_revisions"]
            || report["worker_sha256"] != fixture["observed_source_sha256"]
            || report["organization_dependency"] != "synthetic-minimal"
        {
            return Err("Published migration evidence incomplete".into());
        }
        eprintln!("Published migrations verified; organization dependency is synthetic-minimal");
        if issued_reviews {
            owned.issued_reviews = Some(
                report
                    .get("issued_reviews")
                    .ok_or("Missing issued review oracle")?
                    .clone(),
            );
        }
        Ok(owned)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if let Some(probe) = &self.probe {
            let info = inspect(probe)?;
            let network = format!(
                "container:{}",
                self.postgres.as_ref().ok_or("Missing owner database")?
            );
            if info["Id"] != *probe
                || info["Config"]["Labels"][LABEL] != self.scope
                || info["HostConfig"]["NetworkMode"] != network
                || info["HostConfig"]["ReadonlyRootfs"] != true
            {
                return Err("Refusing migration probe cleanup: identity/topology mismatch".into());
            }
            docker(&["rm", "--force", probe])?;
            self.probe = None;
        }
        if let Some(postgres) = &self.postgres {
            let info = inspect(postgres)?;
            if info["Id"] != *postgres
                || info["Config"]["Labels"][LABEL] != self.scope
                || info["Mounts"]
                    .as_array()
                    .is_none_or(|mounts| !mounts.is_empty())
                || info["HostConfig"]["Tmpfs"]["/var/lib/postgresql/data"] != "rw"
                || info["HostConfig"]["Tmpfs"]["/var/run/postgresql"] != "rw"
            {
                return Err("Refusing database cleanup: identity/storage mismatch".into());
            }
            docker(&["rm", "--force", postgres])?;
            self.postgres = None;
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<(), String> {
        self.cleanup()
    }
}

impl Drop for PublishedDatabase {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Owned published-schema cleanup requires inspection: {error}");
        }
    }
}
