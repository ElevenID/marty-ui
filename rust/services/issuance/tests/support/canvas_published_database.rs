//! Exact-owned disposable Docker database; no deployment URL is accepted.

use serde_json::Value;
use std::{path::Path, process::Command, time::Duration};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.canvas-published-schema";

fn safe_timing_diagnostics(report: &Value) -> Option<&Value> {
    if report["error_class"] != "DeadlineClockDisagreement" {
        return None;
    }
    let diagnostics = report.get("timing_diagnostics")?;
    let fields = diagnostics.as_object()?;
    let keys = [
        "database_elapsed_seconds",
        "monotonic_lower_seconds",
        "monotonic_upper_seconds",
    ];
    (fields.len() == keys.len()
        && keys.iter().all(|key| {
            fields
                .get(*key)
                .and_then(Value::as_f64)
                .is_some_and(|number| number.is_finite() && number.abs() <= 300.0)
        }))
    .then_some(diagnostics)
}

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

fn checked_database_storage(info: &Value, id: &str, scope: &str) -> Result<(), String> {
    if info["Id"] != id
        || info["Config"]["Labels"][LABEL] != scope
        || info["Mounts"]
            .as_array()
            .is_none_or(|mounts| !mounts.is_empty())
        || info["HostConfig"]["Tmpfs"]["/var/lib/postgresql/data"] != "rw"
        || info["HostConfig"]["Tmpfs"]["/var/run/postgresql"] != "rw"
    {
        return Err("Refusing database access: identity/storage mismatch".into());
    }
    Ok(())
}

fn checked_borrow_descriptor(descriptor: &str) -> Result<(String, String), String> {
    // No database URL, credentials, arbitrary Docker arguments or host path can
    // be supplied across this boundary. Errors never echo descriptor contents.
    if descriptor.len() > 256 {
        return Err("Invalid owned database descriptor".into());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Descriptor {
        postgres_id: String,
        scope: String,
    }
    let value: Descriptor =
        serde_json::from_str(descriptor).map_err(|_| "Invalid owned database descriptor")?;
    let id = &value.postgres_id;
    let scope = &value.scope;
    PublishedDatabase::accept_id(id)?;
    let parsed = Uuid::parse_str(scope).map_err(|_| "Invalid owned database scope")?;
    if parsed.get_version_num() != 4
        || parsed.get_variant() != uuid::Variant::RFC4122
        || parsed.to_string() != *scope
    {
        return Err("Invalid owned database scope".into());
    }
    Ok((id.to_owned(), scope.to_owned()))
}

fn checked_borrowed_url(info: &Value, id: &str, scope: &str) -> Result<String, String> {
    checked_database_storage(info, id, scope)?;
    if info["HostConfig"]["Tmpfs"]
        .as_object()
        .is_none_or(|entries| entries.len() != 2)
    {
        return Err("Owned database requires its exact temporary storage topology".into());
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
    ))
    .unwrap();
    if info["State"]["Running"] != true
        || info["Config"]["Image"] != fixture["observed_postgres_image"]
    {
        return Err("Owned database must retain its running pinned image".into());
    }
    let environment = info["Config"]["Env"]
        .as_array()
        .ok_or("Missing owned database configuration")?;
    for (key, expected) in [
        ("POSTGRES_USER", "oracle"),
        ("POSTGRES_PASSWORD", "synthetic-local-only"),
        ("POSTGRES_DB", "canvas_published_schema_test"),
    ] {
        let prefix = format!("{key}=");
        let actual: Vec<_> = environment
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| value.starts_with(&prefix))
            .collect();
        if actual != [format!("{prefix}{expected}")] {
            return Err("Owned database synthetic configuration mismatch".into());
        }
    }
    let ports = info["NetworkSettings"]["Ports"]
        .as_object()
        .ok_or("Missing owned database ports")?;
    let bindings = ports
        .get("5432/tcp")
        .and_then(Value::as_array)
        .ok_or("Missing owned database binding")?;
    if ports.len() != 1 || bindings.len() != 1 || bindings[0]["HostIp"] != "127.0.0.1" {
        return Err("Owned database requires exactly one loopback binding".into());
    }
    let port = bindings[0]["HostPort"]
        .as_str()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or("Invalid owned database port")?;
    Ok(format!(
        "postgresql://oracle:synthetic-local-only@127.0.0.1:{port}/canvas_published_schema_test"
    ))
}

pub struct PublishedDatabase {
    scope: String,
    postgres: Option<String>,
    probe: Option<String>,
    pub url: String,
    pub oracle: Option<Value>,
}

impl PublishedDatabase {
    pub fn borrow_descriptor(&self) -> Result<String, String> {
        let id = self.postgres.as_deref().ok_or("Missing owned database")?;
        let descriptor = serde_json::json!({"postgres_id": id, "scope": self.scope}).to_string();
        if Self::borrowed_url(&descriptor)? != self.url {
            return Err("Owned database binding changed before handoff".into());
        }
        Ok(descriptor)
    }

    /// Read-only handoff: only the surviving outer owner can remove resources.
    pub fn borrowed_url(descriptor: &str) -> Result<String, String> {
        let (id, scope) = checked_borrow_descriptor(descriptor)?;
        checked_borrowed_url(&inspect(&id)?, &id, &scope)
    }

    fn accept_id(id: &str) -> Result<(), String> {
        if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err("Docker did not return an exact container ID".into())
        }
    }

    pub async fn start() -> Result<Self, String> {
        Self::start_probe(None).await
    }

    pub async fn start_with_issued_reviews() -> Result<Self, String> {
        Self::start_probe(Some((
            "issued_review",
            "issued-review",
            "issued_reviews",
            "MARTY_CANVAS_ISSUED_REVIEW_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_mixed_roster() -> Result<Self, String> {
        Self::start_probe(Some((
            "mixed_roster",
            "mixed-roster",
            "mixed_roster",
            "MARTY_CANVAS_MIXED_ROSTER_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_heartbeat_readiness() -> Result<Self, String> {
        Self::start_probe(Some((
            "heartbeat_readiness",
            "heartbeat-readiness",
            "heartbeat_readiness",
            "MARTY_CANVAS_HEARTBEAT_READINESS_ORACLE=1",
        )))
        .await
    }

    async fn start_probe(oracle: Option<(&str, &str, &str, &str)>) -> Result<Self, String> {
        Self::start_probe_with_extra(oracle, None).await
    }

    pub async fn start_with_operations() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "operations",
                "operations",
                "operations",
                "MARTY_CANVAS_OPERATIONS_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_operations_inputs() -> Result<Self, String> {
        Self::start_probe(Some((
            "operations_input",
            "operations-input",
            "operations_inputs",
            "MARTY_CANVAS_OPERATIONS_INPUT_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_enqueue_inputs() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "enqueue_input",
                "enqueue-input",
                "enqueue_inputs",
                "MARTY_CANVAS_ENQUEUE_INPUT_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    async fn start_probe_with_extra(
        oracle: Option<(&str, &str, &str, &str)>,
        extra_fixture: Option<&'static str>,
    ) -> Result<Self, String> {
        Self::start_probe_with_migration(oracle, extra_fixture, false).await
    }

    pub async fn start_with_review_recovery() -> Result<Self, String> {
        Self::start_probe_with_migration(None, None, true).await
    }

    pub async fn start_with_status_provider() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "status_provider",
                "status-provider",
                "status_provider",
                "MARTY_CANVAS_STATUS_PROVIDER_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_provider_configuration() -> Result<Self, String> {
        Self::start_probe(Some((
            "provider_configuration",
            "provider-configuration",
            "provider_configuration",
            "MARTY_CANVAS_PROVIDER_CONFIGURATION_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_utf7_consumer() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "utf7_consumer",
                "utf7-consumer",
                "utf7_consumer",
                "MARTY_CANVAS_UTF7_CONSUMER_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_json_consumer() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "json_consumer",
                "json-consumer",
                "json_consumer",
                "MARTY_CANVAS_JSON_CONSUMER_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_json_depth() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "json_depth",
                "json-depth",
                "json_depth",
                "MARTY_CANVAS_JSON_DEPTH_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_worker_startup() -> Result<Self, String> {
        Self::start_probe(Some((
            "worker_startup",
            "worker-startup",
            "worker_startup",
            "MARTY_CANVAS_WORKER_STARTUP_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_worker_rest() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_rest",
                "worker-rest",
                "worker_rest",
                "MARTY_CANVAS_WORKER_REST_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_facts() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_facts",
                "worker-facts",
                "worker_facts",
                "MARTY_CANVAS_WORKER_FACTS_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_signal(signal: &str) -> Result<Self, String> {
        if !matches!(signal, "SIGINT" | "SIGTERM" | "SIGKILL") {
            return Err("unsupported owned worker signal".into());
        }
        let flag = format!("MARTY_CANVAS_WORKER_PROVIDER_SIGNAL={signal}");
        Self::start_probe_with_extra(
            Some((
                "worker_provider_signals",
                "worker-provider-signals",
                "worker_provider_signals",
                &flag,
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_retry_after(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-retry-after-scenarios.json"),
            "worker_retry_after",
            "worker-retry-after",
            "MARTY_CANVAS_WORKER_RETRY_AFTER_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-scenarios.json"),
            "worker_oauth_revocation",
            "worker-oauth-revocation",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_fence(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-fence-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-fence",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_FENCE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_patch(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-patch-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-patch",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_PATCH_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_retry_after(
        case: &str,
    ) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-oauth-revocation-retry-after-scenarios.json"),
            "worker_oauth_revocation", "worker-oauth-revocation-retry-after",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_RETRY_AFTER_CASE",
        ).await
    }

    pub async fn start_with_worker_validation(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-validation-scenarios.json"),
            "worker_validation",
            "worker-validation",
            "MARTY_CANVAS_WORKER_VALIDATION_CASE",
        )
        .await
    }

    pub async fn start_with_worker_roster_failure(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-roster-failure-scenarios.json"),
            "worker_roster_failure",
            "worker-roster-failure",
            "MARTY_CANVAS_WORKER_ROSTER_FAILURE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_deadline(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-deadline-scenarios.json"),
            "worker_deadline",
            "worker-deadline",
            "MARTY_CANVAS_WORKER_DEADLINE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_timeout(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-timeout-scenarios.json"),
            "worker_timeout",
            "worker-timeout",
            "MARTY_CANVAS_WORKER_TIMEOUT_CASE",
        )
        .await
    }

    pub async fn start_with_worker_dispatch(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-dispatch-scenarios.json"),
            "worker_dispatch",
            "worker-dispatch",
            "MARTY_CANVAS_WORKER_DISPATCH_CASE",
        )
        .await
    }

    pub async fn start_with_worker_mixed_roster(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-mixed-roster-scenarios.json"),
            "worker_mixed_roster",
            "worker-mixed-roster",
            "MARTY_CANVAS_WORKER_MIXED_ROSTER_CASE",
        )
        .await
    }

    pub async fn start_with_worker_resources_unavailable(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-resources-unavailable-scenarios.json"
            ),
            "worker_resources_unavailable",
            "worker-resources-unavailable",
            "MARTY_CANVAS_WORKER_RESOURCES_UNAVAILABLE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_resource_race(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!("../../../../../contracts/canvas-worker-resource-race-scenarios.json"),
            "worker_resource_race",
            "worker-resource-race",
            "MARTY_CANVAS_WORKER_RESOURCE_RACE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_queue(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-queue-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-queue",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_QUEUE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_counters(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-counters-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-counters",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_COUNTERS_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_secrets(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-secrets-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-secrets",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_SECRETS_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_selection(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-selection-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-selection",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_SELECTION_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_lease(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-lease-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-lease",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_LEASE_CASE",
        )
        .await
    }

    pub async fn start_with_worker_oauth_revocation_backoff(case: &str) -> Result<Self, String> {
        Self::start_with_worker_case(
            case,
            include_str!(
                "../../../../../contracts/canvas-worker-oauth-revocation-backoff-scenarios.json"
            ),
            "worker_oauth_revocation",
            "worker-oauth-revocation-backoff",
            "MARTY_CANVAS_WORKER_OAUTH_REVOCATION_BACKOFF_CASE",
        )
        .await
    }

    async fn start_with_worker_case(
        case: &str,
        source: &str,
        script: &str,
        scenario: &str,
        flag_name: &str,
    ) -> Result<Self, String> {
        let scenarios: Value = serde_json::from_str(source).unwrap();
        if !scenarios["cases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["name"] == case)
        {
            return Err("unsupported owned worker matrix case".into());
        }
        let flag = format!("{flag_name}={case}");
        Self::start_probe_with_extra(
            Some((script, scenario, script, &flag)),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_recovery(case: &str) -> Result<Self, String> {
        if !matches!(case, "renewal" | "recovery") {
            return Err("unsupported owned worker recovery case".into());
        }
        let flag = format!("MARTY_CANVAS_WORKER_PROVIDER_RECOVERY={case}");
        Self::start_probe_with_extra(
            Some((
                "worker_provider_recovery",
                "worker-provider-recovery",
                "worker_provider_recovery",
                &flag,
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_reclaimers_retry() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_reclaimers_retry",
                "worker-reclaimers-retry",
                "worker_reclaimers_retry",
                "MARTY_CANVAS_WORKER_RECLAIMERS_RETRY_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_reclaimers() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_reclaimers",
                "worker-reclaimers",
                "worker_reclaimers",
                "MARTY_CANVAS_WORKER_RECLAIMERS_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_concurrent() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_concurrent",
                "worker-concurrent",
                "worker_concurrent",
                "MARTY_CANVAS_WORKER_CONCURRENT_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_final() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_provider_final",
                "worker-provider-final",
                "worker_provider_final",
                "MARTY_CANVAS_WORKER_PROVIDER_FINAL_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_generation() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_provider_generation",
                "worker-provider-generation",
                "worker_provider_generation",
                "MARTY_CANVAS_WORKER_PROVIDER_GENERATION_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_completion() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_provider_completion",
                "worker-provider-completion",
                "worker_provider_completion",
                "MARTY_CANVAS_WORKER_PROVIDER_COMPLETION_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_provider_recovery_first() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_provider_recovery_first",
                "worker-provider-recovery-first",
                "worker_provider_recovery_first",
                "MARTY_CANVAS_WORKER_PROVIDER_RECOVERY_FIRST_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_worker_retry() -> Result<Self, String> {
        Self::start_probe_with_extra(
            Some((
                "worker_retry",
                "worker-retry",
                "worker_retry",
                "MARTY_CANVAS_WORKER_RETRY_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
        )
        .await
    }

    pub async fn start_with_validation_boundary() -> Result<Self, String> {
        Self::start_probe(Some((
            "validation_boundary",
            "validation-boundary",
            "validation_boundary",
            "MARTY_CANVAS_VALIDATION_BOUNDARY_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_timeout_consumer() -> Result<Self, String> {
        Self::start_probe(Some((
            "timeout_consumer",
            "timeout-consumer",
            "timeout_consumer",
            "MARTY_CANVAS_TIMEOUT_CONSUMER_ORACLE=1",
        )))
        .await
    }

    pub async fn start_with_review_lifecycle() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "operations",
                "review-lifecycle",
                "review_lifecycle",
                "MARTY_CANVAS_REVIEW_LIFECYCLE_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_review_inputs() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "operations",
                "review-input",
                "review_inputs",
                "MARTY_CANVAS_REVIEW_INPUT_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    pub async fn start_with_operations_recovery() -> Result<Self, String> {
        Self::start_probe_with_migration(
            Some((
                "operations",
                "operations",
                "operations",
                "MARTY_CANVAS_OPERATIONS_ORACLE=1",
            )),
            Some("canvas-issued-review-scenarios.json"),
            true,
        )
        .await
    }

    async fn start_probe_with_migration(
        oracle: Option<(&str, &str, &str, &str)>,
        extra_fixture: Option<&'static str>,
        recovery_schema: bool,
    ) -> Result<Self, String> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let mut owned = Self {
            scope: Uuid::new_v4().to_string(),
            postgres: None,
            probe: None,
            url: String::new(),
            oracle: None,
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
        let (script, scenario, report_key, flag) = oracle.unwrap_or_default();
        let multibyte_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_multibyte_codec_oracle.py,readonly",
            root.join("scripts/canvas_multibyte_codec_oracle.py").display()
        );
        let gb18030_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_gb18030_codec_oracle.py,readonly",
            root.join("scripts/canvas_gb18030_codec_oracle.py").display()
        );
        let euc_kr_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_euc_kr_codec_oracle.py,readonly",
            root.join("scripts/canvas_euc_kr_codec_oracle.py").display()
        );
        let iso2022_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_iso2022_codec_oracle.py,readonly",
            root.join("scripts/canvas_iso2022_codec_oracle.py").display()
        );
        let ordinal_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_charset_ordinal_oracle.py,readonly",
            root.join("scripts/canvas_charset_ordinal_oracle.py").display()
        );
        let utf7_mount = format!(
            "type=bind,source={},target=/verification/scripts/canvas_utf7_codec_oracle.py,readonly",
            root.join("scripts/canvas_utf7_codec_oracle.py").display()
        );
        let worker_trust_mount = format!(
            "type=bind,source={},target=/verification/worker_trust/sitecustomize.py,readonly",
            root.join("contracts/fixtures/canvas_worker_test_trust.py")
                .display()
        );
        let worker_https = matches!(
            script,
            "worker_rest"
                | "worker_facts"
                | "worker_oauth_revocation"
                | "worker_retry"
                | "worker_retry_after"
                | "worker_validation"
                | "worker_roster_failure"
                | "worker_resource_race"
                | "worker_resources_unavailable"
                | "worker_mixed_roster"
                | "worker_dispatch"
                | "worker_deadline"
                | "worker_timeout"
                | "worker_provider_signals"
                | "worker_provider_recovery"
                | "worker_provider_final"
                | "worker_provider_generation"
                | "worker_provider_completion"
                | "worker_provider_recovery_first"
                | "worker_concurrent"
                | "worker_reclaimers"
                | "worker_reclaimers_retry"
        );
        if worker_https {
            let index = arguments.len() - 2;
            arguments.splice(
                index..index,
                [
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
                    "--mount",
                    &worker_trust_mount,
                ],
            );
        }
        if script == "timeout_consumer" {
            // Only the TLS oracle needs ephemeral certificate storage. Preserve
            // the read-only image and all host mounts; nothing is persisted.
            let index = arguments.len() - 2;
            arguments.splice(
                index..index,
                [
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
                    "--mount",
                    &multibyte_mount,
                    "--mount",
                    &gb18030_mount,
                    "--mount",
                    &euc_kr_mount,
                    "--mount",
                    &iso2022_mount,
                    "--mount",
                    &ordinal_mount,
                    "--mount",
                    &utf7_mount,
                ],
            );
        }
        let mut consumer_helpers: Vec<String> =
            if matches!(script, "utf7_consumer" | "json_consumer" | "json_depth") {
                [
                    "run_canvas_validation_boundary_oracle.py",
                    "run_canvas_status_provider_oracle.py",
                    "canvas_observation_values.py",
                    "canvas_json_tree_observation.py",
                ]
                .into_iter()
                .map(|name| {
                    let path = format!("scripts/{name}");
                    format!(
                        "type=bind,source={},target=/verification/{path},readonly",
                        root.join(&path).display()
                    )
                })
                .collect()
            } else if worker_https {
                [
                    "run_canvas_worker_startup_oracle.py",
                    "test_canvas_lti_https.py",
                    "canvas_worker_https_fixture.py",
                ]
                .into_iter()
                .map(|name| {
                    format!(
                        "type=bind,source={},target=/verification/scripts/{name},readonly",
                        root.join("scripts").join(name).display()
                    )
                })
                .collect()
            } else {
                Vec::new()
            };
        if matches!(
            script,
            "worker_facts"
                | "worker_retry"
                | "worker_oauth_revocation"
                | "worker_retry_after"
                | "worker_validation"
                | "worker_roster_failure"
                | "worker_resource_race"
                | "worker_resources_unavailable"
                | "worker_mixed_roster"
                | "worker_dispatch"
                | "worker_deadline"
                | "worker_timeout"
                | "worker_provider_signals"
                | "worker_provider_recovery"
                | "worker_provider_final"
                | "worker_provider_generation"
                | "worker_provider_completion"
                | "worker_provider_recovery_first"
                | "worker_concurrent"
                | "worker_reclaimers"
                | "worker_reclaimers_retry"
        ) {
            consumer_helpers.extend(
                [
                    "scripts/run_canvas_worker_rest_oracle.py",
                    "contracts/canvas-worker-rest-scenarios.json",
                ]
                .into_iter()
                .map(|path| {
                    format!(
                        "type=bind,source={},target=/verification/{path},readonly",
                        root.join(path).display()
                    )
                }),
            );
        }
        if matches!(
            script,
            "worker_provider_recovery"
                | "worker_provider_final"
                | "worker_provider_generation"
                | "worker_provider_completion"
                | "worker_provider_recovery_first"
                | "worker_concurrent"
                | "worker_reclaimers"
                | "worker_reclaimers_retry"
        ) {
            let path = "scripts/run_canvas_worker_provider_signals_oracle.py";
            consumer_helpers.push(format!(
                "type=bind,source={},target=/verification/{path},readonly",
                root.join(path).display()
            ));
        }
        if matches!(
            script,
            "worker_provider_final"
                | "worker_provider_generation"
                | "worker_provider_completion"
                | "worker_provider_recovery_first"
                | "worker_concurrent"
                | "worker_reclaimers"
                | "worker_reclaimers_retry"
        ) {
            let path = "scripts/run_canvas_worker_provider_recovery_oracle.py";
            consumer_helpers.push(format!(
                "type=bind,source={},target=/verification/{path},readonly",
                root.join(path).display()
            ));
        }
        let extra_scenarios: &[&str] = match script {
            "worker_deadline" => &[
                "scripts/canvas_worker_deadline_https_fixture.py",
                "scripts/canvas_worker_output_capture.py",
                "contracts/canvas-worker-facts-scenarios.json",
                "contracts/canvas-worker-validation-scenarios.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_timeout" => &[
                "scripts/canvas_worker_timeout_https_fixture.py",
                "scripts/canvas_worker_output_capture.py",
                "contracts/canvas-worker-deadline-scenarios.json",
                "contracts/canvas-worker-retry-scenarios.json",
                "contracts/canvas-worker-validation-scenarios.json",
                "contracts/canvas-worker-roster-failure-scenarios.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_dispatch" => &[
                "scripts/canvas_worker_dispatch_hooks.py",
                "contracts/canvas-worker-validation-scenarios.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_mixed_roster" => &[
                "scripts/canvas_worker_mixed_roster_https_fixture.py",
                "contracts/canvas-mixed-roster-scenarios.json",
                "contracts/canvas-mixed-roster-oracle.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_resources_unavailable" => &[
                "contracts/canvas-worker-validation-scenarios.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_roster_failure" => &["contracts/canvas-worker-retry-scenarios.json"],
            "worker_resource_race" => &[
                "contracts/canvas-worker-retry-scenarios.json",
                "scripts/run_canvas_worker_provider_signals_oracle.py",
                "scripts/run_canvas_worker_provider_recovery_oracle.py",
            ],
            "worker_provider_recovery_first" => &[
                "contracts/canvas-worker-provider-completion-scenarios.json",
                "contracts/canvas-worker-provider-final-scenarios.json",
                "scripts/run_canvas_worker_provider_completion_oracle.py",
            ],
            "worker_provider_generation" | "worker_provider_completion" => {
                &["contracts/canvas-worker-provider-final-scenarios.json"]
            }
            "worker_oauth_revocation" if scenario == "worker-oauth-revocation-counters" => &[
                "contracts/canvas-worker-oauth-revocation-scenarios.json",
                "contracts/canvas-worker-oauth-revocation-fence-scenarios.json",
                "scripts/run_canvas_worker_single_cycle.py",
            ],
            "worker_oauth_revocation"
                if matches!(
                    scenario,
                    "worker-oauth-revocation-fence"
                        | "worker-oauth-revocation-secrets"
                        | "worker-oauth-revocation-patch"
                        | "worker-oauth-revocation-retry-after"
                        | "worker-oauth-revocation-backoff"
                        | "worker-oauth-revocation-queue"
                ) =>
            {
                &["contracts/canvas-worker-oauth-revocation-scenarios.json"]
            }
            "worker_oauth_revocation"
                if matches!(
                    scenario,
                    "worker-oauth-revocation-lease" | "worker-oauth-revocation-selection"
                ) =>
            {
                &[
                    "contracts/canvas-worker-oauth-revocation-scenarios.json",
                    "contracts/canvas-worker-oauth-revocation-queue-scenarios.json",
                ]
            }
            "worker_reclaimers" => &[
                "contracts/canvas-worker-provider-final-scenarios.json",
                "contracts/canvas-worker-concurrent-scenarios.json",
            ],
            "worker_reclaimers_retry" => &[
                "contracts/canvas-worker-provider-recovery-scenarios.json",
                "contracts/canvas-worker-reclaimers-scenarios.json",
                "contracts/canvas-worker-concurrent-scenarios.json",
            ],
            _ => &[],
        };
        for path in extra_scenarios {
            consumer_helpers.push(format!(
                "type=bind,source={},target=/verification/{path},readonly",
                root.join(path).display()
            ));
        }
        for mount in &consumer_helpers {
            let index = arguments.len() - 2;
            arguments.splice(index..index, ["--mount", mount]);
        }
        let script_path = format!("scripts/run_canvas_{script}_oracle.py");
        let scenario_path = format!("contracts/canvas-{scenario}-scenarios.json");
        let oracle_script_mount = format!(
            "type=bind,source={},target=/verification/{script_path},readonly",
            root.join(&script_path).display()
        );
        let oracle_scenario_mount = format!(
            "type=bind,source={},target=/verification/{scenario_path},readonly",
            root.join(&scenario_path).display()
        );
        if oracle.is_some() {
            // Insert options before the image, never turn them into Python args.
            let index = arguments.len() - 2;
            arguments.splice(
                index..index,
                [
                    "--env",
                    flag,
                    "--mount",
                    &oracle_script_mount,
                    "--mount",
                    &oracle_scenario_mount,
                ],
            );
        }
        // The operations oracle reuses the existing published-schema seed.
        // Only this private, statically selected fixture is additionally mounted.
        let extra_mount = extra_fixture.map(|name| {
            format!(
                "type=bind,source={},target=/verification/contracts/{name},readonly",
                root.join("contracts").join(name).display()
            )
        });
        if let Some(mount) = extra_mount.as_deref() {
            let index = arguments.len() - 2;
            arguments.splice(index..index, ["--mount", mount]);
        }
        let recovery: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-review-recovery-migration.json"
        ))
        .unwrap();
        let recovery_mount = format!(
            "type=bind,source={},target=/app/{},readonly",
            root.join("contracts/fixtures/canvas_review_recovery_claim.py")
                .display(),
            recovery["source"].as_str().unwrap()
        );
        let recovery_provenance = format!("type=bind,source={},target=/verification/contracts/canvas-review-recovery-migration.json,readonly",
            root.join("contracts/canvas-review-recovery-migration.json").display());
        if recovery_schema {
            let index = arguments.len() - 2;
            arguments.splice(
                index..index,
                [
                    "--env",
                    "MARTY_CANVAS_REVIEW_RECOVERY_SCHEMA=1",
                    "--mount",
                    &recovery_mount,
                    "--mount",
                    &recovery_provenance,
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
                    let timing = safe_timing_diagnostics(&report)
                        .map(|value| format!(", timing_diagnostics={value}"))
                        .unwrap_or_default();
                    return Err(format!("Published probe failed: class={}, frames={}{timing} (exception messages suppressed)",
                        report["error_class"], report["frames"]));
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let report: Value = serde_json::from_str(&docker(&["logs", &probe])?)
            .map_err(|_| "Invalid migration report")?;
        let expected_revisions = if recovery_schema {
            serde_json::json!([recovery["revision"]])
        } else {
            fixture["migration_revisions"].clone()
        };
        if report["status"] != "passed"
            || report["migration_revisions"] != expected_revisions
            || report["worker_sha256"] != fixture["observed_source_sha256"]
            || report["organization_dependency"] != "synthetic-minimal"
        {
            return Err("Published migration evidence incomplete".into());
        }
        if recovery_schema && report["review_recovery_overlay"] != recovery {
            return Err("Official review recovery provenance incomplete".into());
        }
        eprintln!("Published migrations verified; organization dependency is synthetic-minimal");
        if oracle.is_some() {
            owned.oracle = Some(
                report
                    .get(report_key)
                    .ok_or("Missing published behavior oracle")?
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
            checked_database_storage(&info, postgres, &self.scope)?;
            docker(&["rm", "--force", postgres])?;
            self.postgres = None;
        }
        Ok(())
    }

    pub fn close(mut self) -> Result<(), String> {
        self.cleanup()
    }

    pub fn close_verified(mut self) -> Result<(), String> {
        let ids: Vec<_> = [&self.probe, &self.postgres]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        self.cleanup()?;
        for id in ids {
            Self::accept_id(&id)?;
            let filter = format!("id={id}");
            if !docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?.is_empty() {
                return Err("Exact owned database resource remained after cleanup".into());
            }
        }
        Ok(())
    }
}

impl Drop for PublishedDatabase {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("Owned published-schema cleanup requires inspection: {error}");
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use serde_json::json;

    fn borrow_fixture() -> (Value, String, String) {
        let id = "a".repeat(64);
        let scope = "12345678-1234-4234-8234-123456789abc".to_owned();
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../../contracts/canvas-worker-consumer-range-oracle.json"
        ))
        .unwrap();
        let info = json!({
            "Id": id,
            "Config": { "Labels": { LABEL: scope }, "Image": fixture["observed_postgres_image"],
                "Env": ["POSTGRES_USER=oracle", "POSTGRES_PASSWORD=synthetic-local-only", "POSTGRES_DB=canvas_published_schema_test"] },
            "Mounts": [],
            "HostConfig": {"Tmpfs": {"/var/lib/postgresql/data": "rw", "/var/run/postgresql": "rw"}},
            "State": {"Running": true},
            "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "25432"}]}}
        });
        (info, id, scope)
    }

    #[test]
    fn borrowed_database_descriptor_is_closed_and_never_accepts_connection_strings() {
        let (_, id, scope) = borrow_fixture();
        let valid = json!({"postgres_id": id, "scope": scope});
        assert_eq!(
            checked_borrow_descriptor(&valid.to_string()).unwrap(),
            (id, scope)
        );
        for rejected in [
            json!("postgresql://private-sentinel@deployment.invalid/live"),
            json!({"postgres_id": "--all", "scope": valid["scope"]}),
            json!({"postgres_id": valid["postgres_id"], "scope": "private-sentinel"}),
            json!({"postgres_id": valid["postgres_id"], "scope": "00000000-0000-0000-0000-000000000000"}),
            json!({"postgres_id": valid["postgres_id"], "scope": valid["scope"], "url": "private-sentinel"}),
            json!({"scope": valid["scope"]}),
            json!([]),
            json!(null),
        ] {
            let error = checked_borrow_descriptor(&rejected.to_string()).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        assert!(checked_borrow_descriptor(&"x".repeat(257)).is_err());
        let duplicate = format!(
            "{{\"postgres_id\":{},\"scope\":{},\"scope\":{}}}",
            valid["postgres_id"], valid["scope"], valid["scope"]
        );
        assert!(checked_borrow_descriptor(&duplicate).is_err());
        let non_rfc = json!({"postgres_id": valid["postgres_id"], "scope": "12345678-1234-4234-1234-123456789abc"});
        assert!(checked_borrow_descriptor(&non_rfc.to_string()).is_err());
    }

    #[test]
    fn borrowed_database_requires_exact_identity_storage_image_and_loopback_configuration() {
        let (valid, id, scope) = borrow_fixture();
        assert_eq!(
            checked_borrowed_url(&valid, &id, &scope).unwrap(),
            "postgresql://oracle:synthetic-local-only@127.0.0.1:25432/canvas_published_schema_test"
        );
        for (pointer, value) in [
            ("/Id", json!("b".repeat(64))),
            ("/Config/Image", json!("wrong-image")),
            ("/Config/Env", json!(["POSTGRES_USER=private-sentinel"])),
            ("/State/Running", json!(false)),
            ("/Mounts", json!([{"Source": "private-sentinel"}])),
            ("/HostConfig/Tmpfs", json!({})),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostIp",
                json!("0.0.0.0"),
            ),
            ("/NetworkSettings/Ports/5432~1tcp/0/HostPort", json!("0")),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostPort",
                json!("65536"),
            ),
            (
                "/NetworkSettings/Ports/5432~1tcp/0/HostPort",
                json!("private-sentinel"),
            ),
            ("/NetworkSettings/Ports/5432~1tcp", json!([])),
        ] {
            let mut info = valid.clone();
            *info.pointer_mut(pointer).unwrap() = value;
            let error = checked_borrowed_url(&info, &id, &scope).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        let mut wrong_scope = valid.clone();
        wrong_scope["Config"]["Labels"][LABEL] = json!("wrong-scope");
        assert!(checked_borrowed_url(&wrong_scope, &id, &scope).is_err());
        let mut extra_tmpfs = valid.clone();
        extra_tmpfs["HostConfig"]["Tmpfs"]["/unexpected"] = json!("rw");
        assert!(checked_borrowed_url(&extra_tmpfs, &id, &scope).is_err());
        let mut duplicate = valid.clone();
        duplicate["Config"]["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!("POSTGRES_USER=oracle"));
        assert!(checked_borrowed_url(&duplicate, &id, &scope).is_err());
        let mut extra = valid.clone();
        extra["NetworkSettings"]["Ports"]["1234/tcp"] = json!([]);
        assert!(checked_borrowed_url(&extra, &id, &scope).is_err());
        let mut doubled = valid.clone();
        let binding = doubled["NetworkSettings"]["Ports"]["5432/tcp"][0].clone();
        doubled["NetworkSettings"]["Ports"]["5432/tcp"]
            .as_array_mut()
            .unwrap()
            .push(binding);
        assert!(checked_borrowed_url(&doubled, &id, &scope).is_err());
    }

    #[test]
    fn timing_diagnostic_forwarding_accepts_only_closed_bounded_numeric_fields() {
        let valid = json!({
            "error_class": "DeadlineClockDisagreement",
            "timing_diagnostics": {
                "database_elapsed_seconds": 30.1,
                "monotonic_lower_seconds": 29.4,
                "monotonic_upper_seconds": 30.5,
            },
        });
        assert_eq!(
            safe_timing_diagnostics(&valid),
            valid.get("timing_diagnostics")
        );
        for rejected in [
            json!(true),
            json!("synthetic-secret"),
            Value::Null,
            json!([]),
            json!({"payload": "synthetic-secret"}),
            json!(300.001),
            json!(-300.001),
        ] {
            let mut report = valid.clone();
            report["timing_diagnostics"]["database_elapsed_seconds"] = rejected;
            assert!(safe_timing_diagnostics(&report).is_none());
        }
        for boundary in [-300.0, 300.0] {
            let mut report = valid.clone();
            report["timing_diagnostics"]["database_elapsed_seconds"] = json!(boundary);
            assert!(safe_timing_diagnostics(&report).is_some());
        }
        let mut extra = valid.clone();
        extra["timing_diagnostics"]["unexpected"] = json!("synthetic-secret");
        assert!(safe_timing_diagnostics(&extra).is_none());
        let mut missing = valid.clone();
        missing["timing_diagnostics"]
            .as_object_mut()
            .unwrap()
            .remove("monotonic_lower_seconds");
        assert!(safe_timing_diagnostics(&missing).is_none());
        let mut wrong_class = valid;
        wrong_class["error_class"] = json!("UnrelatedError");
        assert!(safe_timing_diagnostics(&wrong_class).is_none());
    }
}
