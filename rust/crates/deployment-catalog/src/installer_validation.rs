//! Bounded, read-only deployment checks. Passing is not installed-journey qualification.
#![cfg(target_os = "linux")]
use crate::{
    installer_doctor,
    installer_runtime::DockerRunner,
    installer_state::LockedInspection,
    installer_trust::{self, TrustInfo},
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const DEADLINE: Duration = Duration::from_secs(90);
const MAX_BODY: usize = 65536;

#[derive(Serialize)]
struct Check {
    name: &'static str,
    required: bool,
    status: &'static str,
    code: &'static str,
}
impl Check {
    fn required(name: &'static str, passed: bool, failure: &'static str) -> Self {
        Self {
            name,
            required: true,
            status: if passed { "pass" } else { "fail" },
            code: if passed { "observed" } else { failure },
        }
    }
}

fn services_passed(v: &Value) -> bool {
    v["services_observed"] == true && v["all_expected_states_observed"] == true
}
fn security_summary(v: &Value) -> Option<Value> {
    let mut summary = serde_json::Map::new();
    for (role, service) in v["services"].as_object()? {
        let Some(posture) = service.get("security_posture") else {
            summary.insert(role.clone(), Value::Null);
            continue;
        };
        if posture["source"] != "docker_inspect"
            || !["root", "numeric_non_root", "named_unresolved"]
                .contains(&posture["user_class"].as_str()?)
        {
            return None;
        }
        summary.insert(
            role.clone(),
            json!({
                "source":"docker_inspect",
                "user_class":posture["user_class"],
                "privileged":posture["privileged"].as_bool()?,
                "read_only_rootfs":posture["read_only_rootfs"].as_bool()?,
                "no_new_privileges":posture["no_new_privileges"].as_bool()?,
                "cap_drop_all":posture["cap_drop_all"].as_bool()?,
                "cap_add_count":posture["cap_add_count"].as_u64()?,
                "device_count":posture["device_count"].as_u64()?,
            "writable_inspected_mount_count":posture["writable_inspected_mount_count"].as_u64()?,
                "published_port_count":posture["published_port_count"].as_u64()?,
            }),
        );
    }
    Some(Value::Object(summary))
}
fn valid_origin(origin: &str) -> Option<u16> {
    let port = origin.strip_prefix("https://localhost:")?;
    let number = port.parse::<u16>().ok()?;
    (number >= 1024 && port == number.to_string()).then_some(number)
}
fn client(trust: &TrustInfo) -> Result<reqwest::Client> {
    let port = valid_origin(&trust.origin).ok_or("invalid bound validation origin")?;
    let ca = reqwest::Certificate::from_pem(trust.ca_certificate_pem.as_bytes())
        .map_err(|_| "invalid bound validation CA")?;
    reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_certs_only([ca])
        .tls_info(true)
        .resolve("localhost", SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "validation transport unavailable".into())
}
struct Probe {
    tls_verified: bool,
    document: Option<Value>,
}
async fn bounded_json(mut response: reqwest::Response) -> Option<Value> {
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).ok()
}
async fn get(client: &reqwest::Client, trust: &TrustInfo, path: &str) -> Probe {
    let failed = || Probe {
        tls_verified: false,
        document: None,
    };
    let Ok(response) = client.get(format!("{}{path}", trust.origin)).send().await else {
        return failed();
    };
    let Some(peer) = response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|v| v.peer_certificate())
    else {
        return failed();
    };
    if format!("{:x}", Sha256::digest(peer)) != trust.certificate_der_sha256 {
        return failed();
    }
    Probe {
        tls_verified: true,
        document: bounded_json(response).await,
    }
}
fn same_origin(value: &Value, origin: &str) -> bool {
    value
        .as_str()
        .and_then(|s| url::Url::parse(s).ok())
        .is_some_and(|u| {
            u.origin().ascii_serialization() == origin
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none()
        })
}
fn issuer_valid(v: &Value, origin: &str) -> bool {
    v["credential_endpoint"] == format!("{origin}/v1/issuance/credential")
        && v["credential_issuer"] == origin
        && v["credential_configurations_supported"]
            .as_object()
            .is_some_and(|v| !v.is_empty())
        && v.get("authorization_servers").is_none_or(|servers| {
            servers
                .as_array()
                .is_some_and(|a| !a.is_empty() && a.iter().all(|s| s == origin))
        })
}
fn authorization_valid(v: &Value, issuer: &Value, origin: &str) -> bool {
    let expected = issuer
        .get("authorization_servers")
        .and_then(|v| v.get(0))
        .unwrap_or(&issuer["credential_issuer"]);
    v["issuer"] == *expected
        && same_origin(&v["issuer"], origin)
        && v["token_endpoint"] == format!("{origin}/v1/issuance/token")
        && v["authorization_endpoint"] == format!("{origin}/v1/issuance/authorize")
}
fn required_services(state: &LockedInspection) -> Result<Vec<String>> {
    let plan: Value = serde_json::from_slice(&state.read_evidence("application-plan.json")?)
        .map_err(|_| "invalid application readiness configuration")?;
    parse_required_services(
        plan["model"]["services"]["gateway"]["environment"]["GATEWAY_REQUIRED_READY_SERVICES"]
            .as_str()
            .unwrap_or(""),
    )
}
fn parse_required_services(raw: &str) -> Result<Vec<String>> {
    let services: Vec<String> = raw.split(',').map(str::to_owned).collect();
    let valid = regex::Regex::new(r"\A[a-z][a-z0-9-]{0,63}\z").unwrap();
    if services.is_empty()
        || services.len() > 32
        || services.iter().any(|s| !valid.is_match(s))
        || services
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != services.len()
    {
        return Err("invalid application readiness configuration".into());
    }
    Ok(services)
}
fn readiness_valid(value: &Value, required: &[String]) -> bool {
    value["status"] == "ready"
        && value["service"] == "api-gateway"
        && value["services"].as_object().is_some_and(|services| {
            services.len() == required.len()
                && required
                    .iter()
                    .all(|name| services.get(name).is_some_and(|v| v["status"] == "healthy"))
        })
}
async fn public_checks(trust: &TrustInfo, required: &[String]) -> Vec<bool> {
    let Ok(client) = client(trust) else {
        return vec![false; 5];
    };
    let health = get(&client, trust, "/health").await;
    let services = get(&client, trust, "/health/ready").await;
    let issuer = get(&client, trust, "/.well-known/openid-credential-issuer").await;
    let authorization = get(&client, trust, "/.well-known/oauth-authorization-server").await;
    let tls = [&health, &services, &issuer, &authorization]
        .iter()
        .all(|p| p.tls_verified);
    let (health, services, issuer, authorization) = (
        health.document,
        services.document,
        issuer.document,
        authorization.document,
    );
    vec![
        tls,
        health.is_some_and(|v| v["status"] == "healthy" && v["service"] == "api-gateway"),
        services.is_some_and(|v| readiness_valid(&v, required)),
        issuer
            .as_ref()
            .is_some_and(|v| issuer_valid(v, &trust.origin)),
        issuer
            .as_ref()
            .zip(authorization.as_ref())
            .is_some_and(|(i, a)| authorization_valid(a, i, &trust.origin)),
    ]
}

/// The caller retains this lock across Docker, HTTPS, re-observation and report persistence.
pub(crate) fn run_locked(
    installation: &Path,
    docker: &Path,
    state: &LockedInspection,
    emit_json: bool,
) -> Result<()> {
    state.require_path_binding(installation)?;
    let started = Instant::now();
    let deadline = started + DEADLINE;
    let journal = state.journal();
    let runtime = journal.runtime();
    let runner = runtime
        .ok_or_else(|| "missing recorded Docker binding".to_owned())
        .and_then(|r| DockerRunner::from_binding(docker, r, installation))
        .map(|r| r.with_deadline(deadline));
    let before = runner.as_ref().ok().and_then(|d| {
        d.preflight()
            .ok()
            .and_then(|_| installer_doctor::services(state, installation, d).ok())
    });
    let owned = before.as_ref().is_some_and(services_passed);
    let trust = if owned {
        installer_trust::inspect_locked(installation, state).ok()
    } else {
        None
    };
    let mut observed = vec![false; 5];
    let required = required_services(state).ok();
    if let (Some(trust), Some(required)) = (&trust, &required) {
        if let (Ok(rt), Some(remaining)) = (
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
            deadline.checked_duration_since(Instant::now()),
        ) {
            observed = rt.block_on(async {
                tokio::time::timeout(remaining, public_checks(trust, required))
                    .await
                    .unwrap_or_else(|_| vec![false; 5])
            });
        }
    }
    // A changed configuration or service identity invalidates this observation.
    let after = runner
        .as_ref()
        .ok()
        .and_then(|d| installer_doctor::services(state, installation, d).ok());
    let stable_inspection = before
        .as_ref()
        .is_some_and(|v| v["services_observed"] == true)
        && before == after
        && Instant::now() < deadline;
    let stable_services = owned && stable_inspection;
    let stable_trust = trust.as_ref().is_some_and(|original| {
        installer_trust::inspect_locked(installation, state)
            .ok()
            .is_some_and(|current| {
                serde_json::to_value(original).ok() == serde_json::to_value(current).ok()
            })
    });
    state.require_path_binding(installation)?;
    let within_deadline = Instant::now() < deadline;
    let mut checks = vec![
        Check::required(
            "Containers and migrations",
            stable_services && within_deadline,
            "service_inspection_failed_or_changed",
        ),
        Check::required(
            "Bound local TLS",
            stable_trust && within_deadline && observed[0],
            "bound_https_checks_incomplete",
        ),
    ];
    for (index, name) in [
        "Gateway",
        "Required public services",
        "Credential issuer metadata",
        "Authorization metadata",
    ]
    .into_iter()
    .enumerate()
    {
        checks.push(Check::required(
            name,
            stable_services && stable_trust && within_deadline && observed[index + 1],
            "public_check_failed_or_unavailable",
        ));
    }
    checks.push(Check {
        name: "Credential journey",
        required: false,
        status: "skip",
        code: "isolated_test_fixtures_required",
    });
    let passed = checks
        .iter()
        .filter(|c| c.required)
        .all(|c| c.status == "pass");
    let container_security_posture = stable_inspection
        .then(|| before.as_ref().and_then(security_summary))
        .flatten();
    let report = json!({"schema":"elevenid.deployment-validation/v1", "validation_id":uuid::Uuid::new_v4(),
        "installation_id":journal.installation_id(), "release":journal.identity(),
        "engine_id":runtime.map(|r|r.engine_id.as_str()), "scope":"read_only_deployment",
        "observed_at":SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"validation clock unavailable")?.as_secs(),
        "elapsed_ms":started.elapsed().as_millis() as u64, "status":if passed {"passed"} else {"failed"},
        "checks":checks, "not_atomic_snapshot":true, "installation_ready":false,
        "host_trust_observed":false, "qualification":"not_assessed",
        "container_security_posture":container_security_posture,
        "trust_evidence_sha256":trust.as_ref().map(|t| &t.evidence_sha256)});
    let bytes =
        serde_json::to_vec_pretty(&report).map_err(|_| "cannot encode validation report")?;
    let entry = state.save_validation_report(&bytes)?;
    state.require_path_binding(installation)?;
    for check in &checks {
        eprintln!("{}  {}", check.status.to_uppercase(), check.name);
    }
    eprintln!("Validation report: evidence/{entry}");
    if emit_json {
        println!(
            "{}",
            String::from_utf8(bytes).map_err(|_| "cannot encode validation report")?
        );
    }
    if passed {
        Ok(())
    } else {
        Err("Deployment validation failed; see the saved validation report. No repair was attempted.".into())
    }
}

pub fn run(installation: &Path, docker: &Path) -> Result<()> {
    let state = LockedInspection::open(installation)?;
    run_locked(installation, docker, &state, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_validation_records_failure_under_existing_writer_lock() {
        use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let mut state = InstallerState::create_with_runtime(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18200,
                profile: crate::installer_state::RuntimeProfile::Rootful,
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        let docker = path.join("docker-stub");
        std::fs::write(&docker,r#"#!/bin/sh
case "$1" in
info) printf '%s\n' '{"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":[]}' ;;
compose) printf '2.39.0\n' ;;
*) exit 17 ;;
esac
"#).unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o700)).unwrap();
        let before = std::fs::read(path.join("installation.json")).unwrap();
        assert!(state
            .with_inspection(|view| run_locked(&path, &docker, view, false))
            .is_err());
        assert!(LockedInspection::open(&path).is_err());
        assert_eq!(
            std::fs::read(path.join("installation.json")).unwrap(),
            before
        );
        let reports: Vec<_> = std::fs::read_dir(path.join("evidence"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(reports.len(), 1);
        let report: Value = serde_json::from_slice(&std::fs::read(&reports[0]).unwrap()).unwrap();
        assert_eq!(report["status"], "failed");
        assert_eq!(report["installation_ready"], false);
        assert_eq!(report["qualification"], "not_assessed");
        drop(state);
        assert!(LockedInspection::open(&path).is_ok());
    }

    #[test]
    fn readiness_matches_installer_ingress_and_saved_gateway_configuration() {
        let compose = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docker-compose.selfhost.prod.yml"
        ));
        let raw = compose
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("GATEWAY_REQUIRED_READY_SERVICES: ")
            })
            .unwrap();
        let required = parse_required_services(raw).unwrap();
        assert!(required.contains(&"signing-keys".to_owned()));
        let mut services = serde_json::Map::new();
        for name in &required {
            services.insert(name.clone(), json!({"status":"healthy"}));
        }
        let mut ready = json!({"status":"ready","service":"api-gateway","services":services});
        assert!(readiness_valid(&ready, &required));
        ready["services"]
            .as_object_mut()
            .unwrap()
            .remove("signing-keys");
        assert!(!readiness_valid(&ready, &required));
        ready["services"]["unexpected"] = json!({"status":"healthy"});
        assert!(!readiness_valid(&ready, &required));
        for bad in ["", "auth,auth", "auth, signing-keys", "foreign/path"] {
            assert!(parse_required_services(bad).is_err());
        }
        assert!(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docker/nginx-selfhost.prod.conf.template"
        ))
        .contains("location = /health/ready"));
    }

    #[test]
    fn missing_or_partial_service_observations_never_pass() {
        for v in [
            json!({}),
            json!({"services_observed":false,"all_expected_states_observed":true}),
            json!({"services_observed":true,"all_expected_states_observed":false}),
        ] {
            assert!(!services_passed(&v));
        }
        assert!(services_passed(
            &json!({"services_observed":true,"all_expected_states_observed":true})
        ));
    }
    #[test]
    fn security_summary_contains_only_sanitized_service_posture() {
        let observed = json!({"services":{
            "gateway":{"security_posture":{"source":"docker_inspect","user_class":"root",
                "privileged":false,"read_only_rootfs":false,"no_new_privileges":false,
                "cap_drop_all":false,"cap_add_count":0,"device_count":0,
                "writable_inspected_mount_count":1,"published_port_count":0,
                "private_option":"private-secret"},
                "private_environment":"CANARY=private-secret"},
            "missing":{"status":"missing"}
        }});
        let summary = security_summary(&observed).unwrap();
        assert_eq!(summary["gateway"]["user_class"], "root");
        assert!(summary["missing"].is_null());
        assert!(!summary.to_string().contains("private-secret"));
        let mut changed = observed;
        changed["services"]["gateway"]["security_posture"]["user_class"] = json!("private-secret");
        assert!(security_summary(&changed).is_none());
    }
    #[test]
    fn fixed_loopback_origin_refuses_url_overrides() {
        for origin in [
            "http://localhost:18443",
            "https://localhost:443",
            "https://localhost:018443",
            "https://foreign:18443",
            "https://localhost:18443/path",
            "https://localhost:18443@foreign",
        ] {
            assert!(valid_origin(origin).is_none());
        }
        assert_eq!(valid_origin("https://localhost:18443"), Some(18443));
    }
    #[test]
    fn metadata_requires_real_configuration_and_bound_public_endpoints() {
        let origin = "https://localhost:18443";
        let mut issuer = json!({"credential_endpoint":format!("{origin}/v1/issuance/credential"),
            "credential_issuer":origin,"credential_configurations_supported":{"test":{}},"authorization_servers":[origin]});
        let mut auth = json!({"issuer":origin,"token_endpoint":format!("{origin}/v1/issuance/token"),
            "authorization_endpoint":format!("{origin}/v1/issuance/authorize")});
        assert!(issuer_valid(&issuer, origin) && authorization_valid(&auth, &issuer, origin));
        auth["authorization_endpoint"] = json!(format!("{origin}/health"));
        assert!(!authorization_valid(&auth, &issuer, origin));
        auth["authorization_endpoint"] = json!(format!("{origin}/v1/issuance/authorize"));
        issuer["authorization_servers"] = json!([format!("{origin}/wrong")]);
        assert!(!issuer_valid(&issuer, origin));
        issuer["authorization_servers"] = json!([origin]);
        auth["issuer"] = json!("https://foreign");
        assert!(!authorization_valid(&auth, &issuer, origin));
        issuer["credential_configurations_supported"] = json!({});
        assert!(!issuer_valid(&issuer, origin));
        assert!(!same_origin(
            &json!("https://user:secret@localhost:18443/path"),
            origin
        ));
    }
}

#[cfg(test)]
#[path = "installer_validation_transport_tests.rs"]
mod transport_tests;
