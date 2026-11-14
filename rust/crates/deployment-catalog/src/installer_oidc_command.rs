//! Operator commands for the one retained external login provider. Compatibility
//! preflight executes the admitted Auth binary with OIDC settings alone.
#![cfg(target_os = "linux")]

use crate::{
    installer_oidc::ExternalOidc,
    installer_state::{InstallerState, LockedMaintenance, Phase, RuntimeBinding},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "external OIDC preflight failed; preserve its private probe evidence; discovery compatibility does not qualify a live login";
const USAGE: &str = "usage: marty-deploy external-oidc preflight --install-dir ABSOLUTE_PATH [--docker-bin ABSOLUTE_PATH]\n       marty-deploy external-oidc rotate-secret --install-dir ABSOLUTE_PATH --client-secret-file ABSOLUTE_PATH [--docker-bin ABSOLUTE_PATH]";
fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn with_probe_cleanup<T>(
    operation: impl FnOnce() -> Result<T>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<T> {
    let outcome = operation();
    let removed = cleanup();
    match outcome {
        Ok(value) => removed.map(|_| value),
        Err(error) => Err(error),
    }
}

fn validate_report(report: &Value, provider: &ExternalOidc) -> Result<()> {
    let expected = provider.preflight_environment()?;
    let fields = [
        "schema",
        "status",
        "issuer",
        "token_endpoint_auth_method",
        "compatible_signing_algorithms",
        "userinfo_fallback_enabled",
        "provider",
        "limitations",
    ];
    require(
        report.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|name| object.contains_key(*name))
        }) && report["schema"] == "elevenid.oidc-provider-preflight/v1"
            && report["status"] == "metadata_compatible"
            && report["issuer"] == provider.issuer_url
            && report["token_endpoint_auth_method"] == expected["OIDC_TOKEN_ENDPOINT_AUTH_METHOD"]
            && report["userinfo_fallback_enabled"]
                == (provider.userinfo_mode == Some(crate::installer_oidc::UserinfoMode::Fallback)),
    )?;
    let algorithms = report["compatible_signing_algorithms"]
        .as_array()
        .ok_or(REFUSED)?;
    require(
        !algorithms.is_empty()
            && algorithms.len() <= provider.allowed_algorithms.len()
            && algorithms.iter().all(|value| {
                value.as_str().is_some_and(|v| {
                    provider
                        .allowed_algorithms
                        .iter()
                        .any(|allowed| allowed == v)
                })
            }),
    )?;
    let capabilities = &report["provider"];
    let fields = [
        "provider_mode",
        "provider_name",
        "registration_supported",
        "account_url",
        "recovery_url",
        "passkey_enrollment_supported",
        "provider_logout_supported",
    ];
    require(
        capabilities.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|name| object.contains_key(*name))
        }) && capabilities["provider_mode"] == "external"
            && capabilities["passkey_enrollment_supported"] == false
            && capabilities["provider_name"].is_string()
            && capabilities["registration_supported"].is_boolean()
            && capabilities["provider_logout_supported"].is_boolean()
            && capabilities["account_url"] == json!(provider.account_url)
            && capabilities["recovery_url"] == json!(provider.recovery_url)
            && report["limitations"]
                .as_array()
                .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string)),
    )
}

fn probe_arguments(image: &str, environment: &Path, name: &str) -> Result<Vec<String>> {
    require(
        image
            .strip_prefix("ghcr.io/elevenid/marty-ui-oss/services@sha256:")
            .is_some_and(identifier),
    )?;
    Ok([
        "create",
        "--pull=never",
        "--name",
        name,
        "--label",
        "com.elevenid.installer.role=oidc-preflight",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32",
        "--memory=134217728",
        "--cpus=0.5",
        "--user=65532:65532",
        "--network=bridge",
        "--log-driver=none",
        "--entrypoint=/usr/local/bin/marty-auth",
        "--env-file",
        environment.to_str().ok_or(REFUSED)?,
        image,
        "oidc-preflight",
    ]
    .map(String::from)
    .to_vec())
}

fn probe(
    installation: &Path,
    docker: &Path,
    runtime: &RuntimeBinding,
    image: &str,
    provider: &ExternalOidc,
    allow_image_pull: bool,
    mut save: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<Value> {
    let values = provider.preflight_environment()?;
    let bytes = values
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    let mut env = tempfile::NamedTempFile::new_in(installation).map_err(|_| REFUSED)?;
    env.write_all(bytes.as_bytes())
        .and_then(|_| env.flush())
        .map_err(|_| REFUSED)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let name = format!("marty-oidc-preflight-{id}");
    let record = |kind: &str| format!("oidc-provider-preflight-{id}-{kind}.json");
    let args = probe_arguments(image, env.path(), &name)?;
    let runner =
        crate::installer_runtime::DockerRunner::from_binding(docker, runtime, installation)?;
    let intent = json!({"schema":"elevenid.installer-oidc-preflight-probe/v1", "container_name":name,
        "image":image, "environment_sha256":digest(bytes.as_bytes()), "provider_read_only":true,
        "customer_secrets_projected":false, "application_resources_changed":false});
    save(
        &record("intent"),
        &serde_json::to_vec(&intent).map_err(|_| REFUSED)?,
    )?;
    if allow_image_pull && runner.run_checked(&["image", "inspect", image]).is_err() {
        runner.run_checked_with_timeout(&["pull", image], Duration::from_secs(900))?;
    }
    let created = runner.run_checked(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    let container = created.trim();
    require(identifier(container))?;
    // This exact full ID is returned by the creation that we own. Evidence
    // failures and process timeouts still remove only this owned probe.
    let output = with_probe_cleanup(
        || {
            save(
                &record("created"),
                &serde_json::to_vec(&json!({"container_id":container,"container_name":name}))
                    .map_err(|_| REFUSED)?,
            )?;
            runner.run_checked_with_timeout(
                &["start", "--attach", container],
                Duration::from_secs(90),
            )
        },
        || {
            runner
                .run_checked(&["rm", "--force", container])
                .map(|_| ())
        },
    )
    .map_err(|_| REFUSED)?;
    require(output.len() <= 65536)?;
    let report = crate::installer_json::decode(output.as_bytes()).map_err(|_| REFUSED)?;
    validate_report(&report, provider)?;
    let result = json!({"schema":"elevenid.installer-oidc-preflight/v1", "provider":report,
        "services_image":image, "probe_container_removed":true, "customer_secrets_projected":false,
        "application_resources_changed":false, "installation_ready":false, "browser_login_qualified":false});
    save(
        &record("result"),
        &serde_json::to_vec(&result).map_err(|_| REFUSED)?,
    )?;
    Ok(result)
}

pub(crate) fn before_provisioning(
    installation: &Path,
    docker: &Path,
    image: &str,
    state: &mut InstallerState,
) -> Result<()> {
    state.require_live_phase(Phase::Verified)?;
    let Some(provider) = state.with_inspection(crate::installer_oidc::external)? else {
        return Ok(());
    };
    let runtime = state.journal().runtime().ok_or(REFUSED)?.clone();
    eprintln!("Marty runtime stage: external OIDC discovery and public-key compatibility (no client credential exchange)");
    probe(
        installation,
        docker,
        &runtime,
        image,
        &provider,
        true,
        |name, raw| state.write_evidence(name, raw),
    )?;
    Ok(())
}

fn installed_preflight(args: &[String]) -> Result<String> {
    let mut values = BTreeMap::new();
    require(args.len().is_multiple_of(2))?;
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--docker-bin"].contains(&pair[0].as_str())
                && Path::new(&pair[1]).is_absolute()
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*values.get("--install-dir").ok_or(USAGE)?);
    let docker = PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    let mut state = LockedMaintenance::open(&installation)?;
    let provider = crate::installer_oidc::external(state.inspection())?.ok_or(REFUSED)?;
    let session = crate::installer_doctor::load_session(state.inspection(), &installation)?;
    let image = session.model["services"]["auth"]["image"]
        .as_str()
        .ok_or(REFUSED)?;
    require(session.inputs.approved_images.contains(image))?;
    let runtime = state.journal().runtime().ok_or(REFUSED)?.clone();
    let result = probe(
        &installation,
        &docker,
        &runtime,
        image,
        &provider,
        false,
        |name, raw| state.write_evidence_exclusive(name, raw),
    )?;
    state.require_unchanged()?;
    serde_json::to_string(&result).map_err(|_| REFUSED.into())
}

pub fn run(args: &[String]) -> Result<String> {
    match args.first().map(String::as_str) {
        Some("preflight") => installed_preflight(&args[1..]),
        Some("rotate-secret") => crate::installer_oidc_rotation::run(&args[1..]),
        Some("--help" | "-h") if args.len() == 1 => Ok(USAGE.into()),
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_write_failure_still_removes_the_exact_owned_probe() {
        let removed = std::cell::Cell::new(false);
        let result: Result<()> = with_probe_cleanup(
            || Err("evidence write failed".into()),
            || {
                removed.set(true);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), "evidence write failed");
        assert!(removed.get());
        assert!(with_probe_cleanup(|| Ok(()), || Err("removal failed".into())).is_err());
    }

    #[test]
    fn metadata_report_cannot_claim_credential_or_browser_qualification() {
        let provider: ExternalOidc = serde_json::from_value(
            json!({"issuer_url":"https://identity.example.test", "client_id":"public",
            "admin_email":"operator@example.test", "allowed_algorithms":["RS256"]}),
        )
        .unwrap();
        let report = json!({"schema":"elevenid.oidc-provider-preflight/v1", "status":"metadata_compatible",
            "issuer":provider.issuer_url, "token_endpoint_auth_method":"none", "compatible_signing_algorithms":["RS256"],
            "userinfo_fallback_enabled":false,"provider":{"provider_mode":"external","provider_name":"External identity provider",
                "registration_supported":false,"account_url":null,"recovery_url":null,"passkey_enrollment_supported":false,"provider_logout_supported":false},
            "limitations":["Client credentials and browser login were not tested"]});
        validate_report(&report, &provider).unwrap();
        for key in [
            "installation_ready",
            "browser_login_qualified",
            "credentials_valid",
        ] {
            let mut changed = report.clone();
            changed[key] = json!(true);
            assert!(validate_report(&changed, &provider).is_err());
        }
        let mut changed = report;
        changed["token_endpoint_auth_method"] = json!("client_secret_basic");
        assert!(validate_report(&changed, &provider).is_err());
    }

    #[test]
    fn probe_uses_only_the_admitted_auth_binary_without_application_mounts_or_entrypoint() {
        let image = format!(
            "ghcr.io/elevenid/marty-ui-oss/services@sha256:{}",
            "a".repeat(64)
        );
        let arguments = probe_arguments(&image, Path::new("/private/env"), "owned-probe").unwrap();
        for required in [
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint=/usr/local/bin/marty-auth",
            "--network=bridge",
            "--log-driver=none",
        ] {
            assert!(arguments.iter().any(|value| value == required));
        }
        assert_eq!(arguments.last().unwrap(), "oidc-preflight");
        assert!(
            !arguments.iter().any(|value| value.contains("entrypoint.sh")
                || value.starts_with("--mount")
                || value.starts_with("--publish"))
        );
        assert!(probe_arguments("services:latest", Path::new("/private/env"), "probe").is_err());
    }
}
