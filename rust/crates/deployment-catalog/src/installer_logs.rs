//! Read-only, bounded diagnostics of recorded application containers. Filtering
//! known credentials is defense in depth, not a guarantee that logs are public.
#![cfg(target_os = "linux")]
use crate::{
    installer_application_model::ApplicationModelPlan,
    installer_application_observation::validate_container_for_logs,
    installer_runtime::DockerRunner,
    installer_state::{LockedInspection, SCALAR_SECRETS},
};
use base64::{engine::general_purpose, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Installer logs refused; ownership, evidence, credential filtering, or bounded capture could not be verified";
const HELPERS: [&str; 5] = [
    "revocation-profile-migrate",
    "db-migrate",
    "kms-initialize",
    "keycloak-configurator",
    "issuance-migrations",
];
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| REFUSED.into())
}
fn identifier(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
struct Arguments {
    installation: PathBuf,
    service: String,
    tail: u16,
    docker: PathBuf,
}
fn arguments(args: &[String]) -> Result<Arguments> {
    require(args.len().is_multiple_of(2))?;
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--service", "--tail", "--docker-bin"].contains(&pair[0].as_str())
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    let installation = PathBuf::from(*values.get("--install-dir").ok_or(REFUSED)?);
    let service = (*values.get("--service").ok_or(REFUSED)?).to_owned();
    let docker = PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker"));
    let tail = values
        .get("--tail")
        .unwrap_or(&"100")
        .parse::<u16>()
        .map_err(|_| REFUSED)?;
    require(
        installation.is_absolute()
            && docker.is_absolute()
            && name(&service)
            && !HELPERS.contains(&service.as_str())
            && (1..=1000).contains(&tail),
    )?;
    Ok(Arguments {
        installation,
        service,
        tail,
        docker,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPlan {
    model: Value,
    selected_services: Vec<String>,
    expected_network_id: String,
    installation_ready: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Created {
    containers: BTreeMap<String, String>,
    redis_volume: String,
    network_id: String,
}
fn one(output: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(output).map_err(|_| REFUSED)?;
    let a = v.as_array().ok_or(REFUSED)?;
    require(a.len() == 1 && a[0].is_object())?;
    Ok(a[0].clone())
}
// Model paths are Compose-escaped; never interpolate an environment variable.
fn decoded_path(s: &str) -> Result<PathBuf> {
    require(!s.replace("$$", "").contains('$'))?;
    Ok(PathBuf::from(s.replace("$$", "$")))
}
fn secret_entry(source: &str, secret_dir: &Path) -> Result<String> {
    let path = decoded_path(source)?;
    require(path.parent() == Some(secret_dir))?;
    let entry = path.file_name().and_then(|s| s.to_str()).ok_or(REFUSED)?;
    require(name(entry))?;
    Ok(entry.to_owned())
}
fn credential_names(plan: &ApplicationModelPlan, installation: &Path) -> Result<BTreeSet<String>> {
    credential_names_at(plan, &installation.join("secrets"))
}
fn credential_names_at(plan: &ApplicationModelPlan, secret_dir: &Path) -> Result<BTreeSet<String>> {
    let mut entries: BTreeSet<String> = SCALAR_SECRETS.iter().map(|s| s.to_string()).collect();
    for role in &plan.selected_services {
        let service = &plan.model["services"][role];
        if let Some(secrets) = service.get("secrets") {
            for secret in secrets.as_array().ok_or(REFUSED)? {
                let source = text(&secret["source"])?;
                entries.insert(secret_entry(
                    text(&plan.model["secrets"][source]["file"])?,
                    secret_dir,
                )?);
            }
        }
        if let Some(volumes) = service.get("volumes") {
            for mount in volumes.as_array().ok_or(REFUSED)? {
                if mount["type"] == "bind" {
                    let source = text(&mount["source"])?;
                    if decoded_path(source)?.starts_with(secret_dir) {
                        entries.insert(secret_entry(source, secret_dir)?);
                    }
                }
            }
        }
    }
    require(entries.len() <= 128)?;
    Ok(entries)
}
fn corpus(state: &LockedInspection, entries: &BTreeSet<String>) -> Result<Vec<Vec<u8>>> {
    let mut result = vec![state.read_operator_password()?];
    for entry in entries {
        result.push(state.read_secret(entry)?);
    }
    Ok(result)
}
fn selected_corpus(
    state: &LockedInspection,
    entries: &BTreeSet<String>,
    installation: &Path,
    generation: Option<&crate::installer_generation_binding::GenerationBinding>,
) -> Result<Vec<Vec<u8>>> {
    // Preserve the original corpus too: historical logs can contain credentials
    // from bootstrap, even when current mounts select a replacement generation.
    let mut result = corpus(state, entries)?;
    if let Some(generation) = generation {
        for name in generation.files.keys() {
            result.push(generation.read(installation, name)?);
        }
    }
    Ok(result)
}
fn patterns(corpus: &[Vec<u8>]) -> Result<Vec<String>> {
    let mut patterns = BTreeSet::new();
    for bytes in corpus {
        let raw = std::str::from_utf8(bytes)
            .map_err(|_| REFUSED)?
            .trim_end_matches(['\r', '\n']);
        if raw.is_empty() {
            continue;
        }
        // No private keys are needed for this installer profile. Refuse
        // unexpected private key custody. Public certificate bytes stay in
        // the corpus too: a PEM prefix must not bypass credential filtering.
        require(!raw.contains("PRIVATE KEY-----"))?;
        require(raw.len() >= 8)?;
        patterns.insert(raw.to_owned());
        let escaped = serde_json::to_string(raw).map_err(|_| REFUSED)?;
        patterns.insert(escaped[1..escaped.len() - 1].to_owned());
        let url = url::form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>();
        patterns.insert(url.replace('+', "%20"));
        patterns.insert(url);
        for engine in [
            general_purpose::STANDARD,
            general_purpose::STANDARD_NO_PAD,
            general_purpose::URL_SAFE,
            general_purpose::URL_SAFE_NO_PAD,
        ] {
            patterns.insert(engine.encode(raw));
        }
    }
    let mut result: Vec<_> = patterns.into_iter().collect();
    result.sort_by_key(|s| std::cmp::Reverse(s.len()));
    Ok(result)
}
fn redact(input: &str, patterns: &[String]) -> Result<String> {
    let mut output = input.to_owned();
    for pattern in patterns {
        output = output.replace(pattern, "[REDACTED]");
    }
    let pem = regex::Regex::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
    )
    .map_err(|_| REFUSED)?;
    output = pem
        .replace_all(&output, "[REDACTED PRIVATE KEY]")
        .into_owned();
    let sensitive = regex::Regex::new(r#"(?i)(authorization|proxy-authorization|set-cookie|cookie|password|passwd|client_secret|access_token|refresh_token|id_token|root_token|unseal_key|api_key|secret|token)\s*["']?\s*[:=]|https?://[^\s/@:]+:[^\s/@]+@"#).map_err(|_| REFUSED)?;
    Ok(output
        .split_inclusive('\n')
        .map(|line| {
            if sensitive.is_match(line) {
                if line.ends_with('\n') {
                    "[REDACTED SENSITIVE LINE]\n"
                } else {
                    "[REDACTED SENSITIVE LINE]"
                }
            } else {
                line
            }
        })
        .collect())
}
fn observe(
    docker: &DockerRunner,
    plan: &ApplicationModelPlan,
    service: &str,
    id: &str,
    project: &str,
) -> Result<()> {
    let network = one(&docker.run_checked(&["network", "inspect", &plan.expected_network_id])?)?;
    require(
        network["Id"] == plan.expected_network_id
            && network["Name"] == plan.model["networks"]["default"]["name"]
            && network["Labels"]["com.docker.compose.project"] == format!("{project}-bao")
            && network["Labels"]["com.docker.compose.network"] == "default",
    )?;
    let image = one(&docker.run_checked(&[
        "image",
        "inspect",
        text(&plan.model["services"][service]["image"])?,
    ])?)?;
    let container = one(&docker.run_checked(&["inspect", "--type", "container", id])?)?;
    validate_container_for_logs(&container, id, service, plan, &image)
}
/// Returns bounded JSON only after both observations and credential snapshots
/// agree. Treat even filtered diagnostics as private installation information.
pub fn logs(args: &[String]) -> Result<String> {
    logs_inner(args).map_err(|_| REFUSED.to_owned())
}
fn logs_inner(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let state = LockedInspection::open(&args.installation)?;
    let binding = state.journal().runtime().ok_or(REFUSED)?;
    let project = state.journal().compose_project();
    let saved = state.read_evidence("application-plan.json")?;
    let created_bytes = state.read_evidence("application-created-resources.json")?;
    let decoded: SavedPlan = serde_json::from_slice(&saved).map_err(|_| REFUSED)?;
    let plan = ApplicationModelPlan {
        model: decoded.model,
        selected_services: decoded.selected_services,
        expected_network_id: decoded.expected_network_id,
        installation_ready: decoded.installation_ready,
    };
    let created: Created = serde_json::from_slice(&created_bytes).map_err(|_| REFUSED)?;
    require(
        !plan.installation_ready
            && plan.model["name"] == project
            && identifier(&plan.expected_network_id)
            && created.network_id == plan.expected_network_id
            && created.redis_volume == format!("{project}_redis-socket")
            && plan.selected_services.contains(&args.service),
    )?;
    let roles =
        crate::installer_application_graph::startup_order(&plan.model, &plan.selected_services)?;
    require(
        created.containers.keys().cloned().collect::<BTreeSet<_>>() == roles.into_iter().collect()
            && created.containers.values().all(|s| identifier(s))
            && created.containers.values().collect::<BTreeSet<_>>().len()
                == created.containers.len(),
    )?;
    let id = created.containers.get(&args.service).ok_or(REFUSED)?;
    let compose_bytes = state.read_evidence("application-compose.json")?;
    require(compose_bytes == crate::installer_application::compose_document(&plan.model)?)?;
    let generation = crate::installer_generation_binding::load_verified(
        &args.installation,
        &state.journal().installation_id().to_string(),
        &binding.engine_id,
    )?;
    let names = if let Some(generation) = &generation {
        crate::installer_generation_binding::verify_model(&args.installation, generation, &plan)?;
        credential_names_at(&plan, &generation.secret_dir(&args.installation)?)?
    } else {
        credential_names(&plan, &args.installation)?
    };
    let credentials = selected_corpus(&state, &names, &args.installation, generation.as_ref())?;
    let patterns = patterns(&credentials)?;
    let docker = DockerRunner::new(
        &args.docker,
        &binding.docker_host,
        &binding.engine_id,
        &args.installation,
    )?;
    docker.preflight()?;
    observe(&docker, &plan, &args.service, id, &project)?;
    let (stdout, stderr) = docker.capture_logs(id, args.tail)?;
    observe(&docker, &plan, &args.service, id, &project)?;
    require(
        credentials == selected_corpus(&state, &names, &args.installation, generation.as_ref())?
            && saved == state.read_evidence("application-plan.json")?
            && created_bytes == state.read_evidence("application-created-resources.json")?
            && compose_bytes == state.read_evidence("application-compose.json")?,
    )?;
    let current_generation = crate::installer_generation_binding::load_verified(
        &args.installation,
        &state.journal().installation_id().to_string(),
        &binding.engine_id,
    )?;
    require(
        serde_json::to_vec(&generation).map_err(|_| REFUSED)?
            == serde_json::to_vec(&current_generation).map_err(|_| REFUSED)?,
    )?;
    state.require_unchanged()?;
    serde_json::to_string(&json!({"schema":"marty.installer.logs.v1","installation_id":state.journal().installation_id(),"service":args.service,"container_id":id,"tail":args.tail,"stdout":redact(&stdout,&patterns)?,"stderr":redact(&stderr,&patterns)?,"filtering":"Known credential literals and common encodings, private-key blocks, and conventional sensitive lines are suppressed. Unknown, fragmented, or differently encoded secrets may remain; keep these diagnostics private.","installation_ready":false})).map_err(|_| REFUSED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_state::{Identity, InstallerState, RuntimeBinding};
    use std::{fs, os::unix::fs::PermissionsExt};

    fn mocked_installation(mode: &str) -> (tempfile::TempDir, Vec<String>) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installation = root.path().join("install");
        let mut state = InstallerState::create_with_runtime(
            &installation,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            RuntimeBinding {
                docker_host: "unix:///var/run/docker.sock".into(),
                engine_id: "test-engine".into(),
                openbao_port: 18200,
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        let project = state.journal().compose_project();
        let network = format!("{project}-bao_default");
        let digest = format!("example.test/services@sha256:{}", "a".repeat(64));
        let mut services = serde_json::Map::new();
        for role in [
            "gateway",
            "postgres",
            "redis",
            "revocation-profile-migrate",
            "db-migrate",
            "kms-initialize",
            "keycloak-configurator",
            "issuance-migrations",
            "cloudflared",
            "cloudflared-beta",
            "tunnel-nginx-proxy",
        ] {
            services.insert(
                role.into(),
                json!({"image":digest,"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        for i in 0..22 {
            services.insert(
                format!("synthetic-{i}"),
                json!({"image":digest,"restart":"no","healthcheck":{"test":["CMD","true"]}}),
            );
        }
        services["kms-initialize"]["depends_on"] = json!({"postgres":{"condition":"service_healthy"},"redis":{"condition":"service_healthy"},"db-migrate":{"condition":"service_completed_successfully"},"revocation-profile-migrate":{"condition":"service_completed_successfully"}});
        services["gateway"]["secrets"] = json!([
            {"source":"openbao_tls_ca_cert","target":"/run/secrets/openbao_tls_ca_cert"},
            {"source":"gateway_scoped_token","target":"/run/secrets/gateway_scoped_token"},
            {"source":"smtp_password","target":"/run/secrets/smtp_password"}
        ]);
        let selected: Vec<String> = services
            .keys()
            .filter(|s| {
                ![
                    "kms-initialize",
                    "cloudflared",
                    "cloudflared-beta",
                    "tunnel-nginx-proxy",
                ]
                .contains(&s.as_str())
            })
            .cloned()
            .collect();
        let plan = ApplicationModelPlan {
            model: json!({"name":project,"services":services,"networks":{"default":{"name":network}},"volumes":{"redis-socket":{"name":format!("{project}_redis-socket")}},"secrets":{
                "openbao_tls_ca_cert":{"file":installation.join("secrets/openbao_tls_ca_cert")},
                "gateway_scoped_token":{"file":installation.join("secrets/gateway_scoped_token")},
                "smtp_password":{"file":installation.join("secrets/smtp_password")}
            }}),
            selected_services: selected,
            expected_network_id: "c".repeat(64),
            installation_ready: false,
        };
        let roles =
            crate::installer_application_graph::startup_order(&plan.model, &plan.selected_services)
                .unwrap();
        let containers: BTreeMap<String, String> = roles
            .into_iter()
            .enumerate()
            .map(|(i, r)| (r, format!("{:064x}", i + 1)))
            .collect();
        let id = containers["gateway"].clone();
        state
            .write_evidence("application-plan.json", &serde_json::to_vec(&plan).unwrap())
            .unwrap();
        state
            .write_evidence(
                "application-compose.json",
                &crate::installer_application::compose_document(&plan.model).unwrap(),
            )
            .unwrap();
        state.write_evidence("application-created-resources.json",&serde_json::to_vec(&json!({"containers":containers,"redis_volume":format!("{project}_redis-socket"),"network_id":plan.expected_network_id})).unwrap()).unwrap();
        fs::create_dir(installation.join("secrets")).unwrap();
        fs::set_permissions(
            installation.join("secrets"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        for name in SCALAR_SECRETS {
            let path = installation.join("secrets").join(name);
            fs::write(&path, "credential-sensitive-123").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
        }
        let ca = installation.join("secrets/openbao_tls_ca_cert");
        fs::write(
            &ca,
            include_bytes!("../tests/fixtures/installer-log-public-ca.txt"),
        )
        .unwrap();
        if mode == "misclassified-ca" {
            fs::write(&ca, b"-----BEGIN CERTIFICATE-----\nnot-a-certificate credential-sensitive-123\n-----END CERTIFICATE-----\n").unwrap();
        }
        fs::set_permissions(&ca, fs::Permissions::from_mode(0o644)).unwrap();
        let scoped = installation.join("secrets/gateway_scoped_token");
        fs::write(&scoped, "scoped-sensitive-789").unwrap();
        fs::set_permissions(&scoped, fs::Permissions::from_mode(0o444)).unwrap();
        let smtp = installation.join("secrets/smtp_password");
        fs::write(&smtp, b"").unwrap();
        fs::set_permissions(&smtp, fs::Permissions::from_mode(0o444)).unwrap();
        fs::write(
            installation.join("operator-password"),
            "operator-sensitive-456",
        )
        .unwrap();
        fs::set_permissions(
            installation.join("operator-password"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        drop(state);
        let image_id = format!("sha256:{}", "b".repeat(64));
        let image = json!([{"Id":image_id,"RepoDigests":[digest],"Config":{"Env":[],"Entrypoint":[],"Cmd":[],"User":"","WorkingDir":""}}]);
        let observed = json!([{"Id":id,"Image":image_id,"Name":format!("/{project}-gateway-1"),
            "Config":{"Image":digest,"Labels":{"com.docker.compose.project":project,"com.docker.compose.service":"gateway","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False"},"Env":[],"Entrypoint":[],"Cmd":[],"User":"","WorkingDir":"","Healthcheck":{"Test":["CMD","true"]}},
            "HostConfig":{"Privileged":false,"ReadonlyRootfs":false,"AutoRemove":false,"RestartPolicy":{"Name":"no"},"IpcMode":"private","NetworkMode":network},
            "NetworkSettings":{"Networks":{network.clone():{"NetworkID":plan.expected_network_id,"Aliases":[format!("{project}-gateway-1"),"gateway"]}},"Ports":{}},"Mounts":[
                {"Type":"bind","Source":ca,"Destination":"/run/secrets/openbao_tls_ca_cert","RW":false,"Propagation":"rprivate"},
                {"Type":"bind","Source":scoped,"Destination":"/run/secrets/gateway_scoped_token","RW":false,"Propagation":"rprivate"},
                {"Type":"bind","Source":smtp,"Destination":"/run/secrets/smtp_password","RW":false,"Propagation":"rprivate"}
            ],"State":{"Status":"exited","ExitCode":17,"Running":false,"Paused":false,"Restarting":false,"OOMKilled":true}}]);
        let mut replacement = observed.clone();
        replacement[0]["Id"] = json!("f".repeat(64));
        for (name, value) in [
            ("image.json", image),
            ("container.json", observed),
            ("replacement.json", replacement),
            (
                "network.json",
                json!([{"Id":plan.expected_network_id,"Name":network,"Labels":{"com.docker.compose.project":format!("{project}-bao"),"com.docker.compose.network":"default"}}]),
            ),
            (
                "info.json",
                json!({"id":"test-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=seccomp,profile=builtin"]}),
            ),
            (
                "foreign-info.json",
                json!({"id":"foreign-engine","os":"linux","architecture":"x86_64","server_version":"28.0.0","security_options":["name=seccomp,profile=builtin"]}),
            ),
        ] {
            fs::write(root.path().join(name), serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let mutation = match mode {
            "engine" => "cp \"$fixture/foreign-info.json\" \"$fixture/info.json\"",
            "container" => "cp \"$fixture/replacement.json\" \"$fixture/container.json\"",
            "rotation" => {
                "chmod 600 \"$fixture/install/secrets/token_hmac_key\"; printf rotated-credential > \"$fixture/install/secrets/token_hmac_key\"; chmod 444 \"$fixture/install/secrets/token_hmac_key\""
            }
            "success" | "misclassified-ca" => ":",
            _ => panic!("invalid fixture mode"),
        };
        let script = format!(
            "#!/bin/sh\nfixture='{}'\ncase \"$1\" in\ninfo) cat \"$fixture/info.json\";;\ncompose) printf '2.40.3';;\nnetwork) cat \"$fixture/network.json\";;\nimage) cat \"$fixture/image.json\";;\ninspect) cat \"$fixture/container.json\";;\nlogs) printf 'out credential-sensitive-123\\n'; printf 'err operator-sensitive-456\\n' >&2; {mutation};;\n*) exit 97;;\nesac\n",
            root.path().display()
        );
        let executable = root.path().join("docker-stub");
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let args = vec![
            "--install-dir".into(),
            installation.to_str().unwrap().into(),
            "--service".into(),
            "gateway".into(),
            "--docker-bin".into(),
            executable.to_str().unwrap().into(),
        ];
        (root, args)
    }
    #[test]
    fn complete_mocked_pipeline_filters_failed_container_logs_and_refuses_races() {
        let (_root, args) = mocked_installation("success");
        let result = logs(&args).unwrap();
        let result: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(result["stdout"], "out [REDACTED]\n");
        assert_eq!(result["stderr"], "err [REDACTED]\n");
        assert_eq!(result["installation_ready"], false);
        for mode in ["engine", "container", "rotation", "misclassified-ca"] {
            let (_root, args) = mocked_installation(mode);
            assert_eq!(logs(&args).unwrap_err(), REFUSED, "{mode}");
        }
    }
    fn args(extra: &[&str]) -> Vec<String> {
        [
            vec!["--install-dir", "/private/install", "--service", "gateway"],
            extra.to_vec(),
        ]
        .concat()
        .into_iter()
        .map(String::from)
        .collect()
    }
    #[test]
    fn closed_arguments_and_helper_refusal() {
        assert_eq!(arguments(&args(&[])).unwrap().tail, 100);
        for extra in [
            vec!["--tail", "0"],
            vec!["--tail", "1001"],
            vec!["--docker-bin", "docker"],
            vec!["--service", "openbao"],
            vec!["--unknown", "x"],
        ] {
            assert!(arguments(&args(&extra)).is_err());
        }
        for role in HELPERS {
            let mut a = args(&[]);
            a[3] = role.into();
            assert!(arguments(&a).is_err());
        }
    }
    #[test]
    fn credential_encodings_and_both_stream_content_are_filtered() {
        let secret = "p@ss word\"with/slash";
        let patterns = patterns(&[secret.as_bytes().to_vec(), vec![]]).unwrap();
        for p in &patterns {
            assert!(!redact(&format!("before {p} after"), &patterns)
                .unwrap()
                .contains(p));
        }
        assert_eq!(
            redact("ordinary diagnostic\n", &patterns).unwrap(),
            "ordinary diagnostic\n"
        );
    }
    #[test]
    fn suppresses_multiline_truncated_keys_and_headers() {
        let output=redact("safe\nAuthorization: Bearer unknown\n{\"password\":\"unknown\"}\n-----BEGIN RSA PRIVATE KEY-----\nunknown material\n",&[]).unwrap();
        assert!(output.starts_with("safe\n"));
        assert!(!output.contains("unknown"));
        assert!(!redact("connect https://user:pass@example.com", &[])
            .unwrap()
            .contains("pass@"));
    }
    #[test]
    fn secret_paths_are_literal_and_confined() {
        let root = Path::new("/private/dollar$install/secrets");
        assert_eq!(
            secret_entry("/private/dollar$$install/secrets/token_name", root).unwrap(),
            "token_name"
        );
        for path in [
            "/private/dollar$install/secrets/token_name",
            "/private/dollar$$install/secrets/../root.token",
            "/other/secrets/token_name",
        ] {
            assert!(secret_entry(path, root).is_err());
        }
        assert!(patterns(&[b"-----BEGIN PRIVATE KEY-----".to_vec()]).is_err());
    }
    #[test]
    fn corpus_covers_other_roles_and_direct_tokens_without_optional_declarations() {
        let mut plan = ApplicationModelPlan {
            model: json!({"services": {
                "gateway": {"secrets":[{"source":"gateway_token"}]},
                "keycloak-configurator": {"secrets":[{"source":"operator_bootstrap_password"}]},
                "installer-ingress": {"volumes":[{"type":"bind","source":"/private/install/secrets/installer_ingress_tls_kms_token"}]}
            },"secrets": {
                "gateway_token":{"file":"/private/install/secrets/gateway_token"},
                "operator_bootstrap_password":{"file":"/private/install/secrets/operator_bootstrap_password"},
                "cloudflare_tunnel_token":{"file":"/missing/optional"}
            }}),
            selected_services: vec![
                "gateway".into(),
                "keycloak-configurator".into(),
                "installer-ingress".into(),
            ],
            expected_network_id: "a".repeat(64),
            installation_ready: false,
        };
        let names = credential_names(&plan, Path::new("/private/install")).unwrap();
        for entry in [
            "gateway_token",
            "operator_bootstrap_password",
            "installer_ingress_tls_kms_token",
        ] {
            assert!(names.contains(entry));
        }
        assert!(!names.contains("cloudflare_tunnel_token"));
        plan.model["secrets"]["gateway_token"]["file"] = json!("/outside/token");
        assert!(credential_names(&plan, Path::new("/private/install")).is_err());
    }
}
