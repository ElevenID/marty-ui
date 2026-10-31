//! Read-only, bounded native Compose diagnostics. Known-credential filtering is
//! defense in depth; even filtered logs remain private installation information.
#![cfg(target_os = "linux")]
use crate::{
    installer_doctor,
    installer_state::{LockedInspection, SCALAR_SECRETS},
};
use base64::{engine::general_purpose, Engine};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "Installer logs refused; ownership, evidence, credential filtering, or bounded capture could not be verified";
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
            && (1..=1000).contains(&tail),
    )?;
    Ok(Arguments {
        installation,
        service,
        tail,
        docker,
    })
}
// Compose 5.6.1 escapes every dollar in rendered JSON for round-tripping.
// Decode only that representation for path checks, never interpolation or an
// executable replacement model.
fn decoded_path(source: &str) -> Result<PathBuf> {
    crate::installer_compose::config_path(&json!(source))
}
fn secret_entry(source: &str, secret_dir: &Path) -> Result<String> {
    let path = decoded_path(source)?;
    require(path.parent() == Some(secret_dir))?;
    let entry = path.file_name().and_then(|s| s.to_str()).ok_or(REFUSED)?;
    require(name(entry))?;
    Ok(entry.to_owned())
}
fn credential_names(
    model: &Value,
    installation: &Path,
    generation_root: Option<&Path>,
) -> Result<BTreeSet<String>> {
    let original = installation.join("secrets");
    let roots: Vec<&Path> = std::iter::once(original.as_path())
        .chain(generation_root)
        .collect();
    let mut entries: BTreeSet<String> = SCALAR_SECRETS.iter().map(|s| s.to_string()).collect();
    let mut insert = |source: &str| -> Result<()> {
        let decoded = decoded_path(source)?;
        let root = roots
            .iter()
            .find(|root| decoded.starts_with(root))
            .ok_or(REFUSED)?;
        entries.insert(secret_entry(source, root)?);
        Ok(())
    };
    for service in model["services"].as_object().ok_or(REFUSED)?.values() {
        if let Some(secrets) = service.get("secrets") {
            for secret in secrets.as_array().ok_or(REFUSED)? {
                insert(text(&model["secrets"][text(&secret["source"])?]["file"])?)?;
            }
        }
        if let Some(volumes) = service.get("volumes") {
            for mount in volumes.as_array().ok_or(REFUSED)? {
                if mount["type"] == "bind" {
                    let source = text(&mount["source"])?;
                    let decoded = decoded_path(source)?;
                    if roots.iter().any(|root| decoded.starts_with(root)) {
                        insert(source)?;
                    }
                }
            }
        }
    }
    require(entries.len() <= 128)?;
    Ok(entries)
}
fn corpus(state: &LockedInspection, entries: &BTreeSet<String>) -> Result<Vec<Vec<u8>>> {
    let external = crate::installer_foundation::load(state)?.is_some();
    let mut result = if external {
        Vec::new()
    } else {
        vec![state.read_operator_password()?]
    };
    for entry in entries {
        if external && crate::installer_state::LOCAL_AUTH_SCALAR_SECRETS.contains(&entry.as_str()) {
            continue;
        }
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
/// Captures only ordinary recorded services through native Compose. Setup jobs
/// are excluded by their admitted phase label, never a duplicate role-name list.
pub fn logs(args: &[String]) -> Result<String> {
    logs_inner(args).map_err(|_| REFUSED.to_owned())
}
fn logs_inner(args: &[String]) -> Result<String> {
    let args = arguments(args)?;
    let state = LockedInspection::open(&args.installation)?;
    let (saved, session) =
        installer_doctor::open_session(&state, &args.installation, &args.docker)?;
    let resources = session.observe_resources()?;
    let identity = resources.containers.get(&args.service).ok_or(REFUSED)?;
    require(!identity.setup && saved.model["services"][&args.service].is_object())?;
    let id = state.journal().installation_id().to_string();
    let engine = &state.journal().runtime().ok_or(REFUSED)?.engine_id;
    let generation =
        crate::installer_generation_binding::load_verified(&args.installation, &id, engine)?;
    let generation_root = generation
        .as_ref()
        .map(|g| g.secret_dir(&args.installation))
        .transpose()?;
    let mut names = credential_names(&saved.model, &args.installation, generation_root.as_deref())?;
    if let Some(generation) = &generation {
        names.extend(generation.files.keys().cloned());
    }
    require(names.len() <= 128)?;
    let credentials = selected_corpus(&state, &names, &args.installation, generation.as_ref())?;
    let patterns = patterns(&credentials)?;
    let output = session.logs(std::slice::from_ref(&args.service), args.tail)?;
    require(
        resources == session.observe_resources()?
            && credentials
                == selected_corpus(&state, &names, &args.installation, generation.as_ref())?
            && serde_json::to_value(&saved).map_err(|_| REFUSED)?
                == serde_json::to_value(installer_doctor::load_session(
                    &state,
                    &args.installation,
                )?)
                .map_err(|_| REFUSED)?
            && generation
                == crate::installer_generation_binding::load_verified(
                    &args.installation,
                    &id,
                    engine,
                )?,
    )?;
    state.require_unchanged()?;
    serde_json::to_string(&json!({"schema":"marty.installer.logs.v2","installation_id":id,
        "service":args.service,"container_id":identity.id,"tail":args.tail,
        "source":"docker_compose_logs","stdout":redact(&output,&patterns)?,
        "filtering":"Known credential literals and common encodings, private-key blocks, and conventional sensitive lines are suppressed. Unknown, fragmented, or differently encoded secrets may remain; keep these diagnostics private.",
        "installation_ready":false})).map_err(|_| REFUSED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn closed_arguments_do_not_enable_unbounded_capture() {
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
    fn native_secret_paths_are_literal_and_confined() {
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
    fn corpus_covers_native_secrets_and_direct_generation_mounts() {
        let mut model = json!({"services": {
            "gateway": {"secrets":[{"source":"gateway_token"}]},
            "initializer": {"secrets":[{"source":"operator_bootstrap_password"}]},
            "installer-ingress": {"volumes":[{"type":"bind","source":"/private/install/application-generation/installer_ingress_tls_kms_token"}]}
        },"secrets": {
            "gateway_token":{"file":"/private/install/secrets/gateway_token"},
            "operator_bootstrap_password":{"file":"/private/install/secrets/operator_bootstrap_password"},
            "unused_optional_token":{"file":"/missing/optional"}
        }});
        let names = credential_names(
            &model,
            Path::new("/private/install"),
            Some(Path::new("/private/install/application-generation")),
        )
        .unwrap();
        for entry in [
            "gateway_token",
            "operator_bootstrap_password",
            "installer_ingress_tls_kms_token",
        ] {
            assert!(names.contains(entry));
        }
        assert!(!names.contains("unused_optional_token"));
        model["secrets"]["gateway_token"]["file"] = json!("/outside/token");
        assert!(credential_names(&model, Path::new("/private/install"), None).is_err());
    }
}
