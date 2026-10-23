//! Scoped, keyless Raft export. No root or unseal material is read.
use crate::operator::{Result, REFUSAL};
use chrono::Utc;
use marty_openbao_http::OpenBaoHttp;
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const POLICY: &str = "selfhost-raft-snapshot-read";
const MAX_INPUT: u64 = 64 * 1024;

/// Keep export authority tied to an explicit local HTTPS port.
pub fn origin(value: &str) -> Result<&str> {
    let parsed = url::Url::parse(value).map_err(|_| REFUSAL)?;
    let local = match parsed.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        _ => false,
    };
    // Url removes a default port; inspect the authority to require an explicit one.
    let authority = value.split_once("://").ok_or(REFUSAL)?.1;
    let authority = match authority.split_once('/') {
        None => authority,
        Some((authority, "")) => authority,
        _ => return Err(REFUSAL),
    };
    let port = authority
        .rsplit(':')
        .next()
        .and_then(|s| s.parse::<u16>().ok());
    if !local
        || parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || port.is_none_or(|port| port == 0)
    {
        return Err(REFUSAL);
    }
    Ok(value.trim_end_matches('/'))
}

fn private_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(REFUSAL);
    }
    let info = fs::symlink_metadata(path).map_err(|_| REFUSAL)?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o7777 != 0o700 {
            return Err(REFUSAL);
        }
    }
    #[cfg(not(unix))]
    {
        Err(REFUSAL)
    }
    #[cfg(unix)]
    fs::canonicalize(path).map_err(|_| REFUSAL)
}

fn private_credential(path: &Path) -> Result<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| REFUSAL)?;
    let info = file.metadata().map_err(|_| REFUSAL)?;
    if !info.is_file() || info.len() > MAX_INPUT {
        return Err(REFUSAL);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if info.permissions().mode() & 0o077 != 0 {
            return Err(REFUSAL);
        }
    }
    let mut value = String::new();
    file.take(MAX_INPUT + 1)
        .read_to_string(&mut value)
        .map_err(|_| REFUSAL)?;
    if value.len() as u64 > MAX_INPUT || value.trim().len() < 20 {
        return Err(REFUSAL);
    }
    Ok(value.trim().to_owned())
}

async fn snapshot_login(bao: &OpenBaoHttp, identity: &Path) -> Result<String> {
    let identity = private_directory(identity)?;
    let role = private_credential(&identity.join("snapshot-role-id"))?;
    let secret = private_credential(&identity.join("snapshot-secret-id"))?;
    let response = bao
        .client()
        .post(format!("{}/v1/auth/selfhost-snapshot/login", bao.origin()))
        .timeout(Duration::from_secs(10))
        .json(&json!({"role_id":role,"secret_id":secret}))
        .send()
        .await
        .map_err(|_| REFUSAL)?;
    if !response.status().is_success() {
        return Err(REFUSAL);
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| REFUSAL)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(REFUSAL);
        }
        bytes.extend_from_slice(&chunk);
    }
    let response: Value = serde_json::from_slice(&bytes).map_err(|_| REFUSAL)?;
    let auth = &response["auth"];
    let token = auth["client_token"]
        .as_str()
        .filter(|s| s.len() >= 20)
        .ok_or(REFUSAL)?;
    let ttl = auth["lease_duration"].as_u64().ok_or(REFUSAL)?;
    if auth["policies"] != json!([POLICY]) || !(1..=3600).contains(&ttl) {
        return Err(REFUSAL);
    }
    for (method, path, body) in [
        (Method::GET, "transit/keys/foreign-snapshot-probe", None),
        (
            Method::POST,
            "auth/token/create",
            Some(json!({"ttl":"invalid"})),
        ),
        (
            Method::GET,
            "sys/policies/acl/selfhost-raft-snapshot-read",
            None,
        ),
    ] {
        let mut request = bao
            .client()
            .request(method, format!("{}/v1/{path}", bao.origin()))
            .timeout(Duration::from_secs(10))
            .header("X-Vault-Token", token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        if request.send().await.map_err(|_| REFUSAL)?.status() != StatusCode::FORBIDDEN {
            return Err(REFUSAL);
        }
    }
    Ok(token.to_owned())
}

/// Create the existing v2 archive with scoped AppRole authority and atomic publication.
pub async fn export(
    state: &Path,
    output: &Path,
    config: &Path,
    endpoint: &str,
    identity: &Path,
) -> Result<PathBuf> {
    let endpoint = origin(endpoint)?;
    let state = fs::canonicalize(state).map_err(|_| REFUSAL)?;
    if !state.is_dir() {
        return Err(REFUSAL);
    }
    let output = private_directory(output)?;
    if output.starts_with(&state) {
        return Err(REFUSAL);
    }
    let config = fs::read(config).map_err(|_| REFUSAL)?;
    if !std::str::from_utf8(&config)
        .map_err(|_| REFUSAL)?
        .contains("storage \"raft\"")
    {
        return Err(REFUSAL);
    }
    let ca = state.join("tls/ca.crt");
    let info = fs::symlink_metadata(&ca).map_err(|_| REFUSAL)?;
    if !info.is_file() || info.file_type().is_symlink() {
        return Err(REFUSAL);
    }
    let bao = OpenBaoHttp::connect_with_read_timeout(endpoint, Some(&ca), Duration::from_secs(300))
        .map_err(|_| REFUSAL)?;
    let token = snapshot_login(&bao, identity).await?;
    let mut response = bao
        .client()
        .get(format!("{}/v1/sys/storage/raft/snapshot", bao.origin()))
        .header("X-Vault-Token", token)
        .send()
        .await
        .map_err(|_| REFUSAL)?;
    if response.status() != StatusCode::OK {
        return Err(REFUSAL);
    }
    let archive = output.join(format!(
        "openbao-raft-{}-{}.zip",
        Utc::now().format("%Y%m%d-%H%M%S"),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let mut partial = tempfile::Builder::new()
        .prefix(".openbao-raft-")
        .suffix(".partial")
        .tempfile_in(&output)
        .map_err(|_| REFUSAL)?;
    {
        let mut bundle = ZipWriter::new(partial.as_file_mut());
        bundle
            .start_file(
                "raft.snap",
                SimpleFileOptions::default()
                    .large_file(true)
                    .compression_method(CompressionMethod::Stored),
            )
            .map_err(|_| REFUSAL)?;
        let mut digest = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|_| REFUSAL)? {
            bundle.write_all(&chunk).map_err(|_| REFUSAL)?;
            digest.update(&chunk);
            size += chunk.len() as u64;
        }
        if size == 0 {
            return Err(REFUSAL);
        }
        bundle
            .start_file(
                "openbao-selfhost.hcl",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .map_err(|_| REFUSAL)?;
        bundle.write_all(&config).map_err(|_| REFUSAL)?;
        bundle
            .start_file(
                "manifest.json",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .map_err(|_| REFUSAL)?;
        let manifest = json!({"created_at":Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "format":"marty-openbao-raft-snapshot-v2", "snapshot_sha256":format!("{:x}",digest.finalize()),
            "warning":"Contains all OpenBao Raft key custody state; hold unseal material separately."});
        serde_json::to_writer_pretty(&mut bundle, &manifest).map_err(|_| REFUSAL)?;
        bundle.write_all(b"\n").map_err(|_| REFUSAL)?;
        bundle
            .finish()
            .map_err(|_| REFUSAL)?
            .sync_all()
            .map_err(|_| REFUSAL)?;
    }
    partial.persist_noclobber(&archive).map_err(|_| REFUSAL)?;
    Ok(archive)
}
