//! Scoped, keyless Raft export. No root or unseal material is read.
use crate::operator::{Result, REFUSAL};
use crate::operator_files::private_directory;
use chrono::Utc;
use marty_openbao_http::OpenBaoHttp;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

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
    let login =
        crate::approle::login(&bao, crate::approle::Role::Snapshot, identity, &json!({})).await?;
    let token = login["token"].as_str().ok_or(REFUSAL)?;
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
