//! Execute the authenticated release download/extraction stage. No Docker or
//! remote provisioning occurs here. Caller exclusively owns private staging,
//! retains it on error, and persists returned evidence before runtime mutation.
#![cfg(target_os = "linux")]

use crate::{
    installer_artifacts,
    installer_fetch::GitHubReleaseFetcher,
    installer_release::{self as release, Channel, Inventory},
    installer_verify::{read_private_record, VerificationTools},
};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct PreparedRelease {
    pub inventory: Inventory,
    pub channel: Option<Channel>,
    pub admission_bytes: Vec<u8>,
    pub inventory_bytes: Vec<u8>,
    pub channel_bytes: Option<Vec<u8>>,
    pub bundle: PathBuf,
}

async fn sidecars(
    fetcher: &GitHubReleaseFetcher,
    tag: &str,
    name: &str,
    directory: &Path,
) -> Result<(), String> {
    for suffix in [".sigstore.json", ".provenance.jsonl"] {
        let asset = format!("{name}{suffix}");
        fetcher
            .fetch_sidecar(tag, &asset, &directory.join(&asset))
            .await?;
    }
    Ok(())
}

/// expected_source/version MUST come from the running binary's embedded build
/// identity; operator_sha MUST be the hash of that executable, not CLI input.
/// download_dir is a new private staging directory, never an existing install.
pub async fn prepare_release(
    admission_path: &Path,
    selected_channel: Option<(&str, &Path)>,
    tools: &VerificationTools,
    download_dir: &Path,
    expected_source: &str,
    expected_version: &str,
    operator_sha: &str,
) -> Result<PreparedRelease, String> {
    let admission_bytes = read_private_record(admission_path)?;
    let admission = release::parse_admission(&admission_bytes)?;
    if admission.source_sha != expected_source || admission.release_tag != expected_version {
        return Err("release differs from running operator build".into());
    }
    let admission_digest = tools.verify(
        admission_path,
        release::PROMOTION_WORKFLOW,
        &admission.promotion_source_sha,
        admission.promotion_run_id,
        admission.promotion_run_attempt,
    )?;
    if admission_digest != release::sha256(&admission_bytes) {
        return Err("admission changed during verification".into());
    }
    let (channel, channel_bytes) = if let Some((name, path)) = selected_channel {
        let bytes = read_private_record(path)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "host clock invalid")?
            .as_secs();
        let channel = release::bind_channel(&bytes, &admission_bytes, name, now)?;
        let channel_digest = tools.verify(
            path,
            release::PROMOTION_WORKFLOW,
            &channel.promotion_source_sha,
            channel.promotion_run_id,
            channel.promotion_run_attempt,
        )?;
        if channel_digest != release::sha256(&bytes) {
            return Err("channel changed during verification".into());
        }
        (Some(channel), Some(bytes))
    } else {
        (None, None)
    };

    let fetcher = GitHubReleaseFetcher::new()?;
    let inventory_path = download_dir.join("installer-inventory.json");
    fetcher
        .fetch_record(
            expected_version,
            "installer-inventory.json",
            &inventory_path,
        )
        .await?;
    sidecars(
        &fetcher,
        expected_version,
        "installer-inventory.json",
        download_dir,
    )
    .await?;
    let workflow = release::build_workflow(expected_version)?;
    let inventory_digest = tools.verify(
        &inventory_path,
        workflow,
        expected_source,
        admission.build_run_id,
        admission.build_run_attempt,
    )?;
    let inventory_bytes = read_private_record(&inventory_path)?;
    if inventory_digest != release::sha256(&inventory_bytes) {
        return Err("inventory changed during verification".into());
    }
    let (_, inventory) = release::bind_release(
        &admission_bytes,
        &inventory_bytes,
        operator_sha,
        expected_source,
        expected_version,
    )?;
    for name in [
        "install.sh",
        "prepared-selfhost-images.json",
        "prepared-selfhost-bundle.zip",
    ] {
        let artifact = inventory.artifact(name)?;
        let path = download_dir.join(name);
        fetcher
            .fetch_verified(
                expected_version,
                name,
                &path,
                artifact.size,
                &artifact.sha256,
            )
            .await?;
        sidecars(&fetcher, expected_version, name, download_dir).await?;
        let hash = tools.verify(
            &path,
            workflow,
            expected_source,
            admission.build_run_id,
            admission.build_run_attempt,
        )?;
        if hash != artifact.sha256 {
            return Err("verified artifact differs from admitted inventory".into());
        }
    }
    let bundle = installer_artifacts::extract_bundle(
        &download_dir.join("prepared-selfhost-bundle.zip"),
        &download_dir.join("extracted"),
        &inventory.artifact("prepared-selfhost-bundle.zip")?.sha256,
    )?;
    // The runtime must validate packaged marker semantics/Compose image roles
    // before starting services. The result here proves authenticated extraction.
    Ok(PreparedRelease {
        inventory,
        channel,
        admission_bytes,
        inventory_bytes,
        channel_bytes,
        bundle,
    })
}
