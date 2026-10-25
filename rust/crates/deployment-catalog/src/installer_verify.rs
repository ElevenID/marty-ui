//! Native verification of private installer artifacts with fixed trust anchors.
//! Callers exclusively own staging and consume the same bytes after verification.
#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, String>;
const COSIGN_SHA: &str = "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa";
// Extracted from the bootstrap-pinned gh2.103.2 archive, SHA62ccf747...959c8.
const GH_SHA: &str = "cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e";

fn file_digest(path: &Path, limit: u64, executable: bool) -> Result<(String, u64)> {
    if !executable {
        crate::installer_runtime::private_parent(
            path.parent().ok_or("verification parent missing")?,
        )?;
    }
    if !path.is_absolute()
        || path
            .canonicalize()
            .map_err(|_| "verification input unavailable")?
            != path
    {
        return Err("verification inputs must use absolute non-symlink paths".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "verification input unavailable")?;
    let m = file
        .metadata()
        .map_err(|_| "verification input unavailable")?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if executable { 0o700 } else { 0o600 }
        || m.len() == 0
        || m.len() > limit
    {
        return Err("verification input is not private ordinary owned data".into());
    }
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut bytes = [0u8; 65536];
    loop {
        let count = file
            .read(&mut bytes)
            .map_err(|_| "cannot read verification input")?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > limit {
            return Err("verification input exceeds bound".into());
        }
        digest.update(&bytes[..count]);
    }
    if size != m.len() {
        return Err("verification input changed".into());
    }
    Ok((format!("{:x}", digest.finalize()), size))
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| "verification path is not UTF-8".into())
}

pub(crate) fn read_private_record(path: &Path) -> Result<Vec<u8>> {
    let before = file_digest(path, 65536, false)?;
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot read installer record")?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read installer record")?;
    if bytes.len() as u64 != before.1 || format!("{:x}", Sha256::digest(&bytes)) != before.0 {
        return Err("installer record changed".into());
    }
    Ok(bytes)
}

pub struct VerificationTools {
    cosign: PathBuf,
    gh: PathBuf,
    staging: PathBuf,
}
impl VerificationTools {
    pub fn new(staging: &Path, gh: &Path) -> Result<Self> {
        let tools = Self {
            cosign: staging.join("cosign"),
            gh: gh.to_path_buf(),
            staging: staging.to_path_buf(),
        };
        tools.check_tools()?;
        Ok(tools)
    }
    fn check_tools(&self) -> Result<()> {
        for (path, expected, size) in [
            (&self.cosign, COSIGN_SHA, 145688404),
            (&self.gh, GH_SHA, 41070752),
        ] {
            let (actual, count) = file_digest(path, size, true)?;
            if actual != expected || count != size {
                return Err("installer verifier trust anchor differs".into());
            }
        }
        Ok(())
    }
    /// Verify both blob signature and exact workflow/run/source provenance.
    /// The subject's returned digest must also match the admitted inventory.
    pub fn verify(
        &self,
        subject: &Path,
        workflow: &str,
        source: &str,
        run: u64,
        attempt: u64,
    ) -> Result<String> {
        if ![
            ".github/workflows/nightly-release.yml",
            ".github/workflows/cd.yml",
            ".github/workflows/installer-promote.yml",
        ]
        .contains(&workflow)
            || !regex::Regex::new(r"\A[0-9a-f]{40}\z")
                .unwrap()
                .is_match(source)
            || run == 0
            || attempt == 0
            || run >= 9007199254740992
            || attempt >= 9007199254740992
        {
            return Err("invalid verification identity".into());
        }
        self.check_tools()?;
        let before = file_digest(subject, 536870912, false)?;
        let signature = sidecar(subject, ".sigstore.json");
        let provenance = sidecar(subject, ".provenance.jsonl");
        let signature_before = file_digest(&signature, 1048576, false)?;
        let provenance_before = file_digest(&provenance, 1048576, false)?;
        let identity = format!("https://github.com/ElevenID/marty-ui/{workflow}@refs/heads/main");
        crate::installer_runtime::run_installer_verifier(
            &self.cosign,
            &[
                "verify-blob",
                text(subject)?,
                "--bundle",
                text(&signature)?,
                "--certificate-identity",
                &identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
            ],
            &self.staging,
        )?;
        let signer = format!("ElevenID/marty-ui/{workflow}");
        let output = crate::installer_runtime::run_installer_verifier(
            &self.gh,
            &[
                "attestation",
                "verify",
                text(subject)?,
                "--bundle",
                text(&provenance)?,
                "--repo",
                "ElevenID/marty-ui",
                "--signer-workflow",
                &signer,
                "--source-ref",
                "refs/heads/main",
                "--source-digest",
                source,
                "--deny-self-hosted-runners",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--format",
                "json",
            ],
            &self.staging,
        )?;
        crate::installer_release::verify_gh_certificate(
            output.as_bytes(),
            workflow,
            source,
            run,
            attempt,
        )?;
        if file_digest(subject, 536870912, false)? != before
            || file_digest(&signature, 1048576, false)? != signature_before
            || file_digest(&provenance, 1048576, false)? != provenance_before
        {
            return Err("installer verification inputs changed".into());
        }
        Ok(before.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn hash_guard_refuses_links_public_modes_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("subject");
        std::fs::write(&path, b"test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(file_digest(&path, 4, false).unwrap().1, 4);
        assert!(file_digest(&path, 3, false).is_err());
        let linked = dir.path().join("linked");
        symlink(&path, &linked).unwrap();
        assert!(file_digest(&linked, 4, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(file_digest(&path, 4, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(file_digest(&path, 4, false).is_err());
    }
    #[test]
    fn unpinned_executable_is_never_launched() {
        let dir = tempfile::tempdir().unwrap();
        let cosign = dir.path().join("cosign");
        std::fs::write(&cosign, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&cosign, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(VerificationTools::new(dir.path(), &dir.path().join("gh")).is_err());
    }
}
