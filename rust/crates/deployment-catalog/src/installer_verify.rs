//! Native verification of private installer artifacts with fixed trust anchors.
//! Callers exclusively own staging and consume the same bytes after verification.
#![cfg(target_os = "linux")]

use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, String>;
const COSIGN_SHA: &str = "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa";
// Extracted from the bootstrap-pinned gh2.103.2 archive, SHA62ccf747...959c8.
const GH_SHA: &str = "cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e";

// This revision covers the complete fixed certificate/output policy, including
// duplicate-field rejection in installer_release::verify_gh_certificate. A
// change to that policy must change this revision. Nothing is persisted across
// transactions, executables, or policy revisions.
const VERIFICATION_POLICY: [&str; 9] = [
    "elevenid.installer-blob-verification/v1",
    crate::installer_release::REPOSITORY,
    crate::installer_release::REF,
    crate::installer_release::ISSUER,
    "1140864197",
    "github-hosted",
    "https://slsa.dev/provenance/v1",
    COSIGN_SHA,
    GH_SHA,
];

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct VerificationKey {
    subject: (String, u64),
    signature: (String, u64),
    provenance: (String, u64),
    workflow: String,
    source: String,
    run: u64,
    attempt: u64,
    policy: [&'static str; 9],
}

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
    read_private_bytes(path, 65536)
}
pub(crate) fn read_private_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    if maximum > 4 * 1024 * 1024 {
        return Err("invalid evidence bound".into());
    }
    let before = file_digest(path, maximum, false)?;
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot read installer record")?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read installer record")?;
    if bytes.len() as u64 != before.1 || format!("{:x}", Sha256::digest(&bytes)) != before.0 {
        return Err("installer record changed".into());
    }
    Ok(bytes)
}

pub(crate) fn current_operator_digest() -> Result<String> {
    let path = std::env::current_exe().map_err(|_| "cannot locate running installer")?;
    operator_digest(&path)
}
pub(crate) fn operator_digest(path: &Path) -> Result<String> {
    crate::installer_runtime::private_parent(path.parent().ok_or("operator parent missing")?)?;
    Ok(file_digest(path, 536870912, true)?.0)
}

/// Check an inert private asset's exact size and digest before verifier invocation.
/// Executable payload copies remain 0600; this never authenticates provenance.
pub(crate) fn check_private_asset(path: &Path, expected_sha: &str, size: u64) -> Result<()> {
    if size == 0 || size > 536870912 {
        return Err("installer asset size outside verification bound".into());
    }
    let observed = file_digest(path, size, false)?;
    if observed.0 != expected_sha || observed.1 != size {
        return Err("installer asset differs from inventory".into());
    }
    Ok(())
}

/// One acquisition transaction's pinned standard tools and successful checks.
/// Reuse this instance through selection and preparation; never persist or
/// reconstruct its cache from an installation receipt.
pub struct VerificationTools {
    cosign: PathBuf,
    gh: PathBuf,
    staging: PathBuf,
    verified: RefCell<BTreeSet<VerificationKey>>,
}
impl VerificationTools {
    pub fn new(staging: &Path, gh: &Path) -> Result<Self> {
        let tools = Self {
            cosign: staging.join("cosign"),
            gh: gh.to_path_buf(),
            staging: staging.to_path_buf(),
            verified: RefCell::new(BTreeSet::new()),
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
    /// Identical content/proofs/policy reuse only this transaction's success;
    /// private-file custody and current bytes are checked even on a cache hit.
    pub fn verify(
        &self,
        subject: &Path,
        workflow: &str,
        source: &str,
        run: u64,
        attempt: u64,
    ) -> Result<String> {
        self.check_tools()?;
        self.verify_with(
            subject,
            workflow,
            source,
            run,
            attempt,
            crate::installer_runtime::run_installer_verifier,
        )
    }

    // The private invocation seam lets tests exercise the real file/cache and
    // certificate checks without executing an unpinned verifier. The public
    // entry above always checks the tools and uses the fixed bounded runner.
    fn verify_with(
        &self,
        subject: &Path,
        workflow: &str,
        source: &str,
        run: u64,
        attempt: u64,
        mut invoke: impl FnMut(&Path, &[&str], &Path) -> Result<String>,
    ) -> Result<String> {
        if ![
            ".github/workflows/nightly-release.yml",
            ".github/workflows/cd.yml",
            ".github/workflows/installer-promote.yml",
            crate::installer_release::ACCEPTANCE_WORKFLOW,
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
        let before = file_digest(subject, 536870912, false)?;
        let signature = sidecar(subject, ".sigstore.json");
        let provenance = sidecar(subject, ".provenance.jsonl");
        let signature_before = file_digest(&signature, 1048576, false)?;
        let provenance_before = file_digest(&provenance, 1048576, false)?;
        // Cache hits retain the path/staging constraints otherwise enforced by
        // constructing arguments and launching the isolated standard tools.
        crate::installer_runtime::private_parent(&self.staging)?;
        for path in [subject, signature.as_path(), provenance.as_path()] {
            text(path)?;
        }
        let key = VerificationKey {
            subject: before.clone(),
            signature: signature_before.clone(),
            provenance: provenance_before.clone(),
            workflow: workflow.into(),
            source: source.into(),
            run,
            attempt,
            policy: VERIFICATION_POLICY,
        };
        if !self.verified.borrow().contains(&key) {
            let identity =
                format!("https://github.com/ElevenID/marty-ui/{workflow}@refs/heads/main");
            invoke(
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
            let output = invoke(
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
        }
        if file_digest(subject, 536870912, false)? != before
            || file_digest(&signature, 1048576, false)? != signature_before
            || file_digest(&provenance, 1048576, false)? != provenance_before
        {
            return Err("installer verification inputs changed".into());
        }
        self.verified.borrow_mut().insert(key);
        Ok(before.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const WORKFLOW: &str = ".github/workflows/nightly-release.yml";
    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, VerificationTools) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let subject = dir.path().join("subject");
        write_private(&subject, b"artifact");
        write_private(&sidecar(&subject, ".sigstore.json"), b"signature");
        write_private(&sidecar(&subject, ".provenance.jsonl"), b"provenance");
        let tools = VerificationTools {
            cosign: dir.path().join("cosign"),
            gh: dir.path().join("gh"),
            staging: dir.path().into(),
            verified: RefCell::new(BTreeSet::new()),
        };
        (dir, subject, tools)
    }

    fn certificate() -> String {
        json!([{"attestation":{},"verificationResult":{"signature":{"certificate":{
            "issuer":crate::installer_release::ISSUER,
            "runnerEnvironment":"github-hosted",
            "sourceRepositoryURI":"https://github.com/ElevenID/marty-ui",
            "sourceRepositoryIdentifier":"1140864197",
            "sourceRepositoryDigest":SOURCE,
            "sourceRepositoryRef":crate::installer_release::REF,
            "buildSignerURI":format!("https://github.com/ElevenID/marty-ui/{WORKFLOW}@refs/heads/main"),
            "runInvocationURI":"https://github.com/ElevenID/marty-ui/actions/runs/42/attempts/2"
        }}}}]).to_string()
    }

    fn verify_counted(
        tools: &VerificationTools,
        subject: &Path,
        calls: &mut usize,
    ) -> Result<String> {
        tools.verify_with(subject, WORKFLOW, SOURCE, 42, 2, |tool, args, staging| {
            *calls += 1;
            assert_eq!(staging, tools.staging.as_path());
            if tool == tools.cosign.as_path() {
                let signature = sidecar(subject, ".sigstore.json");
                assert_eq!(args, [
                    "verify-blob", text(subject)?, "--bundle",
                    text(&signature)?,
                    "--certificate-identity",
                    "https://github.com/ElevenID/marty-ui/.github/workflows/nightly-release.yml@refs/heads/main",
                    "--certificate-oidc-issuer", crate::installer_release::ISSUER,
                ]);
                Ok(String::new())
            } else {
                assert_eq!(tool, tools.gh.as_path());
                let provenance = sidecar(subject, ".provenance.jsonl");
                assert_eq!(args, [
                    "attestation", "verify", text(subject)?, "--bundle",
                    text(&provenance)?,
                    "--repo", crate::installer_release::REPOSITORY,
                    "--signer-workflow", "ElevenID/marty-ui/.github/workflows/nightly-release.yml",
                    "--source-ref", crate::installer_release::REF,
                    "--source-digest", SOURCE, "--deny-self-hosted-runners",
                    "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json",
                ]);
                Ok(certificate())
            }
        })
    }

    #[test]
    fn transaction_reuses_only_identical_content_proofs_and_policy() {
        let (dir, subject, tools) = fixture();
        let mut calls = 0;
        let digest = verify_counted(&tools, &subject, &mut calls).unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            verify_counted(&tools, &subject, &mut calls).unwrap(),
            digest
        );
        let copied = dir.path().join("private-copy");
        for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
            write_private(
                &sidecar(&copied, suffix),
                &std::fs::read(sidecar(&subject, suffix)).unwrap(),
            );
        }
        assert_eq!(verify_counted(&tools, &copied, &mut calls).unwrap(), digest);
        assert_eq!(calls, 2);
        assert_eq!(tools.verified.borrow().len(), 1);
    }

    #[test]
    fn transaction_changed_subject_or_either_proof_requires_verification() {
        for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
            let (_dir, subject, tools) = fixture();
            let mut calls = 0;
            verify_counted(&tools, &subject, &mut calls).unwrap();
            write_private(&sidecar(&subject, suffix), b"changed");
            let result = tools.verify_with(&subject, WORKFLOW, SOURCE, 42, 2, |_, _, _| {
                calls += 1;
                Err("verification failed".into())
            });
            assert!(result.is_err(), "changed input {suffix} reused success");
            assert_eq!(calls, 3);
            assert_eq!(tools.verified.borrow().len(), 1);
            verify_counted(&tools, &subject, &mut calls).unwrap();
            assert_eq!(calls, 5);
            assert_eq!(tools.verified.borrow().len(), 2);
        }
    }

    #[test]
    fn transaction_expected_workflow_source_run_and_attempt_are_bound() {
        let (_dir, subject, tools) = fixture();
        let mut calls = 0;
        verify_counted(&tools, &subject, &mut calls).unwrap();
        for (workflow, source, run, attempt) in [
            (".github/workflows/cd.yml", SOURCE, 42, 2),
            (WORKFLOW, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 42, 2),
            (WORKFLOW, SOURCE, 43, 2),
            (WORKFLOW, SOURCE, 42, 3),
        ] {
            let mut attempted = 0;
            let result = tools.verify_with(&subject, workflow, source, run, attempt, |_, _, _| {
                attempted += 1;
                Ok(certificate())
            });
            assert!(result.is_err());
            assert_eq!(attempted, 2);
            assert_eq!(tools.verified.borrow().len(), 1);
        }
        assert!(tools
            .verify_with(
                &subject,
                ".github/workflows/unapproved.yml",
                SOURCE,
                42,
                2,
                |_, _, _| panic!("invalid policy reached verifier")
            )
            .is_err());
        verify_counted(&tools, &subject, &mut calls).unwrap();
        assert_eq!(calls, 2);
    }

    #[test]
    fn transaction_failed_tools_or_certificate_never_cache_success() {
        for failure in ["cosign", "gh", "issuer", "duplicate"] {
            let (_dir, subject, tools) = fixture();
            let result = tools.verify_with(&subject, WORKFLOW, SOURCE, 42, 2, |tool, _, _| {
                if tool.file_name().unwrap() == failure {
                    return Err("tool failed".into());
                }
                Ok(match failure {
                    "issuer" => certificate()
                        .replace(crate::installer_release::ISSUER, "https://wrong.invalid"),
                    "duplicate" => certificate().replace(
                        "\"certificate\":{",
                        "\"certificate\":{\"issuer\":\"wrong\",",
                    ),
                    _ => certificate(),
                })
            });
            assert!(result.is_err(), "{failure} was accepted");
            assert!(tools.verified.borrow().is_empty());
            let mut calls = 0;
            verify_counted(&tools, &subject, &mut calls).unwrap();
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn transaction_changed_during_verification_is_not_cached() {
        for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
            let (_dir, subject, tools) = fixture();
            let result = tools.verify_with(&subject, WORKFLOW, SOURCE, 42, 2, |tool, _, _| {
                if tool == tools.gh.as_path() {
                    write_private(&sidecar(&subject, suffix), b"changed while verifying");
                }
                Ok(certificate())
            });
            assert!(result.is_err());
            assert!(tools.verified.borrow().is_empty());
            let mut calls = 0;
            verify_counted(&tools, &subject, &mut calls).unwrap();
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn transaction_cached_success_still_requires_private_files_and_pinned_tools() {
        let (dir, subject, tools) = fixture();
        let mut calls = 0;
        verify_counted(&tools, &subject, &mut calls).unwrap();
        for path in [
            subject.clone(),
            sidecar(&subject, ".sigstore.json"),
            sidecar(&subject, ".provenance.jsonl"),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(verify_counted(&tools, &subject, &mut calls).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(calls, 2);
        let other_staging = dir.path().join("other-staging");
        std::fs::create_dir(&other_staging).unwrap();
        std::fs::set_permissions(&other_staging, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut tools = tools;
        tools.staging = other_staging;
        assert!(verify_counted(&tools, &subject, &mut calls).is_err());
        tools.staging = dir.path().to_path_buf();
        let non_utf8 = dir
            .path()
            .join(std::ffi::OsString::from_vec(b"subject-\xff".to_vec()));
        for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
            write_private(
                &sidecar(&non_utf8, suffix),
                &std::fs::read(sidecar(&subject, suffix)).unwrap(),
            );
        }
        assert!(verify_counted(&tools, &non_utf8, &mut calls).is_err());
        assert_eq!(calls, 2);
        assert!(tools.verify(&subject, WORKFLOW, SOURCE, 42, 2).is_err());
        assert_eq!(tools.verified.borrow().len(), 1);
    }

    #[test]
    fn transaction_policy_revision_and_lifetime_cannot_reuse_another_success() {
        let (_dir, subject, tools) = fixture();
        let mut calls = 0;
        verify_counted(&tools, &subject, &mut calls).unwrap();
        let mut prior_policy = tools.verified.borrow().iter().next().unwrap().clone();
        prior_policy.policy[0] = "another-policy";
        tools.verified.borrow_mut().clear();
        tools.verified.borrow_mut().insert(prior_policy);
        verify_counted(&tools, &subject, &mut calls).unwrap();
        assert_eq!(calls, 4);
        let next = VerificationTools {
            verified: RefCell::new(BTreeSet::new()),
            ..tools
        };
        verify_counted(&next, &subject, &mut calls).unwrap();
        assert_eq!(calls, 6);
    }

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
