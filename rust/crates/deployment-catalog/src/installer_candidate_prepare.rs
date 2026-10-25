//! Authenticate an acceptance-only candidate from an exclusively owned local
//! staging directory. No normal admission, channel promotion or runtime action.
//! Local candidate preparation alone does not prove public replay. The optional
//! published fetch helper observes anonymous bytes only when run on the guest;
//! the controller still must authenticate guest identity and the public release.
#![cfg(target_os = "linux")]

use crate::{
    installer_artifacts,
    installer_fetch::{DownloadReceipt, GitHubReleaseFetcher},
    installer_release::{
        self as release, CandidateAuthorization, CandidateContext, CandidatePhase, Inventory,
    },
    installer_runtime,
    installer_verify::{self, read_private_record, VerificationTools},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const ARTIFACTS: [&str; 4] = [
    "install.sh",
    "marty-deploy-linux-amd64",
    "prepared-selfhost-bundle.zip",
    "prepared-selfhost-images.json",
];

pub struct PreparedCandidate {
    pub authorization: CandidateAuthorization,
    pub inventory: Inventory,
    pub authorization_bytes: Vec<u8>,
    pub inventory_bytes: Vec<u8>,
    pub image_lock_bytes: Vec<u8>,
    pub bundle: PathBuf,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "candidate host clock invalid".into())
}

fn input_names(directory: &Path) -> Result<(), String> {
    installer_runtime::private_parent(directory)?;
    let expected: BTreeSet<String> = std::iter::once("installer-inventory.json")
        .chain(ARTIFACTS)
        .flat_map(|name| {
            [
                name.to_owned(),
                format!("{name}.sigstore.json"),
                format!("{name}.provenance.jsonl"),
            ]
        })
        .collect();
    let observed = std::fs::read_dir(directory)
        .map_err(|_| "candidate input directory unavailable")?
        .map(|entry| {
            entry
                .map_err(|_| "candidate input unavailable".to_owned())?
                .file_name()
                .into_string()
                .map_err(|_| "candidate input name invalid".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected {
        return Err("candidate input set differs from exact artifact closure".into());
    }
    Ok(())
}

fn bind_inputs(
    authorization: &[u8],
    inventory: &[u8],
    expected: &CandidateContext,
    embedded_source: &str,
    embedded_version: &str,
    running_operator: &str,
    timestamp: u64,
) -> Result<(CandidateAuthorization, Inventory), String> {
    if expected.source_sha != embedded_source
        || expected.release_tag != embedded_version
        || expected.operator_sha != running_operator
    {
        return Err("candidate differs from running operator identity".into());
    }
    release::bind_candidate_authorization(authorization, inventory, expected, timestamp)
}

fn bind_public_authorization(
    bytes: &[u8],
    expected: &CandidateContext,
    embedded_source: &str,
    embedded_version: &str,
    running_operator: &str,
    timestamp: u64,
) -> Result<CandidateAuthorization, String> {
    if expected.phase != CandidatePhase::Published
        || expected.source_sha != embedded_source
        || expected.release_tag != embedded_version
        || expected.operator_sha != running_operator
    {
        return Err("published candidate differs from running operator".into());
    }
    let authorization = release::parse_candidate_authorization(bytes, timestamp)?;
    if authorization.phase != CandidatePhase::Published
        || authorization.source_sha != expected.source_sha
        || authorization.release_tag != expected.release_tag
        || authorization.operator_sha256 != expected.operator_sha
        || authorization.nonce != expected.nonce
        || authorization.harness_source_sha != expected.harness_source_sha
        || authorization.run_id != expected.run_id
        || authorization.run_attempt != expected.run_attempt
    {
        return Err("published candidate authorization context differs".into());
    }
    Ok(authorization)
}

fn bind_download_receipts(directory: &Path, receipts: &[DownloadReceipt]) -> Result<(), String> {
    for receipt in receipts {
        if receipt.asset.contains('/')
            || receipt.asset.contains('\\')
            || receipt.asset == "."
            || receipt.asset == ".."
        {
            return Err("public candidate receipt asset name invalid".into());
        }
        installer_verify::check_private_asset(
            &directory.join(&receipt.asset),
            &receipt.sha256,
            receipt.bytes,
        )?;
    }
    Ok(())
}

/// Download the exact acceptance-only published candidate over anonymous HTTPS.
/// This does not prove how the *running* operator was bootstrapped. A separate
/// guest bootstrap must fetch and authenticate that executable before invoking
/// this stage. The caller retains this private directory on every failure and
/// later runs prepare_candidate against these same files before any runtime use.
pub async fn fetch_published_inputs(
    authorization_path: &Path,
    inputs_dir: &Path,
    tools: &VerificationTools,
    expected: &CandidateContext,
    embedded_source: &str,
    embedded_version: &str,
) -> Result<Vec<DownloadReceipt>, String> {
    if expected.phase != CandidatePhase::Published {
        return Err("published phase required for public candidate acquisition".into());
    }
    installer_runtime::private_parent(inputs_dir)?;
    if std::fs::read_dir(inputs_dir)
        .map_err(|_| "public candidate input directory unavailable")?
        .next()
        .is_some()
    {
        return Err("public candidate input directory must be fresh".into());
    }
    let authorization_bytes = read_private_record(authorization_path)?;
    let signature = tools.verify(
        authorization_path,
        release::ACCEPTANCE_WORKFLOW,
        &expected.harness_source_sha,
        expected.run_id,
        expected.run_attempt,
    )?;
    if signature != release::sha256(&authorization_bytes) {
        return Err("published candidate authorization changed".into());
    }
    let authorization = bind_public_authorization(
        &authorization_bytes,
        expected,
        embedded_source,
        embedded_version,
        &installer_verify::current_operator_digest()?,
        now()?,
    )?;
    let fetcher = GitHubReleaseFetcher::new()?;
    let mut receipts = Vec::new();
    let inventory_path = inputs_dir.join("installer-inventory.json");
    receipts.push(
        fetcher
            .fetch_record(
                &expected.release_tag,
                "installer-inventory.json",
                &inventory_path,
            )
            .await?,
    );
    for suffix in [".sigstore.json", ".provenance.jsonl"] {
        let name = format!("installer-inventory.json{suffix}");
        receipts.push(
            fetcher
                .fetch_sidecar(&expected.release_tag, &name, &inputs_dir.join(&name))
                .await?,
        );
    }
    bind_download_receipts(inputs_dir, &receipts)?;
    let inventory_bytes = read_private_record(&inventory_path)?;
    if release::sha256(&inventory_bytes) != authorization.inventory_sha256 {
        return Err("public inventory differs from signed candidate authorization".into());
    }
    let (_, inventory) = bind_inputs(
        &authorization_bytes,
        &inventory_bytes,
        expected,
        embedded_source,
        embedded_version,
        &expected.operator_sha,
        now()?,
    )?;
    let workflow = release::build_workflow(&inventory.release_tag)?;
    let verified = tools.verify(
        &inventory_path,
        workflow,
        &inventory.source_sha,
        inventory.build_run_id,
        inventory.build_run_attempt,
    )?;
    if verified != release::sha256(&inventory_bytes) {
        return Err("public inventory provenance differs".into());
    }
    bind_download_receipts(inputs_dir, &receipts)?;
    for name in ARTIFACTS {
        let artifact = inventory.artifact(name)?;
        let path = inputs_dir.join(name);
        receipts.push(
            fetcher
                .fetch_verified(
                    &inventory.release_tag,
                    name,
                    &path,
                    artifact.size,
                    &artifact.sha256,
                )
                .await?,
        );
        for suffix in [".sigstore.json", ".provenance.jsonl"] {
            let sidecar = format!("{name}{suffix}");
            receipts.push(
                fetcher
                    .fetch_sidecar(&inventory.release_tag, &sidecar, &inputs_dir.join(&sidecar))
                    .await?,
            );
        }
        bind_download_receipts(inputs_dir, &receipts[receipts.len() - 3..])?;
        let verified = tools.verify(
            &path,
            workflow,
            &inventory.source_sha,
            inventory.build_run_id,
            inventory.build_run_attempt,
        )?;
        if verified != artifact.sha256 {
            return Err("public artifact provenance differs from signed inventory".into());
        }
        bind_download_receipts(inputs_dir, &receipts[receipts.len() - 3..])?;
    }
    if read_private_record(&inventory_path)? != inventory_bytes
        || read_private_record(authorization_path)? != authorization_bytes
        || installer_verify::current_operator_digest()? != expected.operator_sha
    {
        return Err("published candidate custody changed during acquisition".into());
    }
    release::parse_candidate_authorization(&authorization_bytes, now()?)?;
    bind_download_receipts(inputs_dir, &receipts)?;
    input_names(inputs_dir)?;
    Ok(receipts)
}

/// Verify the exact controller-selected phase, nonce, harness source and run.
/// `expected` MUST NOT be populated by copying the record under verification;
/// embedded_source/version MUST come from this binary's build identity.
/// The running executable must be privately owned 0700; its staged payload copy
/// must be inert 0600. Every input and its sidecars must be private owned files.
///
/// This creates only an exclusive extraction directory after authentication.
/// It does not consume a nonce, establish public acquisition, validate packaged
/// runtime semantics, or grant consumer admission. Before runtime mutation the
/// caller MUST durably consume the controller nonce, persist authenticated
/// evidence, recheck expiry, and validate the bundle against returned inventory
/// and image_lock_bytes. Retain all partial output on failure; never replay it.
#[allow(clippy::too_many_arguments)]
pub fn prepare_candidate(
    authorization_path: &Path,
    inputs_dir: &Path,
    extraction_dir: &Path,
    tools: &VerificationTools,
    expected: &CandidateContext,
    embedded_source: &str,
    embedded_version: &str,
) -> Result<PreparedCandidate, String> {
    input_names(inputs_dir)?;
    installer_runtime::private_parent(
        extraction_dir
            .parent()
            .ok_or("candidate extraction parent missing")?,
    )?;
    // symlink_metadata also refuses dangling links, without adopting a target.
    match std::fs::symlink_metadata(extraction_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("candidate extraction target must be fresh".into()),
    }
    let authorization_bytes = read_private_record(authorization_path)?;
    let inventory_path = inputs_dir.join("installer-inventory.json");
    let inventory_bytes = read_private_record(&inventory_path)?;
    let operator_sha = installer_verify::current_operator_digest()?;
    let (authorization, inventory) = bind_inputs(
        &authorization_bytes,
        &inventory_bytes,
        expected,
        embedded_source,
        embedded_version,
        &operator_sha,
        now()?,
    )?;

    let authorization_digest = tools.verify(
        authorization_path,
        release::ACCEPTANCE_WORKFLOW,
        &expected.harness_source_sha,
        expected.run_id,
        expected.run_attempt,
    )?;
    if authorization_digest != release::sha256(&authorization_bytes) {
        return Err("candidate authorization changed during verification".into());
    }
    let workflow = release::build_workflow(&inventory.release_tag)?;
    let inventory_digest = tools.verify(
        &inventory_path,
        workflow,
        &inventory.source_sha,
        inventory.build_run_id,
        inventory.build_run_attempt,
    )?;
    if inventory_digest != release::sha256(&inventory_bytes) {
        return Err("candidate inventory changed during verification".into());
    }
    // Reject every payload substitution and wrong size before any extraction.
    for name in ARTIFACTS {
        let artifact = inventory.artifact(name)?;
        installer_verify::check_private_asset(
            &inputs_dir.join(name),
            &artifact.sha256,
            artifact.size,
        )?;
    }
    for name in ARTIFACTS {
        let artifact = inventory.artifact(name)?;
        let verified = tools.verify(
            &inputs_dir.join(name),
            workflow,
            &inventory.source_sha,
            inventory.build_run_id,
            inventory.build_run_attempt,
        )?;
        if verified != artifact.sha256 {
            return Err("candidate payload differs from authenticated inventory".into());
        }
        installer_verify::check_private_asset(
            &inputs_dir.join(name),
            &artifact.sha256,
            artifact.size,
        )?;
    }
    let image_lock_bytes = read_private_record(&inputs_dir.join("prepared-selfhost-images.json"))?;
    if release::sha256(&image_lock_bytes)
        != inventory.artifact("prepared-selfhost-images.json")?.sha256
    {
        return Err("candidate image lock changed after verification".into());
    }
    // Recheck the lease before creating output and again after bounded extraction.
    release::parse_candidate_authorization(&authorization_bytes, now()?)?;
    let bundle = installer_artifacts::extract_bundle(
        &inputs_dir.join("prepared-selfhost-bundle.zip"),
        extraction_dir,
        &inventory.artifact("prepared-selfhost-bundle.zip")?.sha256,
    )?;
    release::parse_candidate_authorization(&authorization_bytes, now()?)?;
    if installer_verify::current_operator_digest()? != operator_sha {
        return Err("candidate running operator changed during preparation".into());
    }
    Ok(PreparedCandidate {
        authorization,
        inventory,
        authorization_bytes,
        inventory_bytes,
        image_lock_bytes,
        bundle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_release::CandidatePhase;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (Vec<u8>, Vec<u8>, CandidateContext) {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/installer-candidate-records.json"
        ))
        .unwrap();
        let auth = value["authorization"].as_str().unwrap().as_bytes().to_vec();
        let inventory = value["inventory"].as_str().unwrap().as_bytes().to_vec();
        let parsed = release::parse_candidate_authorization(&auth, 100000).unwrap();
        // Fixture only: production context is independently supplied by controller.
        let expected = CandidateContext {
            operator_sha: parsed.operator_sha256,
            source_sha: parsed.source_sha,
            release_tag: parsed.release_tag,
            phase: CandidatePhase::Staged,
            nonce: parsed.nonce,
            harness_source_sha: parsed.harness_source_sha,
            run_id: parsed.run_id,
            run_attempt: parsed.run_attempt,
        };
        (auth, inventory, expected)
    }

    #[test]
    fn public_authorization_requires_exact_published_identity_and_live_lease() {
        let (staged, _, mut expected) = fixture();
        let mut value: serde_json::Value = serde_json::from_slice(&staged).unwrap();
        value["phase"] = serde_json::Value::from("published");
        let published = serde_json::to_vec(&value).unwrap();
        expected.phase = CandidatePhase::Published;
        let bind = |bytes: &[u8],
                    context: &CandidateContext,
                    source: &str,
                    version: &str,
                    operator: &str,
                    time| {
            bind_public_authorization(bytes, context, source, version, operator, time)
        };
        assert!(bind(
            &published,
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_ok());
        assert!(bind(
            &staged,
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        let mut other = expected.clone();
        other.phase = CandidatePhase::Staged;
        assert!(bind(
            &published,
            &other,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        other = expected.clone();
        other.nonce = "f".repeat(64);
        assert!(bind(
            &published,
            &other,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        assert!(bind(
            &published,
            &expected,
            &"f".repeat(40),
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        assert!(bind(
            &published,
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &"f".repeat(64),
            100000
        )
        .is_err());
        assert!(bind(
            &published,
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            104000
        )
        .is_err());
    }

    #[test]
    fn public_receipts_refuse_payload_and_sidecar_substitution() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let names = [
            "installer-inventory.json",
            "installer-inventory.json.sigstore.json",
            "installer-inventory.json.provenance.jsonl",
        ];
        let receipts: Vec<DownloadReceipt> = names
            .iter()
            .map(|name| {
                let path = directory.path().join(name);
                std::fs::write(&path, b"original public bytes").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                DownloadReceipt {
                    asset: (*name).into(),
                    bytes: 21,
                    sha256: release::sha256(b"original public bytes"),
                    hash_verified: false,
                }
            })
            .collect();
        bind_download_receipts(directory.path(), &receipts).unwrap();
        for name in names {
            let path = directory.path().join(name);
            std::fs::write(&path, b"different public bytes").unwrap();
            assert!(bind_download_receipts(directory.path(), &receipts).is_err());
            std::fs::write(&path, b"original public bytes").unwrap();
        }
        let mut wrong = receipts;
        wrong[1].asset = "../other".into();
        assert!(bind_download_receipts(directory.path(), &wrong).is_err());
    }

    #[test]
    fn candidate_prechecks_bind_running_binary_controller_and_lease() {
        let (auth, inventory, expected) = fixture();
        let bind =
            |context: &CandidateContext, source: &str, version: &str, operator: &str, time| {
                bind_inputs(&auth, &inventory, context, source, version, operator, time)
            };
        assert!(bind(
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_ok());
        assert!(bind(
            &expected,
            &"f".repeat(40),
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        assert!(bind(
            &expected,
            &expected.source_sha,
            "marty-ui@9.9.9",
            &expected.operator_sha,
            100000
        )
        .is_err());
        assert!(bind(
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &"f".repeat(64),
            100000
        )
        .is_err());
        assert!(bind(
            &expected,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            104000
        )
        .is_err());
        let mut changed = expected.clone();
        changed.phase = CandidatePhase::Published;
        assert!(bind(
            &changed,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        changed = expected.clone();
        changed.nonce = "f".repeat(64);
        assert!(bind(
            &changed,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
        changed = expected.clone();
        changed.run_attempt += 1;
        assert!(bind(
            &changed,
            &expected.source_sha,
            &expected.release_tag,
            &expected.operator_sha,
            100000
        )
        .is_err());
    }

    #[test]
    fn exact_input_closure_refuses_missing_extra_and_symlinked_directory() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let inputs = parent.path().join("inputs");
        std::fs::create_dir(&inputs).unwrap();
        std::fs::set_permissions(&inputs, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in std::iter::once("installer-inventory.json").chain(ARTIFACTS) {
            for suffix in ["", ".sigstore.json", ".provenance.jsonl"] {
                std::fs::write(inputs.join(format!("{name}{suffix}")), b"fixture").unwrap();
            }
        }
        assert!(input_names(&inputs).is_ok());
        std::fs::write(inputs.join("extra"), b"fixture").unwrap();
        assert!(input_names(&inputs).is_err());
        std::fs::remove_file(inputs.join("extra")).unwrap();
        std::fs::remove_file(inputs.join("install.sh.provenance.jsonl")).unwrap();
        assert!(input_names(&inputs).is_err());
        let link = parent.path().join("link");
        symlink(&inputs, &link).unwrap();
        assert!(input_names(&link).is_err());
    }

    #[test]
    fn inert_payload_guard_rejects_size_hash_executable_and_link_substitution() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("operator");
        std::fs::write(&path, b"actual bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let digest = release::sha256(b"actual bytes");
        assert!(installer_verify::check_private_asset(&path, &digest, 12).is_ok());
        assert!(installer_verify::check_private_asset(&path, &digest, 11).is_err());
        assert!(installer_verify::check_private_asset(&path, &"f".repeat(64), 12).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(installer_verify::check_private_asset(&path, &digest, 12).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = parent.path().join("linked");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(installer_verify::check_private_asset(&path, &digest, 12).is_err());
    }
}
