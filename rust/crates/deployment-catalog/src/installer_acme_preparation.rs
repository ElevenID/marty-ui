//! Complete fresh application storage creation before an ACME request can pause
//! installation. Continuation observes that boundary; it never reconstructs a
//! fresh-creation capability or adopts a directory left by a partial attempt.
#![cfg(target_os = "linux")]

use crate::{
    installer_creation_identity, installer_host_fs as fs, installer_json, installer_release,
    installer_state::{
        ExecutionScope, Identity, InstallerState, LockedInspection, Phase, RuntimeBinding,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, os::unix::fs::MetadataExt, path::Path};

type Result<T> = std::result::Result<T, String>;
pub(crate) const RECORD: &str = "acme-application-prepared.json";
const REFUSED: &str = "ACME application preparation is incomplete or changed; preserve the installation. Storage creation and credential projection were not replayed";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    directory: bool,
    length: Option<u64>,
    changed_seconds: Option<i64>,
    changed_nanoseconds: Option<i64>,
}

impl Entry {
    fn observe(file: &File, directory: bool, mode: u32, length: Option<u64>) -> Result<Self> {
        let metadata = file.metadata().map_err(|_| REFUSED)?;
        require(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o7777 == mode
                && if directory {
                    metadata.is_dir() && length.is_none()
                } else {
                    metadata.is_file() && metadata.nlink() == 1 && Some(metadata.len()) == length
                },
        )?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode,
            directory,
            length,
            changed_seconds: (!directory).then_some(metadata.ctime()),
            changed_nanoseconds: (!directory).then_some(metadata.ctime_nsec()),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    installation_id: uuid::Uuid,
    release: Identity,
    runtime: RuntimeBinding,
    execution_scope: ExecutionScope,
    provenance: Provenance,
    hosting_selection_sha256: String,
    entries: BTreeMap<String, Entry>,
    prior_evidence_sha256: BTreeMap<String, String>,
    storage_created: bool,
    operator_projection_created: bool,
    application_started: bool,
    deletion_authorized: bool,
    installation_ready: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Provenance {
    OriginalCreationReceipts,
    SignedCandidateQualification,
}

/// Candidate trials retain their own authenticated provenance. They cannot
/// acquire admitted-installation creation/deletion capabilities or Ready.
pub(crate) fn require_supported_scope(state: &LockedInspection) -> Result<()> {
    match state.journal().execution_scope() {
        ExecutionScope::Unclassified => Ok(()),
        ExecutionScope::CandidateTest(_) => {
            crate::installer_rootless_storage_canary::require_completed(state).map(|_| ())
        }
        _ => Err(REFUSED.into()),
    }
}

fn entries(root: &File) -> Result<BTreeMap<String, Entry>> {
    let mut paths = vec![
        ("evidence".to_owned(), true, 0o700, None),
        ("secrets".to_owned(), true, 0o700, None),
        ("state".to_owned(), true, 0o700, None),
        ("state/postgres".to_owned(), true, 0o700, None),
        ("state/redis".to_owned(), true, 0o700, None),
        ("state/applicant".to_owned(), true, 0o2770, None),
        ("backups".to_owned(), true, 0o700, None),
        ("openbao-exports".to_owned(), true, 0o700, None),
        ("openbao-snapshot-identity".to_owned(), true, 0o700, None),
        ("operator-password".to_owned(), false, 0o600, Some(69)),
        (
            "secrets/operator_bootstrap_password".to_owned(),
            false,
            0o444,
            Some(69),
        ),
    ];
    paths.extend(
        crate::installer_application_env::OPTIONAL_EMPTY_SECRETS
            .into_iter()
            .map(|name| (format!("secrets/{name}"), false, 0o444, Some(0))),
    );
    let open = |path: &str| -> Result<File> {
        if let Some((parent, name)) = path.split_once('/') {
            require(!name.contains('/'))?;
            let parent = fs::open_child(root, parent, libc::O_RDONLY | libc::O_DIRECTORY, REFUSED)?;
            fs::open_child(&parent, name, libc::O_PATH, REFUSED)
        } else {
            fs::open_child(root, path, libc::O_PATH, REFUSED)
        }
    };
    let mut observed = BTreeMap::new();
    for (path, directory, mode, length) in &paths {
        observed.insert(
            path.clone(),
            Entry::observe(&open(path)?, *directory, *mode, *length)?,
        );
    }
    for (path, directory, mode, length) in &paths {
        require(
            observed.get(path) == Some(&Entry::observe(&open(path)?, *directory, *mode, *length)?),
        )?;
    }
    Ok(observed)
}

fn observe(state: &LockedInspection, installation: &Path) -> Result<Preparation> {
    state.require_path_binding(installation)?;
    require(state.journal().phase() == Phase::Provisioning)?;
    let mut prior_evidence_sha256 = BTreeMap::new();
    let provenance = match state.journal().execution_scope() {
        ExecutionScope::Unclassified => {
            for (name, schema) in [
                (
                    installer_creation_identity::RECEIPT,
                    "elevenid.installer-created-identity/v1",
                ),
                (
                    installer_creation_identity::CREDENTIAL_RECEIPT,
                    "elevenid.installer-created-credentials/v1",
                ),
                (
                    installer_creation_identity::APPLICATION_RECEIPT,
                    "elevenid.installer-created-application-storage/v1",
                ),
            ] {
                let bytes = state.read_evidence(name)?;
                let value = installer_json::decode(&bytes).map_err(|_| REFUSED)?;
                require(
                    value["schema"] == schema
                        && value["installation_id"]
                            == state.journal().installation_id().to_string()
                        && value["source_sha"] == state.journal().identity().source_sha
                        && value["local_historical_evidence"] == true
                        && value["deletion_authorized"] == false,
                )?;
                prior_evidence_sha256.insert(name.into(), installer_release::sha256(&bytes));
            }
            Provenance::OriginalCreationReceipts
        }
        ExecutionScope::CandidateTest(_) => {
            prior_evidence_sha256 =
                crate::installer_rootless_storage_canary::require_completed(state)?;
            for name in [
                installer_creation_identity::RECEIPT,
                installer_creation_identity::CREDENTIAL_RECEIPT,
                installer_creation_identity::APPLICATION_RECEIPT,
            ] {
                require(state.diagnostic_record(name, true)?.is_none())?;
            }
            Provenance::SignedCandidateQualification
        }
        _ => return Err(REFUSED.into()),
    };
    let preparation = Preparation {
        schema: "elevenid.installer-acme-application-preparation/v2".into(),
        installation_id: state.journal().installation_id(),
        release: state.journal().identity().clone(),
        runtime: state.journal().runtime().ok_or(REFUSED)?.clone(),
        execution_scope: state.journal().execution_scope().clone(),
        provenance,
        hosting_selection_sha256: state
            .journal()
            .hosting_selection_sha256()
            .ok_or(REFUSED)?
            .into(),
        entries: entries(state.installation_directory())?,
        prior_evidence_sha256,
        storage_created: true,
        operator_projection_created: true,
        application_started: false,
        deletion_authorized: false,
        installation_ready: false,
    };
    state.require_path_binding(installation)?;
    Ok(preparation)
}

pub(crate) fn verify(state: &LockedInspection, installation: &Path) -> Result<()> {
    let bytes = state.read_evidence(RECORD)?;
    require(bytes.len() <= 16 * 1024)?;
    let preparation: Preparation =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(preparation == observe(state, installation)?)
}

/// The active generation owns live application storage after first startup.
/// Recurring certificate work retains the original preparation's provenance,
/// not its now-historical storage ownership/mode observations.
pub(crate) fn verify_retained_provenance(
    state: &LockedInspection,
    installation: &Path,
) -> Result<()> {
    state.require_path_binding(installation)?;
    let bytes = state.read_evidence(RECORD)?;
    require(bytes.len() <= 16 * 1024)?;
    let preparation: Preparation =
        serde_json::from_value(installer_json::decode(&bytes).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
    require(
        preparation.schema == "elevenid.installer-acme-application-preparation/v2"
            && preparation.installation_id == state.journal().installation_id()
            && preparation.release == *state.journal().identity()
            && Some(&preparation.runtime) == state.journal().runtime()
            && preparation.execution_scope == *state.journal().execution_scope()
            && Some(preparation.hosting_selection_sha256.as_str())
                == state.journal().hosting_selection_sha256()
            && preparation.storage_created
            && preparation.operator_projection_created
            && !preparation.application_started
            && !preparation.deletion_authorized
            && !preparation.installation_ready,
    )?;
    let originals = [
        installer_creation_identity::RECEIPT,
        installer_creation_identity::CREDENTIAL_RECEIPT,
        installer_creation_identity::APPLICATION_RECEIPT,
    ];
    match (&preparation.execution_scope, preparation.provenance) {
        (ExecutionScope::Unclassified, Provenance::OriginalCreationReceipts) => {
            require(
                preparation.prior_evidence_sha256.len() == originals.len()
                    && originals
                        .iter()
                        .all(|name| preparation.prior_evidence_sha256.contains_key(*name)),
            )?;
        }
        (ExecutionScope::CandidateTest(_), Provenance::SignedCandidateQualification) => {
            require(preparation.prior_evidence_sha256.len() == 19)?;
            for name in originals {
                require(state.diagnostic_record(name, true)?.is_none())?;
            }
        }
        _ => return Err(REFUSED.into()),
    }
    for (name, expected) in preparation.prior_evidence_sha256 {
        require(installer_release::sha256(&state.read_evidence(&name)?) == expected)?;
    }
    state.require_path_binding(installation)
}

pub(crate) fn prepare(state: &mut InstallerState, installation: &Path) -> Result<()> {
    state.require_live_phase(Phase::Provisioning)?;
    state.with_inspection(require_supported_scope)?;
    require(
        state
            .with_inspection(crate::installer_hosting::resolve)?
            .certificate_source()
            == crate::installer_hosting::CertificateSource::Acme,
    )?;
    state.prepare_application_storage()?;
    state.persist_application_storage_creation_receipt(installation)?;
    state.stage_operator_password()?;
    let prepared = state.with_inspection(|view| observe(view, installation))?;
    state.write_evidence(RECORD, &serde_json::to_vec(&prepared).map_err(|_| REFUSED)?)?;
    state.with_inspection(|view| verify(view, installation))
}

#[cfg(test)]
pub(crate) fn prepared_fixture(
    hosting: &serde_json::Value,
    runtime: RuntimeBinding,
) -> (tempfile::TempDir, std::path::PathBuf, InstallerState) {
    use std::os::unix::fs::PermissionsExt;
    let files = tempfile::tempdir().unwrap();
    std::fs::set_permissions(files.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let installation = files.path().join("installation");
    let mut state = InstallerState::create_with_runtime(
        &installation,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        runtime,
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.create_private_directory("downloads").unwrap();
    state
        .persist_initial_creation_receipt(&installation)
        .unwrap();
    state.advance(Phase::Verified).unwrap();
    let selection = files.path().join("hosting.json");
    std::fs::write(&selection, serde_json::to_vec(hosting).unwrap()).unwrap();
    std::fs::set_permissions(&selection, std::fs::Permissions::from_mode(0o600)).unwrap();
    crate::installer_hosting::select(
        crate::installer_hosting::prepare(Some(&selection), None).unwrap(),
        &mut state,
    )
    .unwrap();
    state.advance(Phase::Provisioning).unwrap();
    state
        .generate_local_credentials(&serde_json::json!({
            "passwordPolicy": crate::installer_state::PASSWORD_POLICY
        }))
        .unwrap();
    state
        .persist_credential_creation_receipt(&installation)
        .unwrap();
    prepare(&mut state, &installation).unwrap();
    (files, installation, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn prepared_storage_survives_lock_reopen_but_not_projection_or_receipt_replacement() {
        let hosting = serde_json::json!({
            "schema":"elevenid.installation-hosting/v1", "mode":"direct",
            "public_origin":"https://login.example.com",
            "listener":{"bind_address":"0.0.0.0","port":8443},
            "tls":{"termination":"marty-keyless","certificate_source":"acme",
                "http01_host_port":18080,
                "acme":{"environment":"production",
                    "directory_url":"https://acme-v02.api.letsencrypt.org/directory",
                    "profile":"shortlived",
                    "terms_url":"https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf",
                    "terms_agreed":true}}
        });
        for mutation in [
            "none",
            "password-inode",
            "credential-receipt",
            "missing-directory",
        ] {
            let (_files, installation, state) = prepared_fixture(
                &hosting,
                RuntimeBinding {
                    docker_host: "unix:///var/run/docker.sock".into(),
                    engine_id: "fixture-engine".into(),
                    openbao_port: 18200,
                    profile: crate::installer_state::RuntimeProfile::Rootful,
                },
            );
            let journal = std::fs::read(installation.join("installation.json")).unwrap();
            let evidence = std::fs::read(installation.join("evidence").join(RECORD)).unwrap();
            let password = std::fs::read(installation.join("operator-password")).unwrap();
            assert!(!evidence
                .windows(password.len())
                .any(|window| window == password));
            drop(state);
            match mutation {
                "password-inode" => {
                    let target = installation.join("secrets/operator_bootstrap_password");
                    std::fs::rename(&target, installation.join("retained-projection")).unwrap();
                    std::fs::write(&target, &password).unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444))
                        .unwrap();
                }
                "credential-receipt" => {
                    let path = installation
                        .join("evidence")
                        .join(installer_creation_identity::CREDENTIAL_RECEIPT);
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes.push(b' ');
                    std::fs::write(path, bytes).unwrap();
                }
                "missing-directory" => {
                    std::fs::rename(
                        installation.join("backups"),
                        installation.join("retained-backups"),
                    )
                    .unwrap();
                }
                _ => {}
            }
            let inspection = LockedInspection::open(&installation).unwrap();
            assert_eq!(
                verify(&inspection, &installation).is_ok(),
                mutation == "none",
                "{mutation}"
            );
            assert_eq!(
                std::fs::read(installation.join("installation.json")).unwrap(),
                journal
            );
            assert_eq!(
                std::fs::read(installation.join("evidence").join(RECORD)).unwrap(),
                evidence
            );
        }
    }

    #[test]
    fn metadata_only_proof_rejects_replaced_or_writable_operator_projection() {
        let root = tempfile::tempdir().unwrap();
        let file_path = root.path().join("projection");
        std::fs::write(&file_path, [b'x'; 69]).unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let held = File::open(&file_path).unwrap();
        let original = Entry::observe(&held, false, 0o444, Some(69)).unwrap();
        assert!(!serde_json::to_string(&original)
            .unwrap()
            .contains(&"x".repeat(69)));
        std::fs::rename(&file_path, root.path().join("original")).unwrap();
        std::fs::write(&file_path, [b'x'; 69]).unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_ne!(
            original,
            Entry::observe(&File::open(&file_path).unwrap(), false, 0o444, Some(69)).unwrap()
        );
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Entry::observe(&File::open(&file_path).unwrap(), false, 0o444, Some(69)).is_err());
    }
}
