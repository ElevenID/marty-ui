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
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_settings_sha256: Option<String>,
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
    SignedAcceptanceQualification,
}

const CANDIDATE_EVIDENCE: [&str; 6] = [
    "candidate-test-inventory.json",
    "candidate-test-inventory.json.sigstore.json",
    "candidate-test-inventory.json.provenance.jsonl",
    "installer-inventory.json",
    "installer-inventory.json.sigstore.json",
    "installer-inventory.json.provenance.jsonl",
];

fn qualification_provenance(scope: &ExecutionScope) -> Result<Provenance> {
    match scope {
        ExecutionScope::CandidateTest(_) => Ok(Provenance::SignedCandidateQualification),
        ExecutionScope::AcceptanceOnly(_) => Ok(Provenance::SignedAcceptanceQualification),
        _ => Err(REFUSED.into()),
    }
}

/// Exact filenames and the journal-pinned acceptance grant bytes distinguish
/// the two qualification sources. A same-sized substituted map is insufficient.
fn require_qualification_evidence(
    scope: &ExecutionScope,
    provenance: &Provenance,
    evidence: &BTreeMap<String, String>,
) -> Result<()> {
    let sources: &[&str] = match (scope, provenance) {
        (ExecutionScope::CandidateTest(_), Provenance::SignedCandidateQualification) => {
            &CANDIDATE_EVIDENCE
        }
        (ExecutionScope::AcceptanceOnly(scope), Provenance::SignedAcceptanceQualification) => {
            let retained = scope
                .authenticated_evidence_sha256
                .as_ref()
                .ok_or(REFUSED)?;
            let names = &crate::installer_state::ACCEPTANCE_AUTHENTICATED_EVIDENCE;
            require(
                retained.len() == names.len()
                    && names.iter().all(|name| {
                        retained
                            .get(*name)
                            .is_some_and(|hash| evidence.get(*name) == Some(hash))
                    }),
            )?;
            names
        }
        _ => return Err(REFUSED.into()),
    };
    let expected: BTreeSet<_> = crate::installer_rootless_storage_canary::COMPLETED_EVIDENCE
        .iter()
        .chain(sources)
        .copied()
        .collect();
    require(evidence.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected)
}

/// Qualification trials retain their own authenticated provenance. They cannot
/// acquire admitted-installation creation/deletion capabilities or Ready.
pub(crate) fn require_supported_scope(state: &LockedInspection) -> Result<()> {
    match state.journal().execution_scope() {
        ExecutionScope::Unclassified => Ok(()),
        scope @ (ExecutionScope::CandidateTest(_) | ExecutionScope::AcceptanceOnly(_)) => {
            let evidence = crate::installer_rootless_storage_canary::require_completed(state)?;
            require_qualification_evidence(scope, &qualification_provenance(scope)?, &evidence)
        }
        #[cfg(feature = "installer-development")]
        ExecutionScope::UnsignedDevelopment(_) => Err(REFUSED.into()),
    }
}

fn entries(state: &LockedInspection) -> Result<BTreeMap<String, Entry>> {
    let root = state.installation_directory();
    let settings = crate::installer_settings::load(state)?;
    if let Some(settings) = &settings {
        settings.verify_secrets(root)?;
    }
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
        crate::installer_application_env::OPTIONAL_INTEGRATION_SECRETS
            .into_iter()
            .map(|name| {
                (
                    format!("secrets/{name}"),
                    false,
                    0o444,
                    Some(
                        settings
                            .as_ref()
                            .map_or(0, |s| s.fingerprints()[name].size_bytes),
                    ),
                )
            }),
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
    if let Some(settings) = &settings {
        settings.verify_secrets(root)?;
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
        scope @ (ExecutionScope::CandidateTest(_) | ExecutionScope::AcceptanceOnly(_)) => {
            prior_evidence_sha256 =
                crate::installer_rootless_storage_canary::require_completed(state)?;
            let provenance = qualification_provenance(scope)?;
            require_qualification_evidence(scope, &provenance, &prior_evidence_sha256)?;
            for name in [
                installer_creation_identity::RECEIPT,
                installer_creation_identity::CREDENTIAL_RECEIPT,
                installer_creation_identity::APPLICATION_RECEIPT,
            ] {
                require(state.diagnostic_record(name, true)?.is_none())?;
            }
            provenance
        }
        #[cfg(feature = "installer-development")]
        ExecutionScope::UnsignedDevelopment(_) => return Err(REFUSED.into()),
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
        application_settings_sha256: state
            .journal()
            .application_settings_sha256()
            .map(str::to_owned),
        entries: entries(state)?,
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
            && preparation.application_settings_sha256.as_deref()
                == state.journal().application_settings_sha256()
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
    match (&preparation.execution_scope, &preparation.provenance) {
        (ExecutionScope::Unclassified, Provenance::OriginalCreationReceipts) => {
            require(
                preparation.prior_evidence_sha256.len() == originals.len()
                    && originals
                        .iter()
                        .all(|name| preparation.prior_evidence_sha256.contains_key(*name)),
            )?;
        }
        (ExecutionScope::CandidateTest(_), Provenance::SignedCandidateQualification)
        | (ExecutionScope::AcceptanceOnly(_), Provenance::SignedAcceptanceQualification) => {
            require_qualification_evidence(
                &preparation.execution_scope,
                &preparation.provenance,
                &preparation.prior_evidence_sha256,
            )?;
            for name in originals {
                require(state.diagnostic_record(name, true)?.is_none())?;
            }
        }
        _ => return Err(REFUSED.into()),
    }
    for (name, expected) in preparation.prior_evidence_sha256 {
        require(installer_release::sha256(&state.read_evidence(&name)?) == expected)?;
    }
    if let Some(settings) = crate::installer_settings::load(state)? {
        settings.verify_secrets(state.installation_directory())?;
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
    fn historical_six_input_inventory_is_not_adopted_as_current_preparation() {
        let root = tempfile::tempdir().unwrap();
        let installation = root.path().join("installation");
        let mut state = InstallerState::create(
            &installation,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        state.advance(Phase::Verified).unwrap();
        state.advance(Phase::Provisioning).unwrap();
        for name in [
            "evidence",
            "secrets",
            "state",
            "state/postgres",
            "state/redis",
            "state/applicant",
            "backups",
            "openbao-exports",
            "openbao-snapshot-identity",
        ] {
            let path = installation.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(if name == "state/applicant" {
                    0o2770
                } else {
                    0o700
                }),
            )
            .unwrap();
        }
        for (name, mode) in [
            ("operator-password", 0o600),
            ("secrets/operator_bootstrap_password", 0o444),
        ] {
            let path = installation.join(name);
            std::fs::write(&path, [b'x'; 69]).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        for name in [
            "google_client_id",
            "google_client_secret",
            "google_analytics_measurement_id",
            "google_site_verification",
            "smtp_password",
            "canvas_credentials_shared_secret",
        ] {
            let path = installation.join("secrets").join(name);
            std::fs::write(&path, []).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        assert!(state.with_inspection(entries).is_err());
        assert!(!installation
            .join("secrets/passport_tenant_api_keys")
            .exists());
        for name in [
            "passport_tenant_api_keys",
            "personalization_bureau_api_key",
            "canvas_credentials_api_token",
        ] {
            let path = installation.join("secrets").join(name);
            std::fs::write(&path, []).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        let current = state.with_inspection(entries).unwrap();
        assert_eq!(current.len(), 20);
    }

    #[test]
    fn qualification_provenance_requires_exact_named_records_and_acceptance_pins() {
        let candidate = ExecutionScope::CandidateTest(crate::installer_state::CandidateTestScope {
            inventory_sha256: "a".repeat(64),
            build_run_id: 1,
            build_run_attempt: 1,
        });
        let mut candidate_evidence: BTreeMap<String, String> =
            crate::installer_rootless_storage_canary::COMPLETED_EVIDENCE
                .iter()
                .chain(&CANDIDATE_EVIDENCE)
                .map(|name| ((*name).into(), "b".repeat(64)))
                .collect();
        require_qualification_evidence(
            &candidate,
            &Provenance::SignedCandidateQualification,
            &candidate_evidence,
        )
        .unwrap();
        candidate_evidence.remove(CANDIDATE_EVIDENCE[0]);
        candidate_evidence.insert("unrelated-same-sized-map.json".into(), "b".repeat(64));
        assert!(require_qualification_evidence(
            &candidate,
            &Provenance::SignedCandidateQualification,
            &candidate_evidence
        )
        .is_err());

        let pins: BTreeMap<String, String> =
            crate::installer_state::ACCEPTANCE_AUTHENTICATED_EVIDENCE
                .iter()
                .map(|name| ((*name).into(), "c".repeat(64)))
                .collect();
        let scope = crate::installer_state::AcceptanceScope {
            authorization_sha256: "d".repeat(64),
            context_sha256: "e".repeat(64),
            consumption_id: "f".repeat(64),
            authenticated_evidence_sha256: Some(pins.clone()),
        };
        let mut acceptance_evidence = pins;
        acceptance_evidence.extend(
            crate::installer_rootless_storage_canary::COMPLETED_EVIDENCE
                .iter()
                .map(|name| ((*name).into(), "b".repeat(64))),
        );
        let acceptance = ExecutionScope::AcceptanceOnly(scope.clone());
        require_qualification_evidence(
            &acceptance,
            &Provenance::SignedAcceptanceQualification,
            &acceptance_evidence,
        )
        .unwrap();
        assert!(require_qualification_evidence(
            &acceptance,
            &Provenance::SignedCandidateQualification,
            &acceptance_evidence
        )
        .is_err());
        assert!(require_qualification_evidence(
            &candidate,
            &Provenance::SignedAcceptanceQualification,
            &acceptance_evidence
        )
        .is_err());
        for mutation in [
            "legacy-no-pins",
            "changed-pin",
            "missing-pin",
            "same-count-substitution",
        ] {
            let mut scope = scope.clone();
            let mut evidence = acceptance_evidence.clone();
            match mutation {
                "legacy-no-pins" => scope.authenticated_evidence_sha256 = None,
                "changed-pin" => {
                    scope
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .insert(
                            crate::installer_state::ACCEPTANCE_AUTHENTICATED_EVIDENCE[0].into(),
                            "0".repeat(64),
                        );
                }
                "missing-pin" => {
                    scope
                        .authenticated_evidence_sha256
                        .as_mut()
                        .unwrap()
                        .remove(crate::installer_state::ACCEPTANCE_AUTHENTICATED_EVIDENCE[0]);
                }
                "same-count-substitution" => {
                    evidence
                        .remove(crate::installer_rootless_storage_canary::COMPLETED_EVIDENCE[0]);
                    evidence.insert("another-canary.json".into(), "b".repeat(64));
                }
                _ => unreachable!(),
            }
            assert!(
                require_qualification_evidence(
                    &ExecutionScope::AcceptanceOnly(scope),
                    &Provenance::SignedAcceptanceQualification,
                    &evidence
                )
                .is_err(),
                "{mutation}"
            );
        }
    }

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
