use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::BTreeMap,
    fs as files,
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, MetadataExt, PermissionsExt},
    },
};

#[derive(Clone, Copy, Debug)]
enum SettingsInput {
    Absent,
    Default,
    Explicit,
}

struct SettingsFixture {
    _files: tempfile::TempDir,
    installation: PathBuf,
    state: InstallerState,
}

fn settings_fixture(input: SettingsInput) -> SettingsFixture {
    let files = tempfile::tempdir().unwrap();
    files::set_permissions(files.path(), files::Permissions::from_mode(0o700)).unwrap();
    let installation = files.path().join("installation");
    let mut state = InstallerState::create(
        &installation,
        crate::installer_state::Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    let prepared = match input {
        SettingsInput::Absent => None,
        SettingsInput::Default => Some(crate::installer_settings::prepare(None, true).unwrap()),
        SettingsInput::Explicit => {
            let path = files.path().join("settings.json");
            files::write(
                &path,
                br#"{"schema":"elevenid.installer-application-settings/v1","values":{"RATE_LIMIT_RPM":1234},"secret_files":{}}"#,
            )
            .unwrap();
            files::set_permissions(&path, files::Permissions::from_mode(0o600)).unwrap();
            Some(crate::installer_settings::prepare(Some(&path), true).unwrap())
        }
    };
    if let Some(prepared) = prepared {
        crate::installer_settings::select(prepared, &mut state).unwrap();
    }
    SettingsFixture {
        _files: files,
        installation,
        state,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RetainedFile {
    mode: u32,
    links: u64,
    bytes: Vec<u8>,
}

fn retained_files(fixture: &SettingsFixture) -> BTreeMap<PathBuf, RetainedFile> {
    let mut paths = vec![fixture.installation.join("installation.json")];
    paths.extend(
        files::read_dir(fixture.installation.join("evidence"))
            .unwrap()
            .map(|entry| entry.unwrap().path()),
    );
    paths
        .into_iter()
        .map(|path| {
            let metadata = files::symlink_metadata(&path).unwrap();
            let bytes = if metadata.file_type().is_symlink() {
                files::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            } else {
                files::read(&path).unwrap()
            };
            (
                path,
                RetainedFile {
                    mode: metadata.mode(),
                    links: metadata.nlink(),
                    bytes,
                },
            )
        })
        .collect()
}

fn read_only_settings_gate(fixture: &SettingsFixture) -> Result<()> {
    let before = retained_files(fixture);
    let result = fixture.state.with_inspection(before_application);
    assert_eq!(retained_files(fixture), before);
    result
}

#[test]
fn initial_order_gate_accepts_authenticated_default_and_explicit_settings() {
    for input in [SettingsInput::Default, SettingsInput::Explicit] {
        let mut fixture = settings_fixture(input);
        assert!(fixture
            .state
            .with_inspection(crate::installer_settings::load)
            .unwrap()
            .is_some());
        assert!(read_only_settings_gate(&fixture).is_err(), "{input:?}");
        fixture.state.advance(Phase::Provisioning).unwrap();
        for name in [
            crate::installer_settings::SOURCE,
            crate::installer_settings::RECORD,
        ] {
            assert!(fixture.installation.join("evidence").join(name).is_file());
        }
        // Use the same producer and phase order as install_inner. Both records
        // are policy selection, not proof that an application has started.
        read_only_settings_gate(&fixture).unwrap();
    }
}

#[test]
fn initial_order_gate_preserves_absence_but_rejects_unbound_settings() {
    let mut fixture = settings_fixture(SettingsInput::Absent);
    fixture.state.advance(Phase::Provisioning).unwrap();
    assert!(fixture
        .state
        .with_inspection(crate::installer_settings::load)
        .unwrap()
        .is_none());
    read_only_settings_gate(&fixture).unwrap();
    let selected = settings_fixture(SettingsInput::Default);
    for name in [
        crate::installer_settings::SOURCE,
        crate::installer_settings::RECORD,
    ] {
        fixture
            .state
            .write_evidence(
                name,
                &files::read(selected.installation.join("evidence").join(name)).unwrap(),
            )
            .unwrap();
    }
    assert!(fixture
        .state
        .with_inspection(crate::installer_settings::load)
        .is_err());
    assert!(read_only_settings_gate(&fixture).is_err());
}

#[test]
fn initial_order_gate_rejects_missing_changed_or_unsafe_settings() {
    for mutation in [
        "source-missing",
        "selection-missing",
        "source-changed",
        "selection-changed",
        "foreign-selection",
        "source-link",
        "selection-link",
        "source-mode",
        "selection-mode",
        "source-hardlink",
    ] {
        let mut fixture = settings_fixture(SettingsInput::Default);
        fixture.state.advance(Phase::Provisioning).unwrap();
        read_only_settings_gate(&fixture).unwrap();
        let evidence = fixture.installation.join("evidence");
        let source = evidence.join(crate::installer_settings::SOURCE);
        let selection = evidence.join(crate::installer_settings::RECORD);
        match mutation {
            "source-missing" => files::remove_file(&source).unwrap(),
            "selection-missing" => files::remove_file(&selection).unwrap(),
            "source-changed" => {
                files::write(&source, b"synthetic-private-settings-marker").unwrap()
            }
            "selection-changed" => {
                files::write(&selection, b"synthetic-private-settings-marker").unwrap()
            }
            "foreign-selection" => {
                let foreign = settings_fixture(SettingsInput::Default);
                files::write(
                    &selection,
                    files::read(
                        foreign
                            .installation
                            .join("evidence")
                            .join(crate::installer_settings::RECORD),
                    )
                    .unwrap(),
                )
                .unwrap();
            }
            "source-link" | "selection-link" => {
                let target = if mutation == "source-link" {
                    &source
                } else {
                    &selection
                };
                let retained = evidence.join("retained-settings.json");
                files::rename(target, &retained).unwrap();
                symlink(&retained, target).unwrap();
            }
            "source-mode" | "selection-mode" => {
                let target = if mutation == "source-mode" {
                    &source
                } else {
                    &selection
                };
                files::set_permissions(target, files::Permissions::from_mode(0o644)).unwrap();
            }
            "source-hardlink" => {
                files::hard_link(&source, evidence.join("retained-settings.json")).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            fixture
                .state
                .with_inspection(crate::installer_settings::load)
                .is_err(),
            "{mutation}"
        );
        let error = read_only_settings_gate(&fixture).unwrap_err();
        assert!(!error.contains("synthetic-private-settings-marker"));
    }
}

#[test]
fn initial_order_gate_keeps_later_ownership_closed_with_settings() {
    for marker in [
        "generation-pending.json",
        "application-started.json",
        "application-settings-extra.json",
        "application-settings-input.json.bak",
        "application-settings-selection.json.bak",
        "compose-generation-result.json",
        "compose-application-result.json",
        "lifecycle-config.json",
        "uninstall-intent.json",
        "compose-session.json",
        "installer-nginx.conf",
    ] {
        let mut fixture = settings_fixture(SettingsInput::Explicit);
        fixture.state.advance(Phase::Provisioning).unwrap();
        read_only_settings_gate(&fixture).unwrap();
        fixture.state.write_evidence(marker, b"{}").unwrap();
        assert!(fixture
            .state
            .with_inspection(crate::installer_settings::load)
            .unwrap()
            .is_some());
        assert!(read_only_settings_gate(&fixture).is_err(), "{marker}");
    }
}

#[test]
fn expired_candidate_reference_alone_cannot_grant_original_preparation_authority() {
    let fixture = crate::installer_acme::tests::Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    let expiry = prior.metadata()["not_after"].as_u64().unwrap();
    let environment = prior.environment();
    let mut state = LockedMaintenance::open(fixture.installation()).unwrap();
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    let data = PermitData {
        schema: "elevenid.installer-acme-initial-rollover/v1".into(),
        installation_id: state.journal().installation_id(),
        environment,
        cycle: 1,
        prior_cycle: 0,
        prior_candidate: value(&prior).unwrap(),
        configuration_sha256: sha(&serde_json::to_vec(&configuration).unwrap()),
        // These are deliberately only fixture references. The test proves that
        // even a valid expired predecessor cannot bypass the actual setup gate.
        host_intent_sha256: "a".repeat(64),
        host_prepared_sha256: "b".repeat(64),
        created_at: expiry,
    };
    state
        .write_evidence_exclusive(
            &InitialRolloverPermit::record_name(environment, 1),
            &encode(&data).unwrap(),
        )
        .unwrap();
    assert!(
        InitialRolloverPermit::load(state.inspection(), environment, 1).is_err(),
        "future expiry cannot grant an early replacement"
    );
    fixture.advance(expiry - installer_acme::now().unwrap());
    let permit = InitialRolloverPermit::load(state.inspection(), environment, 1).unwrap();
    assert_eq!(permit.cycle(), 1);
    assert_eq!(
        permit.prior_candidate().unwrap().metadata(),
        prior.metadata()
    );
    assert!(matches!(
        permit.reason(),
        IssuanceReason::InitialCandidateExpired { .. }
    ));
    let saved = Ledger::load(state.inspection(), environment)
        .unwrap()
        .unwrap();
    let key = RetainedIngressKey::from_recorded_public_key(
        &state.journal().installation_id().to_string(),
        saved.binding.ingress_key_version,
        &STANDARD.decode(saved.binding.ingress_spki_base64).unwrap(),
    )
    .unwrap();
    assert!(permit
        .require_current(
            state.inspection(),
            fixture.installation(),
            &configuration,
            &key
        )
        .is_err());
    assert!(
        Ledger::load_cycle(state.inspection(), environment, 1)
            .unwrap()
            .is_none(),
        "no order stream is created without full original preparation"
    );
    assert_eq!(
        InitialRolloverPermit::load(state.inspection(), environment, 1)
            .unwrap()
            .sha256(),
        permit.sha256()
    );
}

#[test]
fn initial_replacement_refuses_a_live_predecessor_or_missing_completed_cycle() {
    let fixture = crate::installer_acme::tests::Fixture::new();
    let prior = fixture.finish().candidate.unwrap();
    let expiry = prior.metadata()["not_after"].as_u64().unwrap();
    fixture.advance(expiry - installer_acme::now().unwrap());
    let mut state = LockedMaintenance::open(fixture.installation()).unwrap();
    let configuration = BoundAcmeConfiguration::from_selection(state.inspection()).unwrap();
    for (cycle, prior_cycle, created_at) in [(1, 0, expiry - 1), (2, 1, expiry)] {
        let data = PermitData {
            schema: "elevenid.installer-acme-initial-rollover/v1".into(),
            installation_id: state.journal().installation_id(),
            environment: prior.environment(),
            cycle,
            prior_cycle,
            prior_candidate: value(&prior).unwrap(),
            configuration_sha256: sha(&serde_json::to_vec(&configuration).unwrap()),
            host_intent_sha256: "a".repeat(64),
            host_prepared_sha256: "b".repeat(64),
            created_at,
        };
        state
            .write_evidence_exclusive(
                &InitialRolloverPermit::record_name(prior.environment(), cycle),
                &encode(&data).unwrap(),
            )
            .unwrap();
        assert!(
            InitialRolloverPermit::load(state.inspection(), prior.environment(), cycle).is_err()
        );
        assert!(
            Ledger::load_cycle(state.inspection(), prior.environment(), cycle)
                .unwrap()
                .is_none()
        );
    }
}
