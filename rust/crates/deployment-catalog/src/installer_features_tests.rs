use super::*;
use crate::installer_state::{Identity, RuntimeBinding, RuntimeProfile};
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn config() -> Configuration {
    serde_json::from_value(json!({"schema":SCHEMA,"agent_trust":{
        "organization_id":"00000000-0000-4000-8000-000000000001",
        "enrollment":{"audience":"https://api.example.test","policy_profile":"urn:marty:managed-key-enrollment-policy:v1","policy_revision":1},
        "approval":{"profile":"urn:marty:organization-approval:v1","version":"1","status_ref":"https://api.example.test/v1/delegation/status"},
        "delegated_use":{"activation":"awaiting_owner_configuration"}
    }})).unwrap()
}
fn source(root: &Path, configuration: &Configuration) -> PathBuf {
    let path = root.join("feature-profile.json");
    write(&path, &serde_json::to_vec(configuration).unwrap(), 0o600);
    path
}
fn state(root: &Path, profile: RuntimeProfile) -> (PathBuf, InstallerState) {
    let path = root.join("installation");
    let runtime = RuntimeBinding {
        docker_host: if profile == RuntimeProfile::Rootless {
            format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            })
        } else {
            "unix:///var/run/docker.sock".into()
        },
        engine_id: "feature-profile-engine".into(),
        openbao_port: 18200,
        profile,
    };
    let mut state = InstallerState::create_with_runtime(
        &path,
        Identity {
            source_sha: "a".repeat(40),
            release_tag: "v1.2.3".into(),
            inventory_sha256: format!("sha256:{}", "b".repeat(64)),
        },
        runtime,
    )
    .unwrap();
    state.create_private_directory("evidence").unwrap();
    state.advance(Phase::Verified).unwrap();
    (path, state)
}
fn selected(configuration: Configuration) -> Selection {
    Selection {
        schema: SELECTION_SCHEMA.into(),
        installation_id: uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
        source_sha256: digest(&serde_json::to_vec(&configuration).unwrap()),
        configuration,
        imports: BTreeMap::new(),
        generation: None,
    }
}

#[test]
fn absence_preserves_legacy_journal_bytes_and_creates_no_feature_evidence() {
    let root = root();
    let (path, mut state) = state(root.path(), RuntimeProfile::Rootful);
    let before = std::fs::read(path.join("installation.json")).unwrap();
    select(prepare(None, false).unwrap(), &mut state).unwrap();
    assert!(state.with_inspection(load).unwrap().is_none());
    assert_eq!(
        before,
        std::fs::read(path.join("installation.json")).unwrap()
    );
    assert!(!path.join("evidence").join(SOURCE).exists());
}

#[test]
fn selection_is_once_only_rootless_and_source_hash_bound() {
    let root = root();
    let input = source(root.path(), &config());
    let (path, mut state) = state(root.path(), RuntimeProfile::Rootless);
    select(prepare(Some(&input), true).unwrap(), &mut state).unwrap();
    let selected = state.with_inspection(load).unwrap().unwrap();
    assert_eq!(
        selected.profile_sha256().unwrap(),
        state.journal().feature_profile_sha256().unwrap()
    );
    assert!(select(prepare(Some(&input), true).unwrap(), &mut state).is_err());
    let mut changed = config();
    changed.agent_trust.as_mut().unwrap().approval.version = "2".into();
    write(
        &path.join("evidence").join(SOURCE),
        &serde_json::to_vec(&changed).unwrap(),
        0o600,
    );
    assert!(state.with_inspection(load).is_err());
}

#[test]
fn external_database_and_rootful_selection_are_rejected_before_feature_creation() {
    let root = root();
    let input = source(root.path(), &config());
    assert!(prepare(Some(&input), false).is_err());
    let (path, mut state) = state(root.path(), RuntimeProfile::Rootful);
    assert!(select(prepare(Some(&input), true).unwrap(), &mut state).is_err());
    assert!(state.journal().feature_profile_sha256().is_none());
    assert!(!path.join("evidence").join(SOURCE).exists());
}

#[test]
fn profile_refuses_unknown_fields_duplicate_keys_and_weak_types() {
    let original = serde_json::to_value(config()).unwrap();
    for (key, value) in [
        ("environment", json!({"MARTY_AGENT_ADMIN_ENABLED":"true"})),
        ("layers", json!(["/tmp/extra.yml"])),
        ("image", json!("latest")),
        ("secret_files", json!({})),
    ] {
        let mut altered = original.clone();
        altered[key] = value;
        assert!(decode::<Configuration>(&serde_json::to_vec(&altered).unwrap()).is_err());
    }
    assert!(decode::<Configuration>(br#"{"schema":"elevenid.installer-feature-profile/v1","schema":"elevenid.installer-feature-profile/v1"}"#).is_err());
    for value in [json!(0), json!("true"), json!(true)] {
        let mut altered = original.clone();
        altered["agent_trust"]["organization_id"] = value;
        assert!(decode::<Configuration>(&serde_json::to_vec(&altered).unwrap()).is_err());
    }
    let mut pending = original.clone();
    pending["agent_trust"]["delegated_use"]["configuration"] = json!({});
    assert!(decode::<Configuration>(&serde_json::to_vec(&pending).unwrap()).is_err());
    let mut altered = original;
    altered["agent_trust"]["enrollment"]["policy_revision"] = json!(0);
    assert!(
        decode::<Configuration>(&serde_json::to_vec(&altered).unwrap())
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn profile_rejects_secret_text_shell_interpolation_and_unsafe_authorities() {
    for value in [
        "https://user:password@example.test",
        "https://example.test/#fragment",
        "https://example.test/$SECRET",
        "https://example.test/\\escape",
        "PRIVATE KEY",
    ] {
        let mut configuration = config();
        configuration
            .agent_trust
            .as_mut()
            .unwrap()
            .approval
            .status_ref = value.into();
        assert!(configuration.validate().is_err(), "{value}");
    }
    let mut empty = config();
    empty.agent_trust = None;
    assert!(empty.validate().is_err());
    let mut nil = config();
    nil.agent_trust.as_mut().unwrap().organization_id = uuid::Uuid::nil();
    assert!(nil.validate().is_err());
}

#[test]
fn operator_source_is_private_regular_single_link_and_not_followed() {
    let root = root();
    let input = source(root.path(), &config());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(prepare(Some(&input), true).is_err());
    std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
    let linked = root.path().join("symlink");
    symlink(&input, &linked).unwrap();
    assert!(prepare(Some(&linked), true).is_err());
    std::fs::hard_link(&input, root.path().join("hardlink")).unwrap();
    assert!(prepare(Some(&input), true).is_err());
}

#[test]
fn pending_delegated_use_never_selects_a_runtime_or_claims_governed_configuration() {
    let selected = selected(config());
    assert!(selected
        .layers()
        .iter()
        .any(|p| p.ends_with("compose.agent-trust.yml")));
    assert!(!selected
        .layers()
        .iter()
        .any(|p| p.ends_with("/compose.delegated-use.yml")));
    assert!(!selected
        .runtime_layers()
        .iter()
        .any(|p| p.ends_with("compose.delegated-use-runtime.yml")));
    let identity = selected.identity_selection().unwrap().unwrap();
    assert!(identity.delegated_use);
    assert_eq!(identity.receipt()["governed_authority_created"], false);
    assert!(!selected
        .credential_names()
        .unwrap()
        .contains("feature_delegated_use_workload_bindings"));
}

fn approval_mounts(installation: &Path) -> Value {
    json!({"volumes":["approval_runtime","approval_consent","approval_authority","approval_organization"].into_iter()
        .map(|name|format!("feature_{name}_database_url")).chain(["feature_postgres_ca".into()])
        .map(|name|json!({"type":"bind","source":installation.join(DIRECTORY).join(&name),"target":format!("/run/feature-profile/{name}"),"read_only":true,"bind":{"create_host_path":false}})).collect::<Vec<_>>()})
}

#[test]
fn approval_and_command_cannot_gain_each_others_producer_or_migration_credentials() {
    let root = root();
    let selected = selected(config());
    let service = approval_mounts(root.path());
    let model = json!({"delegation-approval":service});
    selected
        .validate_feature_mounts(root.path(), model.as_object().unwrap())
        .unwrap();
    for forbidden in [
        "feature_command_writer_database_url",
        "feature_delegation_owner_database_url",
        "feature_database_passwords",
    ] {
        let mut wrong = model.clone();
        wrong["delegation-approval"]["volumes"][0]["source"] =
            json!(root.path().join(DIRECTORY).join(forbidden));
        wrong["delegation-approval"]["volumes"][0]["target"] =
            json!(format!("/run/feature-profile/{forbidden}"));
        assert!(selected
            .validate_feature_mounts(root.path(), wrong.as_object().unwrap())
            .is_err());
    }
    let mut command = model.clone();
    let service = command
        .as_object_mut()
        .unwrap()
        .remove("delegation-approval")
        .unwrap();
    command["delegation-commands"] = service;
    assert!(selected
        .validate_feature_mounts(root.path(), command.as_object().unwrap())
        .is_err());
}

#[test]
fn feature_mounts_reject_directory_ancestors_writes_aliases_and_automatic_creation() {
    let root = root();
    let selected = selected(config());
    let model = json!({"delegation-approval":approval_mounts(root.path())});
    for source in [root.path().to_path_buf(), root.path().join(DIRECTORY)] {
        let mut wrong = model.clone();
        wrong["delegation-approval"]["volumes"][0]["source"] = json!(source);
        assert!(selected
            .validate_feature_mounts(root.path(), wrong.as_object().unwrap())
            .is_err());
    }
    for (field, value) in [
        ("target", json!("/alternate")),
        ("read_only", json!(false)),
        ("type", json!("volume")),
        ("bind", json!({"create_host_path":true})),
    ] {
        let mut wrong = model.clone();
        wrong["delegation-approval"]["volumes"][0][field] = value;
        assert!(selected
            .validate_feature_mounts(root.path(), wrong.as_object().unwrap())
            .is_err());
    }
    let mut secret_alias = model;
    secret_alias["delegation-approval"]["secrets"] =
        json!(["feature_approval_runtime_database_url"]);
    assert!(selected
        .validate_feature_mounts(root.path(), secret_alias.as_object().unwrap())
        .is_err());
}

#[test]
fn adapter_pin_is_the_authenticated_image_digest_and_inputs_never_contain_credentials() {
    let root = root();
    let selected = selected(config());
    let images = ["postgres", "db-migrate", "gateway"]
        .into_iter()
        .map(|role| {
            (
                role.into(),
                format!("example.test/{role}@sha256:{}", "a".repeat(64)),
            )
        })
        .collect();
    let mut env = b"UI_BASE_URL=https://console.example.test\n".to_vec();
    selected
        .append_environment(&mut env, root.path(), &images)
        .unwrap();
    let text = String::from_utf8(env).unwrap();
    assert!(text.contains(&format!(
        "FEATURE_APPROVAL_ARTIFACT_DIGEST='sha256:{}'",
        "a".repeat(64)
    )));
    assert!(!text.contains("postgresql://"));
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("FEATURE_USE_FLOW_DEFINITION_ID"));
    assert!(text.contains("FEATURE_POSTGRES_TLS_DIR="));
}
