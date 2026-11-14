//! External confidential-client secret replacement inside the existing immutable
//! credential generation transaction. The original provider selection and every
//! OpenBao producer/activation receipt remain authoritative and unchanged.
#![cfg(target_os = "linux")]

use crate::{
    installer_generation_binding::{GenerationBinding, SuccessorBinding},
    installer_state::{LockedInspection, LockedMaintenance},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str = "external OIDC secret replacement differs from the retained provider or generation; preserve its request and installation evidence";
pub(crate) const SECRET: &str = "external_oidc_client_secret";
const SCHEMA: &str = "elevenid.installer-external-oidc-secret-rotation/v1";

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}
fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}
fn record_name(sequence: u64) -> String {
    format!("generation-oidc-{sequence:020}-request.json")
}
fn secret_name(sequence: u64) -> String {
    format!("generation-oidc-{sequence:020}-secret")
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(crate::installer_json::decode(bytes).map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}
fn read(installation: &Path, name: &str) -> Result<Vec<u8>> {
    crate::installer_verify::read_private_bytes(&installation.join("evidence").join(name), 65536)
}
fn optional(installation: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(installation.join("evidence").join(name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) => read(installation, name).map(Some),
        Err(_) => Err(REFUSED.into()),
    }
}
fn valid_secret(bytes: &[u8]) -> Result<()> {
    crate::installer_oidc::validate_secret_bytes(bytes).map_err(|_| REFUSED.into())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    installation_id: String,
    engine_id: String,
    sequence: u64,
    parent_binding_sha256: String,
    provider_selection_sha256: String,
    previous_secret_sha256: String,
    secret_sha256: String,
    secret_size: usize,
}

fn selected(installation: &Path, parent: &GenerationBinding) -> Result<String> {
    require(
        !parent.imported_foundation() && (parent.managed_ingress() || parent.public_ingress()),
    )?;
    let (raw, provider) = crate::installer_oidc::record(
        installation,
        uuid::Uuid::parse_str(&parent.installation_id).map_err(|_| REFUSED)?,
    )?
    .ok_or(REFUSED)?;
    require(
        provider
            .configuration
            .external_oidc
            .client_secret_file
            .is_some()
            && parent.files.get(SECRET).is_some_and(|value| value.size > 0),
    )?;
    Ok(digest(&raw))
}

fn request_for(installation: &Path, parent: &GenerationBinding, bytes: &[u8]) -> Result<Request> {
    valid_secret(bytes)?;
    let previous = parent.files.get(SECRET).ok_or(REFUSED)?;
    let result = Request {
        schema: SCHEMA.into(),
        installation_id: parent.installation_id.clone(),
        engine_id: parent.engine_id.clone(),
        sequence: parent.sequence().checked_add(1).ok_or(REFUSED)?,
        parent_binding_sha256: parent.sha256()?,
        provider_selection_sha256: selected(installation, parent)?,
        previous_secret_sha256: previous.sha256.clone(),
        secret_sha256: digest(bytes),
        secret_size: bytes.len(),
    };
    require(result.secret_sha256 != result.previous_secret_sha256)?;
    Ok(result)
}

/// The optional request is admitted only for this exact next generation. A
/// pending renewal cannot acquire a new request after its intent was written.
pub(crate) fn for_parent(
    installation: &Path,
    parent: &GenerationBinding,
) -> Result<Option<String>> {
    let sequence = parent.sequence().checked_add(1).ok_or(REFUSED)?;
    let Some(raw) = optional(installation, &record_name(sequence))? else {
        return Ok(None);
    };
    let request: Request = decode(&raw)?;
    let bytes = read(installation, &secret_name(sequence))?;
    require(
        request == request_for(installation, parent, &bytes)?
            && serde_json::to_vec(&request).map_err(|_| REFUSED)? == raw,
    )?;
    Ok(Some(digest(&raw)))
}

pub(crate) fn candidate(
    installation: &Path,
    parent: &GenerationBinding,
    successor: &SuccessorBinding,
) -> Result<Option<Vec<u8>>> {
    let expected = for_parent(installation, parent)?;
    require(successor.oidc_secret_rotation_sha256 == expected)?;
    let Some(expected) = expected else {
        return Ok(None);
    };
    require(
        successor.sequence == parent.sequence().checked_add(1).ok_or(REFUSED)?
            && successor.parent_binding_sha256 == parent.sha256()?,
    )?;
    // The existing producer journal already binds this intent. Check the new
    // field explicitly before adding the independent input to the candidate.
    let scope = crate::installer_generation_maintenance::attempt::Attempt::new(
        successor.sequence,
        successor.attempt,
    );
    let intent: serde_json::Value = decode(&crate::installer_verify::read_private_bytes(
        &installation.join("evidence").join(scope.record("intent")),
        4 * 1024 * 1024,
    )?)?;
    require(
        intent["oidc_secret_rotation_sha256"] == expected
            && intent["parent_binding_sha256"] == successor.parent_binding_sha256,
    )?;
    read(installation, &secret_name(successor.sequence)).map(Some)
}

fn stage(
    installation: &Path,
    state: &mut LockedMaintenance,
    parent: &GenerationBinding,
    bytes: &[u8],
) -> Result<String> {
    state.inspection().require_path_binding(installation)?;
    let request = request_for(installation, parent, bytes)?;
    let raw = serde_json::to_vec(&request).map_err(|_| REFUSED)?;
    for (name, value) in [
        (secret_name(request.sequence), bytes),
        (record_name(request.sequence), raw.as_slice()),
    ] {
        match state.read_evidence(&name)? {
            Some(existing) => require(existing == value)?,
            None => state.write_evidence_exclusive(&name, value)?,
        }
    }
    require(for_parent(installation, parent)? == Some(digest(&raw)))?;
    Ok(digest(&raw))
}

fn arguments(args: &[String]) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let mut values = BTreeMap::new();
    require(args.len().is_multiple_of(2))?;
    for pair in args.chunks_exact(2) {
        require(
            ["--install-dir", "--client-secret-file", "--docker-bin"].contains(&pair[0].as_str())
                && Path::new(&pair[1]).is_absolute()
                && values.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
        )?;
    }
    Ok((
        PathBuf::from(*values.get("--install-dir").ok_or(REFUSED)?),
        PathBuf::from(*values.get("--client-secret-file").ok_or(REFUSED)?),
        PathBuf::from(*values.get("--docker-bin").unwrap_or(&"/usr/bin/docker")),
    ))
}

pub(crate) fn run(args: &[String]) -> Result<String> {
    let (installation, path, docker) = arguments(args)?;
    let bytes = crate::installer_verify::read_private_bytes(&path, 65536)?;
    valid_secret(&bytes)?;
    let mut state = LockedMaintenance::open(&installation)?;
    crate::installer_operator_upgrade::require_selected_caller(state.inspection(), &installation)?;
    crate::installer_lifecycle::require_running_intent(&state, &installation, &docker)?;
    crate::installer_root_retirement::require_no_pending_for_generation(state.inspection())?;
    let parent = crate::installer_generation_binding::load_verified(
        &installation,
        &state.journal().installation_id().to_string(),
        &state.journal().runtime().ok_or(REFUSED)?.engine_id,
    )?
    .ok_or(REFUSED)?;
    selected(&installation, &parent)?;
    // An ordinary later renewal inherits the selected secret. Desired bytes
    // already active remain idempotent even when the latest successor itself
    // did not introduce the replacement.
    let already_active = parent
        .files
        .get(SECRET)
        .is_some_and(|value| value.sha256 == digest(&bytes));
    let binding = if already_active {
        parent
    } else {
        let existing = for_parent(&installation, &parent)?;
        if existing.is_none() {
            require(
                !crate::installer_generation_maintenance::has_pending_generation(
                    state.inspection(),
                    &installation,
                )?,
            )?;
        }
        stage(&installation, &mut state, &parent, &bytes)?;
        crate::installer_generation_maintenance::rotate_oidc_secret_locked(
            &installation,
            &docker,
            &mut state,
            &parent,
        )?
    };
    require(
        binding
            .files
            .get(SECRET)
            .is_some_and(|value| value.sha256 == digest(&bytes)),
    )?;
    let readiness = crate::installer_validation::observe_locked(
        &installation,
        &docker,
        state.inspection(),
        false,
    )?;
    state.require_unchanged()?;
    serde_json::to_string(
        &json!({"schema":"elevenid.installer-external-oidc-secret-rotation-result/v1",
        "installation_id":state.journal().installation_id(), "generation":binding.sequence(),
        "generation_binding_sha256":binding.sha256()?, "activation_observed":true,
        "readiness_status":"passed", "validation_record":readiness.record_name,
        "validation_sha256":readiness.record_sha256, "provider_selection_changed":false,
        "installation_ready":false, "browser_login_qualified":false,
        "outcome":if already_active {"already_active"} else {"activated"}}),
    )
    .map_err(|_| REFUSED.into())
}

/// Include previous confidential values when redacting historical service logs.
pub(crate) fn redaction_values(
    view: &LockedInspection,
    installation: &Path,
) -> Result<Vec<Vec<u8>>> {
    view.require_path_binding(installation)?;
    let dir = crate::installer_host_fs::directory(&installation.join("evidence"), REFUSED)?;
    let names = crate::installer_host_fs::file_names(&dir, REFUSED)?;
    let mut values = Vec::new();
    let mut total = 0usize;
    for name in names {
        if name.starts_with("generation-oidc-") && name.ends_with("-secret") {
            require(
                name.len() == secret_name(0).len()
                    && values.len() < 10000
                    && name.as_bytes()[16..36].iter().all(u8::is_ascii_digit),
            )?;
            let bytes = view.read_evidence(&name)?;
            valid_secret(&bytes)?;
            total = total.checked_add(bytes.len()).ok_or(REFUSED)?;
            require(total <= 4 * 1024 * 1024)?;
            values.push(bytes);
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installer_generation_binding::{GenerationFile, GenerationSource};
    use crate::installer_state::{Identity, InstallerState, Phase};
    use std::os::unix::fs::PermissionsExt;

    fn private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture(confidential: bool) -> (tempfile::TempDir, PathBuf, GenerationBinding) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("installation");
        let mut state = InstallerState::create(
            &path,
            Identity {
                source_sha: "a".repeat(40),
                release_tag: "v1.2.3".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        state.create_private_directory("evidence").unwrap();
        state.advance(Phase::Verified).unwrap();
        let mut config = json!({"schema":"elevenid.installer-external-oidc/v1", "external_oidc":{
            "issuer_url":"https://identity.example.test/tenant", "client_id":"same-client",
            "admin_email":"operator@example.test", "allowed_algorithms":["RS256"]}});
        let before = if confidential {
            b"old-secret".as_slice()
        } else {
            b"".as_slice()
        };
        if confidential {
            let secret = root.path().join("original-secret");
            private(&secret, before);
            config["external_oidc"]["client_secret_file"] = json!(secret);
        }
        let input = root.path().join("provider.json");
        private(&input, &serde_json::to_vec(&config).unwrap());
        crate::installer_oidc::select(
            crate::installer_oidc::prepare(Some(&input), false).unwrap(),
            &mut state,
        )
        .unwrap();
        let (_generation_root, generations) =
            crate::installer_generation_binding::test_lineage_fixture(0);
        let mut parent = generations[0].clone();
        parent.installation_id = state.journal().installation_id().to_string();
        parent.files.insert(
            SECRET.into(),
            GenerationFile {
                source: GenerationSource::Original,
                sha256: digest(before),
                size: before.len() as u64,
                source_mode: 0o444,
                mode: 0o444,
            },
        );
        parent.sha256().unwrap();
        drop(state);
        (root, path, parent)
    }

    #[test]
    fn replacement_preserves_provider_record_and_resumes_same_immutable_request() {
        let (_root, path, parent) = fixture(true);
        let before =
            std::fs::read(path.join("evidence").join(crate::installer_oidc::RECORD)).unwrap();
        let mut state = LockedMaintenance::open(&path).unwrap();
        let first = stage(&path, &mut state, &parent, b"next-secret").unwrap();
        drop(state);
        let mut reopened = LockedMaintenance::open(&path).unwrap();
        assert_eq!(
            stage(&path, &mut reopened, &parent, b"next-secret").unwrap(),
            first
        );
        assert!(stage(&path, &mut reopened, &parent, b"different-secret").is_err());
        assert_eq!(for_parent(&path, &parent).unwrap(), Some(first));
        assert_eq!(
            std::fs::read(path.join("evidence").join(crate::installer_oidc::RECORD)).unwrap(),
            before
        );
        assert_eq!(
            redaction_values(reopened.inspection(), &path).unwrap(),
            vec![b"next-secret".to_vec()]
        );
        assert!(!path
            .join("evidence/application-generation-current.json")
            .exists());
    }

    #[test]
    fn candidate_requires_matching_parent_provider_secret_and_generation_intent() {
        let (_root, path, parent) = fixture(true);
        let mut state = LockedMaintenance::open(&path).unwrap();
        let request = stage(&path, &mut state, &parent, b"next-secret").unwrap();
        let mut next = SuccessorBinding {
            sequence: 1,
            attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: parent.sha256().unwrap(),
            native_operation: "generation-1-wait-000001".into(),
            oidc_secret_rotation_sha256: Some(request.clone()),
        };
        assert!(candidate(&path, &parent, &next).is_err());
        let intent_name =
            crate::installer_generation_maintenance::attempt::Attempt::new(1, 0).record("intent");
        let intent = json!({"parent_binding_sha256":parent.sha256().unwrap(),"oidc_secret_rotation_sha256":request});
        state
            .write_evidence_exclusive(&intent_name, &serde_json::to_vec(&intent).unwrap())
            .unwrap();
        assert_eq!(
            candidate(&path, &parent, &next).unwrap(),
            Some(b"next-secret".to_vec())
        );
        next.oidc_secret_rotation_sha256 = None;
        assert!(candidate(&path, &parent, &next).is_err());
        next.oidc_secret_rotation_sha256 = Some("f".repeat(64));
        assert!(candidate(&path, &parent, &next).is_err());
        let mut changed_parent = parent.clone();
        changed_parent.engine_id = "other-engine".into();
        assert!(for_parent(&path, &changed_parent).is_err());
        private(
            &path.join("evidence").join(secret_name(1)),
            b"tampered-secret",
        );
        assert!(for_parent(&path, &parent).is_err());
    }

    #[test]
    fn public_clients_unchanged_secrets_and_provider_migration_are_refused() {
        let (_root, path, public) = fixture(false);
        let mut state = LockedMaintenance::open(&path).unwrap();
        assert!(stage(&path, &mut state, &public, b"new-secret").is_err());
        drop(state);
        let (_root, path, confidential) = fixture(true);
        let mut state = LockedMaintenance::open(&path).unwrap();
        assert!(stage(&path, &mut state, &confidential, b"old-secret").is_err());
        stage(&path, &mut state, &confidential, b"next-secret").unwrap();
        let selection_path = path.join("evidence").join(crate::installer_oidc::RECORD);
        let mut selection: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&selection_path).unwrap()).unwrap();
        selection["configuration"]["external_oidc"]["client_id"] = json!("other-client");
        private(&selection_path, &serde_json::to_vec(&selection).unwrap());
        assert!(for_parent(&path, &confidential).is_err());
        assert!(arguments(&[
            "--install-dir".into(),
            path.to_str().unwrap().into(),
            "--issuer-url".into(),
            "https://other.example".into()
        ])
        .is_err());
    }

    #[test]
    fn staged_secret_is_not_a_ready_generation_or_a_source_of_custody_credentials() {
        let (_root, path, parent) = fixture(true);
        let mut state = LockedMaintenance::open(&path).unwrap();
        let hash = stage(&path, &mut state, &parent, b"next-secret").unwrap();
        let mut successor = parent.clone();
        successor.successor = Some(SuccessorBinding {
            sequence: 1,
            attempt: 0,
            parent_attempt: 0,
            parent_binding_sha256: parent.sha256().unwrap(),
            native_operation: "generation-00000000000000000001-wait-000001".into(),
            oidc_secret_rotation_sha256: Some(hash),
        });
        successor.files.get_mut(SECRET).unwrap().source = GenerationSource::Candidate;
        // A valid shape alone still has no complete custody producer proof,
        // runtime activation, selected session, or current-generation selector.
        assert!(crate::installer_generation_binding::verify(&path, &successor).is_err());
        assert_eq!(parent.files.len(), successor.files.len());
        assert!(!successor.activated && !successor.installation_ready);
        for (name, value) in &parent.files {
            if name != SECRET {
                assert_eq!(successor.files[name], *value);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn test_stage(installation: &Path, parent: &GenerationBinding, bytes: &[u8]) -> String {
    let mut state = LockedMaintenance::open(installation).unwrap();
    stage(installation, &mut state, parent, bytes).unwrap()
}
