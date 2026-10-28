//! Exact, fail-closed Docker volume removal primitive. Dormant until a purge
//! coordinator persists and verifies an explicit destructive confirmation and
//! a durable remove intent for this exact recorded volume before calling it.
//! The coordinator must keep that intent across interruption and distinguish a
//! first attempt from a retry. This module never infers creation from a name.
#![cfg(target_os = "linux")]

use crate::installer_runtime::DockerRunner;
use chrono::DateTime;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::{Variant, Version};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "Recorded volume purge refused; preserve the durable intent and installation data";

/// Must come from verified creation evidence, not from a legacy name-only
/// resource list. Docker volumes have no immutable ID; exact CreatedAt, labels,
/// name and Engine binding are the available identity evidence.
pub(crate) struct RecordedVolume {
    pub installation_id: uuid::Uuid,
    pub engine_id: String,
    pub name: String,
    pub created_at: String,
    pub labels: BTreeMap<String, String>,
}

/// Both variants require the coordinator to have already persisted and
/// reloaded the exact volume-remove intent. Only Retry accepts prior absence.
pub(crate) enum PersistedVolumeRemoveIntent {
    FirstAttempt,
    Retry,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum VolumePurgeOutcome {
    Removed,
    AlreadyAbsentAfterRetry,
}

trait DockerCommands {
    fn engine_id(&self) -> Result<String>;
    fn run(&self, args: &[&str]) -> Result<String>;
}

impl DockerCommands for DockerRunner {
    fn engine_id(&self) -> Result<String> {
        Ok(self.preflight()?.engine_id)
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        self.run_checked(args)
    }
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn validate_recorded(v: &RecordedVolume) -> Result<()> {
    require(
        v.installation_id.get_version() == Some(Version::Random)
            && v.installation_id.get_variant() == Variant::RFC4122,
    )?;
    let project = format!("marty-install-{}", v.installation_id.simple());
    require(
        v.name == format!("{project}_redis-socket")
            && !v.engine_id.is_empty()
            && v.engine_id.len() <= 128
            && v.engine_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._-".contains(&b))
            && DateTime::parse_from_rfc3339(&v.created_at).is_ok()
            && v.created_at.len() <= 64
            && v.labels.len() >= 2
            && v.labels.len() <= 8
            && v.labels.get("com.docker.compose.project") == Some(&project)
            && v.labels.get("com.docker.compose.volume") == Some(&"redis-socket".into())
            && v.labels.iter().all(|(key, value)| {
                !key.is_empty()
                    && key.len() <= 128
                    && value.len() <= 256
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && !value.chars().any(char::is_control)
            }),
    )?;
    Ok(())
}

fn names(output: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for line in output.lines() {
        require(
            !line.is_empty()
                && line.len() <= 255
                && line
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && result.insert(line.into()),
        )?;
    }
    Ok(result)
}

fn single(output: &str) -> Result<Value> {
    let parsed: Value = serde_json::from_str(output).map_err(|_| REFUSED)?;
    let list = parsed.as_array().ok_or(REFUSED)?;
    require(list.len() == 1 && list[0].is_object())?;
    Ok(list[0].clone())
}

fn observed<D: DockerCommands>(docker: &D, v: &RecordedVolume) -> Result<bool> {
    let listed = names(&docker.run(&[
        "volume",
        "ls",
        "-q",
        "--filter",
        &format!("name={}", v.name),
    ])?)?;
    if !listed.contains(&v.name) {
        return Ok(false);
    }
    // A failed inspect is never interpreted as an absent volume.
    let inspect = single(&docker.run(&["volume", "inspect", &v.name])?)?;
    let labels = inspect["Labels"].as_object().ok_or(REFUSED)?;
    require(
        inspect["Name"] == v.name
            && inspect["Driver"] == "local"
            && inspect["Scope"] == "local"
            && inspect["CreatedAt"] == v.created_at
            && (inspect["Options"].is_null() || inspect["Options"] == serde_json::json!({}))
            && labels.len() == v.labels.len()
            && v.labels
                .iter()
                .all(|(key, value)| labels.get(key) == Some(&Value::String(value.clone()))),
    )?;
    Ok(true)
}

fn no_container_uses_volume<D: DockerCommands>(docker: &D, name: &str) -> Result<()> {
    // Global inventory includes stopped containers and is deliberately not
    // filtered to the installer's Compose project.
    let output = docker.run(&[
        "ps",
        "-a",
        "--no-trunc",
        "--filter",
        &format!("volume={name}"),
        "--format",
        "{{.ID}}",
    ])?;
    require(output.is_empty())
}

fn remove_with<D: DockerCommands>(
    docker: &D,
    recorded: &RecordedVolume,
    intent: PersistedVolumeRemoveIntent,
) -> Result<VolumePurgeOutcome> {
    validate_recorded(recorded)?;
    require(docker.engine_id()? == recorded.engine_id)?;
    let present = observed(docker, recorded)?;
    no_container_uses_volume(docker, &recorded.name)?;
    if !present {
        require(matches!(intent, PersistedVolumeRemoveIntent::Retry))?;
        require(!observed(docker, recorded)?)?;
        return Ok(VolumePurgeOutcome::AlreadyAbsentAfterRetry);
    }
    require(observed(docker, recorded)?)?;
    let removed = docker.run(&["volume", "rm", &recorded.name])?;
    require(removed.trim_end_matches('\n') == recorded.name)?;
    require(!observed(docker, recorded)?)?;
    Ok(VolumePurgeOutcome::Removed)
}

/// No caller may use this until the coordinator verifies exact creation
/// evidence and a persisted volume-remove intent under the installation lock.
#[allow(dead_code)] // Coordinator wiring is a later, separately reviewed milestone.
pub(crate) fn remove_recorded(
    docker: &DockerRunner,
    recorded: &RecordedVolume,
    intent: PersistedVolumeRemoveIntent,
) -> Result<VolumePurgeOutcome> {
    remove_with(docker, recorded, intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    struct MockDocker {
        engine: String,
        record: Value,
        present: Cell<bool>,
        attached: bool,
        inspect_error: bool,
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl DockerCommands for MockDocker {
        fn engine_id(&self) -> Result<String> {
            Ok(self.engine.clone())
        }
        fn run(&self, args: &[&str]) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| s.to_string()).collect());
            match args {
                ["volume", "ls", "-q", "--filter", _] => Ok(if self.present.get() {
                    format!("{}\n", self.record["Name"].as_str().unwrap())
                } else {
                    String::new()
                }),
                ["volume", "inspect", _] if !self.inspect_error => Ok(format!("[{}]", self.record)),
                ["volume", "inspect", _] => Err("inspect unavailable".into()),
                ["ps", "-a", "--no-trunc", "--filter", _, "--format", "{{.ID}}"] => {
                    Ok(if self.attached {
                        format!("{}\n", "a".repeat(64))
                    } else {
                        String::new()
                    })
                }
                ["volume", "rm", _] => {
                    self.present.set(false);
                    Ok(format!("{}\n", self.record["Name"].as_str().unwrap()))
                }
                _ => Err("unexpected Docker command".into()),
            }
        }
    }
    fn fixture() -> (RecordedVolume, MockDocker) {
        let installation_id =
            uuid::Uuid::parse_str("12345678-1234-4234-8234-123456789abc").unwrap();
        let project = format!("marty-install-{}", installation_id.simple());
        let name = format!("{project}_redis-socket");
        let labels = BTreeMap::from([
            ("com.docker.compose.project".into(), project),
            ("com.docker.compose.volume".into(), "redis-socket".into()),
        ]);
        let created_at = "2026-10-27T12:30:00Z".to_string();
        let recorded = RecordedVolume {
            installation_id,
            engine_id: "owned-engine".into(),
            name: name.clone(),
            created_at: created_at.clone(),
            labels: labels.clone(),
        };
        let docker = MockDocker {
            engine: "owned-engine".into(),
            record: serde_json::json!({"Name":name,"Driver":"local","Scope":"local",
                "CreatedAt":created_at,"Options":null,"Labels":labels}),
            present: Cell::new(true),
            attached: false,
            inspect_error: false,
            calls: RefCell::new(Vec::new()),
        };
        (recorded, docker)
    }
    fn mutated(docker: &MockDocker) -> bool {
        docker.calls.borrow().iter().any(|c| {
            c.first().is_some_and(|s| s == "volume") && c.get(1).is_some_and(|s| s == "rm")
        })
    }
    #[test]
    fn removes_only_exact_recorded_volume_after_global_attachment_check() {
        let (recorded, docker) = fixture();
        assert_eq!(
            remove_with(
                &docker,
                &recorded,
                PersistedVolumeRemoveIntent::FirstAttempt
            )
            .unwrap(),
            VolumePurgeOutcome::Removed
        );
        let calls = docker.calls.borrow();
        assert!(calls.iter().any(|c| c
            == &vec![
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                &format!("volume={}", recorded.name),
                "--format",
                "{{.ID}}"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.get(1).is_some_and(|s| s == "rm"))
                .count(),
            1
        );
        assert!(!calls
            .iter()
            .any(|c| c.iter().any(|s| s == "prune" || s == "--force")));
    }
    #[test]
    fn absence_requires_verified_retry_intent_and_never_removes() {
        let (recorded, docker) = fixture();
        docker.present.set(false);
        assert!(remove_with(
            &docker,
            &recorded,
            PersistedVolumeRemoveIntent::FirstAttempt
        )
        .is_err());
        assert!(!mutated(&docker));
        assert_eq!(
            remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).unwrap(),
            VolumePurgeOutcome::AlreadyAbsentAfterRetry
        );
        assert!(!mutated(&docker));
    }
    #[test]
    fn refuses_foreign_identity_attachment_and_legacy_uncertainty_before_removal() {
        let (mut recorded, docker) = fixture();
        recorded.created_at.clear();
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
        let (recorded, mut docker) = fixture();
        docker.engine = "other-engine".into();
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
        let (recorded, mut docker) = fixture();
        docker.record["Labels"]["com.docker.compose.project"] = serde_json::json!("foreign");
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
        let (recorded, mut docker) = fixture();
        docker.record["CreatedAt"] = serde_json::json!("2026-10-28T00:00:00Z");
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
        let (recorded, mut docker) = fixture();
        docker.attached = true;
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
        let (recorded, mut docker) = fixture();
        docker.inspect_error = true;
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
    }
    #[test]
    fn refuses_changed_name_driver_scope_options_and_extra_labels() {
        for (field, replacement) in [
            ("Name", serde_json::json!("unrelated_volume")),
            ("Driver", serde_json::json!("external")),
            ("Scope", serde_json::json!("global")),
            ("Options", serde_json::json!({"device":"/foreign"})),
        ] {
            let (recorded, mut docker) = fixture();
            docker.record[field] = replacement;
            assert!(
                remove_with(
                    &docker,
                    &recorded,
                    PersistedVolumeRemoveIntent::FirstAttempt
                )
                .is_err(),
                "{field}"
            );
            assert!(!mutated(&docker), "{field}");
        }
        let (recorded, mut docker) = fixture();
        docker.record["Labels"]["foreign"] = serde_json::json!("unexpected");
        assert!(remove_with(&docker, &recorded, PersistedVolumeRemoveIntent::Retry).is_err());
        assert!(!mutated(&docker));
    }
}
