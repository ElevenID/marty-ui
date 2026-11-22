//! Local creation observations for native Compose operations, never deletion authority.
//! Existing volumes are deliberately not adopted. The caller holds the installer
//! lock and supplies the fresh inventory persisted before the one-use operation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const REFUSED: &str =
    "Native Compose volume creation evidence is incomplete; preserve operation evidence";

pub(crate) struct CaptureContext {
    pub installation_id: Uuid,
    pub project: String,
    pub engine_id: String,
    pub operation: String,
    pub configuration_sha256: String,
    pub intent_sha256: String,
    pub result_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VolumeIdentity {
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub created_at: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatedVolumes {
    pub schema: String,
    pub installation_id: Uuid,
    pub project: String,
    pub engine_id: String,
    pub operation: String,
    pub configuration_sha256: String,
    pub intent_sha256: String,
    pub result_sha256: String,
    pub prior_volume_names: BTreeSet<String>,
    pub created_volumes: BTreeMap<String, VolumeIdentity>,
    pub point_in_time: bool,
    pub cryptographic_authentication: bool,
    pub deletion_authorized: bool,
}

fn require(ok: bool) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

fn valid_context(context: &CaptureContext) -> bool {
    !context.installation_id.is_nil()
        && !context.project.is_empty()
        && context.project.len() <= 96
        && !context.engine_id.is_empty()
        && context.engine_id.len() <= 256
        && !context.engine_id.chars().any(char::is_control)
        && !context.operation.is_empty()
        && context.operation.len() <= 96
        && [&context.project, &context.operation]
            .into_iter()
            .all(|value| {
                value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
            })
        && hash(&context.configuration_sha256)
        && hash(&context.intent_sha256)
        && hash(&context.result_sha256)
}

fn identity(name: &str, project: &str, key: &str, value: Value) -> Result<VolumeIdentity, String> {
    let labels: BTreeMap<String, String> =
        serde_json::from_value(value["Labels"].clone()).map_err(|_| REFUSED)?;
    let created_at = value["CreatedAt"].as_str().ok_or(REFUSED)?;
    require(
        value["Name"] == name
            && value["Driver"] == "local"
            && value["Scope"] == "local"
            && (value["Options"].is_null()
                || value["Options"].as_object().is_some_and(|o| o.is_empty()))
            && created_at.len() <= 64
            && chrono::DateTime::parse_from_rfc3339(created_at)
                .is_ok_and(|time| time.timestamp() > 0)
            && (2..=16).contains(&labels.len())
            && labels
                .iter()
                .all(|(k, v)| k.len() <= 256 && v.len() <= 4096)
            && labels.get("com.docker.compose.project").map(String::as_str) == Some(project)
            && labels.get("com.docker.compose.volume").map(String::as_str) == Some(key),
    )?;
    Ok(VolumeIdentity {
        name: name.into(),
        driver: "local".into(),
        scope: "local".into(),
        created_at: created_at.into(),
        labels,
    })
}

/// Only the difference of fresh pre-operation and validated post-operation
/// inventories can acquire a creation observation. Missing/uncertain evidence
/// never becomes an empty successful receipt, and inspection is repeated before
/// writing to detect replacement or changed metadata during acquisition.
pub(crate) fn capture(
    context: CaptureContext,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    declared: &BTreeMap<String, String>,
    mut inspect: impl FnMut(&str) -> Result<Value, String>,
) -> Result<Option<CreatedVolumes>, String> {
    require(valid_context(&context) && before.is_subset(after))?;
    let added: Vec<_> = after.difference(before).collect();
    if added.is_empty() {
        return Ok(None);
    }
    let mut created_volumes = BTreeMap::new();
    for name in added {
        let key = declared.get(name).ok_or(REFUSED)?;
        require(
            name.len() <= 255
                && name.starts_with(&format!("{}_", context.project))
                && !key.is_empty(),
        )?;
        let first = identity(
            name,
            &context.project,
            key,
            inspect(name).map_err(|_| REFUSED)?,
        )?;
        let second = identity(
            name,
            &context.project,
            key,
            inspect(name).map_err(|_| REFUSED)?,
        )?;
        require(first == second)?;
        created_volumes.insert(name.clone(), first);
    }
    Ok(Some(CreatedVolumes {
        schema: "elevenid.installer-compose-created-volumes/v1".into(),
        installation_id: context.installation_id,
        project: context.project,
        engine_id: context.engine_id,
        operation: context.operation,
        configuration_sha256: context.configuration_sha256,
        intent_sha256: context.intent_sha256,
        result_sha256: context.result_sha256,
        prior_volume_names: before.clone(),
        created_volumes,
        point_in_time: true,
        cryptographic_authentication: false,
        deletion_authorized: false,
    }))
}

/// Read exact native creation bytes against their original operation context.
/// This checks historical metadata only. It never manufactures a receipt for
/// an existing volume or replaces the planner's fresh Docker/custody checks.
/// Derive context and inventories independently from validated original operation
/// intent/result/model evidence; copying fields from this record is insufficient.
pub(crate) fn validate_record(
    context: &CaptureContext,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    declared: &BTreeMap<String, String>,
    bytes: &[u8],
) -> Result<CreatedVolumes, String> {
    require(valid_context(context))?;
    require(!bytes.is_empty() && bytes.len() <= 2 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    require(serde_json::to_vec(&value).map_err(|_| REFUSED)? == bytes)?;
    let record: CreatedVolumes = serde_json::from_value(value).map_err(|_| REFUSED)?;
    let added: BTreeSet<_> = after.difference(before).cloned().collect();
    require(
        before.is_subset(after)
            && !added.is_empty()
            && record.schema == "elevenid.installer-compose-created-volumes/v1"
            && record.installation_id == context.installation_id
            && record.project == context.project
            && record.engine_id == context.engine_id
            && record.operation == context.operation
            && record.configuration_sha256 == context.configuration_sha256
            && record.intent_sha256 == context.intent_sha256
            && record.result_sha256 == context.result_sha256
            && record.prior_volume_names == *before
            && record
                .created_volumes
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
                == added
            && record.point_in_time
            && !record.cryptographic_authentication
            && !record.deletion_authorized,
    )?;
    for (name, recorded) in &record.created_volumes {
        let key = declared.get(name).ok_or(REFUSED)?;
        require(
            name.len() <= 255
                && name.starts_with(&format!("{}_", context.project))
                && !key.is_empty(),
        )?;
        // Format adaptation shares native capture's metadata constraints; this
        // conversion is deliberately not described as a Docker observation.
        let projected = serde_json::json!({"Name":recorded.name,"Driver":recorded.driver,
            "Scope":recorded.scope,"CreatedAt":recorded.created_at,"Labels":recorded.labels,
            "Options":null});
        require(identity(name, &context.project, key, projected)? == *recorded)?;
    }
    Ok(record)
}

#[cfg(target_os = "linux")]
#[derive(Eq, PartialEq)]
pub(crate) struct InitialVolumeEvidence {
    pub volumes: BTreeMap<String, VolumeIdentity>,
    pub creation_record_sha256: Option<String>,
    pub source_records: BTreeMap<&'static str, Vec<u8>>,
}

/// Follow the original installation owner's bound cleanup plan and model, not
/// fields copied from a creation record. Volumes predating the application
/// operation or introduced by another operation remain unproven here. Their
/// independently qualified producer chain must be added before planning them.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_initial_volumes(
    locked: &crate::installer_state::LockedInspection,
    installation: &std::path::Path,
    selected: &crate::installer_doctor::SavedSession,
) -> Result<InitialVolumeEvidence, String> {
    use crate::installer_compose::{
        self as compose, ComposeReceipt, ProjectResources, RuntimeCleanupPlan,
    };
    const PLAN: &str = compose::RUNTIME_CLEANUP_PLAN;
    const MODEL: &str = "application-native-model.json";
    const INTENT: &str = "compose-application-up-intent.json";
    const RESULT: &str = "compose-application-up-result.json";
    const CREATED: &str = "compose-application-up-created-volumes.json";
    let inspect = || -> Result<InitialVolumeEvidence, String> {
        locked.require_path_binding(installation)?;
        locked.require_unchanged()?;
        let initial = crate::installer_doctor::load_initial_session(locked, installation)?;
        require(initial.schema == "elevenid.installer-compose-session/v1")?;
        let mut records = BTreeMap::new();
        for name in [PLAN, MODEL, INTENT, RESULT] {
            records.insert(name, locked.read_evidence(name)?);
        }
        let plan: RuntimeCleanupPlan = serde_json::from_value(
            crate::installer_json::decode(&records[PLAN]).map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED)?;
        let model = crate::installer_json::decode(&records[MODEL]).map_err(|_| REFUSED)?;
        let intent = crate::installer_json::decode(&records[INTENT]).map_err(|_| REFUSED)?;
        let result: ComposeReceipt = serde_json::from_value(
            crate::installer_json::decode(&records[RESULT]).map_err(|_| REFUSED)?,
        )
        .map_err(|_| REFUSED)?;
        let plan_path = installation.join("evidence").join(PLAN);
        let plan_hash = crate::installer_release::sha256(&records[PLAN]);
        let journal = locked.journal();
        let engine = &journal.runtime().ok_or(REFUSED)?.engine_id;
        let project = journal.compose_project();
        require(
            plan.schema == "elevenid.installer-runtime-cleanup-plan/v1"
                && plan.installation_id == journal.installation_id().to_string()
                && plan.inputs.installation == installation
                && plan.inputs.project == project
                && plan.inputs.services.is_empty()
                && initial.receipt.input_files.get(&plan_path) == Some(&plan_hash)
                && compose::model_sha256(&plan.model)? == plan.configuration_sha256
                && model["name"] == project
                && plan.model["name"] == project
                && compose::model_sha256(&model)? == plan.application_configuration_sha256
                && result.schema == "elevenid.installer-compose-operation/v1"
                && result.operation == "application-up"
                && result.project == project
                && result.engine_id == *engine
                && result.configuration_sha256 == plan.application_configuration_sha256
                && result.input_files.get(&plan_path) == Some(&plan_hash)
                && result.command_succeeded
                && result.client_exit_code == Some(0)
                && result.failure_class.is_none()
                && result.observation_validated
                && !result.installation_ready
                && intent["schema"] == "elevenid.installer-compose-intent/v1"
                && intent["project"] == project
                && intent["engine_id"] == *engine
                && intent["configuration_sha256"] == plan.application_configuration_sha256
                && intent["input_files"]
                    == serde_json::to_value(&result.input_files).map_err(|_| REFUSED)?
                && intent["command"]
                    == serde_json::json!([
                        "up",
                        "--no-build",
                        "--pull",
                        "never",
                        "--no-recreate",
                        "--wait",
                        "--wait-timeout",
                        "720"
                    ])
                && intent["selected_services"] == serde_json::json!([])
                && intent["automatic_retry"] == false
                && intent["installation_ready"] == false,
        )?;
        let before = if let Some(prior) = &plan.inputs.prior {
            require(
                prior.project == project
                    && prior.engine_id == *engine
                    && prior.command_succeeded
                    && prior.client_exit_code == Some(0)
                    && prior.failure_class.is_none()
                    && prior.observation_validated
                    && prior
                        .input_files
                        .iter()
                        .all(|(path, hash)| result.input_files.get(path) == Some(hash)),
            )?;
            prior.resources.as_ref().ok_or(REFUSED)?.clone()
        } else {
            ProjectResources::default()
        };
        let after = result.resources.as_ref().ok_or(REFUSED)?;
        let current = selected.receipt.resources.as_ref().ok_or(REFUSED)?;
        require(
            intent["prior_resources"] == serde_json::to_value(&before).map_err(|_| REFUSED)?
                && before
                    .containers
                    .iter()
                    .all(|(role, identity)| after.containers.get(role) == Some(identity))
                && before
                    .networks
                    .iter()
                    .all(|(name, id)| after.networks.get(name) == Some(id))
                && before.volumes.is_empty()
                && after.volumes == current.volumes
                && selected.inputs.project == project
                && selected.receipt.engine_id == *engine,
        )?;
        let created = locked.diagnostic_record(CREATED, true)?;
        let (volumes, creation_record_sha256) = if after.volumes.is_empty() {
            require(created.is_none())?;
            (BTreeMap::new(), None)
        } else {
            let bytes = created.as_ref().ok_or(REFUSED)?;
            let mut declared = BTreeMap::new();
            for (key, value) in model["volumes"].as_object().ok_or(REFUSED)? {
                let name = value["name"].as_str().ok_or(REFUSED)?;
                require(declared.insert(name.to_owned(), key.clone()).is_none())?;
            }
            let record = validate_record(
                &CaptureContext {
                    installation_id: journal.installation_id(),
                    project: project.clone(),
                    engine_id: engine.clone(),
                    operation: "application-up".into(),
                    configuration_sha256: plan.application_configuration_sha256.clone(),
                    intent_sha256: crate::installer_release::sha256(&records[INTENT]),
                    result_sha256: crate::installer_release::sha256(&records[RESULT]),
                },
                &before.volumes,
                &after.volumes,
                &declared,
                bytes,
            )?;
            (
                record.created_volumes,
                Some(crate::installer_release::sha256(bytes)),
            )
        };
        for (name, bytes) in &records {
            require(locked.read_evidence(name)? == *bytes)?;
        }
        require(
            locked.diagnostic_record(CREATED, true)? == created
                && serde_json::to_value(crate::installer_doctor::load_initial_session(
                    locked,
                    installation,
                )?)
                .map_err(|_| REFUSED)?
                    == serde_json::to_value(&initial).map_err(|_| REFUSED)?
                && serde_json::to_value(crate::installer_doctor::load_session(
                    locked,
                    installation,
                )?)
                .map_err(|_| REFUSED)?
                    == serde_json::to_value(selected).map_err(|_| REFUSED)?,
        )?;
        locked.require_path_binding(installation)?;
        locked.require_unchanged()?;
        if let Some(bytes) = created {
            records.insert(CREATED, bytes);
        }
        Ok(InitialVolumeEvidence {
            volumes,
            creation_record_sha256,
            source_records: records,
        })
    };
    inspect().map_err(|_| REFUSED.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context() -> CaptureContext {
        CaptureContext {
            installation_id: Uuid::from_u128(7),
            project: "marty-install-fixture".into(),
            engine_id: "synthetic-engine".into(),
            operation: "application-up".into(),
            configuration_sha256: "a".repeat(64),
            intent_sha256: "b".repeat(64),
            result_sha256: "c".repeat(64),
        }
    }
    fn volume() -> Value {
        json!({"Name":"marty-install-fixture_redis-socket", "Driver":"local", "Scope":"local",
            "CreatedAt":"2026-11-15T20:00:00Z", "Options":null,
            "Labels":{"com.docker.compose.project":"marty-install-fixture", "com.docker.compose.volume":"redis-socket"}})
    }
    fn names() -> BTreeSet<String> {
        BTreeSet::from(["marty-install-fixture_redis-socket".into()])
    }
    fn declared() -> BTreeMap<String, String> {
        BTreeMap::from([(
            "marty-install-fixture_redis-socket".into(),
            "redis-socket".into(),
        )])
    }

    #[test]
    fn fresh_operation_records_stable_exact_metadata_without_authority() {
        let mut reads = 0;
        let record = capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
            reads += 1;
            Ok(volume())
        })
        .unwrap()
        .unwrap();
        assert_eq!(reads, 2);
        assert!(record.prior_volume_names.is_empty());
        assert_eq!(record.created_volumes.len(), 1);
        assert_eq!(
            record.created_volumes.values().next().unwrap().labels.len(),
            2
        );
        assert!(!record.cryptographic_authentication && !record.deletion_authorized);
    }

    #[test]
    fn existing_volumes_cannot_be_retroactively_adopted() {
        assert!(capture(context(), &names(), &names(), &declared(), |_| {
            panic!("existing volume must never be inspected into creation evidence")
        })
        .unwrap()
        .is_none());
        assert!(
            capture(context(), &names(), &BTreeSet::new(), &declared(), |_| Ok(
                volume()
            ))
            .is_err()
        );
    }

    fn record_bytes() -> Vec<u8> {
        let record = capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
            Ok(volume())
        })
        .unwrap()
        .unwrap();
        // Match ComposeSession::write's Value serialization exactly.
        serde_json::to_vec(&serde_json::to_value(record).unwrap()).unwrap()
    }

    #[test]
    fn persisted_creation_record_is_bound_to_original_operation_and_scope() {
        let bytes = record_bytes();
        assert!(
            validate_record(&context(), &BTreeSet::new(), &names(), &declared(), &bytes).is_ok()
        );
        let mut wrong = context();
        wrong.result_sha256 = "d".repeat(64);
        assert!(validate_record(&wrong, &BTreeSet::new(), &names(), &declared(), &bytes).is_err());
        assert!(validate_record(&context(), &names(), &names(), &declared(), &bytes).is_err());
        let mut extra = names();
        extra.insert("marty-install-fixture_unknown".into());
        assert!(
            validate_record(&context(), &BTreeSet::new(), &extra, &declared(), &bytes).is_err()
        );
    }

    #[test]
    fn rewritten_duplicate_unknown_or_authoritative_creation_records_are_refused() {
        let original = record_bytes();
        for field in [
            "schema",
            "installation_id",
            "project",
            "engine_id",
            "operation",
            "configuration_sha256",
            "intent_sha256",
            "result_sha256",
            "prior_volume_names",
            "created_volumes",
            "point_in_time",
            "cryptographic_authentication",
            "deletion_authorized",
            "unknown",
        ] {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            value[field] = serde_json::json!("invalid-or-private-canary");
            assert!(
                validate_record(
                    &context(),
                    &BTreeSet::new(),
                    &names(),
                    &declared(),
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err(),
                "{field}"
            );
        }
        for field in ["cryptographic_authentication", "deletion_authorized"] {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            value[field] = serde_json::json!(true);
            assert!(validate_record(
                &context(),
                &BTreeSet::new(),
                &names(),
                &declared(),
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err());
        }
        let mut duplicate = b"{\"point_in_time\":true,".to_vec();
        duplicate.extend_from_slice(&original[1..]);
        assert!(validate_record(
            &context(),
            &BTreeSet::new(),
            &names(),
            &declared(),
            &duplicate
        )
        .is_err());
        let mut newline = original;
        newline.push(b'\n');
        assert!(validate_record(
            &context(),
            &BTreeSet::new(),
            &names(),
            &declared(),
            &newline
        )
        .is_err());
    }

    #[test]
    fn observation_failures_are_sanitized_and_never_become_empty_receipts() {
        let result = capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
            Err("private-path-and-volume-label-canary".into())
        });
        assert_eq!(result.err().unwrap(), REFUSED);
        assert!(
            capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
                let mut value = volume();
                value["Options"] = json!({"type":"nfs", "device":"private-path-canary"});
                Ok(value)
            })
            .is_err()
        );
    }

    #[test]
    fn foreign_undeclared_or_changed_volume_metadata_is_refused() {
        for field in ["Name", "Driver", "Scope", "CreatedAt", "Options", "Labels"] {
            let result = capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
                let mut value = volume();
                value[field] = json!("foreign-or-invalid");
                Ok(value)
            });
            assert!(result.is_err(), "{field}");
        }
        assert!(capture(
            context(),
            &BTreeSet::new(),
            &names(),
            &BTreeMap::new(),
            |_| Ok(volume())
        )
        .is_err());
        for label in ["com.docker.compose.project", "com.docker.compose.volume"] {
            assert!(
                capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
                    let mut value = volume();
                    value["Labels"][label] = json!("foreign");
                    Ok(value)
                })
                .is_err()
            );
        }
        let mut reads = 0;
        assert!(
            capture(context(), &BTreeSet::new(), &names(), &declared(), |_| {
                reads += 1;
                let mut value = volume();
                if reads == 2 {
                    value["CreatedAt"] = json!("2026-11-15T20:00:01Z");
                }
                Ok(value)
            })
            .is_err()
        );
    }
}
