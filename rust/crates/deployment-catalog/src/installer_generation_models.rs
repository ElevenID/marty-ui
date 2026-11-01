//! Read-only comparison of native generation models. The executable inputs
//! remain the authenticated Compose files and their bound dotenv selection.
use super::*;
use std::collections::BTreeSet;

const SETUP: &str = "com.elevenid.installer.phase";

fn replace_path(value: &mut Value, old: &Path, new: &Path) -> Result<()> {
    let path = installer_compose::config_path(value)?;
    if path.starts_with(old) {
        let relative = path.strip_prefix(old).map_err(|_| REFUSED)?;
        require(relative.components().count() == 1)?;
        *value = Value::String(
            new.join(relative)
                .to_str()
                .ok_or(REFUSED)?
                .replace('$', "$$"),
        );
    }
    Ok(())
}
fn replace_generation_paths(model: &mut Value, old: &Path, new: &Path) -> Result<()> {
    for declaration in model
        .get_mut("secrets")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|map| map.values_mut())
    {
        if let Some(value) = declaration.get_mut("file") {
            replace_path(value, old, new)?;
        }
    }
    for service in model["services"]
        .as_object_mut()
        .ok_or(REFUSED)?
        .values_mut()
    {
        for mount in service
            .get_mut("volumes")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if mount["type"] == "bind" {
                replace_path(&mut mount["source"], old, new)?;
            }
        }
    }
    Ok(())
}

/// Compose omits inactive services and their unused top-level resources. Only
/// declarations actually referenced by the compared services can affect them.
fn projection(model: &Value, include_setup: bool) -> Result<Value> {
    let mut result = model.clone();
    let services = result["services"].as_object_mut().ok_or(REFUSED)?;
    if !include_setup {
        services.retain(|_, service| service["labels"][SETUP] != "setup");
    }
    require(!services.is_empty())?;
    let mut secrets = BTreeSet::new();
    let mut configs = BTreeSet::new();
    let mut networks = BTreeSet::new();
    let mut volumes = BTreeSet::new();
    for service in services.values() {
        for (key, names) in [("secrets", &mut secrets), ("configs", &mut configs)] {
            for reference in service[key].as_array().into_iter().flatten() {
                names.insert(reference["source"].as_str().ok_or(REFUSED)?.to_owned());
            }
        }
        for name in service["networks"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.keys())
        {
            networks.insert(name.clone());
        }
        for mount in service["volumes"].as_array().into_iter().flatten() {
            if mount["type"] == "volume" {
                volumes.insert(mount["source"].as_str().ok_or(REFUSED)?.to_owned());
            }
        }
    }
    for (key, names) in [
        ("secrets", secrets),
        ("configs", configs),
        ("networks", networks),
        ("volumes", volumes),
    ] {
        if let Some(map) = result.get_mut(key).and_then(Value::as_object_mut) {
            require(names.iter().all(|name| map.contains_key(name)))?;
            map.retain(|name, _| names.contains(name));
            if map.is_empty() {
                result.as_object_mut().ok_or(REFUSED)?.remove(key);
            }
        } else {
            require(names.is_empty())?;
            result.as_object_mut().ok_or(REFUSED)?.remove(key);
        }
    }
    Ok(result)
}

pub(super) fn require_transition_model(
    installation: &Path,
    parent: &GenerationBinding,
    candidate: &GenerationBinding,
    parent_model: &Value,
    helper_model: &Value,
    model: &Value,
    full: bool,
) -> Result<()> {
    require(
        candidate.sequence() == parent.sequence().checked_add(1).ok_or(REFUSED)?
            && candidate.successor.as_ref().is_some_and(|s| {
                parent
                    .sha256()
                    .is_ok_and(|hash| hash == s.parent_binding_sha256)
            }),
    )?;
    let mut expected = parent_model.clone();
    replace_generation_paths(
        &mut expected,
        &parent.secret_dir(installation)?,
        &candidate.secret_dir(installation)?,
    )?;
    if full {
        require(helper_model["services"]["installer-generation"].is_object())?;
        expected["services"]["installer-generation"] =
            helper_model["services"]["installer-generation"].clone();
    }
    require(projection(&expected, full)? == projection(model, full)?)?;
    if !full {
        require(
            model["services"]
                .as_object()
                .ok_or(REFUSED)?
                .values()
                .all(|v| v["labels"][SETUP] != "setup"),
        )?;
    }
    require_runtime_files(installation, candidate, model)
}

fn require_runtime_files(
    installation: &Path,
    binding: &GenerationBinding,
    model: &Value,
) -> Result<()> {
    let root = binding.secret_dir(installation)?;
    let mut used = BTreeSet::new();
    for service in model["services"]
        .as_object()
        .ok_or(REFUSED)?
        .values()
        .filter(|service| service["labels"][SETUP] != "setup")
    {
        for reference in service["secrets"].as_array().into_iter().flatten() {
            let name = reference["source"].as_str().ok_or(REFUSED)?;
            require(
                binding.files.contains_key(name)
                    && installer_compose::config_path(&model["secrets"][name]["file"])?
                        == root.join(name),
            )?;
            used.insert(name.to_owned());
        }
        for mount in service["volumes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|mount| mount["type"] == "bind")
        {
            let path = installer_compose::config_path(&mount["source"])?;
            if path.starts_with(&root) {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(REFUSED)?;
                require(
                    path.parent() == Some(root.as_path())
                        && mount["read_only"] == true
                        && binding.files.contains_key(name),
                )?;
                used.insert(name.to_owned());
            } else {
                require(
                    ![
                        "secrets",
                        "application-generation",
                        "application-generations",
                    ]
                    .iter()
                    .any(|base| path.starts_with(installation.join(base))),
                )?;
            }
        }
    }
    require(
        !used.is_empty()
            && used.contains("installer_ingress_tls_cert")
            && used.contains("installer_ingress_tls_kms_token"),
    )
}

pub(crate) fn require_runtime_model(
    installation: &Path,
    binding: &GenerationBinding,
    model: &Value,
) -> Result<()> {
    require(binding.sequence() > 0)?;
    // Reading an immediate predecessor is deliberately nonrecursive: the
    // binding owner has already walked and verified the immutable ancestry.
    let parent = generation::read_recorded_sequence(installation, binding.sequence() - 1)?;
    let bytes = read(installation, &record_name(binding.sequence(), "intent"))?;
    let intent: Value = decode(&bytes)?;
    let previous: SavedSession =
        serde_json::from_value(intent["parent_session"].clone()).map_err(|_| REFUSED)?;
    let recorded = if parent.sequence() == 0 {
        read(installation, installer_doctor::SESSION_RECORD)?
    } else {
        read(installation, &record_name(parent.sequence(), "session"))?
    };
    let recorded: SavedSession = decode(&recorded)?;
    require(
        encode(&previous)? == encode(&recorded)?
            && intent["parent_binding_sha256"] == parent.sha256()?
            && intent["sequence"] == binding.sequence()
            && previous.configuration_sha256 == installer_compose::model_sha256(&previous.model)?
            && intent["helper_configuration_sha256"]
                == installer_compose::model_sha256(&intent["helper_model"])?,
    )?;
    require_transition_model(
        installation,
        &parent,
        binding,
        &previous.model,
        &intent["helper_model"],
        model,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_rewrite_preserves_absent_optional_declarations_and_mounts() {
        let original = json!({"services":{"plain":{"image":"approved"},
            "mounted":{"image":"approved","volumes":[{"type":"bind",
                "source":"/installation/application-generation/token","target":"/run/token"}]}}});
        let mut changed = original.clone();
        replace_generation_paths(
            &mut changed,
            Path::new("/installation/application-generation"),
            Path::new("/installation/application-generations/next"),
        )
        .unwrap();
        assert!(changed.get("secrets").is_none());
        assert!(changed["services"]["plain"].get("volumes").is_none());
        assert_eq!(changed["services"]["plain"], original["services"]["plain"]);
        assert_eq!(
            changed["services"]["mounted"]["volumes"][0]["source"],
            "/installation/application-generations/next/token"
        );
        let mut expected = original;
        expected["services"]["mounted"]["volumes"][0]["source"] =
            json!("/installation/application-generations/next/token");
        assert_eq!(changed, expected);
    }

    #[test]
    fn projection_keeps_every_runtime_setting_but_omits_inactive_resource_declarations() {
        let value = json!({"name":"p","services":{"app":{"image":"approved","environment":{"A":"1"},"networks":{"default":{}},"secrets":[{"source":"credential"}]},"setup":{"labels":{SETUP:"setup"},"secrets":[{"source":"bootstrap"}]}},"secrets":{"credential":{"file":"/x/current/credential"},"bootstrap":{"file":"/x/bootstrap"}},"networks":{"default":{"name":"p_default"}}});
        let runtime = projection(&value, false).unwrap();
        assert!(!runtime["services"]
            .as_object()
            .unwrap()
            .contains_key("setup"));
        assert!(!runtime["secrets"]
            .as_object()
            .unwrap()
            .contains_key("bootstrap"));
        let mut changed = value.clone();
        changed["services"]["app"]["environment"]["A"] = json!("2");
        assert_ne!(runtime, projection(&changed, false).unwrap());
        let mut changed = value;
        changed["secrets"]["credential"]["file"] = json!("/x/foreign");
        assert_ne!(runtime, projection(&changed, false).unwrap());
    }
}
