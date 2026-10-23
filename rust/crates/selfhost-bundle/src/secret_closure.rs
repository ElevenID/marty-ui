//! Read declarations and example filenames only; never read operator secret values.
use crate::Result;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

fn names(value: &Value) -> Result<BTreeSet<String>> {
    let list = value.as_array().ok_or("required secrets must be a list")?;
    let mut result = BTreeSet::new();
    for item in list {
        let name = item.as_str().ok_or("required secrets contain a non-name")?;
        if !result.insert(name.to_owned()) {
            return Err("required secrets contain duplicates".into());
        }
    }
    Ok(result)
}

/// Validate source or extracted-install declarations without starting services.
/// All paths are supplied by the caller, with no dependency on the checkout.
pub fn validate(compose: &Path, catalog: &Path, stack: &Path, examples: &Path) -> Result<Value> {
    let read = |path: &Path| {
        fs::read_to_string(path).map_err(|_| "cannot read declaration input".to_owned())
    };
    let model: Value =
        serde_yaml::from_str(&read(compose)?).map_err(|_| "invalid Compose declaration")?;
    let catalog: Value =
        serde_json::from_str(&read(catalog)?).map_err(|_| "invalid secret catalog")?;
    let stack: Value =
        serde_json::from_str(&read(stack)?).map_err(|_| "invalid stack specification")?;
    let services = model["services"]
        .as_object()
        .ok_or("Compose has no service map")?;
    let declarations = model["secrets"]
        .as_object()
        .filter(|m| !m.is_empty())
        .ok_or("Compose has no secret declarations")?;
    let declared: BTreeSet<_> = declarations.keys().cloned().collect();
    let catalog = catalog["secrets"]
        .as_object()
        .ok_or("catalog has no secret map")?;
    let required = names(&stack["required_secrets"])?;
    let mut referenced = BTreeSet::new();
    for service in services.values() {
        if !service.is_object() {
            return Err("service is not an object".into());
        }
        if let Some(entries) = service.get("secrets") {
            for entry in entries.as_array().ok_or("service secrets must be a list")? {
                let name = entry
                    .as_str()
                    .or_else(|| entry.get("source").and_then(Value::as_str))
                    .ok_or("invalid service secret reference")?;
                referenced.insert(name.to_owned());
            }
        }
    }
    if referenced != declared {
        return Err("Compose declared/reference mismatch".into());
    }
    let mut mapped = BTreeMap::new();
    let mut catalog_required = BTreeSet::new();
    for (name, entry) in catalog {
        if !entry.is_object() {
            return Err("catalog entry is not an object".into());
        }
        if let Some(compose_name) = entry.get("compose_secret").filter(|v| !v.is_null()) {
            let compose_name = compose_name
                .as_str()
                .ok_or("invalid catalog Compose secret")?;
            if mapped.insert(compose_name.to_owned(), name).is_some() {
                return Err("catalog duplicate Compose secret".into());
            }
        }
        if let Some(scopes) = entry.get("required_for") {
            if scopes
                .as_array()
                .ok_or("catalog scopes must be a list")?
                .iter()
                .any(|v| v == "selfhost-production")
            {
                catalog_required.insert(name.clone());
            }
        }
    }
    if !declared.iter().all(|name| mapped.contains_key(name)) {
        return Err("Compose secrets absent from catalog".into());
    }
    if required != catalog_required {
        return Err("stack/catalog required mismatch".into());
    }
    if !catalog_required.is_subset(&declared) {
        return Err("required catalog secrets absent from Compose".into());
    }
    for (name, entry) in declarations {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':']) {
            return Err("Compose secret name must be a single filename".into());
        }
        let expected = format!("${{SELFHOST_SECRET_DIR:?SELFHOST_SECRET_DIR must be set}}/{name}");
        if entry.get("file").and_then(Value::as_str) != Some(expected.as_str()) {
            return Err("Compose secret does not use its isolated file path".into());
        }
        if !fs::symlink_metadata(examples.join(name)).is_ok_and(|m| m.file_type().is_file()) {
            return Err("Compose secret lacks a regular example file".into());
        }
    }
    Ok(
        json!({"schema":"marty.selfhost-install-secret-closure/v1", "qualification":"unqualified",
              "declared_secret_names":declared,"required_secret_names":catalog_required}),
    )
}
