//! Deployment metadata and native KMS operator commands.

mod aggregate_plan;
pub mod beta_runtime_config;
mod compose_model;
mod deployment_admission;
mod deployment_environment;
mod deployment_lifecycle;
pub mod installer_application;
pub mod installer_application_env;
pub mod installer_application_graph;
pub mod installer_application_model;
pub mod installer_application_observation;
pub mod installer_application_start;
pub mod installer_artifacts;
pub mod installer_bundle;
#[cfg(target_os = "linux")]
pub mod installer_candidate_command;
pub mod installer_candidate_nonce;
pub mod installer_candidate_prepare;
pub mod installer_command;
pub mod installer_fetch;
pub mod installer_generation;
pub mod installer_generation_binding;
pub mod installer_generation_host;
pub mod installer_ingress;
pub mod installer_ingress_config;
pub mod installer_ingress_model;
pub mod installer_ingress_outputs;
pub mod installer_ingress_provision;
pub mod installer_keycloak;
pub mod installer_keycloak_bridge;
pub mod installer_logs;
pub mod installer_openbao;
pub mod installer_prepare;
pub mod installer_release;
pub mod installer_renewal;
pub mod installer_renewal_bootstrap;
pub mod installer_runtime;
pub mod installer_state;
pub mod installer_tls;
pub mod installer_tls_outputs;
pub mod installer_uninstall;
pub mod installer_verify;
pub mod kubernetes_secrets;
pub mod passport_model;

use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub struct Catalog {
    pub root: PathBuf,
    pub services: Map<String, Value>,
    pub groups: Map<String, Value>,
    pub input_specs: Map<String, Value>,
    pub artifacts: Map<String, Value>,
    pub stacks: Map<String, Value>,
    pub bundles: Map<String, Value>,
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object().and_then(|o| o.get(name))
}

fn string(value: &Value) -> Option<&str> {
    value.as_str()
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn windows_path_without_verbatim_prefix(path: &str) -> String {
    if let Some(share) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{share}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}

fn list(value: &Value) -> Vec<&Value> {
    value
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .map(list)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| string(v).map(str::to_owned))
        .collect()
}

fn validate_string_list(errors: &mut Vec<String>, label: &str, value: Option<&Value>) {
    if let Some(value) = value {
        match value.as_array() {
            Some(items) if items.iter().all(Value::is_string) => {}
            _ => errors.push(format!("{label} must be an array of strings")),
        }
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        _ => value.to_string(),
    }
}

fn pyrepr(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn dedupe(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|v| seen.insert(v.clone()))
        .collect()
}

fn read_json(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Err(format!(
            "Missing deployment metadata file: {}",
            path.display()
        ));
    }
    let data = fs::read_to_string(path).map_err(|e| {
        format!(
            "Cannot read deployment metadata file {}: {e}",
            path.display()
        )
    })?;
    let payload: Value = serde_json::from_str(&data).map_err(|e| {
        format!(
            "Invalid JSON in deployment metadata file: {}: {e}",
            path.display()
        )
    })?;
    if !payload.is_object() {
        return Err(format!(
            "Deployment metadata file must contain a JSON object: {}",
            path.display()
        ));
    }
    Ok(payload)
}

fn read_named(dir: &Path) -> Result<Map<String, Value>> {
    if !dir.exists() {
        return Err(format!(
            "Missing deployment metadata directory: {}",
            dir.display()
        ));
    }
    let mut paths = fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    let mut result = Map::new();
    for path in paths {
        let value = read_json(&path)?;
        let name = field(&value, "name")
            .filter(|value| python_truthy(value))
            .and_then(string)
            .map(str::to_owned)
            .or_else(|| {
                if field(&value, "name").is_some_and(python_truthy) {
                    None
                } else {
                    path.file_stem().map(|s| s.to_string_lossy().into_owned())
                }
            })
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "Deployment metadata document {} has no valid name",
                    path.display()
                )
            })?;
        result.insert(name, value);
    }
    Ok(result)
}

impl Catalog {
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let canonical = root.as_ref().canonicalize().map_err(|e| e.to_string())?;
        // Windows canonicalize adds a verbatim prefix that Python Path.resolve did not
        // expose in the catalog's public CLI output.
        let root = if cfg!(windows) {
            let display = canonical.to_string_lossy();
            PathBuf::from(windows_path_without_verbatim_prefix(&display))
        } else {
            canonical
        };
        let catalog_dir = root.join("deploy-config/catalog");
        let services = read_json(&catalog_dir.join("services.json"))?;
        let input_manifest = read_json(&catalog_dir.join("secrets.json"))?;
        let artifacts = read_json(&catalog_dir.join("artifacts.json"))?;
        let result = Self {
            root: root.clone(),
            services: object(
                field(&services, "services").unwrap_or(&Value::Null),
                "services",
            )?
            .clone(),
            groups: object(field(&services, "groups").unwrap_or(&Value::Null), "groups")?.clone(),
            input_specs: object(
                field(&input_manifest, "secrets").unwrap_or(&Value::Null),
                "secrets",
            )?
            .clone(),
            artifacts: object(
                field(&artifacts, "artifacts").unwrap_or(&Value::Null),
                "artifacts",
            )?
            .clone(),
            stacks: read_named(&root.join("deploy-config/stacks"))?,
            bundles: read_named(&root.join("deploy-config/bundles"))?,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();
        for (group, ids) in &self.groups {
            validate_string_list(
                &mut errors,
                &format!("service group {} members", pyrepr(group)),
                Some(ids),
            );
            for id in strings(Some(ids)) {
                if !self.services.contains_key(&id) {
                    errors.push(format!(
                        "service group {} references unknown service {}",
                        pyrepr(group),
                        pyrepr(&id)
                    ));
                }
            }
        }
        for (id, service) in &self.services {
            if !service.is_object() {
                errors.push(format!(
                    "service {} descriptor must be an object",
                    pyrepr(id)
                ));
                continue;
            }
            if let Some(group) = field(service, "group").filter(|group| python_truthy(group)) {
                if let Some(group) = string(group) {
                    if !self.groups.contains_key(group) {
                        errors.push(format!(
                            "service {} references unknown group {}",
                            pyrepr(id),
                            pyrepr(group)
                        ));
                    }
                } else {
                    errors.push(format!("service {} group must be a string", pyrepr(id)));
                }
            }
        }
        for (id, descriptor) in &self.input_specs {
            if !descriptor.is_object() {
                errors.push(format!(
                    "secret {} descriptor must be an object",
                    pyrepr(id)
                ));
                continue;
            }
            validate_string_list(
                &mut errors,
                &format!("secret {} required_for", pyrepr(id)),
                field(descriptor, "required_for"),
            );
            for stack in strings(field(descriptor, "required_for")) {
                if !self.stacks.contains_key(&stack) {
                    errors.push(format!(
                        "secret {} references unknown required_for stack {}",
                        pyrepr(id),
                        pyrepr(&stack)
                    ));
                }
            }
        }
        for (name, artifact) in &self.artifacts {
            if !artifact.is_object() {
                errors.push(format!(
                    "artifact profile {} descriptor must be an object",
                    pyrepr(name)
                ));
            }
        }
        for (name, stack) in &self.stacks {
            if !stack.is_object() {
                errors.push(format!(
                    "stack {} descriptor must be an object",
                    pyrepr(name)
                ));
                continue;
            }
            for key in [
                "compose_files",
                "compose_profiles",
                "deployment_targets",
                "domains",
                "required_service_groups",
                "required_services",
                "optional_services",
                "required_secrets",
            ] {
                validate_string_list(
                    &mut errors,
                    &format!("stack {} {key}", pyrepr(name)),
                    field(stack, key),
                );
            }
            if let Some(operations) = field(stack, "operations") {
                if let Some(operations) = operations.as_object() {
                    for (operation, args) in operations {
                        validate_string_list(
                            &mut errors,
                            &format!("stack {} operation {}", pyrepr(name), pyrepr(operation)),
                            Some(args),
                        );
                    }
                } else {
                    errors.push(format!(
                        "stack {} operations must be an object",
                        pyrepr(name)
                    ));
                }
            }
            for compose in strings(field(stack, "compose_files")) {
                if !self.root.join(&compose).exists() {
                    errors.push(format!(
                        "stack {} references missing compose file {}",
                        pyrepr(name),
                        pyrepr(&compose)
                    ));
                }
            }
            for (key, known, label) in [
                ("required_service_groups", &self.groups, "service group"),
                ("required_services", &self.services, "service"),
                ("optional_services", &self.services, "optional service"),
                ("required_secrets", &self.input_specs, "secret"),
            ] {
                for id in strings(field(stack, key)) {
                    if !known.contains_key(&id) {
                        errors.push(format!(
                            "stack {} references unknown {} {}",
                            pyrepr(name),
                            label,
                            pyrepr(&id)
                        ));
                    }
                }
            }
            let artifact = field(stack, "artifact_profile")
                .and_then(string)
                .unwrap_or_default();
            if !self.artifacts.contains_key(artifact) {
                errors.push(format!(
                    "stack {} references unknown artifact profile {}",
                    pyrepr(name),
                    pyrepr(artifact)
                ));
            }
            if let Some(parent) = field(stack, "parent_stack").and_then(string) {
                if !parent.is_empty() && !self.stacks.contains_key(parent) {
                    errors.push(format!(
                        "stack {} references unknown parent stack {}",
                        pyrepr(name),
                        pyrepr(parent)
                    ));
                }
            }
        }
        for (name, bundle) in &self.bundles {
            if !bundle.is_object() {
                errors.push(format!(
                    "bundle {} descriptor must be an object",
                    pyrepr(name)
                ));
                continue;
            }
            validate_string_list(
                &mut errors,
                &format!("bundle {} assets", pyrepr(name)),
                field(bundle, "assets"),
            );
            let stack = field(bundle, "stack").and_then(string).unwrap_or_default();
            if !self.stacks.contains_key(stack) {
                errors.push(format!(
                    "bundle {} references unknown stack {}",
                    pyrepr(name),
                    pyrepr(stack)
                ));
            }
            let artifact = field(bundle, "artifact_profile")
                .and_then(string)
                .unwrap_or_default();
            if !self.artifacts.contains_key(artifact) {
                errors.push(format!(
                    "bundle {} references unknown artifact profile {}",
                    pyrepr(name),
                    pyrepr(artifact)
                ));
            }
            for asset in strings(field(bundle, "assets")) {
                if !self.root.join(&asset).exists() {
                    errors.push(format!(
                        "bundle {} references missing asset {}",
                        pyrepr(name),
                        pyrepr(&asset)
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Deployment catalog validation failed:\n{}",
                errors
                    .iter()
                    .map(|e| format!("- {e}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
    }

    pub fn stack(&self, name: &str) -> Result<&Value> {
        self.stacks
            .get(name)
            .ok_or_else(|| format!("Unknown stack: {name}"))
    }

    pub fn bundle(&self, name: &str) -> Result<&Value> {
        self.bundles
            .get(name)
            .ok_or_else(|| format!("Unknown bundle: {name}"))
    }

    pub fn group_services(&self, group: &str) -> Result<Vec<String>> {
        self.groups
            .get(group)
            .map(|v| strings(Some(v)))
            .ok_or_else(|| format!("Unknown service group: {group}"))
    }

    pub fn expanded_services(
        &self,
        stack_name: &str,
        include_optional: bool,
    ) -> Result<Vec<String>> {
        let stack = self.stack(stack_name)?;
        let mut ids = Vec::new();
        for group in strings(field(stack, "required_service_groups")) {
            if let Some(members) = self.groups.get(&group) {
                ids.extend(strings(Some(members)));
            }
        }
        ids.extend(strings(field(stack, "required_services")));
        let optional = strings(field(stack, "optional_services"));
        Ok(dedupe(
            ids.into_iter()
                .filter(|id| include_optional || !optional.contains(id)),
        ))
    }

    pub fn running_services(
        &self,
        stack_name: &str,
        include_optional: bool,
    ) -> Result<Vec<String>> {
        Ok(self
            .expanded_services(stack_name, include_optional)?
            .into_iter()
            .filter(|id| {
                self.services
                    .get(id)
                    .and_then(|s| field(s, "lifecycle"))
                    .is_none_or(|lifecycle| lifecycle.as_str() == Some("running"))
            })
            .collect())
    }

    pub fn service_field(&self, id: &str, name: &str) -> Result<String> {
        let service = self
            .services
            .get(id)
            .ok_or_else(|| format!("Unknown service: {id}"))?;
        if name == "id" {
            return Ok(id.to_owned());
        }
        Ok(field(service, name).map(text).unwrap_or_default())
    }

    pub fn required_input_ids(&self, stack_name: &str) -> Result<Vec<String>> {
        let stack = self.stack(stack_name)?;
        let mut ids = strings(field(stack, "required_secrets"));
        for (id, descriptor) in &self.input_specs {
            if strings(field(descriptor, "required_for")).contains(&stack_name.to_owned()) {
                ids.push(id.clone());
            }
        }
        Ok(dedupe(ids))
    }

    pub fn public_input_field(&self, id: &str, name: &str) -> Result<String> {
        if name == "id" {
            return Ok(id.to_owned());
        }
        // This catalog contains names and policy metadata, never secret contents.
        // Keep the public CLI's metadata fields explicit so a future JSON field
        // containing a value cannot be selected for stdout.
        let name = match name {
            "env" => "env",
            "file_env" => "file_env",
            "compose_secret" => "compose_secret",
            "no_log" => "no_log",
            "allow_empty" => "allow_empty",
            "required_for" => "required_for",
            _ => return Err(format!("Unsupported secret metadata field: {name}")),
        };
        let descriptor = self
            .input_specs
            .get(id)
            .ok_or_else(|| format!("Unknown secret: {id}"))?;
        match field(descriptor, name) {
            Some(Value::Array(values)) => Ok(values.iter().map(text).collect::<Vec<_>>().join(",")),
            Some(value) => Ok(text(value)),
            None => Ok(String::new()),
        }
    }

    pub fn compose_command(&self, stack_name: &str, operation: &str) -> Result<Vec<String>> {
        let stack = self.stack(stack_name)?;
        let operations = field(stack, "operations")
            .and_then(Value::as_object)
            .ok_or_else(|| "Missing operations".to_owned())?;
        let operation_args = operations.get(operation).ok_or_else(|| {
            let mut names = operations.keys().cloned().collect::<Vec<_>>();
            names.sort();
            format!(
                "Stack {} does not define operation {}; available: {}",
                pyrepr(stack_name),
                pyrepr(operation),
                if names.is_empty() {
                    "<none>".to_owned()
                } else {
                    names.join(", ")
                }
            )
        })?;
        let mut command = vec![
            "docker".to_owned(),
            "compose".to_owned(),
            "--env-file".to_owned(),
            field(stack, "env_file").map(text).unwrap_or_default(),
        ];
        for compose in strings(field(stack, "compose_files")) {
            command.extend(["-f".to_owned(), compose]);
        }
        for profile in strings(field(stack, "compose_profiles")) {
            command.extend(["--profile".to_owned(), profile]);
        }
        command.extend(strings(Some(operation_args)));
        Ok(command)
    }

    pub fn plan(&self, stack_name: &str) -> Result<Value> {
        let stack = self.stack(stack_name)?;
        let mut plan = Map::new();
        for (name, value) in [
            (
                "artifact_profile",
                field(stack, "artifact_profile")
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "compose_files",
                Value::from(strings(field(stack, "compose_files"))),
            ),
            (
                "compose_profiles",
                Value::from(strings(field(stack, "compose_profiles"))),
            ),
            (
                "deployment_targets",
                Value::from(strings(field(stack, "deployment_targets"))),
            ),
            (
                "description",
                field(stack, "description")
                    .cloned()
                    .unwrap_or(Value::from("")),
            ),
            ("domains", Value::from(strings(field(stack, "domains")))),
            (
                "env_file",
                field(stack, "env_file").cloned().unwrap_or(Value::Null),
            ),
            ("name", Value::from(stack_name)),
            (
                "required_secret_names",
                Value::from(self.required_input_ids(stack_name)?),
            ),
            (
                "required_services",
                Value::from(self.expanded_services(stack_name, false)?),
            ),
            (
                "running_services",
                Value::from(self.running_services(stack_name, false)?),
            ),
        ] {
            plan.insert(name.to_owned(), value);
        }
        Ok(Value::Object(plan))
    }

    pub fn bundle_assets(&self, name: &str) -> Result<Vec<PathBuf>> {
        Ok(strings(field(self.bundle(name)?, "assets"))
            .into_iter()
            .map(|p| {
                if cfg!(windows) {
                    self.root.join(p.replace('/', "\\"))
                } else {
                    self.root.join(p)
                }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{read_named, windows_path_without_verbatim_prefix};
    use std::fs;

    #[test]
    fn named_documents_reject_truthy_non_string_names_and_fallback_for_falsy_names() {
        let dir = std::env::temp_dir().join(format!(
            "marty-deployment-catalog-names-{}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let document = dir.join("example.json");
        fs::write(&document, r#"{"name":["selfhost"]}"#).unwrap();
        assert!(read_named(&dir).unwrap_err().contains("has no valid name"));
        fs::write(&document, r#"{"name":1}"#).unwrap();
        assert!(read_named(&dir).unwrap_err().contains("has no valid name"));
        fs::write(&document, r#"{"name":[]}"#).unwrap();
        assert!(read_named(&dir).unwrap().contains_key("example"));
        fs::write(&document, r#"{"name":0}"#).unwrap();
        assert!(read_named(&dir).unwrap().contains_key("example"));
        fs::write(&document, r#"{"name":"explicit"}"#).unwrap();
        assert!(read_named(&dir).unwrap().contains_key("explicit"));
        fs::remove_file(document).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn windows_verbatim_unc_path_remains_absolute() {
        assert_eq!(
            windows_path_without_verbatim_prefix(r"\\?\UNC\server\share\repo"),
            r"\\server\share\repo"
        );
        assert_eq!(
            windows_path_without_verbatim_prefix(r"\\?\C:\repo"),
            r"C:\repo"
        );
    }
}

pub mod activation_preflight;
pub mod approle;
pub mod ca_issuer;
pub mod generation;
pub mod keycloak;
pub mod keycloak_provision;
pub mod leaf_tokens;
pub mod operator;
pub mod operator_certificates;
mod operator_files;
mod operator_http;
pub mod snapshot;
