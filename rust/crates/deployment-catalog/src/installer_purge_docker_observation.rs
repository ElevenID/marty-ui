//! Read-only Docker census. Names and labels can force refusal, never adoption.
//! The caller must separately authenticate creation and cleanup records and
//! preserve custody and stopped-writer requirements. This authorizes no deletion.
use crate::installer_compose_volume_creation::VolumeIdentity;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationError {
    Incomplete,
    IdentityChanged,
    ResourcesRemain,
}
pub(crate) trait DockerRead {
    fn engine_id(&self) -> Result<String, ()>;
    fn run(&self, args: &[&str]) -> Result<String, ()>;
}
pub(crate) struct Scope {
    pub installation_id: String,
    pub engine_id: String,
    pub project: String,
    pub container_ids: BTreeSet<String>,
    pub network_ids: BTreeSet<String>,
    pub retained_volume_names: BTreeSet<String>,
    pub volumes: BTreeMap<String, VolumeIdentity>,
}
fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn lines(output: &str, names: bool) -> Option<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for item in output.lines() {
        let valid = if names {
            !item.is_empty()
                && item.len() <= 255
                && item
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        } else {
            hex64(item)
        };
        if !valid || !result.insert(item.to_owned()) {
            return None;
        }
    }
    Some(result)
}
fn single(output: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(output).ok()?;
    let list = value.as_array()?;
    (list.len() == 1 && list[0].is_object()).then(|| list[0].clone())
}
pub(crate) fn observe<D: DockerRead>(docker: &D, plan: &Scope) -> Result<(), ObservationError> {
    use ObservationError::*;
    // The production owner derives this namespace from its UUID. Refuse any
    // caller context that could change the meaning of Docker name filters.
    let id = uuid::Uuid::parse_str(&plan.installation_id).map_err(|_| Incomplete)?;
    if id.is_nil() || plan.project != format!("marty-install-{}", id.simple()) {
        return Err(Incomplete);
    }
    if docker.engine_id().map_err(|_| Incomplete)? != plan.engine_id {
        return Err(IdentityChanged);
    }
    let run = |args: &[&str]| docker.run(args).map_err(|_| Incomplete);
    let all_containers = lines(&run(&["ps", "-aq", "--no-trunc"])?, false).ok_or(Incomplete)?;
    let project_filter = format!("label=com.docker.compose.project={}", plan.project);
    let install_filter = format!("label=com.elevenid.installer.id={}", plan.installation_id);
    let namespace_filter = format!("name={}", plan.project);
    for filter in [&project_filter, &install_filter, &namespace_filter] {
        if !lines(
            &run(&["ps", "-aq", "--no-trunc", "--filter", filter])?,
            false,
        )
        .ok_or(Incomplete)?
        .is_empty()
        {
            return Err(ResourcesRemain);
        }
    }
    if plan
        .container_ids
        .iter()
        .any(|id| all_containers.contains(id))
    {
        return Err(ResourcesRemain);
    }
    let all_networks =
        lines(&run(&["network", "ls", "-q", "--no-trunc"])?, false).ok_or(Incomplete)?;
    if plan.network_ids.iter().any(|id| all_networks.contains(id)) {
        return Err(ResourcesRemain);
    }
    for filter in [&project_filter, &install_filter, &namespace_filter] {
        if !lines(
            &run(&["network", "ls", "-q", "--no-trunc", "--filter", filter])?,
            false,
        )
        .ok_or(Incomplete)?
        .is_empty()
        {
            return Err(ResourcesRemain);
        }
    }
    let expected: BTreeSet<_> = plan.volumes.keys().cloned().collect();
    let listed = lines(&run(&["volume", "ls", "-q"])?, true).ok_or(Incomplete)?;
    let scoped: BTreeSet<_> = listed
        .iter()
        .filter(|name| {
            name.starts_with(&format!("{}_", plan.project))
                || name.starts_with(&format!("{}-", plan.project))
        })
        .cloned()
        .collect();
    let labelled = lines(
        &run(&["volume", "ls", "-q", "--filter", &project_filter])?,
        true,
    )
    .ok_or(Incomplete)?;
    let installation_labelled = lines(
        &run(&["volume", "ls", "-q", "--filter", &install_filter])?,
        true,
    )
    .ok_or(Incomplete)?;
    if !installation_labelled.is_subset(&expected)
        || scoped != expected
        || labelled != expected
        || !expected.is_subset(&listed)
        || expected != plan.retained_volume_names
    {
        return Err(ResourcesRemain);
    }
    for (name, identity) in &plan.volumes {
        let attached = lines(
            &run(&[
                "ps",
                "-a",
                "-q",
                "--no-trunc",
                "--filter",
                &format!("volume={name}"),
            ])?,
            false,
        )
        .ok_or(Incomplete)?;
        if !attached.is_empty() {
            return Err(ResourcesRemain);
        }
        let observed = single(&run(&["volume", "inspect", name])?).ok_or(Incomplete)?;
        let labels: BTreeMap<String, String> =
            serde_json::from_value(observed["Labels"].clone()).map_err(|_| Incomplete)?;
        if observed["Name"] != *name
            || observed["CreatedAt"] != identity.created_at
            || observed["Driver"] != identity.driver
            || observed["Scope"] != identity.scope
            || !(observed["Options"].is_null() || observed["Options"] == serde_json::json!({}))
            || labels != identity.labels
        {
            return Err(IdentityChanged);
        }
    }
    // A context/socket can change while the read-only census is in flight.
    // An initial engine match cannot qualify observations from its replacement.
    if docker.engine_id().map_err(|_| Incomplete)? != plan.engine_id {
        return Err(IdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Mock {
        engine: String,
        outputs: BTreeMap<Vec<String>, String>,
    }
    impl Mock {
        fn put(&mut self, args: &[&str], output: String) {
            self.outputs
                .insert(args.iter().map(|s| (*s).into()).collect(), output);
        }
    }
    impl DockerRead for Mock {
        fn engine_id(&self) -> Result<String, ()> {
            Ok(self.engine.clone())
        }
        fn run(&self, args: &[&str]) -> Result<String, ()> {
            self.outputs
                .get(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>())
                .cloned()
                .ok_or(())
        }
    }
    fn fixture(with_volumes: bool) -> (Scope, Mock) {
        let id = "12345678-1234-4234-8234-123456789abc";
        let project = "marty-install-12345678123442348234123456789abc";
        let mut scope = Scope {
            installation_id: id.into(),
            engine_id: "synthetic-engine".into(),
            project: project.into(),
            container_ids: BTreeSet::from(["a".repeat(64)]),
            network_ids: BTreeSet::from(["b".repeat(64)]),
            retained_volume_names: BTreeSet::new(),
            volumes: BTreeMap::new(),
        };
        let mut mock = Mock {
            engine: scope.engine_id.clone(),
            outputs: BTreeMap::new(),
        };
        // Unrelated workloads are permitted and never selected for mutation.
        mock.put(&["ps", "-aq", "--no-trunc"], "c".repeat(64));
        mock.put(&["network", "ls", "-q", "--no-trunc"], "d".repeat(64));
        for filter in [
            format!("label=com.docker.compose.project={project}"),
            format!("label=com.elevenid.installer.id={id}"),
            format!("name={project}"),
        ] {
            mock.put(
                &["ps", "-aq", "--no-trunc", "--filter", &filter],
                String::new(),
            );
            mock.put(
                &["network", "ls", "-q", "--no-trunc", "--filter", &filter],
                String::new(),
            );
        }
        if with_volumes {
            // Multiple volume names; no fixed redis-only or count assumption.
            for key in ["data", "socket"] {
                let name = format!("{project}_{key}");
                let identity = VolumeIdentity {
                    name: name.clone(),
                    driver: "local".into(),
                    scope: "local".into(),
                    created_at: "2026-11-15T12:00:00Z".into(),
                    labels: BTreeMap::from([
                        ("com.docker.compose.project".into(), project.into()),
                        ("com.docker.compose.volume".into(), key.into()),
                    ]),
                };
                mock.put(
                    &["volume", "inspect", &name],
                    json!([{"Name":name,
                    "Driver":identity.driver,"Scope":identity.scope,"CreatedAt":identity.created_at,
                    "Labels":identity.labels,"Options":null}])
                    .to_string(),
                );
                mock.put(
                    &[
                        "ps",
                        "-a",
                        "-q",
                        "--no-trunc",
                        "--filter",
                        &format!("volume={name}"),
                    ],
                    String::new(),
                );
                scope.retained_volume_names.insert(name.clone());
                scope.volumes.insert(name, identity);
            }
        }
        let names = scope.volumes.keys().cloned().collect::<Vec<_>>().join("\n");
        mock.put(
            &["volume", "ls", "-q"],
            format!("unrelated-workload-data\n{names}")
                .trim_end()
                .into(),
        );
        mock.put(
            &[
                "volume",
                "ls",
                "-q",
                "--filter",
                &format!("label=com.docker.compose.project={project}"),
            ],
            names,
        );
        // Compose volumes need not have an installer label. If present it is
        // only a suspicious-resource filter, never creation evidence.
        mock.put(
            &[
                "volume",
                "ls",
                "-q",
                "--filter",
                &format!("label=com.elevenid.installer.id={id}"),
            ],
            String::new(),
        );
        (scope, mock)
    }
    #[test]
    fn empty_and_multiple_retained_volume_censuses_allow_unrelated_workloads() {
        for with_volumes in [false, true] {
            let (scope, mock) = fixture(with_volumes);
            assert_eq!(observe(&mock, &scope), Ok(()));
        }
    }
    #[test]
    fn foreign_named_installation_labelled_network_or_volume_blocks_candidate() {
        for kind in ["network", "volume"] {
            let (scope, mut mock) = fixture(true);
            let filter = format!("label=com.elevenid.installer.id={}", scope.installation_id);
            if kind == "network" {
                mock.put(
                    &["network", "ls", "-q", "--no-trunc", "--filter", &filter],
                    "e".repeat(64),
                );
            } else {
                mock.put(
                    &["volume", "ls", "-q", "--filter", &filter],
                    "foreign-named-volume".into(),
                );
            }
            assert_eq!(
                observe(&mock, &scope),
                Err(ObservationError::ResourcesRemain)
            );
        }
    }
    #[test]
    fn recorded_unlabelled_ids_and_namespace_collisions_block_candidate() {
        for kind in [
            "container-id",
            "network-id",
            "container-name",
            "network-name",
        ] {
            let (scope, mut mock) = fixture(false);
            let filter = format!("name={}", scope.project);
            match kind {
                "container-id" => mock.put(&["ps", "-aq", "--no-trunc"], "a".repeat(64)),
                "network-id" => mock.put(&["network", "ls", "-q", "--no-trunc"], "b".repeat(64)),
                "container-name" => mock.put(
                    &["ps", "-aq", "--no-trunc", "--filter", &filter],
                    "e".repeat(64),
                ),
                _ => mock.put(
                    &["network", "ls", "-q", "--no-trunc", "--filter", &filter],
                    "e".repeat(64),
                ),
            }
            assert_eq!(
                observe(&mock, &scope),
                Err(ObservationError::ResourcesRemain)
            );
        }
    }
    #[test]
    fn missing_or_extra_volume_is_never_treated_as_empty_or_adopted() {
        for extra in [false, true] {
            let (scope, mut mock) = fixture(true);
            let output = if extra {
                format!(
                    "{}\n{}_unknown",
                    scope.volumes.keys().cloned().collect::<Vec<_>>().join("\n"),
                    scope.project
                )
            } else {
                String::new()
            };
            mock.put(&["volume", "ls", "-q"], output);
            assert_eq!(
                observe(&mock, &scope),
                Err(ObservationError::ResourcesRemain)
            );
        }
    }
    #[test]
    fn attachments_changed_metadata_and_engine_replacement_are_refused() {
        for field in [
            "attachment",
            "Name",
            "CreatedAt",
            "Driver",
            "Scope",
            "Options",
            "Labels",
            "engine",
        ] {
            let (scope, mut mock) = fixture(true);
            let name = scope.volumes.keys().next().unwrap();
            if field == "attachment" {
                mock.put(
                    &[
                        "ps",
                        "-a",
                        "-q",
                        "--no-trunc",
                        "--filter",
                        &format!("volume={name}"),
                    ],
                    "e".repeat(64),
                );
            } else if field == "engine" {
                mock.engine = "replacement".into();
            } else {
                let args: Vec<String> = ["volume", "inspect", name]
                    .iter()
                    .map(|s| (*s).into())
                    .collect();
                let mut value: serde_json::Value =
                    serde_json::from_str(&mock.outputs[&args]).unwrap();
                value[0][field] = if field == "Labels" {
                    json!({"foreign":"label"})
                } else {
                    json!("changed")
                };
                mock.outputs.insert(args, value.to_string());
            }
            assert!(observe(&mock, &scope).is_err(), "{field}");
        }
    }
    #[test]
    fn unavailable_or_malformed_census_and_unsafe_namespace_are_incomplete() {
        let (scope, mut mock) = fixture(false);
        mock.outputs
            .remove(&vec!["ps".into(), "-aq".into(), "--no-trunc".into()]);
        assert_eq!(observe(&mock, &scope), Err(ObservationError::Incomplete));
        let (mut scope, mut mock) = fixture(false);
        mock.put(&["network", "ls", "-q", "--no-trunc"], "short-id".into());
        assert_eq!(observe(&mock, &scope), Err(ObservationError::Incomplete));
        scope.project = ".*".into();
        assert_eq!(observe(&mock, &scope), Err(ObservationError::Incomplete));
    }

    #[test]
    fn engine_identity_is_repeated_after_the_entire_resource_census() {
        struct ReplacedEngine {
            inner: Mock,
            reads: std::cell::Cell<usize>,
        }
        impl DockerRead for ReplacedEngine {
            fn engine_id(&self) -> Result<String, ()> {
                let reads = self.reads.get();
                self.reads.set(reads + 1);
                if reads == 0 {
                    self.inner.engine_id()
                } else {
                    Ok("replacement-engine".into())
                }
            }
            fn run(&self, args: &[&str]) -> Result<String, ()> {
                self.inner.run(args)
            }
        }
        let (scope, inner) = fixture(true);
        let replaced = ReplacedEngine {
            inner,
            reads: std::cell::Cell::new(0),
        };
        assert_eq!(
            observe(&replaced, &scope),
            Err(ObservationError::IdentityChanged)
        );
        assert_eq!(replaced.reads.get(), 2);
    }
}
