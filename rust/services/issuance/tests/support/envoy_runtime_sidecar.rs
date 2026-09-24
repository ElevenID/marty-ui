//! Exact-image Envoy sidecar in the already-owned unpublished PG namespace.
//! No extraction/relinking of Envoy, Docker socket, host ports or operator files.
use super::{
    base_runtime_container::{digest, regular_file},
    canvas_published_database::{docker, inspect, inspect_with_timeout, PublishedDatabase},
};
use marty_release_evidence::envoy_config::{encode, parse, render, NATIVE_CLUSTER};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use uuid::Uuid;

const LABEL: &str = "com.elevenid.test.envoy-native";
const BINARY: &str = "/usr/local/bin/envoy";
const CONFIG: &str = "/etc/envoy/envoy.yaml";
const DESCRIPTOR: &str = "/etc/envoy/proto_descriptor.pb";

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn exact_id(id: &str) -> Result<(), String> {
    require(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "Envoy ownership requires exact container ID",
    )
}

fn absent(path: &Path) -> bool {
    path.symlink_metadata()
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn remove_owned_files(
    directory: &Path,
    hashes: &mut BTreeMap<PathBuf, String>,
) -> Result<(), String> {
    if hashes.is_empty() && absent(directory) {
        return Ok(());
    }
    for (path, expected) in hashes.iter() {
        require(
            path.parent() == Some(directory),
            "Envoy cleanup target escaped owned directory",
        )?;
        regular_file(path)?;
        require(
            digest(path)? == *expected,
            "Owned Envoy artifact changed during runtime",
        )?;
    }
    for path in hashes.keys().cloned().collect::<Vec<_>>() {
        std::fs::remove_file(&path).map_err(|_| "Owned Envoy file cleanup failed")?;
        require(absent(&path), "Owned Envoy file remained after removal")?;
        hashes.remove(&path);
    }
    // No recursive removal: unexpected contents remain recoverable and fail the gate.
    std::fs::remove_dir(directory).map_err(|_| "Owned Envoy directory cleanup failed")?;
    require(
        absent(directory),
        "Owned Envoy directory remained after removal",
    )
}

fn cleanup_candidates(known: Option<&str>, ids: &[&str]) -> Result<bool, String> {
    require(
        ids.len() <= 1 && known.is_none_or(|id| ids.is_empty() || ids == [id]),
        "Envoy cleanup identity missing or ambiguous",
    )?;
    Ok(ids.is_empty() && known.is_some())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    Candidate,
    Baseline,
}

fn is_fixture_peer(cluster: &Value) -> bool {
    matches!(
        cluster["name"].as_str(),
        Some(NATIVE_CLUSTER | "auth_grpc" | "issuance_grpc")
    )
}

fn legacy_reference(native: &Value) -> Result<Value, String> {
    let mut legacy = native.clone();
    let clusters = legacy["static_resources"]["clusters"]
        .as_array_mut()
        .ok_or("Envoy clusters missing from legacy reference")?;
    let matches: Vec<_> = clusters
        .iter_mut()
        .filter(|cluster| cluster["name"] == NATIVE_CLUSTER)
        .collect();
    require(
        matches.len() == 1,
        "Envoy native cluster is ambiguous in legacy reference",
    )?;
    let cluster = matches.into_iter().next().unwrap();
    cluster["name"] = json!("issuance_grpc");
    cluster["load_assignment"]["cluster_name"] = json!("issuance_grpc");
    cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
        ["socket_address"]["address"] = json!("issuance");

    let routes = legacy["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]
        ["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
        .as_array_mut()
        .ok_or("Envoy routes missing from legacy reference")?;
    for prefix in ["/marty.ui.issuance.v1.IssuanceService/", "/v1/issuance/"] {
        let matches: Vec<_> = routes
            .iter_mut()
            .filter(|route| route["match"]["prefix"] == prefix)
            .collect();
        require(
            matches.len() == 1,
            "Envoy issuance route is ambiguous in legacy reference",
        )?;
        matches.into_iter().next().unwrap()["route"]["cluster"] = json!("issuance_grpc");
    }
    Ok(legacy)
}

fn fixture_projection(candidate: &Value, selection: Selection) -> Value {
    let mut fixture = candidate.clone();
    for cluster in fixture["static_resources"]["clusters"]
        .as_array_mut()
        .unwrap()
    {
        if is_fixture_peer(cluster) {
            let native = cluster["name"] == NATIVE_CLUSTER;
            let auth = cluster["name"] == "auth_grpc";
            let address = &mut cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]
                ["endpoint"]["address"]["socket_address"];
            *address = json!({"address":"127.0.0.1","port_value":if native{9005}else if auth{19001}else{19005}});
            // Envoy can start before the in-process fixture peers. Its default
            // no-traffic retry cadence is longer than this bounded integration
            // test, so normalize only the projected fixture configuration.
            cluster["health_checks"][0]["no_traffic_interval"] = json!("1s");
        }
    }
    if selection == Selection::Baseline {
        fixture["static_resources"]["listeners"][0]["address"]["socket_address"]["port_value"] =
            json!(19000);
        fixture["admin"]["address"]["socket_address"]["port_value"] = json!(19901);
    }
    fixture
}

pub(super) struct OwnedEnvoy {
    scope: String,
    image: String,
    database: String,
    network: String,
    directory: PathBuf,
    hashes: BTreeMap<PathBuf, String>,
    id: Option<String>,
    creation_attempted: bool,
    validate: bool,
    selection: Selection,
}

impl OwnedEnvoy {
    fn command(&self) -> Vec<&'static str> {
        let mut command = vec![
            "-c",
            CONFIG,
            "--concurrency",
            "1",
            "--log-level",
            "error",
            "--disable-hot-restart",
        ];
        if self.validate {
            command.extend(["--mode", "validate"]);
        }
        command
    }

    fn checked(&self, info: &Value, id: &str) -> Result<(), String> {
        exact_id(id)?;
        require(
            info["Id"] == id
                && info["Image"] == self.image
                && info["Config"]["Image"] == self.image
                && info["Config"]["Labels"][LABEL] == self.scope
                && info["Config"]["Entrypoint"] == json!([BINARY])
                && info["Config"]["Cmd"] == json!(self.command())
                && info["HostConfig"]["NetworkMode"] == self.network
                && info["HostConfig"]["ReadonlyRootfs"] == true
                && info["HostConfig"]["CapDrop"] == json!(["ALL"])
                && info["HostConfig"]["SecurityOpt"] == json!(["no-new-privileges"])
                && info["HostConfig"]["PortBindings"]
                    .as_object()
                    .is_some_and(|v| v.is_empty())
                && info["NetworkSettings"]["Ports"]
                    .as_object()
                    .is_some_and(|v| v.is_empty()),
            "Refusing Envoy access/cleanup: ownership or isolation mismatch",
        )?;
        let mounts = info["Mounts"].as_array().ok_or("Envoy mounts missing")?;
        require(mounts.len() == 3, "Envoy mount inventory differs")?;
        for (file, target) in [
            ("candidate.yaml", CONFIG),
            ("descriptor.pb", DESCRIPTOR),
            ("canonical.yaml", "/etc/envoy/canonical-source.yaml"),
        ] {
            let matches: Vec<_> = mounts
                .iter()
                .filter(|m| m["Destination"] == target)
                .collect();
            require(
                matches.len() == 1
                    && matches[0]["Type"] == "bind"
                    && matches[0]["RW"] == false
                    && matches[0]["Source"] == self.directory.join(file).to_str().unwrap(),
                "Envoy mount identity differs",
            )?;
        }
        Ok(())
    }

    pub(super) async fn start(owned: &PublishedDatabase) -> Result<Self, String> {
        Self::start_selected(owned, Selection::Candidate).await
    }

    pub(super) async fn start_baseline(owned: &PublishedDatabase) -> Result<Self, String> {
        Self::start_selected(owned, Selection::Baseline).await
    }

    async fn start_selected(
        owned: &PublishedDatabase,
        selection: Selection,
    ) -> Result<Self, String> {
        // The daemon image/namespace is Linux. Configuration validation does
        // not require the host's Rust executable to be Linux; full native-main
        // composition retains its separate mandatory Linux-host assertion.
        let database = owned.borrow_descriptor()?;
        let descriptor: Value =
            serde_json::from_str(&database).map_err(|_| "Invalid owned database descriptor")?;
        let postgres = descriptor["postgres_id"]
            .as_str()
            .ok_or("Missing exact owned database ID")?;
        exact_id(postgres)?;
        let selected = std::env::var("MARTY_ENVOY_TEST_IMAGE")
            .map_err(|_| "Exact built Envoy test image ID is required")?;
        exact_id(
            selected
                .strip_prefix("sha256:")
                .ok_or("Envoy image must be an immutable local ID")?,
        )?;
        let images: Value = serde_json::from_str(&docker(&["image", "inspect", &selected])?)
            .map_err(|_| "Invalid Envoy image inspection")?;
        require(
            images.as_array().is_some_and(|v| v.len() == 1)
                && images[0]["Id"] == selected
                && images[0]["Os"] == "linux",
            "Exact Linux Envoy image is unavailable",
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let source = regular_file(&root.join("config/envoy/envoy.yaml"))?;
        let proto = regular_file(&root.join("config/envoy/proto_descriptor.pb"))?;
        let source_before = digest(&source)?;
        let proto_before = digest(&proto)?;
        let base = std::fs::read(&source).map_err(|_| "Cannot read canonical Envoy config")?;
        let descriptor_bytes =
            std::fs::read(&proto).map_err(|_| "Cannot read canonical Envoy descriptor")?;
        let candidate = render(&base, &descriptor_bytes)?;
        let selected_model = match selection {
            Selection::Candidate => candidate,
            Selection::Baseline => legacy_reference(&candidate)?,
        };
        let fixture = encode(&fixture_projection(&selected_model, selection))?;
        // Match the existing wallet fixture's boundary: canonicalize to verify
        // ownership, not for Docker arguments (Windows extended paths are not
        // portable Docker bind source syntax).
        let parent = std::env::temp_dir();
        require(parent.is_absolute(), "Fixture temp root must be absolute")?;
        let resolved_parent = parent
            .canonicalize()
            .map_err(|_| "Fixture temp root missing")?;
        let directory = parent.join(format!("marty-envoy-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)
            .map_err(|_| "Cannot create owned Envoy staging directory")?;
        require(
            directory
                .canonicalize()
                .map_err(|_| "Cannot verify owned Envoy staging directory")?
                .parent()
                == Some(resolved_parent.as_path()),
            "Owned Envoy staging escaped resolved temp root",
        )?;
        let mut owned = Self {
            scope: Uuid::new_v4().to_string(),
            image: selected,
            database,
            network: format!("container:{postgres}"),
            directory,
            hashes: BTreeMap::new(),
            id: None,
            creation_attempted: false,
            validate: true,
            selection,
        };
        for (file, bytes) in [
            ("canonical.yaml", base.as_slice()),
            ("descriptor.pb", descriptor_bytes.as_slice()),
            ("candidate.yaml", fixture.as_bytes()),
        ] {
            let path = owned.directory.join(file);
            std::fs::write(&path, bytes).map_err(|_| "Cannot stage owned Envoy file")?;
            owned.hashes.insert(path.clone(), digest(&path)?);
        }
        require(
            digest(&source)? == source_before && digest(&proto)? == proto_before,
            "Envoy source changed during staging",
        )?;
        owned.create()?;
        // Setup/create/start retain the shared fixture's bounded per-command
        // budget. Once started, the validation polling phase has this total
        // deadline; checked() below is pure and cannot hide more Docker calls.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let id = owned.id.as_deref().unwrap();
            require(
                Instant::now() < deadline,
                "Envoy configuration validation deadline exceeded",
            )?;
            let state =
                inspect_with_timeout(id, deadline.saturating_duration_since(Instant::now()))?;
            owned.checked(&state, id)?;
            if state["State"]["Running"] == false {
                if state["State"]["ExitCode"] != 0 {
                    // Only the validated fixture container can reach this path.
                    // Its inputs are public canonical config/descriptor, not
                    // operator configuration, secrets or application requests.
                    let output = super::bounded_fixture_command::run(
                        Command::new("docker").args(["logs", id]),
                        None,
                        deadline.saturating_duration_since(Instant::now()),
                        16 * 1024,
                    )
                    .map_err(|_| "Envoy validation diagnostics unavailable or exceeded bounds")?;
                    require(output.status.success(), "Envoy validation logs unavailable")?;
                    eprintln!(
                        "Owned public-config Envoy validation stdout: {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    eprintln!(
                        "Owned public-config Envoy validation stderr: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                require(
                    state["State"]["ExitCode"] == 0,
                    "Actual Envoy rejected the generated configuration/descriptor",
                )?;
                eprintln!("Envoy validation evidence: image={} container={} canonical_sha256={} descriptor_sha256={} candidate_sha256={}",
                    owned.image,id,source_before,proto_before,owned.hashes[&owned.directory.join("candidate.yaml")]);
                break;
            }
            require(
                Instant::now() < deadline,
                "Envoy configuration validation deadline exceeded",
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        owned.cleanup_container()?;
        owned.validate = false;
        owned.create()?;
        eprintln!(
            "Envoy actual-image/config gate started with owned container {}",
            owned.id.as_deref().unwrap()
        );
        Ok(owned)
    }

    fn create(&mut self) -> Result<(), String> {
        PublishedDatabase::borrowed_url(&self.database)?;
        for (path, expected) in &self.hashes {
            regular_file(path)?;
            require(
                digest(path)? == *expected,
                "Owned Envoy staging changed before creation",
            )?;
        }
        let label = format!("{LABEL}={}", self.scope);
        let mounts: Vec<_> = [
            ("candidate.yaml", CONFIG),
            ("descriptor.pb", DESCRIPTOR),
            ("canonical.yaml", "/etc/envoy/canonical-source.yaml"),
        ]
        .into_iter()
        .map(|(file, target)| {
            format!(
                "type=bind,source={},target={target},readonly",
                self.directory.join(file).display()
            )
        })
        .collect();
        let command = self.command();
        let mut args = vec![
            "create",
            "--pull=never",
            "--label",
            &label,
            "--network",
            &self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            BINARY,
        ];
        for mount in &mounts {
            args.extend(["--mount", mount]);
        }
        args.push(&self.image);
        args.extend(command);
        self.creation_attempted = true;
        let id = docker(&args)?;
        exact_id(&id)?;
        self.id = Some(id.clone());
        self.checked(&inspect(&id)?, &id)?;
        eprintln!(
            "Owned Envoy {:?} {} container: {}",
            self.selection,
            if self.validate {
                "validation"
            } else {
                "server"
            },
            id
        );
        docker(&["start", &id])?;
        Ok(())
    }

    fn cleanup_container(&mut self) -> Result<(), String> {
        if !self.creation_attempted {
            return Ok(());
        }
        PublishedDatabase::borrowed_url(&self.database)?;
        let filter = format!("label={LABEL}={}", self.scope);
        let found = docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter])?;
        let ids: Vec<_> = found.lines().collect();
        if cleanup_candidates(self.id.as_deref(), &ids)? {
            if let Some(id) = &self.id {
                let exact = format!("id={id}");
                require(
                    docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &exact])?
                        .is_empty(),
                    "Envoy label disappeared but exact container still exists",
                )?;
            }
        }
        for id in ids {
            self.checked(&inspect(id)?, id)?;
            docker(&["rm", "--force", id])?;
            let exact = format!("id={id}");
            require(
                docker(&["ps", "--all", "--quiet", "--no-trunc", "--filter", &exact])?.is_empty(),
                "Owned Envoy remained after removal",
            )?;
        }
        self.id = None;
        self.creation_attempted = false;
        Ok(())
    }

    pub(super) fn close_verified(&mut self) -> Result<(), String> {
        self.cleanup_container()?;
        remove_owned_files(&self.directory, &mut self.hashes)
    }
}

#[test]
fn missing_label_requires_separate_exact_id_absence_not_assumed_cleanup() {
    assert!(cleanup_candidates(Some("known"), &[]).unwrap());
    assert!(!cleanup_candidates(Some("known"), &["known"]).unwrap());
    assert!(!cleanup_candidates(None, &[]).unwrap());
    assert!(cleanup_candidates(Some("known"), &["different"]).is_err());
    assert!(cleanup_candidates(None, &["first", "second"]).is_err());
}

#[test]
fn exact_image_namespace_and_mount_checks_reject_ownership_mutations() {
    let id = "a".repeat(64);
    let owner = OwnedEnvoy {
        scope: "synthetic-owned-scope".into(),
        image: format!("sha256:{}", "b".repeat(64)),
        database: "unused-by-pure-check".into(),
        network: format!("container:{}", "c".repeat(64)),
        directory: std::env::temp_dir().join(format!("marty-envoy-check-{}", Uuid::new_v4())),
        hashes: BTreeMap::new(),
        id: None,
        creation_attempted: false,
        validate: true,
        selection: Selection::Candidate,
    };
    let original = json!({
        "Id":id,"Image":owner.image,
        "Config":{"Image":owner.image,"Labels":{LABEL:owner.scope},"Entrypoint":[BINARY],"Cmd":owner.command()},
        "HostConfig":{"NetworkMode":owner.network,"ReadonlyRootfs":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"PortBindings":{}},
        "NetworkSettings":{"Ports":{}},
        "Mounts":[
            {"Type":"bind","RW":false,"Source":owner.directory.join("candidate.yaml"),"Destination":CONFIG},
            {"Type":"bind","RW":false,"Source":owner.directory.join("descriptor.pb"),"Destination":DESCRIPTOR},
            {"Type":"bind","RW":false,"Source":owner.directory.join("canonical.yaml"),"Destination":"/etc/envoy/canonical-source.yaml"}
        ]
    });
    owner.checked(&original, &id).unwrap();
    for (pointer, replacement) in [
        ("/Id", json!("d".repeat(64))),
        ("/Image", json!("sha256:other")),
        ("/Config/Image", json!("mutable:latest")),
        (
            "/Config/Labels/com.elevenid.test.envoy-native",
            json!("other"),
        ),
        ("/Config/Cmd", json!(["other"])),
        ("/HostConfig/NetworkMode", json!("host")),
        ("/HostConfig/ReadonlyRootfs", json!(false)),
        (
            "/HostConfig/PortBindings",
            json!({"9000/tcp":[{"HostPort":"9000"}]}),
        ),
        ("/Mounts/0/RW", json!(true)),
        (
            "/Mounts/0/Source",
            json!(format!(
                "/foreign/{}",
                owner.directory.join("candidate.yaml").display()
            )),
        ),
        (
            "/Mounts/1/Destination",
            json!("/different/proto_descriptor.pb"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(owner.checked(&changed, &id).is_err(), "{pointer}");
    }
    let mut extra = original.clone();
    extra["Mounts"]
        .as_array_mut()
        .unwrap()
        .push(json!({"Destination":"/var/run/docker.sock"}));
    assert!(owner.checked(&extra, &id).is_err());
}

#[test]
fn explicit_file_cleanup_is_verified_and_preserves_changed_or_foreign_content() {
    let directory = std::env::temp_dir().join(format!("marty-envoy-cleanup-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("candidate.yaml");
    std::fs::write(&path, "original").unwrap();
    let mut hashes = BTreeMap::from([(path.clone(), digest(&path).unwrap())]);
    std::fs::write(&path, "changed").unwrap();
    assert!(remove_owned_files(&directory, &mut hashes)
        .unwrap_err()
        .contains("changed"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "changed");
    std::fs::write(&path, "original").unwrap();
    let unexpected = directory.join("foreign.txt");
    std::fs::write(&unexpected, "retain").unwrap();
    assert!(remove_owned_files(&directory, &mut hashes)
        .unwrap_err()
        .contains("directory cleanup failed"));
    assert!(absent(&path));
    assert_eq!(std::fs::read_to_string(&unexpected).unwrap(), "retain");
    // Test-created control is removed explicitly; the owner never deletes it.
    std::fs::remove_file(unexpected).unwrap();
    remove_owned_files(&directory, &mut hashes).unwrap();
    assert!(absent(&directory));
    remove_owned_files(&directory, &mut hashes).unwrap();
}

impl Drop for OwnedEnvoy {
    fn drop(&mut self) {
        if let Err(error) = self.close_verified() {
            eprintln!("Owned Envoy cleanup requires inspection: {error}");
        }
    }
}

#[test]
fn fixture_projection_preserves_every_field_except_fixture_socket_and_cadence() {
    let base = include_bytes!("../../../../../config/envoy/envoy.yaml");
    let candidate = render(base, marty_release_evidence::envoy_config::DESCRIPTOR).unwrap();
    for selection in [Selection::Candidate, Selection::Baseline] {
        let selected = if selection == Selection::Candidate {
            candidate.clone()
        } else {
            legacy_reference(&candidate).unwrap()
        };
        let mut changed = fixture_projection(&selected, selection);
        for cluster in changed["static_resources"]["clusters"]
            .as_array_mut()
            .unwrap()
        {
            if is_fixture_peer(cluster) {
                let native = cluster["name"] == NATIVE_CLUSTER;
                let auth = cluster["name"] == "auth_grpc";
                let address = &mut cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]
                    ["endpoint"]["address"]["socket_address"];
                assert_eq!(
                    *address,
                    json!({"address":"127.0.0.1","port_value":if native{9005}else if auth{19001}else{19005}})
                );
                *address = json!({"address":if native{"issuance-native"}else if auth{"auth"}else{"issuance"},"port_value":if auth{9001}else{9005}});
                assert_eq!(cluster["health_checks"][0]["no_traffic_interval"], "1s");
                assert_eq!(
                    cluster["health_checks"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("no_traffic_interval"),
                    Some(json!("1s"))
                );
            }
        }
        if selection == Selection::Baseline {
            assert_eq!(
                changed["static_resources"]["listeners"][0]["address"]["socket_address"]
                    ["port_value"],
                19000
            );
            assert_eq!(
                changed["admin"]["address"]["socket_address"]["port_value"],
                19901
            );
            changed["static_resources"]["listeners"][0]["address"]["socket_address"]
                ["port_value"] = json!(9000);
            changed["admin"]["address"]["socket_address"]["port_value"] = json!(9901);
        }
        assert_eq!(changed, selected);
        assert_eq!(
            parse(encode(&changed).unwrap().as_bytes()).unwrap(),
            selected
        );
    }
}

#[test]
fn feature_unified_renderer_emits_scalar_ports_for_external_yaml_consumers() {
    let source = include_bytes!("../../../../../config/envoy/envoy.yaml");
    let parsed = parse(source).unwrap();
    assert_eq!(
        parsed["static_resources"]["listeners"][0]["address"]["socket_address"]["port_value"]
            .as_u64(),
        Some(9000)
    );
    let candidate = render(source, marty_release_evidence::envoy_config::DESCRIPTOR).unwrap();
    let encoded = encode(&candidate).unwrap();
    assert!(!encoded.contains("$serde_json::private::Number"));
    // Independent YAML consumer must see scalar numeric nodes. A JSON-only
    // roundtrip can silently reconstruct the private Number marker instead.
    let yaml: serde_yaml::Value = serde_yaml::from_str(&encoded).unwrap();
    assert_eq!(
        yaml["static_resources"]["listeners"][0]["address"]["socket_address"]["port_value"]
            .as_u64(),
        Some(9000)
    );
    for cluster in yaml["static_resources"]["clusters"].as_sequence().unwrap() {
        assert!(
            cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
                ["socket_address"]["port_value"]
                .as_u64()
                .is_some()
        );
        assert_eq!(
            cluster["health_checks"][0]["healthy_threshold"].as_u64(),
            Some(2)
        );
    }
}
