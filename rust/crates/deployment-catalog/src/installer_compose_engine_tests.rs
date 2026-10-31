//! Explicit opt-in synthetic engine evidence, not signed-release or Marty
//! application qualification. Uses one already cached, supervisor-approved
//! immutable image and fresh private projects. Failure retains every artifact.
use crate::{
    installer_compose::{BoundFile, ComposeInputs, ComposeReceipt, ComposeSession},
    installer_runtime::DockerRunner,
    installer_state::{
        CandidateTestScope, Identity, InstallerState, LockedMaintenance, Phase, RuntimeBinding,
        RuntimeProfile,
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
fn need(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("synthetic Compose lifecycle assertion failed; preserve the printed private fixture scope".into())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn write(path: &Path, bytes: &[u8]) -> Result<BoundFile> {
    fs::write(path, bytes).map_err(|_| "cannot create private fixture input")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect fixture input")?;
    Ok(BoundFile {
        path: path.into(),
        sha256: hash(bytes),
    })
}

struct Fixture {
    path: PathBuf,
    docker: PathBuf,
    binding: RuntimeBinding,
    image: String,
    base: BoundFile,
    runtime: BoundFile,
    env: BoundFile,
    state: Option<InstallerState>,
}
impl Fixture {
    fn create() -> Result<Self> {
        crate::installer_command::require_rootless_process()?;
        let image = std::env::var("MARTY_INSTALLER_COMPOSE_FIXTURE_IMAGE")
            .map_err(|_| "set the already cached approved shell-capable image digest")?;
        need(image.split_once("@sha256:").is_some_and(|(_, d)| {
            d.len() == 64
                && d.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }))?;
        let engine = std::env::var("MARTY_INSTALLER_TEST_ENGINE_ID")
            .map_err(|_| "set the exact rootless engine ID")?;
        let docker = PathBuf::from(
            std::env::var("MARTY_INSTALLER_TEST_DOCKER")
                .unwrap_or_else(|_| "/usr/bin/docker".into()),
        );
        let parent = PathBuf::from(
            std::env::var("MARTY_INSTALLER_COMPOSE_FIXTURE_PARENT")
                .map_err(|_| "set the existing private qualification artifact directory")?,
        );
        need(
            parent.is_absolute()
                && parent
                    .canonicalize()
                    .map_err(|_| "fixture parent unavailable")?
                    == parent,
        )?;
        let temp = tempfile::Builder::new()
            .prefix("compose-native-")
            .tempdir_in(parent)
            .map_err(|_| "cannot create fixture directory")?;
        let root = temp.keep();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect fixture directory")?;
        eprintln!("Synthetic Compose evidence retained at {}", root.display());
        let path = root.join("installation");
        let binding = RuntimeBinding {
            docker_host: format!("unix:///run/user/{}/docker.sock", unsafe {
                libc::geteuid()
            }),
            engine_id: engine,
            openbao_port: 18443,
            profile: RuntimeProfile::Rootless,
        };
        let mut state = InstallerState::create_test_with_runtime(
            &path,
            Identity {
                source_sha: "0".repeat(40),
                release_tag: "v0.0.0".into(),
                inventory_sha256: format!("sha256:{}", "b".repeat(64)),
            },
            binding.clone(),
            CandidateTestScope {
                inventory_sha256: "b".repeat(64),
                build_run_id: 1,
                build_run_attempt: 1,
            },
        )?;
        state.create_private_directory("evidence")?;
        state.advance(Phase::Verified)?;
        state.advance(Phase::Provisioning)?;
        let data = path.join("state");
        fs::create_dir(&data).map_err(|_| "cannot create fixture state")?;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect fixture state")?;
        let base = write(&path.join("compose.yml"), BRIDGE.as_bytes())?;
        let runtime = write(
            &path.join("runtime.yml"),
            b"services:\n  app:\n    depends_on:\n      migrate: !reset null\n",
        )?;
        let env = write(
            &path.join("fixture.env"),
            format!("FIXTURE_IMAGE='{image}'\n").as_bytes(),
        )?;
        state.write_evidence("synthetic-fixture.json",&serde_json::to_vec(&json!({"schema":"elevenid.compose-native-synthetic-fixture/v1",
            "signed_release_admission":false,"application_qualification":false,"image":image,"source":"synthetic shell fixture; no application image rebuild", 
            "automatic_cleanup_on_failure":false,"host_data_retained":true})).map_err(|_|"fixture evidence encoding")?)?;
        let result = Self {
            path,
            docker,
            binding,
            image,
            base,
            runtime,
            env,
            state: Some(state),
        };
        let runner = result.runner()?;
        let resident: Vec<Value> =
            serde_json::from_str(&runner.run_checked(&["image", "inspect", &result.image])?)
                .map_err(|_| "cached image inspection invalid")?;
        need(resident.len() == 1)?;
        crate::installer_compose::validate_image_digest(&resident[0], &result.image)?;
        Ok(result)
    }
    fn runner(&self) -> Result<DockerRunner> {
        DockerRunner::from_binding(&self.docker, &self.binding, &self.path)
    }
    fn inputs(
        &self,
        profiles: &[&str],
        services: &[&str],
        prior: Option<ComposeReceipt>,
        runtime: bool,
    ) -> ComposeInputs {
        let mut files = vec![self.base.clone()];
        if runtime {
            files.push(self.runtime.clone());
        }
        let project = self
            .state
            .as_ref()
            .map(|s| s.journal().compose_project())
            .unwrap_or_else(|| prior.as_ref().unwrap().project.clone());
        ComposeInputs {
            installation: self.path.clone(),
            project,
            files,
            bound_inputs: Vec::new(),
            environment: self.env.clone(),
            profiles: profiles.iter().map(|s| (*s).into()).collect(),
            services: services.iter().map(|s| (*s).into()).collect(),
            approved_images: BTreeSet::from([self.image.clone()]),
            #[cfg(feature = "installer-development")]
            development_image: None,
            writable_bind_roots: BTreeSet::from([self.path.join("state")]),
            readonly_bind_roots: BTreeSet::new(),
            allowed_loopback_ports: BTreeSet::new(),
            prior,
        }
    }
    fn session(
        &self,
        profiles: &[&str],
        services: &[&str],
        prior: Option<ComposeReceipt>,
        runtime: bool,
    ) -> Result<ComposeSession> {
        ComposeSession::new(
            &self.docker,
            &self.binding,
            self.inputs(profiles, services, prior, runtime),
        )
        .map_err(|error| {
            format!(
                "synthetic Compose session construction failed (profiles={profiles:?}, services={services:?}): {error}"
            )
        })
    }
    fn state(&mut self) -> &mut InstallerState {
        self.state.as_mut().unwrap()
    }
    fn identity_snapshot(&self, receipt: &ComposeReceipt) -> Result<Value> {
        let ids: Vec<_> = receipt
            .resources
            .as_ref()
            .ok_or("fixture identity absent")?
            .containers
            .values()
            .map(|c| c.id.as_str())
            .collect();
        let mut args = vec!["inspect"];
        args.extend(ids);
        let rows: Vec<Value> = serde_json::from_str(&self.runner()?.run_checked(&args)?)
            .map_err(|_| "invalid fixture identities")?;
        Ok(Value::Array(
            rows.into_iter()
                .map(|v| {
                    json!({"Id":v["Id"],"Config":v["Config"],"HostConfig":v["HostConfig"],
            "StartedAt":v["State"]["StartedAt"],"RestartCount":v["RestartCount"]})
                })
                .collect(),
        ))
    }
    fn setup_snapshot(&self, receipt: &ComposeReceipt) -> Result<Value> {
        let mut jobs = receipt.clone();
        jobs.resources
            .as_mut()
            .ok_or("fixture resources missing")?
            .containers
            .retain(|_, c| c.setup);
        self.identity_snapshot(&jobs)
    }
    fn restart_existing(
        &mut self,
        receipt: ComposeReceipt,
        ordinal: u32,
    ) -> Result<ComposeReceipt> {
        // Exercise the production maintenance operations under their actual
        // exclusive maintenance lock. Ordinary start selects only the two
        // retained runtime services and never runs `up` or initialization.
        let stop_inputs = self.inputs(&["setup", "init", "runtime"], &[], Some(receipt), true);
        self.state.take();
        let mut locked = LockedMaintenance::open(&self.path)?;
        let stopped = ComposeSession::new(&self.docker, &self.binding, stop_inputs)?.stop(
            &mut locked,
            &format!("synthetic-stop-{ordinal:04}"),
            Duration::from_secs(5),
        )?;
        // The pinned native `config --hash '*'` requires the selected service's
        // profile explicitly; ordinary restart still excludes setup and init.
        let start_inputs = self.inputs(&["runtime"], &["database", "app"], Some(stopped), true);
        ComposeSession::new(&self.docker, &self.binding, start_inputs)?.start_existing(
            &mut locked,
            &format!("synthetic-start-{ordinal:04}"),
            Duration::from_secs(30),
        )
    }
    fn stop_down(&mut self, receipt: ComposeReceipt) -> Result<ComposeReceipt> {
        let inputs = self.inputs(&["setup", "init", "runtime"], &[], Some(receipt), true);
        self.state.take();
        let mut locked = LockedMaintenance::open(&self.path)?;
        let stop = ComposeSession::new(&self.docker, &self.binding, inputs.clone())?.stop(
            &mut locked,
            "stop",
            Duration::from_secs(5),
        )?;
        let mut down_inputs = inputs;
        down_inputs.prior = Some(stop);
        ComposeSession::new(&self.docker, &self.binding, down_inputs)?.down(
            &mut locked,
            "down",
            Duration::from_secs(5),
        )
    }
}

// Health and completion transitions are fixture workloads; only Compose waits
// for them. There is no Rust polling/scheduling loop or readiness wait script.
const BRIDGE: &str = r#"
x-common: &common
  image: ${FIXTURE_IMAGE:?explicit cached digest required}
  init: true
  user: "0:0"
  mem_limit: 64m
  read_only: true
  security_opt: ["no-new-privileges:true"]
  cap_drop: [ALL]
  entrypoint: [/bin/sh, -ec]
  restart: "no"
  volumes:
    - {type: bind, source: ./state, target: /data, bind: {create_host_path: false}}
    - {type: volume, source: preserved, target: /preserved}
  labels: {com.elevenid.installer.phase: runtime}
services:
  database:
    <<: *common
    command: ["sleep 2; touch /data/healthy; exec sleep 600"]
    healthcheck: {test: [CMD, /bin/sh, -ec, "test -f /data/healthy"], interval: 1s, timeout: 1s, retries: 20}
  credential:
    <<: *common
    profiles: [setup]
    labels: {com.elevenid.installer.phase: setup}
    command: ["test -f /data/healthy; test ! -f /data/credential; printf once > /data/credential"]
    depends_on: {database: {condition: service_healthy}}
  migrate:
    <<: *common
    profiles: [init]
    labels: {com.elevenid.installer.phase: setup}
    command: ["test -f /data/credential; test ! -f /data/migrated; printf once > /data/migrated; printf retained > /preserved/value"]
    depends_on: {database: {condition: service_healthy}}
  app:
    <<: *common
    profiles: [runtime]
    command: ["test -f /data/credential; test -f /data/migrated; exec sleep 600"]
    healthcheck: {test: [CMD, /bin/sh, -ec, "test -f /data/credential && test -f /data/migrated"], interval: 1s, timeout: 1s, retries: 10}
    depends_on:
      database: {condition: service_healthy}
      migrate: {condition: service_completed_successfully}
  failed:
    <<: *common
    profiles: [failure]
    labels: {com.elevenid.installer.phase: setup}
    command: ["printf attempted > /data/failed; exit 7"]
  blocked:
    <<: *common
    profiles: [failure]
    command: ["printf must-not-run > /data/blocked; exec sleep 600"]
    depends_on: {failed: {condition: service_completed_successfully}}
  uncertain:
    <<: *common
    profiles: [uncertain]
    labels: {com.elevenid.installer.phase: setup}
    command: ["printf must-not-run > /data/uncertain"]
  broken-runtime:
    <<: *common
    profiles: [runtime-failure]
    command: ["printf runtime-failed > /data/runtime-failed; exec sleep 600"]
    healthcheck: {test: [CMD, /bin/sh, -ec, "exit 1"], interval: 1s, timeout: 1s, retries: 1}
volumes:
  preserved: {}
"#;

#[test]
#[ignore = "explicit real rootless engine and cached shell image; creates two fresh synthetic projects, retains data and all evidence"]
fn actual_native_health_jobs_restart_and_neighbor_preservation() -> Result<()> {
    let mut neighbor = Fixture::create()?;
    let neighbor_receipt = neighbor.session(&[], &["database"], None, false)?.up_wait(
        neighbor.state(),
        "database",
        Duration::from_secs(30),
    )?;
    let neighbor_before = neighbor.identity_snapshot(&neighbor_receipt)?;
    let mut fixture = Fixture::create()?;
    let database = fixture.session(&[], &["database"], None, false)?.up_wait(
        fixture.state(),
        "database",
        Duration::from_secs(30),
    )?;
    let database_before = fixture.identity_snapshot(&database)?;
    let credential = fixture
        .session(&["setup"], &["credential"], Some(database.clone()), false)?
        .run_setup_job(fixture.state(), "credential")?;
    need(fixture.identity_snapshot(&database)? == database_before)?;
    need(
        fs::read(fixture.path.join("state/credential")).map_err(|_| "credential marker missing")?
            == b"once",
    )?;
    let repeat = fixture.session(&["setup"], &["credential"], Some(credential.clone()), false)?;
    need(repeat.run_setup_job(fixture.state(), "credential").is_err())?;
    let runtime = fixture
        .session(&["init", "runtime"], &["app"], Some(credential), false)?
        .up_wait(fixture.state(), "application", Duration::from_secs(30))?;
    let jobs_before = fixture.setup_snapshot(&runtime)?;
    let checkpoint = fixture
        .session(&["setup", "init", "runtime"], &[], Some(runtime), true)?
        .checkpoint(fixture.state(), "maintenance-union")?;
    let restarted = fixture.restart_existing(checkpoint, 1)?;
    need(fixture.setup_snapshot(&restarted)? == jobs_before)?;
    need(
        fs::read(fixture.path.join("state/migrated")).map_err(|_| "migration marker missing")?
            == b"once",
    )?;
    let restarted = fixture.restart_existing(restarted, 2)?;
    need(fixture.setup_snapshot(&restarted)? == jobs_before)?;
    need(
        fs::read(fixture.path.join("state/credential")).map_err(|_| "credential marker missing")?
            == b"once",
    )?;
    let down = fixture.stop_down(restarted)?;
    let retained = down.resources.as_ref().ok_or("cleanup receipt absent")?;
    need(
        retained.containers.is_empty()
            && retained.networks.is_empty()
            && retained.volumes.len() == 1,
    )?;
    need(
        fs::read(fixture.path.join("state/credential"))
            .map_err(|_| "retained host input missing")?
            == b"once",
    )?;
    need(neighbor.identity_snapshot(&neighbor_receipt)? == neighbor_before)?;
    neighbor
        .session(&[], &["database"], Some(neighbor_receipt.clone()), false)?
        .observe_resources()?;
    neighbor.stop_down(neighbor_receipt)?;
    Ok(())
}

#[test]
#[ignore = "explicit real rootless engine and cached shell image; failed scope is preserved for separately reviewed cleanup"]
fn actual_failed_dependency_and_uncertain_intent_do_not_run_dependents_or_repeat() -> Result<()> {
    let mut fixture = Fixture::create()?;
    let failing = fixture.session(&["failure"], &["blocked"], None, false)?;
    need(
        failing
            .up_wait(fixture.state(), "expected-failure", Duration::from_secs(30))
            .is_err(),
    )?;
    need(
        fs::read(fixture.path.join("state/failed")).map_err(|_| "failed job marker missing")?
            == b"attempted",
    )?;
    need(!fixture.path.join("state/blocked").exists())?;
    let failed: ComposeReceipt = serde_json::from_slice(
        &fs::read(
            fixture
                .path
                .join("evidence/compose-expected-failure-result.json"),
        )
        .map_err(|_| "failure receipt absent")?,
    )
    .map_err(|_| "failure receipt invalid")?;
    need(
        !failed.command_succeeded && failed.failure_class.is_some() && failed.observation_validated,
    )?;
    need(
        fixture
            .session(&["failure"], &["blocked"], Some(failed), false)
            .is_err(),
    )?;
    let mut uncertain = Fixture::create()?;
    let session = uncertain.session(&["uncertain"], &["uncertain"], None, false)?;
    uncertain.state().write_evidence(
        "compose-setup-uncertain-intent.json",
        b"{\"synthetic_uncertain_intent\":true,\"no_authority\":true}",
    )?;
    need(
        session
            .run_setup_job(uncertain.state(), "uncertain")
            .is_err(),
    )?;
    need(!uncertain.path.join("state/uncertain").exists())?;
    need(session.status()?.is_empty())?;
    Ok(())
}

#[test]
#[ignore = "explicit real rootless engine and cached shell image; failed runtime cleanup preserves data and neighboring project"]
fn actual_finite_runtime_failure_allows_only_bound_data_preserving_cleanup() -> Result<()> {
    let mut neighbor = Fixture::create()?;
    let neighbor_receipt = neighbor.session(&[], &["database"], None, false)?.up_wait(
        neighbor.state(),
        "database",
        Duration::from_secs(30),
    )?;
    let neighbor_before = neighbor.identity_snapshot(&neighbor_receipt)?;
    let mut fixture = Fixture::create()?;
    let database = fixture.session(&[], &["database"], None, false)?.up_wait(
        fixture.state(),
        "database",
        Duration::from_secs(30),
    )?;
    let credential = fixture
        .session(&["setup"], &["credential"], Some(database), false)?
        .run_setup_job(fixture.state(), "credential")?;
    let runtime = fixture
        .session(&["init", "runtime"], &["app"], Some(credential), false)?
        .up_wait(
            fixture.state(),
            "initial-application",
            Duration::from_secs(30),
        )?;
    let jobs_before = fixture.setup_snapshot(&runtime)?;
    let failing = fixture.session(
        &["runtime-failure"],
        &["broken-runtime"],
        Some(runtime),
        true,
    )?;
    need(
        failing
            .up_wait(fixture.state(), "application-up", Duration::from_secs(30))
            .is_err(),
    )?;
    let result_path = fixture
        .path
        .join("evidence/compose-application-up-result.json");
    let original = fs::read(&result_path).map_err(|_| "failed-runtime receipt absent")?;
    let failed: ComposeReceipt =
        serde_json::from_slice(&original).map_err(|_| "failed-runtime receipt invalid")?;
    need(
        !failed.command_succeeded
            && failed
                .client_exit_code
                .is_some_and(|code| (1..=125).contains(&code))
            && failed.failure_class.as_deref() == Some("client_exit_nonzero")
            && failed.observation_validated,
    )?;
    let inputs = fixture.inputs(
        &["setup", "init", "runtime", "runtime-failure"],
        &[],
        Some(failed.clone()),
        true,
    );
    need(ComposeSession::new(&fixture.docker, &fixture.binding, inputs.clone()).is_err())?;
    let cleanup = ComposeSession::for_failed_runtime_cleanup(
        &fixture.docker,
        &fixture.binding,
        inputs.clone(),
        None,
    )?;
    cleanup.observe_resources()?;
    need(cleanup.pull().is_err())?;
    need(
        cleanup
            .up_wait(fixture.state(), "forbidden-up", Duration::from_secs(30))
            .is_err(),
    )?;
    need(
        cleanup
            .run_setup_job(fixture.state(), "credential")
            .is_err(),
    )?;
    fixture.state.take();
    let mut locked = LockedMaintenance::open(&fixture.path)?;
    need(
        cleanup
            .start_existing(&mut locked, "forbidden-start", Duration::from_secs(30))
            .is_err(),
    )?;
    let stopped = cleanup.stop(&mut locked, "cleanup-stop", Duration::from_secs(5))?;
    need(stopped.schema == crate::installer_compose::CLEANUP_RECEIPT_SCHEMA)?;
    let mut cannot_promote = inputs;
    cannot_promote.prior = Some(stopped);
    need(ComposeSession::new(&fixture.docker, &fixture.binding, cannot_promote).is_err())?;
    need(fixture.setup_snapshot(&failed)? == jobs_before)?;
    let down = cleanup.down(&mut locked, "cleanup-down", Duration::from_secs(5))?;
    let retained = down
        .resources
        .as_ref()
        .ok_or("failed-runtime cleanup evidence absent")?;
    need(
        retained.containers.is_empty()
            && retained.networks.is_empty()
            && retained.volumes.len() == 1,
    )?;
    need(fs::read(&result_path).map_err(|_| "original failure evidence unavailable")? == original)?;
    need(
        fs::read(fixture.path.join("state/credential"))
            .map_err(|_| "retained credential marker absent")?
            == b"once",
    )?;
    need(
        !fixture
            .path
            .join("evidence/compose-forbidden-up-intent.json")
            .exists()
            && !fixture
                .path
                .join("evidence/uninstall-compose-forbidden-start-intent.json")
                .exists(),
    )?;
    need(neighbor.identity_snapshot(&neighbor_receipt)? == neighbor_before)?;
    neighbor.stop_down(neighbor_receipt)?;
    Ok(())
}
